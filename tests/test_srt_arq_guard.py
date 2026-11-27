import threading

import pytest

import srt_arq_guard as srt


def guard(**kwargs):
    return srt.SrtArqGuard(**kwargs)


def connected(g, stream_id="s1", **listener_kwargs):
    g.open_listener(stream_id, **listener_kwargs)
    return g.connect_caller(stream_id,
                            passphrase=listener_kwargs.get("passphrase"))


def test_open_listener_rejects_invalid_stream_id():
    g = guard()
    for bad_id in ("", "   ", "x" * 65):
        with pytest.raises(srt.SrtError) as exc:
            g.open_listener(bad_id)
        assert exc.value.code == "SRT_INVALID_REQUEST"
    assert g.stats()["submitted"] == 0


def test_duplicate_stream_and_capacity_rejected():
    g = guard(max_streams=1)
    g.open_listener("alpha")
    with pytest.raises(srt.SrtError) as exc:
        g.open_listener("alpha")
    assert exc.value.code == "SRT_STREAM_EXISTS"
    with pytest.raises(srt.SrtError) as exc:
        g.open_listener("beta")
    assert exc.value.code == "SRT_CAPACITY_EXCEEDED"


def test_handshake_never_downgrades_to_plaintext():
    g = guard()
    g.open_listener("s1", passphrase="s3cret")
    with pytest.raises(srt.SrtError) as exc:
        g.connect_caller("s1")
    assert exc.value.code == "SRT_HANDSHAKE_FAILED"
    with pytest.raises(srt.SrtError) as exc:
        g.connect_caller("s1", passphrase="wrong")
    assert exc.value.code == "SRT_HANDSHAKE_FAILED"
    assert g.stream_state("s1") == "listening"
    caller = g.connect_caller("s1", passphrase="s3cret")
    assert caller.state == "connected"
    assert caller.role == "caller"


def test_connect_marks_stream_connected():
    g = guard()
    g.open_listener("s1")
    caller = g.connect_caller("s1")
    assert caller.state == "connected"
    assert caller.initial_seq == 0
    assert g.stream_state("s1") == "connected"


def test_submit_requires_connected_stream():
    g = guard()
    g.open_listener("s1")
    with pytest.raises(srt.SrtError) as exc:
        g.submit_packet("s1", "payload")
    assert exc.value.code == "SRT_STREAM_STATE"
    assert g.stats()["submitted"] == 0


def test_submit_assigns_monotonic_sequence():
    g = guard()
    connected(g)
    packets = [g.submit_packet("s1", index, now=index) for index in range(3)]
    assert [packet.sequence for packet in packets] == [0, 1, 2]
    assert [packet.retransmits for packet in packets] == [0, 0, 0]
    assert [packet.delivered for packet in packets] == [False, False, False]
    assert packets[1].submitted_at == 1


def test_sequence_wraps_at_32_bits():
    g = guard()
    start = srt.SEQ_MODULUS - 2
    connected(g, initial_seq=start)
    sequences = [g.submit_packet("s1", index).sequence for index in range(3)]
    assert sequences == [start, srt.SEQ_MODULUS - 1, 0]


def test_full_window_queues_instead_of_dropping():
    g = guard()
    connected(g, window=2)
    for index in range(4):
        g.submit_packet("s1", index)
    assert len(g.pending_packets("s1")) == 4
    assert g.stats()["submitted"] == 4
    assert g.stats()["queued"] == 2


def test_ack_advances_window_and_duplicate_ack_is_noop():
    g = guard()
    connected(g)
    for index in range(3):
        g.submit_packet("s1", index)
    state = g.handle_ack("s1", 1)
    assert state.ack_seq == 1
    assert state.acked_packets == 2
    assert state.pending == 1
    assert g.pending_packets("s1") == (2,)
    again = g.handle_ack("s1", 1)
    assert again.acked_packets == 0
    assert again.pending == 1
    assert g.stats()["acked"] == 2


def test_ack_beyond_submitted_is_rejected():
    g = guard()
    connected(g)
    g.submit_packet("s1", "a")
    g.submit_packet("s1", "b")
    with pytest.raises(srt.SrtError) as exc:
        g.handle_ack("s1", 5)
    assert exc.value.code == "SRT_ACK_INVALID"
    assert g.pending_packets("s1") == (0, 1)


def test_nak_retransmit_budget_then_too_late():
    g = guard(max_retransmits=2)
    connected(g)
    packet = g.submit_packet("s1", "payload")
    first = g.handle_nak("s1", packet.sequence)
    assert first.retransmits == 1
    second = g.handle_nak("s1", packet.sequence)
    assert second.retransmits == 2
    assert g.handle_nak("s1", packet.sequence) is None
    assert g.retransmit_count("s1") == 2
    assert g.too_late_count("s1") == 1
    assert g.pending_packets("s1") == ()


def test_receive_packet_discards_duplicate_sequence():
    g = guard()
    connected(g)
    assert g.receive_packet("s1", 5, "payload", now=0) is True
    assert g.receive_packet("s1", 5, "payload", now=1) is False


def test_out_of_order_receive_delivers_in_sequence_order():
    g = guard()
    connected(g)
    assert g.receive_packet("s1", 2, "c", now=0) is True
    assert g.receive_packet("s1", 0, "a", now=0) is True
    assert g.receive_packet("s1", 1, "b", now=0) is True
    packets = g.deliver("s1", now=1000)
    assert [packet.sequence for packet in packets] == [0, 1, 2]
    assert [packet.payload for packet in packets] == ["a", "b", "c"]
    assert g.deliver("s1", now=1000) == ()


def test_snapshot_restore_preserves_sequence_space():
    g = guard()
    connected(g)
    g.submit_packet("s1", "a")
    g.submit_packet("s1", "b")
    state = g.snapshot()

    clone = guard()
    clone.restore(state)
    assert clone.stream_state("s1") == "connected"
    assert clone.pending_packets("s1") == (0, 1)
    assert clone.submit_packet("s1", "c").sequence == 2
    with pytest.raises(srt.SrtError) as exc:
        clone.restore({})
    assert exc.value.code == "SRT_SNAPSHOT_INVALID"
    assert clone.pending_packets("s1") == (0, 1, 2)


def test_concurrent_submit_issues_unique_sequences():
    g = guard()
    connected(g)
    sequences = []
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            packet = g.submit_packet("s1", index, now=0)
            sequences.append(packet.sequence)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(sequences) == list(range(8))
    assert g.stats()["submitted"] == 8
    assert g.pending_packets("s1") == tuple(range(8))
