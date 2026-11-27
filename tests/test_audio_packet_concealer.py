import threading

import pytest

import audio_packet_concealer as ac


def concealer(**kwargs):
    return ac.AudioPacketConcealer(**kwargs)


def samples(value, count=8):
    return [value] * count


def test_push_starts_a_stream():
    c = concealer(frame_samples=8)
    assert c.push("a", 10, samples(0)) == 0
    assert c.gap_ranges("a") == ()
    timeline = c.timeline("a")
    assert len(timeline) == 1
    slot = timeline[0]
    assert (slot.seq, slot.kind) == (10, "real")
    assert slot.samples == (0,) * 8
    assert c.stats()["injected"] == 1


def test_gap_ranges_reports_missing_sequence_numbers():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 1, samples(1))
    c.push("a", 4, samples(1))
    assert c.gap_ranges("a") == ((2, 3),)
    assert c.gap_ranges("missing") == ()


def test_late_packet_inside_window_fills_gap_before_conceal():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 1, samples(1))
    c.push("a", 4, samples(1))
    assert c.push("a", 2, samples(2)) == 2
    assert c.gap_ranges("a") == ((3, 3),)
    timeline = c.timeline("a")
    assert [slot.seq for slot in timeline] == [0, 1, 2, 4]


def test_conceal_fills_each_gap_only_once():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 1, samples(1))
    c.push("a", 4, samples(1))
    assert c.conceal("a") == 2
    assert c.conceal("a") == 0
    timeline = c.timeline("a")
    assert [slot.seq for slot in timeline] == [0, 1, 2, 3, 4]
    assert [slot.kind for slot in timeline] == [
        "real", "real", "conceal", "conceal", "real"]


def test_conceal_repeats_the_pitch_period():
    pattern = [3, -2, 5, 0, 3, -2, 5, 0]
    c = concealer(frame_samples=8)
    c.push("a", 0, pattern)
    c.push("a", 2, pattern)
    assert c.conceal("a") == 1
    fake = c.timeline("a")[1]
    assert fake.kind == "conceal"
    assert fake.samples == tuple(pattern)


def test_long_gap_switches_to_silence_after_limit():
    c = concealer(frame_samples=8, max_conceal=3)
    c.push("a", 0, samples(4))
    c.push("a", 7, samples(4))
    assert c.conceal("a") == 6
    timeline = c.timeline("a")
    assert [slot.kind for slot in timeline] == [
        "real", "conceal", "conceal", "conceal",
        "silence", "silence", "silence", "real"]
    assert timeline[4].samples == (0,) * 8
    assert timeline[3].samples == (4,) * 8


def test_max_conceal_is_per_stream():
    c = concealer(frame_samples=8, max_conceal=3)
    c.set_max_conceal("a", 1)
    c.push("a", 0, samples(4))
    c.push("a", 7, samples(4))
    c.push("b", 0, samples(4))
    c.push("b", 7, samples(4))
    c.conceal("a")
    c.conceal("b")
    a_kinds = [slot.kind for slot in c.timeline("a")]
    b_kinds = [slot.kind for slot in c.timeline("b")]
    assert a_kinds == ["real", "conceal"] + ["silence"] * 5 + ["real"]
    assert b_kinds == ["real"] + ["conceal"] * 3 + ["silence"] * 3 + ["real"]
    with pytest.raises(ac.AudioConcealError) as exc:
        c.set_max_conceal("a", -1)
    assert exc.value.code == "AUDIO_INVALID_LIMIT"


def test_late_packet_replaces_fake_slot():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 1, samples(1))
    c.push("a", 4, samples(1))
    c.conceal("a")
    before = c.timeline("a")
    assert c.push("a", 2, samples(9)) == 2
    timeline = c.timeline("a")
    assert len(timeline) == len(before) == 5
    assert timeline[2].seq == 2
    assert timeline[2].kind == "real"
    assert timeline[2].samples == (9,) * 8
    assert c.stats()["replaced"] == 1


def test_duplicate_and_out_of_window_packets():
    c = concealer(frame_samples=8, reorder_window=4)
    c.push("a", 10, samples(1))
    c.push("a", 10, samples(2))
    assert c.stats()["duplicates"] == 1
    assert c.timeline("a")[0].samples == (1,) * 8
    with pytest.raises(ac.AudioConcealError) as exc:
        c.push("a", 5, samples(1))
    assert exc.value.code == "AUDIO_SEQ_REGRESSION"
    with pytest.raises(ac.AudioConcealError) as exc:
        c.push("a", -1, samples(1))
    assert exc.value.code == "AUDIO_INVALID_SEQ"
    with pytest.raises(ac.AudioConcealError) as exc:
        c.push("", 11, samples(1))
    assert exc.value.code == "AUDIO_INVALID_STREAM"
    with pytest.raises(ac.AudioConcealError) as exc:
        c.push("a", 11, samples(1, 7))
    assert exc.value.code == "AUDIO_BAD_FRAME"


def test_history_keeps_a_fixed_length():
    c = concealer(frame_samples=4, history_frames=3)
    for i in range(6):
        c.push("x", i, samples(i, 4))
    history = c.history("x")
    assert len(history) == 3
    assert tuple(packet[0] for packet in history) == (3, 4, 5)


def test_streams_are_isolated():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 1, samples(1))
    c.push("a", 4, samples(1))
    c.push("b", 0, samples(1))
    assert c.gap_ranges("a") == ((2, 3),)
    assert c.gap_ranges("b") == ()
    c.conceal("a")
    assert len(c.timeline("a")) == 5
    assert len(c.timeline("b")) == 1
    assert c.stats()["streams"] == 2
    assert c.stats()["injected"] == 4
    assert c.stats()["concealed"] == 2


def test_stats_after_conceal_and_replacement():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 1, samples(1))
    c.push("a", 4, samples(1))
    c.conceal("a")
    c.push("a", 2, samples(2))
    assert c.stats() == {"streams": 1, "injected": 4, "concealed": 2,
                         "silenced": 0, "replaced": 1, "duplicates": 0}


def test_snapshot_is_deep_copy_and_restore_resumes():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    c.push("a", 3, samples(2))
    c.conceal("a")
    snap = c.snapshot()
    assert snap["version"] == 1
    assert snap["streams"]["a"]["highest"] == 3
    assert len(snap["streams"]["a"]["slots"]) == 4
    snap["streams"]["a"]["slots"].append([99, "real", [0] * 8])
    assert len(c.timeline("a")) == 4
    q = concealer(frame_samples=8)
    q.restore(c.snapshot())
    assert q.timeline("a") == c.timeline("a")
    assert q.gap_ranges("a") == c.gap_ranges("a")
    assert q.stats() == c.stats()


def test_restore_rejects_bad_state_without_change():
    c = concealer(frame_samples=8)
    c.push("a", 0, samples(1))
    before = c.snapshot()
    for bad in ({"version": 2}, {"version": 1, "streams": "no"}, None):
        with pytest.raises(ac.AudioConcealError) as exc:
            c.restore(bad)
        assert exc.value.code == "AUDIO_SNAPSHOT_INVALID"
    assert c.snapshot() == before


def test_parallel_streams_stay_isolated():
    c = concealer(frame_samples=8)

    def worker(sid):
        for i in range(10):
            c.push(sid, i, samples(i))

    threads = [threading.Thread(target=worker, args=(sid,)) for sid in ("x", "y")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(c.timeline("x")) == 10
    assert len(c.timeline("y")) == 10
    assert c.gap_ranges("x") == ()
    assert c.gap_ranges("y") == ()
    assert c.stats()["streams"] == 2
    assert c.stats()["injected"] == 20
