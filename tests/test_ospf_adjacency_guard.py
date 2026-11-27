import copy
import threading

import pytest

import ospf_adjacency_guard as og

AREA = "0.0.0.0"
R1 = "2.2.2.2"


def guard(**kwargs):
    return og.OspfAdjacencyGuard(**kwargs)


def configured(**kwargs):
    instance = guard(**kwargs)
    instance.configure_interface("eth0", area_id=AREA)
    return instance


def hello(router_id=R1, hello_interval=10, dead_interval=40, **kwargs):
    return og.HelloPacket(router_id=router_id, area_id=AREA,
                          hello_interval=hello_interval,
                          dead_interval=dead_interval, **kwargs)


def lsa(seq, *, checksum="0x1111", age=0.0, lsa_type=1, link_state_id="10.0.0.0"):
    return og.Lsa(lsa_type=lsa_type, link_state_id=link_state_id,
                  adv_router=R1, seq=seq, checksum=checksum, age=age)


def test_hello_creates_neighbor_in_init_state():
    gate = configured()
    state = gate.process_hello("eth0", hello(), now=5.0)
    assert state.state == "init"
    assert state.router_id == R1
    assert state.iface == "eth0"
    assert state.area_id == AREA
    assert state.dead_at == 45.0
    assert gate.neighbor(R1, "eth0") == state
    assert gate.stats()["hellos"] == 1


def test_hello_interval_mismatch_refuses_to_form_neighbor():
    gate = configured()
    with pytest.raises(og.OspfError) as exc:
        gate.process_hello("eth0", hello(hello_interval=30), now=0.0)
    assert exc.value.code == "OSPF_HELLO_MISMATCH"
    assert gate.neighbors() == []
    assert gate.neighbor(R1, "eth0") is None


def test_authentication_mismatch_is_counted_and_creates_nothing():
    gate = guard()
    gate.configure_interface("eth0", area_id=AREA, auth_type=1, auth_data="s3cret")
    with pytest.raises(og.OspfError) as exc:
        gate.process_hello("eth0", hello(auth_type=1, auth_data="wrong"), now=0.0)
    assert exc.value.code == "OSPF_AUTH_FAILED"
    assert gate.neighbors() == []
    assert gate.stats()["auth_failures"] == 1


def test_repeated_hello_refreshes_dead_timer_without_duplicating():
    gate = configured()
    first = gate.process_hello("eth0", hello(), now=0.0)
    second = gate.process_hello("eth0", hello(), now=10.0)
    assert first.dead_at == 40.0
    assert second.dead_at == 50.0
    assert len(gate.neighbors()) == 1
    assert gate.stats()["hellos"] == 2


def test_dead_interval_demotes_neighbor_then_hello_revives_to_init():
    gate = configured()
    gate.process_hello("eth0", hello(), now=0.0)
    gate.age_tick(now=39.0)
    assert gate.neighbor(R1, "eth0").state == "init"
    gate.age_tick(now=40.0)
    assert gate.neighbor(R1, "eth0").state == "down"
    assert gate.stats()["neighbors_down"] == 1
    revived = gate.process_hello("eth0", hello(), now=41.0)
    assert revived.state == "init"
    assert revived.dead_at == 81.0


def test_new_lsa_is_stored_and_looked_up_by_triple():
    gate = guard()
    record = lsa(1)
    assert gate.load_lsa(record, now=0.0) == "loaded"
    assert gate.lookup_lsa(1, "10.0.0.0", R1) == record
    assert gate.lsdb() == [record]
    assert gate.stats()["lsa_loaded"] == 1


def test_higher_sequence_replaces_stored_instance():
    gate = guard()
    gate.load_lsa(lsa(1), now=0.0)
    assert gate.load_lsa(lsa(2, checksum="0x2222"), now=1.0) == "refreshed"
    stored = gate.lookup_lsa(1, "10.0.0.0", R1)
    assert stored.seq == 2
    assert stored.checksum == "0x2222"
    assert gate.stats()["lsa_refreshed"] == 1


def test_lower_sequence_is_reported_stale_and_kept_out():
    gate = guard()
    gate.load_lsa(lsa(5), now=0.0)
    assert gate.load_lsa(lsa(4), now=1.0) == "stale"
    assert gate.lookup_lsa(1, "10.0.0.0", R1).seq == 5
    assert gate.stats()["lsa_stale"] == 1


def test_same_sequence_and_checksum_is_a_duplicate():
    gate = guard()
    first = lsa(3)
    gate.load_lsa(first, now=0.0)
    assert gate.load_lsa(lsa(3), now=9.0) == "duplicate"
    assert gate.lookup_lsa(1, "10.0.0.0", R1) == first
    assert gate.stats()["lsa_duplicate"] == 1


def test_invalid_arguments_are_rejected():
    gate = guard()
    with pytest.raises(og.OspfError) as exc:
        gate.configure_interface("", area_id=AREA)
    assert exc.value.code == "OSPF_INVALID_ARGUMENT"
    with pytest.raises(og.OspfError) as exc:
        gate.load_lsa(lsa(-1), now=0.0)
    assert exc.value.code == "OSPF_INVALID_ARGUMENT"
    with pytest.raises(og.OspfError) as exc:
        gate.load_lsa(lsa(1, lsa_type=6), now=0.0)
    assert exc.value.code == "OSPF_INVALID_ARGUMENT"
    with pytest.raises(og.OspfError) as exc:
        gate.lookup_lsa(1, "  ", R1)
    assert exc.value.code == "OSPF_INVALID_ARGUMENT"


def test_aging_marks_max_age_and_flush_removes():
    gate = guard()
    gate.load_lsa(lsa(1, age=3590.0), now=0.0)
    assert gate.age_tick(now=5.0) == 0
    assert gate.age_tick(now=10.0) == 1
    assert gate.lookup_lsa(1, "10.0.0.0", R1) is not None
    assert gate.flush_max_age(now=10.0) == 1
    assert gate.lookup_lsa(1, "10.0.0.0", R1) is None
    assert gate.stats()["lsa_maxage"] == 1
    assert gate.stats()["lsa_flushed"] == 1


def test_concurrent_loads_keep_only_the_newest_instance():
    gate = guard()
    errors = []
    barrier = threading.Barrier(8)

    def worker(seq):
        try:
            barrier.wait(timeout=5)
            gate.load_lsa(lsa(seq), now=0.0)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(seq,)) for seq in range(1, 9)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(gate.lsdb()) == 1
    assert gate.lookup_lsa(1, "10.0.0.0", R1).seq == 8


def test_snapshot_is_detached_and_restore_roundtrips():
    gate = configured()
    gate.process_hello("eth0", hello(), now=0.0)
    gate.load_lsa(lsa(2), now=1.0)
    state = gate.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "neighbors", "lsdb", "maxage",
                             "overflow", "stats"}

    state["neighbors"].clear()
    state["stats"]["hellos"] = 999
    assert gate.neighbors() != []
    assert gate.stats()["hellos"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.neighbors()[0].state == "init"
    assert clone.lookup_lsa(1, "10.0.0.0", R1).seq == 2
    assert clone.stats() == gate.stats()


def test_restore_rejects_malformed_state_without_touching_live_data():
    gate = configured()
    gate.process_hello("eth0", hello(), now=0.0)
    gate.load_lsa(lsa(1), now=0.0)
    good = gate.snapshot()
    bad_states = [
        None,
        {},
        dict(good, version=2),
        dict(good, neighbors="nope"),
        dict(good, stats={"hellos": 1}),
        dict(good, lsdb={}),
    ]
    for bad in bad_states:
        with pytest.raises(og.OspfError) as exc:
            gate.restore(bad)
        assert exc.value.code == "OSPF_SNAPSHOT_INVALID"

    assert gate.stats()["hellos"] == 1
    assert gate.neighbors()[0].state == "init"
    assert gate.lookup_lsa(1, "10.0.0.0", R1).seq == 1


def test_stats_track_every_lsa_outcome():
    gate = configured()
    gate.process_hello("eth0", hello(), now=0.0)
    gate.load_lsa(lsa(1), now=1.0)
    gate.load_lsa(lsa(2), now=2.0)
    gate.load_lsa(lsa(1), now=3.0)
    gate.load_lsa(lsa(2), now=4.0)
    assert gate.stats() == {
        "hellos": 1,
        "neighbors_down": 0,
        "lsa_loaded": 1,
        "lsa_refreshed": 1,
        "lsa_stale": 1,
        "lsa_duplicate": 1,
        "lsa_conflict": 0,
        "lsa_maxage": 0,
        "lsa_flushed": 0,
        "auth_failures": 0,
    }
