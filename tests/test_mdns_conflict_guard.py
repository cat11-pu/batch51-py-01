import threading

import pytest

import mdns_conflict_guard as md

NOW = 1000
NAME = "printer"
TYPE = "_ipp._tcp"
IFACE = "eth0"


def guard(**kwargs):
    return md.MdnsConflictGuard(**kwargs)


def add(g, instance="i1", name=NAME, service_type=TYPE, port=631,
        iface=IFACE, target="10.0.0.5", unique=True):
    return g.register_instance(instance, name=name, service_type=service_type,
                               port=port, iface=iface, target=target,
                               unique=unique, now=NOW)


def observed(target="10.0.0.9", port=631, name=NAME, service_type=TYPE):
    return {"name": name, "service_type": service_type,
            "target": target, "port": port}


def test_register_instance_is_scoped_by_interface():
    g = guard()
    first = add(g)
    second = add(g, instance="i2", iface="eth1", target="10.0.0.6")
    assert (first.name, first.service_type, first.port, first.iface) == (
        NAME, TYPE, 631, IFACE)
    assert first.unique is True
    assert g.instance_record("i1") == first
    assert g.instance_record("missing") is None
    assert g.records_for(IFACE) == (first,)
    assert g.records_for("eth1") == (second,)
    assert g.records_for("eth2") == ()
    assert g.resolve(NAME, TYPE, IFACE) == (first,)


def test_shared_records_coexist_and_resolve_sorted():
    g = guard()
    later = add(g, instance="i9", unique=False)
    earlier = add(g, instance="i3", unique=False, target="10.0.0.7")
    assert g.resolve(NAME, TYPE, IFACE) == (earlier, later)
    assert [row.instance for row in g.records_for(IFACE)] == ["i3", "i9"]


def test_duplicate_unique_name_is_refused():
    g = guard()
    add(g)
    with pytest.raises(md.MdnsError) as exc:
        add(g, instance="i2", target="10.0.0.8")
    assert exc.value.code == "MDNS_NAME_TAKEN"
    assert g.resolve(NAME, TYPE, IFACE) == (g.instance_record("i1"),)


def test_begin_probe_starts_countdown():
    g = guard()
    state = g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    assert (state.state, state.remaining) == ("probing", 3)
    assert state.next_probe_at == NOW + 250
    assert state.announced_at is None
    assert g.probe_state(NAME, TYPE, IFACE) == state
    with pytest.raises(md.MdnsError) as exc:
        g.begin_probe(NAME, TYPE, IFACE, now=NOW + 10)
    assert exc.value.code == "MDNS_NAME_TAKEN"


def test_tick_before_deadline_does_nothing():
    g = guard()
    g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    assert g.tick(NOW + 249) == 0
    state = g.probe_state(NAME, TYPE, IFACE)
    assert (state.state, state.remaining, state.next_probe_at) == (
        "probing", 3, NOW + 250)
    assert g.stats()["probes"] == 0


def test_tick_promotes_after_last_probe():
    g = guard(probe_count=2)
    g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    assert g.tick(NOW + 250) == 1
    state = g.probe_state(NAME, TYPE, IFACE)
    assert (state.state, state.remaining, state.next_probe_at) == (
        "probing", 1, NOW + 500)
    assert g.tick(NOW + 500) == 1
    state = g.probe_state(NAME, TYPE, IFACE)
    assert (state.state, state.remaining) == ("announced", 0)
    assert state.next_probe_at is None
    assert state.announced_at == NOW + 500
    assert g.stats()["probes"] == 2
    assert g.stats()["announced"] == 1


def test_announce_only_after_claim_and_then_defends():
    g = guard(probe_count=1)
    g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    assert g.announce(NAME, TYPE, IFACE, now=NOW + 100) is False
    assert g.probe_state(NAME, TYPE, IFACE).state == "probing"
    assert g.tick(NOW + 250) == 1
    assert g.announce(NAME, TYPE, IFACE, now=NOW + 400) is True
    state = g.probe_state(NAME, TYPE, IFACE)
    assert state.state == "announced"
    assert state.announced_at == NOW + 400
    assert g.defend(NAME, TYPE, IFACE) == "defend"


def test_observe_identical_record_is_duplicate_only():
    g = guard()
    add(g)
    assert g.observe(observed(target="10.0.0.5"), IFACE, now=NOW) == "duplicate"
    assert g.instance_record("i1").name == NAME
    assert g.stats()["conflicts"] == 0
    assert g.probe_state(NAME, TYPE, IFACE) is None


def test_observe_conflict_renames_and_reprobes():
    g = guard()
    add(g)
    assert g.observe(observed(), IFACE, now=NOW) == "conflict"
    record = g.instance_record("i1")
    assert record.name == "printer-2"
    state = g.probe_state("printer-2", TYPE, IFACE)
    assert (state.state, state.remaining, state.next_probe_at) == (
        "probing", 3, NOW + 250)
    assert g.resolve(NAME, TYPE, IFACE) == ()
    assert g.resolve("printer-2", TYPE, IFACE) == (record,)
    assert g.stats()["conflicts"] == 1


def test_cache_flush_marks_and_clears_once():
    g = guard()
    record = add(g)
    add(g, instance="i2", name="scanner")
    assert g.mark_cache_flush(NAME, TYPE, IFACE) == 1
    assert g.take_flushed(IFACE) == (record,)
    assert g.take_flushed(IFACE) == ()
    assert g.stats()["flushed"] == 1
    assert g.resolve(NAME, TYPE, IFACE) == (record,)


def test_records_per_interface_are_capped():
    g = guard(max_records_per_interface=2)
    add(g, instance="i1", unique=False)
    add(g, instance="i2", unique=False, target="10.0.0.7")
    with pytest.raises(md.MdnsError) as exc:
        add(g, instance="i3", name="scanner")
    assert exc.value.code == "MDNS_CAPACITY_EXCEEDED"
    assert [row.instance for row in g.records_for(IFACE)] == ["i1", "i2"]


def test_stats_track_each_step():
    g = guard(probe_count=2)
    g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    g.tick(NOW + 250)
    g.tick(NOW + 500)
    add(g)
    g.observe(observed(target="10.0.0.5"), IFACE, now=NOW)
    g.observe(observed(name="other"), IFACE, now=NOW)
    assert g.release(NAME, TYPE, IFACE) is True
    assert g.stats() == {
        "probes": 2,
        "announced": 1,
        "conflicts": 0,
        "released": 1,
        "refreshed": 1,
        "flushed": 0,
    }


def test_snapshot_restore_keeps_remaining_probes():
    g = guard(probe_count=3)
    record = add(g)
    g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    g.tick(NOW + 250)
    state = g.snapshot()
    assert set(state) == {"version", "instances", "states", "flushed", "stats"}
    state["states"].clear()
    assert g.probe_state(NAME, TYPE, IFACE).remaining == 2

    clone = guard(probe_count=3)
    clone.restore(g.snapshot())
    restored = clone.probe_state(NAME, TYPE, IFACE)
    assert (restored.remaining, restored.next_probe_at) == (2, NOW + 500)
    assert clone.resolve(NAME, TYPE, IFACE) == (record,)
    assert clone.tick(NOW + 500) == 1
    assert clone.probe_state(NAME, TYPE, IFACE).remaining == 1
    assert clone.tick(NOW + 750) == 1
    assert clone.probe_state(NAME, TYPE, IFACE).state == "announced"
    assert clone.stats()["announced"] == 1


def test_restore_rejects_malformed_state_without_touching_live_state():
    g = guard()
    add(g)
    g.begin_probe(NAME, TYPE, IFACE, now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "instances": {}, "states": {}, "flushed": {}, "stats": {}},
        {"version": 1, "instances": [], "states": {}, "flushed": {}, "stats": {}},
        {"version": 1, "instances": {}, "states": [], "flushed": {}, "stats": {}},
        {"version": 1, "instances": {}, "states": {}, "flushed": {}},
    ]
    for bad in bad_states:
        with pytest.raises(md.MdnsError) as exc:
            g.restore(bad)
        assert exc.value.code == "MDNS_SNAPSHOT_INVALID"
    assert g.probe_state(NAME, TYPE, IFACE).remaining == 3
    assert g.instance_record("i1") is not None


def test_concurrent_probe_has_single_claimant():
    g = guard()
    winners = []
    failures = []
    barrier = threading.Barrier(2)

    def worker():
        try:
            barrier.wait(timeout=5)
            g.begin_probe(NAME, TYPE, IFACE, now=NOW)
            winners.append("ok")
        except Exception as exc:  # pragma: no cover - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert winners == ["ok"]
    assert len(failures) == 1
    assert isinstance(failures[0], md.MdnsError)
    assert failures[0].code == "MDNS_NAME_TAKEN"
    assert g.probe_state(NAME, TYPE, IFACE).remaining == 3
    assert g.stats()["probes"] == 0
