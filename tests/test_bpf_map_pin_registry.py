import copy
import threading

import pytest

import bpf_map_pin_registry as bpf

PIN = "/sys/fs/bpf/t1/conn_map"


def new_reg(**kwargs):
    return bpf.BpfMapPinRegistry(**kwargs)


def pin(reg, path=PIN, *, tenant="t1", map_id="map-a", owner_pid=100,
        owner_start=1000):
    return reg.pin(path, tenant=tenant, map_id=map_id, owner_pid=owner_pid,
                   owner_start=owner_start)


def test_pin_records_owner_and_lists_by_tenant():
    reg = new_reg()
    first = pin(reg)
    second = pin(reg, "/sys/fs/bpf/t2/other_map", tenant="t2", map_id="map-b",
                 owner_pid=200, owner_start=2000)
    assert first.path == PIN
    assert (first.tenant, first.map_id, first.owner_pid,
            first.owner_start) == ("t1", "map-a", 100, 1000)
    assert first.refcount == 0
    assert reg.lookup(PIN) == first
    assert reg.refcount(PIN) == 0
    assert [row.path for row in reg.list_pins("t1")] == [PIN]
    assert [row.path for row in reg.list_pins("t2")] == [second.path]
    assert reg.list_pins("t9") == ()
    assert reg.stats()["pinned"] == 2


def test_pin_rejects_duplicate_path_across_tenants():
    reg = new_reg()
    pin(reg)
    with pytest.raises(bpf.BpfError) as exc:
        pin(reg, map_id="map-other")
    assert exc.value.code == "BPF_PIN_EXISTS"
    with pytest.raises(bpf.BpfError) as exc:
        pin(reg, tenant="t2", owner_pid=200, owner_start=2000)
    assert exc.value.code == "BPF_PIN_EXISTS"
    assert reg.lookup(PIN).tenant == "t1"
    assert reg.stats()["pinned"] == 1
    assert reg.stats()["refused"] == 2


def test_pin_validates_input():
    reg = new_reg()
    bad_calls = [
        dict(path=""),
        dict(path="relative/pin"),
        dict(path="/trailing/pin/"),
        dict(path="/has space"),
        dict(path=7),
        dict(path="/pin", tenant=""),
        dict(path="/pin", map_id=""),
        dict(path="/pin", owner_pid=0),
        dict(path="/pin", owner_start=0),
    ]
    for kwargs in bad_calls:
        path = kwargs.pop("path")
        with pytest.raises(bpf.BpfError) as exc:
            reg.pin(path, tenant=kwargs.get("tenant", "t1"),
                    map_id=kwargs.get("map_id", "map-a"),
                    owner_pid=kwargs.get("owner_pid", 1),
                    owner_start=kwargs.get("owner_start", 1))
        assert exc.value.code == "BPF_INVALID_REQUEST"
    assert reg.list_pins("t1") == ()
    assert reg.stats()["pinned"] == 0
    assert reg.stats()["refused"] == len(bad_calls)


def test_open_unknown_path_is_rejected():
    reg = new_reg()
    with pytest.raises(bpf.BpfError) as exc:
        reg.open_pinned("/pin/ghost", tenant="t1", pid=1, start=10)
    assert exc.value.code == "BPF_PIN_NOT_FOUND"
    assert reg.stats()["opened"] == 0
    assert reg.stats()["refused"] == 1


def test_open_is_tenant_scoped_until_granted():
    reg = new_reg()
    pin(reg)
    owner_handle = reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    assert reg.refcount(PIN) == 1
    with pytest.raises(bpf.BpfError) as exc:
        reg.open_pinned(PIN, tenant="t2", pid=200, start=2000)
    assert exc.value.code == "BPF_TENANT_DENIED"
    assert reg.refcount(PIN) == 1

    reg.grant_cross_tenant(PIN, "t2")
    reg.grant_cross_tenant(PIN, "t2")
    guest_handle = reg.open_pinned(PIN, tenant="t2", pid=200, start=2000)
    assert guest_handle != owner_handle
    assert reg.refcount(PIN) == 2
    assert reg.list_pins("t2") == ()
    assert reg.stats()["opened"] == 2
    assert reg.stats()["refused"] == 1


def test_open_twice_and_close_decrements_refcount():
    reg = new_reg()
    pin(reg)
    first = reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    second = reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    assert first != second
    assert reg.refcount(PIN) == 2
    assert reg.openers(PIN) == ((100, 1000, "t1"), (100, 1000, "t1"))
    assert reg.close_handle(first) is True
    assert reg.refcount(PIN) == 1
    assert reg.lookup(PIN) is not None
    assert reg.close_handle(first) is False
    assert reg.refcount(PIN) == 1
    assert reg.close_handle(second) is True
    assert reg.refcount(PIN) == 0
    assert reg.close_handle(second) is False
    assert reg.stats()["opened"] == 2
    assert reg.stats()["closed"] == 2


def test_unpin_refused_while_open_then_succeeds():
    reg = new_reg()
    pin(reg)
    handle = reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    with pytest.raises(bpf.BpfError) as exc:
        reg.unpin(PIN, tenant="t1")
    assert exc.value.code == "BPF_PIN_BUSY"
    assert reg.lookup(PIN) is not None
    assert reg.close_handle(handle) is True
    assert reg.unpin(PIN, tenant="t1") is True
    assert reg.lookup(PIN) is None
    assert reg.unpin(PIN, tenant="t1") is False
    assert reg.stats()["unpinned"] == 1


def test_unpin_wrong_tenant_is_denied():
    reg = new_reg()
    pin(reg)
    with pytest.raises(bpf.BpfError) as exc:
        reg.unpin(PIN, tenant="t2")
    assert exc.value.code == "BPF_TENANT_DENIED"
    assert reg.lookup(PIN) is not None
    assert reg.stats()["unpinned"] == 0


def test_reclaim_orphans_removes_dead_owners_only():
    reg = new_reg()
    pin(reg, "/pin/dead", owner_pid=10, owner_start=100)
    pin(reg, "/pin/alive", tenant="t2", owner_pid=20, owner_start=200)
    assert reg.reclaim_orphans(lambda pid, start: pid == 20) == ("/pin/dead",)
    assert reg.lookup("/pin/dead") is None
    assert reg.lookup("/pin/alive") is not None
    assert reg.stats()["reclaimed"] == 1
    assert reg.reclaim_orphans(lambda pid, start: True) == ()


def test_scan_marks_stale_and_quarantines_unregistered():
    reg = new_reg()
    pin(reg, "/pin/a")
    pin(reg, "/pin/b", tenant="t2", owner_pid=200, owner_start=2000)
    result = reg.scan(["/pin/b", "/pin/c"])
    assert result == {"stale": ("/pin/a",), "quarantined": ("/pin/c",)}
    assert reg.lookup("/pin/a") is None
    assert reg.lookup("/pin/b") is not None
    assert reg.lookup("/pin/c") is None
    assert reg.quarantined() == ("/pin/c",)
    again = reg.scan(["/pin/b", "/pin/c", "/pin/d"])
    assert again == {"stale": (), "quarantined": ("/pin/d",)}
    assert reg.quarantined() == ("/pin/c", "/pin/d")
    assert reg.stats()["quarantined"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    reg = new_reg()
    pin(reg)
    handle = reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    reg.grant_cross_tenant(PIN, "t2")
    reg.scan([PIN, "/pin/new"])
    state = reg.snapshot()
    assert set(state) == {"version", "pins", "handles", "grants", "quarantine",
                          "next_handle", "stats"}
    pristine = copy.deepcopy(state)
    state["pins"].clear()
    state["stats"]["pinned"] = 99
    assert reg.lookup(PIN) is not None
    assert reg.refcount(PIN) == 1
    assert reg.stats()["pinned"] == 1

    clone = new_reg()
    clone.restore(pristine)
    assert clone.refcount(PIN) == 1
    extra = clone.open_pinned(PIN, tenant="t2", pid=200, start=2000)
    assert clone.refcount(PIN) == 2
    assert clone.close_handle(handle) is True
    assert clone.close_handle(extra) is True
    assert clone.refcount(PIN) == 0
    assert clone.quarantined() == ("/pin/new",)
    assert clone.unpin(PIN, tenant="t1") is True
    assert clone.stats()["pinned"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    reg = new_reg()
    pin(reg)
    reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    good = reg.snapshot()

    bad_states = [None, {}]
    case = copy.deepcopy(good)
    case["version"] = 4
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["pins"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["pins"][PIN] = {"tenant": "t1"}
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["handles"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["stats"].pop("opened")
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["next_handle"] = 0
    bad_states.append(case)

    for bad in bad_states:
        with pytest.raises(bpf.BpfError) as exc:
            reg.restore(bad)
        assert exc.value.code == "BPF_SNAPSHOT_INVALID"

    assert reg.lookup(PIN) is not None
    assert reg.refcount(PIN) == 1
    assert reg.stats()["pinned"] == 1


def test_pin_limit_is_enforced():
    reg = new_reg(max_pins=1)
    pin(reg, "/pin/a")
    with pytest.raises(bpf.BpfError) as exc:
        pin(reg, "/pin/b")
    assert exc.value.code == "BPF_PIN_LIMIT"
    assert reg.list_pins("t1") == (reg.lookup("/pin/a"),)
    assert reg.stats()["refused"] == 1


def test_concurrent_opens_increment_refcount_atomically():
    reg = new_reg()
    pin(reg)
    handles = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            handles.append(reg.open_pinned(PIN, tenant="t1", pid=100,
                                           start=1000))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(set(handles)) == 8
    assert reg.refcount(PIN) == 8
    assert reg.stats()["opened"] == 8
    for handle in handles:
        assert reg.close_handle(handle) is True
    assert reg.refcount(PIN) == 0
    assert reg.stats()["closed"] == 8


def test_stats_track_each_operation_exactly():
    reg = new_reg()
    pin(reg)
    handle = reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    assert reg.close_handle(handle) is True
    reg.scan([PIN, "/pin/z"])
    assert reg.unpin(PIN, tenant="t1") is True
    with pytest.raises(bpf.BpfError):
        reg.open_pinned(PIN, tenant="t1", pid=100, start=1000)
    assert reg.stats() == {"pinned": 1, "opened": 1, "closed": 1,
                           "unpinned": 1, "reclaimed": 0, "quarantined": 1,
                           "refused": 1}
