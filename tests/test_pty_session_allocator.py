import copy
import threading

import pytest

import pty_session_allocator as pty

DEVICES = ("pts/0", "pts/1", "pts/2", "pts/3")


def pool(**kwargs):
    kwargs.setdefault("devices", DEVICES)
    kwargs.setdefault("max_per_tenant", 2)
    return pty.PtySessionAllocator(**kwargs)


def test_allocate_picks_lowest_free_device_and_counts_usage():
    alloc = pool(devices=("pts/2", "pts/0", "pts/1"), max_per_tenant=2)
    rec = alloc.allocate("t1", now=1)
    assert rec.device_id == "pts/0"
    assert rec.state == "allocated"
    assert rec.tenant == "t1"
    assert rec.session_id is None
    assert rec.leader_pid is None
    assert rec.generation == 1
    assert alloc.usage("t1") == 1
    assert alloc.lookup("pts/0") == rec
    assert alloc.stats()["allocations"] == 1
    assert alloc.stats()["refused"] == 0
    second = alloc.allocate("t1")
    assert second.device_id == "pts/1"
    assert alloc.usage("t1") == 2


def test_allocate_exhausts_pool_without_leaking_tenants():
    alloc = pool(devices=("pts/0", "pts/1"), max_per_tenant=3)
    assert alloc.allocate("t1").device_id == "pts/0"
    assert alloc.allocate("t2").device_id == "pts/1"
    with pytest.raises(pty.PtyError) as exc:
        alloc.allocate("t3")
    assert exc.value.code == "PTY_POOL_EXHAUSTED"
    assert alloc.usage("t3") == 0
    assert alloc.stats()["allocations"] == 2
    assert alloc.stats()["refused"] == 1
    assert alloc.lookup("pts/1").tenant == "t2"


def test_tenant_quota_refuses_extra_lease():
    alloc = pool(max_per_tenant=2)
    alloc.allocate("t1")
    alloc.allocate("t1")
    with pytest.raises(pty.PtyError) as exc:
        alloc.allocate("t1")
    assert exc.value.code == "PTY_TENANT_QUOTA"
    assert alloc.usage("t1") == 2
    assert alloc.stats()["allocations"] == 2
    assert alloc.stats()["refused"] == 1


def test_allocate_specific_device_checks_owner():
    alloc = pool()
    rec = alloc.allocate("t1", device_id="pts/3")
    assert rec.device_id == "pts/3"
    again = alloc.allocate("t1", device_id="pts/3")
    assert again.generation == 1
    assert again.session_id is None
    assert alloc.stats()["allocations"] == 1
    with pytest.raises(pty.PtyError) as exc:
        alloc.allocate("t2", device_id="pts/3")
    assert exc.value.code == "PTY_DEVICE_BUSY"
    with pytest.raises(pty.PtyError) as exc:
        alloc.allocate("t2", device_id="pts/9")
    assert exc.value.code == "PTY_DEVICE_UNKNOWN"
    assert alloc.lookup("pts/9") is None


def test_bind_session_records_leader_and_rejects_rebind():
    alloc = pool()
    alloc.allocate("t1")
    rec = alloc.bind_session("pts/0", session_id="s-1", leader_pid=101,
                             leader_start=500)
    assert rec.state == "bound"
    assert rec.session_id == "s-1"
    assert rec.leader_pid == 101
    assert rec.leader_start == 500
    assert alloc.stats()["bindings"] == 1
    with pytest.raises(pty.PtyError) as exc:
        alloc.bind_session("pts/0", session_id="s-2", leader_pid=102,
                           leader_start=501)
    assert exc.value.code == "PTY_STATE_INVALID"
    with pytest.raises(pty.PtyError) as exc:
        alloc.bind_session("pts/2", session_id="s-3", leader_pid=103,
                           leader_start=502)
    assert exc.value.code == "PTY_STATE_INVALID"
    assert alloc.lookup("pts/0").session_id == "s-1"
    assert alloc.lookup("pts/2").state == "free"


def test_bind_session_rejects_duplicate_session_id():
    alloc = pool(max_per_tenant=2)
    alloc.allocate("t1")
    alloc.bind_session("pts/0", session_id="s-1", leader_pid=11, leader_start=1)
    alloc.allocate("t1")
    with pytest.raises(pty.PtyError) as exc:
        alloc.bind_session("pts/1", session_id="s-1", leader_pid=12,
                           leader_start=2)
    assert exc.value.code == "PTY_SESSION_CONFLICT"
    assert alloc.lookup("pts/1").state == "allocated"
    assert alloc.lookup("pts/1").session_id is None
    assert alloc.stats()["bindings"] == 1


def test_release_is_idempotent_and_blocks_reallocation_until_flush():
    alloc = pool(devices=("pts/0",), max_per_tenant=2)
    alloc.allocate("t1")
    alloc.bind_session("pts/0", session_id="s", leader_pid=7, leader_start=70)
    assert alloc.release("pts/0") is True
    assert alloc.lookup("pts/0").state == "releasing"
    assert alloc.release("pts/0") is False
    assert alloc.stats()["releases"] == 1
    with pytest.raises(pty.PtyError) as exc:
        alloc.allocate("t2")
    assert exc.value.code == "PTY_POOL_EXHAUSTED"
    assert alloc.flush_release("pts/0", alive=lambda pid, start: False) is True
    assert alloc.lookup("pts/0").state == "free"
    assert alloc.stats()["flushed"] == 1
    rec = alloc.allocate("t2")
    assert rec.generation == 2
    assert rec.tenant == "t2"


def test_flush_release_refuses_while_leader_alive():
    alloc = pool(devices=("pts/0",), max_per_tenant=1)
    alloc.allocate("t1")
    alloc.bind_session("pts/0", session_id="s", leader_pid=7, leader_start=70)
    alloc.release("pts/0")
    still_alive = lambda pid, start: pid == 7 and start == 70
    assert alloc.flush_release("pts/0", alive=still_alive) is False
    assert alloc.lookup("pts/0").state == "releasing"
    assert alloc.stats()["flushed"] == 0
    with pytest.raises(pty.PtyError) as exc:
        alloc.flush_release("pts/8")
    assert exc.value.code == "PTY_DEVICE_UNKNOWN"


def test_reclaim_orphans_frees_only_dead_leaders():
    alloc = pool(devices=("pts/0", "pts/1"), max_per_tenant=2)
    alloc.allocate("t1")
    alloc.bind_session("pts/0", session_id="s0", leader_pid=10, leader_start=100)
    alloc.allocate("t2")
    alloc.bind_session("pts/1", session_id="s1", leader_pid=20, leader_start=200)
    freed = alloc.reclaim_orphans(alive=lambda pid, start: pid == 20)
    assert freed == ("pts/0",)
    assert alloc.lookup("pts/0").state == "free"
    assert alloc.lookup("pts/0").tenant is None
    assert alloc.lookup("pts/1").state == "bound"
    assert alloc.stats()["reclaimed"] == 1
    assert alloc.reclaim_orphans(alive=lambda pid, start: True) == ()


def test_invalid_requests_raise_and_leave_pool_untouched():
    alloc = pool(devices=("pts/0",), max_per_tenant=2)
    calls = [
        lambda: alloc.allocate(""),
        lambda: alloc.allocate(" t1"),
        lambda: alloc.allocate(7),
        lambda: alloc.allocate("t1", device_id="pts/x"),
        lambda: alloc.bind_session("pts/0", session_id="", leader_pid=1,
                                   leader_start=1),
        lambda: alloc.bind_session("pts/0", session_id="s", leader_pid=0,
                                   leader_start=1),
        lambda: alloc.bind_session("pts/0", session_id="s", leader_pid=1,
                                   leader_start=-1),
    ]
    for call in calls:
        with pytest.raises(pty.PtyError) as exc:
            call()
        assert exc.value.code == "PTY_INVALID_REQUEST"
    assert alloc.lookup("pts/0").state == "free"
    assert alloc.usage("t1") == 0
    assert alloc.stats() == {"allocations": 0, "bindings": 0, "releases": 0,
                             "flushed": 0, "reclaimed": 0, "refused": 7}


def test_records_for_is_sorted_and_tenant_scoped():
    alloc = pool()
    alloc.allocate("t1", device_id="pts/2")
    alloc.allocate("t1", device_id="pts/0")
    alloc.allocate("t2", device_id="pts/1")
    rows = alloc.records_for("t1")
    assert [row.device_id for row in rows] == ["pts/0", "pts/2"]
    assert [row.tenant for row in rows] == ["t1", "t1"]
    assert [row.device_id for row in alloc.records_for("t2")] == ["pts/1"]
    assert alloc.records_for("t9") == ()


def test_add_device_extends_pool_and_rejects_bad_ids():
    alloc = pool(devices=("pts/0",), max_per_tenant=1)
    alloc.add_device("pts/1")
    assert alloc.lookup("pts/1").state == "free"
    assert alloc.allocate("t1").device_id == "pts/0"
    assert alloc.allocate("t2").device_id == "pts/1"
    assert alloc.lookup("pts/1").generation == 1
    with pytest.raises(pty.PtyError) as exc:
        alloc.add_device("pts/1")
    assert exc.value.code == "PTY_DEVICE_EXISTS"
    with pytest.raises(pty.PtyError) as exc:
        alloc.add_device("ttyS0")
    assert exc.value.code == "PTY_INVALID_REQUEST"


def test_snapshot_is_detached_and_restore_roundtrips():
    alloc = pool(devices=("pts/0", "pts/1"), max_per_tenant=2)
    alloc.allocate("t1")
    alloc.bind_session("pts/0", session_id="s", leader_pid=9, leader_start=90)
    state = alloc.snapshot()
    assert set(state) == {"version", "devices", "stats", "max_per_tenant"}
    pristine = copy.deepcopy(state)
    state["devices"].clear()
    state["stats"]["allocations"] = 99
    assert alloc.lookup("pts/0").state == "bound"
    assert alloc.lookup("pts/0").session_id == "s"
    assert alloc.stats()["allocations"] == 1

    clone = pty.PtySessionAllocator(devices=("pts/0", "pts/1"),
                                    max_per_tenant=2)
    clone.restore(pristine)
    assert clone.lookup("pts/0").session_id == "s"
    assert clone.lookup("pts/0").leader_pid == 9
    assert clone.usage("t1") == 1
    assert clone.stats()["allocations"] == 1
    assert clone.lookup("pts/1").state == "free"
    assert clone.release("pts/0") is True


def test_restore_rejects_malformed_state_without_touching_live_data():
    alloc = pool(devices=("pts/0", "pts/1"), max_per_tenant=2)
    alloc.allocate("t1")
    alloc.bind_session("pts/0", session_id="s", leader_pid=5, leader_start=50)
    good = alloc.snapshot()

    bad_states = [None, {}]
    case = copy.deepcopy(good)
    case["version"] = 2
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["devices"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["devices"]["pts/0"] = {"tenant": "t1"}
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["stats"].pop("allocations")
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["max_per_tenant"] = 0
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["devices"]["pts/0"] = {}
    bad_states.append(case)

    for bad in bad_states:
        with pytest.raises(pty.PtyError) as exc:
            alloc.restore(bad)
        assert exc.value.code == "PTY_SNAPSHOT_INVALID"

    assert alloc.lookup("pts/0").session_id == "s"
    assert alloc.stats()["allocations"] == 1
    assert alloc.usage("t1") == 1


def test_concurrent_allocations_never_hand_out_same_device():
    alloc = pool(devices=tuple(f"pts/{index}" for index in range(6)),
                 max_per_tenant=6)
    errors = []
    results = []
    barrier = threading.Barrier(6)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(alloc.allocate("t1").device_id)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(results) == [f"pts/{index}" for index in range(6)]
    assert alloc.usage("t1") == 6
    assert alloc.stats()["allocations"] == 6
    assert alloc.stats()["refused"] == 0
