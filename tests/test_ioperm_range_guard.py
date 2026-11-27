import copy
import threading

import pytest

import ioperm_range_guard as io

PID = 4100


def guard(**kwargs):
    return io.IopermRangeGuard(**kwargs)


def test_grant_keeps_disjoint_ranges_sorted():
    g = guard()
    assert g.grant_range(PID, 400, 409) == ((400, 409),)
    assert g.grant_range(PID, 200, 209) == ((200, 209), (400, 409))
    assert g.ranges(PID) == ((200, 209), (400, 409))
    assert g.stats()["grants"] == 2
    assert g.stats()["processes"] == 1


def test_grant_merges_adjacent_and_overlapping_ranges():
    g = guard()
    g.grant_range(PID, 100, 109)
    assert g.grant_range(PID, 110, 119) == ((100, 119),)
    assert g.grant_range(PID, 105, 112) == ((100, 119),)
    assert g.grant_range(PID, 119, 130) == ((100, 130),)
    assert g.stats()["grants"] == 4


def test_invalid_pid_and_range_are_rejected():
    g = guard()
    with pytest.raises(io.IoportError) as exc:
        g.grant_range(0, 10, 20)
    assert exc.value.code == "IOPORT_INVALID_PID"
    for bad in ((10, 9), (-1, 5), (0, 65536)):
        with pytest.raises(io.IoportError) as exc:
            g.grant_range(PID, *bad)
        assert exc.value.code == "IOPORT_INVALID_RANGE"
        assert exc.value.detail == {"start": bad[0], "end": bad[1]}
    assert g.stats()["grants"] == 0
    with pytest.raises(io.IoportError) as exc:
        g.ranges(PID)
    assert exc.value.code == "IOPORT_UNKNOWN_PROCESS"


def test_missing_rawio_capability_changes_nothing():
    g = guard()
    with pytest.raises(io.IoportError) as exc:
        g.grant_range(PID, 0, 7, cap_rawio=False)
    assert exc.value.code == "IOPORT_CAP_MISSING"
    with pytest.raises(io.IoportError) as exc:
        g.ranges(PID)
    assert exc.value.code == "IOPORT_UNKNOWN_PROCESS"
    assert g.stats()["processes"] == 0


def test_iopl_three_opens_every_port():
    g = guard()
    assert g.set_iopl(PID, 3) == 3
    assert g.process_level(PID) == 3
    for port in (0, 1, 443, 65535):
        assert g.allowed(PID, port) is True
    assert g.ranges(PID) == ()
    assert g.stats()["iopl_changes"] == 1


def test_iopl_rejects_unsupported_levels_and_missing_capability():
    g = guard()
    for bad in (1, 2, 4, -1):
        with pytest.raises(io.IoportError) as exc:
            g.set_iopl(PID, bad)
        assert exc.value.code == "IOPORT_INVALID_LEVEL"
    with pytest.raises(io.IoportError) as exc:
        g.set_iopl(PID, 3, cap_rawio=False)
    assert exc.value.code == "IOPORT_CAP_MISSING"
    with pytest.raises(io.IoportError) as exc:
        g.ranges(PID)
    assert exc.value.code == "IOPORT_UNKNOWN_PROCESS"


def test_revoke_whole_covered_range_removes_it():
    g = guard()
    g.grant_range(PID, 100, 119)
    assert g.revoke_range(PID, 100, 119) == ()
    assert g.ranges(PID) == ()
    assert g.stats()["revokes"] == 1


def test_revoke_partial_overlap_truncates_the_edge():
    g = guard()
    g.grant_range(PID, 100, 109)
    assert g.revoke_range(PID, 100, 104) == ((105, 109),)
    assert g.revoke_range(PID, 107, 130) == ((105, 106),)
    g.grant_range(PID, 300, 309)
    assert g.revoke_range(PID, 280, 304) == ((105, 106), (305, 309))


def test_revoke_outside_bitmap_is_noop_and_unknown_pid_fails():
    g = guard()
    g.grant_range(PID, 100, 109)
    assert g.revoke_range(PID, 200, 209) == ((100, 109),)
    assert g.revoke_range(PID, 90, 99) == ((100, 109),)
    with pytest.raises(io.IoportError) as exc:
        g.revoke_range(9999, 100, 109)
    assert exc.value.code == "IOPORT_UNKNOWN_PROCESS"


def test_per_process_range_capacity():
    g = guard(max_ranges_per_process=2)
    g.grant_range(PID, 100, 109)
    g.grant_range(PID, 200, 209)
    with pytest.raises(io.IoportError) as exc:
        g.grant_range(PID, 300, 309)
    assert exc.value.code == "IOPORT_LIMIT_EXCEEDED"
    assert g.ranges(PID) == ((100, 109), (200, 209))

    assert g.grant_range(PID, 105, 115) == ((100, 115), (200, 209))


def test_exec_reset_clears_bitmap_and_level():
    g = guard()
    g.grant_range(PID, 100, 109)
    snapshot = g.exec_reset(PID)
    assert snapshot.pid == PID
    assert snapshot.level == 0
    assert snapshot.ranges == ()
    assert snapshot.inherited is False
    assert g.ranges(PID) == ()
    assert g.allowed(PID, 100) is False
    assert g.stats()["exec_resets"] == 1

    with pytest.raises(io.IoportError) as exc:
        g.exec_reset(4321)
    assert exc.value.code == "IOPORT_UNKNOWN_PROCESS"


def test_fork_child_starts_empty_without_explicit_inheritance():
    g = guard()
    g.grant_range(PID, 10, 19)
    child = g.fork_child(PID, PID + 1)
    assert child.pid == PID + 1
    assert child.ranges == ()
    assert child.level == 0
    assert child.inherited is False
    assert g.ranges(PID) == ((10, 19),)
    assert g.stats()["forks"] == 1

    with pytest.raises(io.IoportError) as exc:
        g.fork_child(PID, PID + 1)
    assert exc.value.code == "IOPORT_PID_EXISTS"
    with pytest.raises(io.IoportError) as exc:
        g.fork_child(7777, 7778)
    assert exc.value.code == "IOPORT_UNKNOWN_PROCESS"


def test_allowed_reflects_bitmap_boundaries():
    g = guard()
    g.grant_range(PID, 100, 109)
    assert g.allowed(PID, 100) is True
    assert g.allowed(PID, 109) is True
    assert g.allowed(PID, 99) is False
    assert g.allowed(PID, 110) is False
    assert g.allowed(90210, 100) is False
    with pytest.raises(io.IoportError) as exc:
        g.allowed(PID, 65536)
    assert exc.value.code == "IOPORT_INVALID_RANGE"


def test_concurrent_grants_merge_into_one_interval():
    g = guard()
    barrier = threading.Barrier(16)
    errors = []

    def worker(index):
        try:
            barrier.wait(timeout=5)
            g.grant_range(PID, index * 2, index * 2 + 1)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.ranges(PID) == ((0, 31),)
    assert g.stats()["grants"] == 16


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    g.grant_range(PID, 100, 109)
    g.set_iopl(PID + 1, 3)
    state = g.snapshot()
    assert set(state) == {"version", "processes", "counters"}
    pristine = copy.deepcopy(state)

    state["processes"].clear()
    state["counters"]["grants"] = 999
    assert g.ranges(PID) == ((100, 109),)
    assert g.stats()["grants"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.ranges(PID) == ((100, 109),)
    assert clone.process_level(PID + 1) == 3
    assert clone.stats()["grants"] == 1

    for bad in (None, {}, {"version": 1, "processes": [], "counters": {}},
                {"version": 1, "processes": {}, "counters": {}}):
        with pytest.raises(io.IoportError) as exc:
            g.restore(bad)
        assert exc.value.code == "IOPORT_SNAPSHOT_INVALID"
    assert g.ranges(PID) == ((100, 109),)
