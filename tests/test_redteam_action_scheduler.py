import copy
import threading

import pytest

import redteam_action_scheduler as rs


def scheduler(**kwargs):
    return rs.RedteamActionScheduler(**kwargs)


def test_enqueue_validates_identity_mode_and_window():
    sch = scheduler()
    sch.enqueue("a1", "switch-1", window_start=0, window_end=10)
    with pytest.raises(rs.SchedulerError) as exc:
        sch.enqueue("a1", "switch-2", window_start=0, window_end=10)
    assert exc.value.code == "RT_DUPLICATE_ACTION"

    cases = [
        (dict(action_id="", asset_id="sw"), "RT_INVALID_ACTION"),
        (dict(action_id="a9", asset_id="   "), "RT_INVALID_ACTION"),
        (dict(action_id="a9", asset_id="sw", mode="write"), "RT_INVALID_MODE"),
        (dict(action_id="a9", asset_id="sw", window_start=10, window_end=10),
         "RT_INVALID_WINDOW"),
    ]
    for kwargs, code in cases:
        with pytest.raises(rs.SchedulerError) as exc:
            sch.enqueue(**kwargs)
        assert exc.value.code == code
    assert sch.stats()["enqueued"] == 1


def test_destructive_actions_exclude_each_other_on_same_asset():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-1")
    first = sch.acquire_asset("a1", at=2)
    second = sch.acquire_asset("a2", at=3)
    assert first.granted is True
    assert first.reason == "granted"
    assert second.granted is False
    assert second.reason == "asset_busy"
    assert sch.active_for("sw-1") == ("a1",)
    assert sch.state_of("a2") == "queued"
    assert sch.stats()["blocked"] == 1


def test_readonly_coexists_with_destructive_and_readonly():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-1", mode="readonly")
    sch.enqueue("a3", "sw-1", mode="readonly")
    assert sch.acquire_asset("a1", at=1).granted is True
    assert sch.acquire_asset("a3", at=2).granted is True
    assert sch.acquire_asset("a2", at=3).granted is True
    assert sch.active_for("sw-1") == ("a1", "a2", "a3")


def test_acquire_requires_maintenance_window():
    sch = scheduler()
    sch.enqueue("early", "sw-1", window_start=5, window_end=10)
    sch.enqueue("late", "sw-2", window_start=5, window_end=10)
    sch.enqueue("edge", "sw-3", window_start=5, window_end=10)
    assert sch.acquire_asset("early", at=4).reason == "window_closed"
    assert sch.acquire_asset("late", at=10).reason == "window_closed"
    assert sch.state_of("early") == "queued"
    ok = sch.acquire_asset("edge", at=5)
    assert ok.granted is True
    assert ok.reason == "granted"


def test_release_frees_asset_and_done_action_cannot_reacquire():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-1")
    sch.acquire_asset("a1", at=1)
    again = sch.acquire_asset("a1", at=2)
    assert (again.granted, again.reason) == (True, "already_held")
    assert len(sch.timeline()) == 1
    assert sch.release_asset("a1") is True
    assert sch.release_asset("a1") is False
    assert sch.release_asset("ghost") is False
    assert sch.state_of("a1") == "done"
    with pytest.raises(rs.SchedulerError) as exc:
        sch.acquire_asset("a1", at=3)
    assert exc.value.code == "RT_ACTION_CLOSED"
    assert sch.acquire_asset("a2", at=4).granted is True
    assert sch.active_for("sw-1") == ("a2",)


def test_cancel_running_action_releases_asset_and_drops_steps():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-1")
    sch.acquire_asset("a1", at=1)
    sch.dispatch_step("a1", "recon")
    sch.dispatch_step("a1", "exploit")
    result = sch.cancel("a1", at=5)
    assert result.released is True
    assert result.dropped_steps == ("recon", "exploit")
    assert result.state == "cancelled"
    assert sch.active_for("sw-1") == ()
    assert sch.steps_for("a1") == ()
    assert sch.stats()["dropped_steps"] == 2
    assert sch.cancel("a1").released is False
    assert sch.stats()["cancelled"] == 1
    with pytest.raises(rs.SchedulerError) as exc:
        sch.dispatch_step("a1", "persist")
    assert exc.value.code == "RT_ACTION_CANCELLED"
    with pytest.raises(rs.SchedulerError) as exc:
        sch.acquire_asset("a1", at=6)
    assert exc.value.code == "RT_ACTION_CANCELLED"


def test_cancel_waiting_action_leaves_running_holder_untouched():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-1")
    sch.acquire_asset("a1", at=1)
    assert sch.acquire_asset("a2", at=2).reason == "asset_busy"
    result = sch.cancel("a2", at=3)
    assert result.released is False
    assert result.dropped_steps == ()
    assert sch.active_for("sw-1") == ("a1",)
    assert sch.state_of("a2") == "cancelled"


def test_dispatch_step_appends_and_step_cap_is_hard():
    sch = scheduler(max_steps=2)
    sch.enqueue("a1", "sw-1")
    sch.acquire_asset("a1", at=1)
    assert sch.dispatch_step("a1", "recon") == ("recon",)
    assert sch.dispatch_step("a1", "exploit") == ("recon", "exploit")
    with pytest.raises(rs.SchedulerError) as exc:
        sch.dispatch_step("a1", "persist")
    assert exc.value.code == "RT_STEP_LIMIT"
    assert sch.steps_for("a1") == ("recon", "exploit")


def test_timeline_orders_by_start_then_action_id():
    sch = scheduler()
    sch.enqueue("b", "sw-1")
    sch.enqueue("a", "sw-2")
    sch.enqueue("c", "sw-3")
    sch.enqueue("z", "sw-4")
    sch.acquire_asset("c", at=7)
    sch.acquire_asset("b", at=2)
    sch.acquire_asset("a", at=2)
    rows = sch.timeline()
    assert [(row.action_id, row.started_at) for row in rows] == [
        ("a", 2), ("b", 2), ("c", 7)]
    assert rows[0].asset_id == "sw-2"
    assert rows[0].mode == "destructive"
    assert rows[0].state == "running"
    sch.cancel("b", at=9)
    assert [(row.action_id, row.state) for row in sch.timeline()] == [
        ("a", "running"), ("b", "cancelled"), ("c", "running")]


def test_action_cap_is_hard_and_leaves_state_untouched():
    sch = scheduler(max_actions=2)
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-2")
    with pytest.raises(rs.SchedulerError) as exc:
        sch.enqueue("a3", "sw-3")
    assert exc.value.code == "RT_CAPACITY_EXCEEDED"
    assert sch.stats()["enqueued"] == 2
    assert sch.state_of("a3") is None


def test_unknown_action_errors_and_empty_accessors():
    sch = scheduler()
    with pytest.raises(rs.SchedulerError) as exc:
        sch.acquire_asset("ghost", at=1)
    assert exc.value.code == "RT_UNKNOWN_ACTION"
    with pytest.raises(rs.SchedulerError) as exc:
        sch.cancel("ghost")
    assert exc.value.code == "RT_UNKNOWN_ACTION"
    with pytest.raises(rs.SchedulerError) as exc:
        sch.dispatch_step("ghost", "recon")
    assert exc.value.code == "RT_UNKNOWN_ACTION"
    assert sch.release_asset("ghost") is False
    assert sch.steps_for("ghost") == ()
    assert sch.state_of("ghost") is None
    assert sch.active_for("sw-1") == ()


def test_stats_track_scheduler_operations():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.enqueue("a2", "sw-1")
    sch.acquire_asset("a1", at=1)
    sch.acquire_asset("a2", at=2)
    sch.dispatch_step("a1", "recon")
    sch.release_asset("a1")
    sch.cancel("a2")
    assert sch.stats() == {
        "enqueued": 2,
        "granted": 1,
        "blocked": 1,
        "released": 1,
        "cancelled": 1,
        "dropped_steps": 0,
        "restores": 0,
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    sch = scheduler()
    sch.enqueue("a1", "sw-1", steps=("recon",))
    sch.enqueue("a2", "sw-1")
    sch.acquire_asset("a1", at=2)
    sch.dispatch_step("a1", "recon")
    state = sch.snapshot()
    assert set(state) == {"version", "actions", "active", "timeline", "stats"}
    pristine = copy.deepcopy(state)
    state["actions"].clear()
    state["stats"]["granted"] = 99
    assert sch.stats()["granted"] == 1
    assert sch.active_for("sw-1") == ("a1",)

    clone = scheduler()
    clone.restore(pristine)
    assert clone.active_for("sw-1") == ("a1",)
    assert clone.state_of("a1") == "running"
    assert clone.steps_for("a1") == ("recon",)
    assert [(row.action_id, row.started_at) for row in clone.timeline()] == [
        ("a1", 2)]
    assert clone.stats()["granted"] == 1
    assert clone.stats()["restores"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    sch = scheduler()
    sch.enqueue("a1", "sw-1")
    sch.acquire_asset("a1", at=1)
    stats = {"enqueued": 1, "granted": 1, "blocked": 0, "released": 0,
             "cancelled": 0, "dropped_steps": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"version": 3, "actions": [], "active": {}, "timeline": [],
         "stats": stats},
        {"version": 1, "actions": "nope", "active": {}, "timeline": [],
         "stats": stats},
        {"version": 1, "actions": [], "active": {}, "timeline": [],
         "stats": {"granted": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(rs.SchedulerError) as exc:
            sch.restore(bad)
        assert exc.value.code == "RT_SNAPSHOT_INVALID"

    assert sch.stats() == stats
    assert sch.active_for("sw-1") == ("a1",)


def test_concurrent_acquire_yields_single_holder():
    sch = scheduler()
    for index in range(8):
        sch.enqueue(f"a{index}", "sw-1")
    winners = []
    errors = []
    barrier = threading.Barrier(8)

    def worker(action_id):
        try:
            barrier.wait(timeout=5)
            grant = sch.acquire_asset(action_id, at=1)
            if grant.granted:
                winners.append(action_id)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(f"a{index}",))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(winners) == 1
    assert sch.active_for("sw-1") == tuple(winners)
    assert sch.stats()["granted"] == 1
