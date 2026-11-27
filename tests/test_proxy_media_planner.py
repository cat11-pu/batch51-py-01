import copy

import pytest

import proxy_media_planner as pm


def planner(**kwargs):
    return pm.ProxyMediaPlanner(**kwargs)


def enqueue(plan, asset="asset-a", *, checksum="c1", tier="half"):
    return plan.enqueue(asset, checksum=checksum, tier=tier)


def test_enqueue_returns_queued_record():
    plan = planner()
    task = plan.enqueue("  asset-a ", checksum=" c1 ", tier="half")
    assert task.asset_id == "asset-a"
    assert task.checksum == "c1"
    assert task.tier == "half"
    assert (task.status, task.attempts, task.output_path) == ("queued", 0, None)
    assert task.stale is False
    assert task.task_id

    row = plan.progress(task.task_id)
    assert (row["asset_id"], row["checksum"], row["tier"]) == ("asset-a", "c1", "half")
    assert row["status"] == "queued"
    assert plan.stats()["enqueued"] == 1
    assert plan.stats()["live"] == 1


def test_enqueue_rejects_bad_input_and_bad_config():
    plan = planner()
    bad_calls = [
        dict(asset="", checksum="c1", tier="half"),
        dict(asset="   ", checksum="c1", tier="half"),
        dict(asset="asset-a", checksum="  ", tier="half"),
        dict(asset="asset-a", checksum="c1", tier="nope"),
    ]
    for call in bad_calls:
        with pytest.raises(pm.ProxyError) as exc:
            plan.enqueue(call["asset"], checksum=call["checksum"], tier=call["tier"])
        assert exc.value.code == "PROXY_INVALID"
    assert plan.stats()["enqueued"] == 0

    for kwargs in ({"tiers": ()}, {"tiers": ("half", "half")}, {"tiers": ("",)},
                   {"max_tasks": 0}, {"max_workers": 0}, {"max_attempts": 0}):
        with pytest.raises(pm.ProxyError) as exc:
            planner(**kwargs)
        assert exc.value.code == "PROXY_INVALID_CONFIG"


def test_enqueue_capacity_counts_only_live_tasks():
    plan = planner(max_tasks=1)
    first = enqueue(plan)
    with pytest.raises(pm.ProxyError) as exc:
        enqueue(plan, "asset-b")
    assert exc.value.code == "PROXY_CAPACITY"

    assert plan.start_next() == first.task_id
    with pytest.raises(pm.ProxyError) as exc:
        enqueue(plan, "asset-b")
    assert exc.value.code == "PROXY_CAPACITY"

    plan.complete(first.task_id, output_path="proxy/a_half.mov")
    second = enqueue(plan, "asset-b")
    assert second.status == "queued"
    assert plan.stats()["live"] == 1


def test_start_next_promotes_oldest_and_returns_none_when_empty():
    plan = planner()
    assert plan.start_next() is None

    first = enqueue(plan, "asset-a")
    second = enqueue(plan, "asset-b")
    assert plan.start_next() == first.task_id
    assert plan.progress(first.task_id)["status"] == "running"
    assert plan.start_next() == second.task_id
    assert plan.start_next() is None
    assert plan.stats()["started"] == 2


def test_start_next_respects_worker_limit():
    plan = planner(max_workers=1)
    first = enqueue(plan, "asset-a")
    second = enqueue(plan, "asset-b")
    assert plan.start_next() == first.task_id
    assert plan.start_next() is None
    plan.complete(first.task_id, output_path="proxy/a.mov")
    assert plan.start_next() == second.task_id


def test_complete_requires_running_task():
    plan = planner()
    task = enqueue(plan)
    with pytest.raises(pm.ProxyError) as exc:
        plan.complete(task.task_id, output_path="proxy/x.mov")
    assert exc.value.code == "PROXY_INVALID_STATE"

    with pytest.raises(pm.ProxyError) as exc:
        plan.complete("task-999", output_path="proxy/x.mov")
    assert exc.value.code == "PROXY_UNKNOWN"

    plan.start_next()
    with pytest.raises(pm.ProxyError) as exc:
        plan.complete(task.task_id, output_path="   ")
    assert exc.value.code == "PROXY_INVALID"

    plan.complete(task.task_id, output_path="proxy/x.mov")
    with pytest.raises(pm.ProxyError) as exc:
        plan.complete(task.task_id, output_path="proxy/y.mov")
    assert exc.value.code == "PROXY_INVALID_STATE"
    assert plan.stats()["completed"] == 1


def test_complete_marks_done_and_resolve_returns_record():
    plan = planner()
    task = enqueue(plan)
    plan.start_next()
    record = plan.complete(task.task_id, output_path="  proxy/a_half.mov ")
    assert record.status == "done"
    assert record.output_path == "proxy/a_half.mov"

    resolved = plan.resolve("asset-a", tier="half")
    assert resolved.task_id == task.task_id
    assert resolved.checksum == "c1"
    assert plan.stats()["completed"] == 1
    assert plan.stats()["live"] == 0


def test_resolve_distinguishes_unknown_and_not_ready():
    plan = planner()
    with pytest.raises(pm.ProxyError) as exc:
        plan.resolve("ghost", tier="half")
    assert exc.value.code == "PROXY_UNKNOWN"

    task = enqueue(plan)
    with pytest.raises(pm.ProxyError) as exc:
        plan.resolve("asset-a", tier="half")
    assert exc.value.code == "PROXY_NOT_READY"

    with pytest.raises(pm.ProxyError) as exc:
        plan.progress("task-999")
    assert exc.value.code == "PROXY_UNKNOWN"


def test_fail_requires_running_task():
    plan = planner()
    task = enqueue(plan)
    with pytest.raises(pm.ProxyError) as exc:
        plan.fail(task.task_id)
    assert exc.value.code == "PROXY_INVALID_STATE"

    with pytest.raises(pm.ProxyError) as exc:
        plan.fail("task-999")
    assert exc.value.code == "PROXY_UNKNOWN"
    assert plan.stats()["retries"] == 0


def test_fail_increments_attempts_and_requeues():
    plan = planner()
    task = enqueue(plan)
    plan.start_next()
    record = plan.fail(task.task_id)
    assert record.attempts == 1
    assert record.status == "queued"
    assert plan.stats()["retries"] == 1
    assert plan.stats()["live"] == 1
    assert plan.start_next() == task.task_id


def test_fail_exhausts_attempts_into_failed():
    plan = planner(max_attempts=2)
    task = enqueue(plan)
    plan.start_next()
    plan.fail(task.task_id)
    plan.start_next()
    record = plan.fail(task.task_id)
    assert record.attempts == 2
    assert record.status == "failed"
    assert plan.stats()["failed"] == 1
    assert plan.stats()["live"] == 0

    with pytest.raises(pm.ProxyError) as exc:
        plan.fail(task.task_id)
    assert exc.value.code == "PROXY_INVALID_STATE"


def test_invalidate_marks_live_tasks():
    plan = planner()
    first = enqueue(plan, "asset-a", checksum="c1")
    second = enqueue(plan, "asset-b", checksum="c2")
    assert plan.invalidate("asset-a") == 1
    assert plan.progress(first.task_id)["status"] == "invalid"
    assert plan.progress(second.task_id)["status"] == "queued"
    assert plan.stats()["invalidated"] == 1
    assert plan.stats()["live"] == 1
    assert plan.invalidate("asset-a") == 0

    with pytest.raises(pm.ProxyError) as exc:
        plan.resolve("asset-a", tier="half")
    assert exc.value.code == "PROXY_INVALIDATED"


def test_relink_returns_completed_output_path():
    plan = planner()
    task = enqueue(plan, checksum="c1")
    with pytest.raises(pm.ProxyError) as exc:
        plan.relink("asset-a", checksum="c1", tier="half")
    assert exc.value.code == "PROXY_NOT_READY"

    plan.start_next()
    plan.complete(task.task_id, output_path="proxy/a.mov")
    assert plan.relink("asset-a", checksum="c1", tier="half") == "proxy/a.mov"

    with pytest.raises(pm.ProxyError) as exc:
        plan.relink("ghost", checksum="c1", tier="half")
    assert exc.value.code == "PROXY_UNKNOWN"


def test_snapshot_is_detached_and_restore_roundtrips():
    plan = planner(max_workers=2)
    first = enqueue(plan, "asset-a", checksum="c1", tier="half")
    second = enqueue(plan, "asset-b", checksum="c2", tier="quarter")
    plan.start_next()
    plan.start_next()
    plan.fail(first.task_id)

    state = plan.snapshot()
    pristine = copy.deepcopy(state)
    state["tasks"].clear()
    state["stats"]["enqueued"] = 99

    assert plan.stats()["enqueued"] == 2
    assert plan.progress(first.task_id)["attempts"] == 1

    clone = planner(max_workers=2)
    clone.restore(pristine)
    assert clone.stats() == plan.stats()
    assert clone.progress(first.task_id)["status"] == "queued"
    assert clone.progress(first.task_id)["attempts"] == 1
    assert clone.progress(second.task_id)["status"] == "running"
    assert clone.start_next() == first.task_id


def test_restore_rejects_malformed_state_without_mutating():
    plan = planner()
    task = enqueue(plan)
    bad_states = [
        None,
        {},
        {"version": 2, "next_task": 1, "tasks": [], "stats": {}},
        {"version": 1, "next_task": 1, "tasks": "nope", "stats": {}},
        {"version": 1, "next_task": 1, "tasks": [{"task_id": "x"}], "stats": {}},
        {"version": 1, "next_task": 1, "tasks": [{
            "task_id": "x", "asset_id": "a", "checksum": "c", "tier": "half",
            "status": "paused", "attempts": 0, "output_path": None,
            "mtime": None}], "stats": {}},
        {"version": 1, "next_task": 1, "tasks": [], "stats": {"enqueued": "many"}},
    ]
    for state in bad_states:
        with pytest.raises(pm.ProxyError) as exc:
            plan.restore(state)
        assert exc.value.code == "PROXY_SNAPSHOT_INVALID"

    assert plan.progress(task.task_id)["status"] == "queued"
    assert plan.stats()["enqueued"] == 1
