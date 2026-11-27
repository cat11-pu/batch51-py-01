import pytest

import userfaultfd_budget_guard as ug

PAGE = 4096


def guard(**kwargs):
    return ug.UserfaultfdBudgetGuard(**kwargs)


def with_tenant(g, name="t1", *, instances=4, threads=4, capacity=8):
    g.set_tenant_quota(name, max_instances=instances, max_threads=threads,
                       queue_capacity=capacity)
    return g


def test_register_creates_open_instance():
    g = with_tenant(guard())
    view = g.register("i1", "t1", now=0)
    assert (view.instance_id, view.tenant, view.state) == ("i1", "t1", "open")
    assert view.ranges == ()
    assert view.threads == ()
    assert view.queued == 0
    assert g.stats()["registered"] == 1


def test_duplicate_instance_is_refused():
    g = with_tenant(guard())
    g.register("i1", "t1")
    with pytest.raises(ug.UffdError) as excinfo:
        g.register("i1", "t1")
    assert excinfo.value.code == "UFFD_DUPLICATE_INSTANCE"
    assert g.describe("i1").state == "open"


def test_instance_quota_is_per_tenant():
    g = with_tenant(guard(), instances=1)
    g.register("i1", "t1")
    with pytest.raises(ug.UffdError) as excinfo:
        g.register("i2", "t1")
    assert excinfo.value.code == "UFFD_QUOTA_EXCEEDED"
    with pytest.raises(ug.UffdError) as excinfo:
        g.set_tenant_quota("t1", max_instances=0, max_threads=4,
                           queue_capacity=8)
    assert excinfo.value.code == "UFFD_QUOTA_EXCEEDED"
    with_tenant(g, "t2", instances=1)
    assert g.register("x1", "t2").tenant == "t2"
    with pytest.raises(ug.UffdError) as excinfo:
        g.register("i3", "t1")
    assert excinfo.value.code == "UFFD_QUOTA_EXCEEDED"
    with pytest.raises(ug.UffdError) as excinfo:
        g.register("y1", "t9")
    assert excinfo.value.code == "UFFD_TENANT_UNKNOWN"


def test_attach_range_returns_half_open_span():
    g = with_tenant(guard())
    g.register("i1", "t1")
    assert g.attach_range("i1", 0, 3 * PAGE) == (0, 3 * PAGE)
    assert g.attach_range("i1", 4 * PAGE, PAGE) == (4 * PAGE, 5 * PAGE)
    assert g.attach_range("i1", 3 * PAGE, PAGE) == (3 * PAGE, 4 * PAGE)
    assert g.describe("i1").ranges == ((0, 3 * PAGE), (3 * PAGE, 4 * PAGE),
                                       (4 * PAGE, 5 * PAGE))


def test_overlapping_range_is_refused():
    g = with_tenant(guard())
    g.register("i1", "t1")
    g.attach_range("i1", 0, 2 * PAGE)
    with pytest.raises(ug.UffdError) as excinfo:
        g.attach_range("i1", PAGE, 2 * PAGE)
    assert excinfo.value.code == "UFFD_RANGE_OVERLAP"
    assert g.describe("i1").ranges == ((0, 2 * PAGE),)
    assert g.stats()["attached"] == 1


def test_unaligned_range_is_refused():
    g = with_tenant(guard())
    g.register("i1", "t1")
    for start, length in ((1, PAGE), (0, 0), (0, PAGE + 1), (-PAGE, PAGE)):
        with pytest.raises(ug.UffdError) as excinfo:
            g.attach_range("i1", start, length)
        assert excinfo.value.code == "UFFD_RANGE_INVALID"
    assert g.describe("i1").ranges == ()


def test_detach_range_releases_whole_span():
    g = with_tenant(guard())
    g.register("i1", "t1")
    g.attach_range("i1", 0, 2 * PAGE)
    assert g.detach_range("i1", 0, 2 * PAGE) == ()
    assert g.describe("i1").ranges == ()
    assert g.stats()["detached"] == 1
    with pytest.raises(ug.UffdError) as excinfo:
        g.detach_range("i1", 0, PAGE)
    assert excinfo.value.code == "UFFD_RANGE_INVALID"


def test_handler_add_and_retire():
    g = with_tenant(guard())
    g.register("i1", "t1")
    g.spawn_handler("i1", "w1")
    g.spawn_handler("i1", "w2")
    assert g.describe("i1").threads == ("w1", "w2")
    with pytest.raises(ug.UffdError) as excinfo:
        g.spawn_handler("i1", "w1")
    assert excinfo.value.code == "UFFD_DUPLICATE_HANDLER"
    g.retire_handler("i1", "w1")
    assert g.describe("i1").threads == ("w2",)
    with pytest.raises(ug.UffdError) as excinfo:
        g.retire_handler("i1", "w9")
    assert excinfo.value.code == "UFFD_HANDLER_UNKNOWN"


def test_thread_quota_is_enforced():
    g = with_tenant(guard(), threads=2)
    g.register("i1", "t1")
    g.spawn_handler("i1", "w1")
    g.spawn_handler("i1", "w2")
    with pytest.raises(ug.UffdError) as excinfo:
        g.spawn_handler("i1", "w3")
    assert excinfo.value.code == "UFFD_THREAD_QUOTA_EXCEEDED"
    assert g.describe("i1").threads == ("w1", "w2")


def test_drop_policy_keeps_oldest_events():
    g = guard(queue_capacity=2)
    with_tenant(g, capacity=8)
    g.register("i1", "t1")
    assert g.enqueue_event("i1", "e1", policy="drop") == "queued"
    assert g.enqueue_event("i1", "e2", policy="drop") == "queued"
    assert g.enqueue_event("i1", "e3", policy="drop") == "dropped"
    assert g.describe("i1").queued == 2
    assert g.drain("i1") == ["e1", "e2"]
    assert g.stats()["dropped"] == 1
    assert g.stats()["queued"] == 2


def test_block_policy_marks_backpressure():
    g = guard(queue_capacity=1)
    with_tenant(g)
    g.register("i1", "t1")
    g.enqueue_event("i1", "a")
    assert g.enqueue_event("i1", "b", policy="block") == "blocked"
    assert g.stats()["blocked"] == 1
    assert g.describe("i1").queued == 1
    assert g.drain("i1") == ["a"]
    with pytest.raises(ug.UffdError) as excinfo:
        g.enqueue_event("i1", "c", policy="keep")
    assert excinfo.value.code == "UFFD_POLICY_INVALID"


def test_drain_respects_max_events():
    g = with_tenant(guard())
    g.register("i1", "t1")
    for item in ("e1", "e2", "e3"):
        g.enqueue_event("i1", item)
    assert g.drain("i1", max_events=1) == ["e1"]
    assert g.drain("i1", max_events=5) == ["e2", "e3"]
    assert g.drain("i1") == []
    assert g.stats()["drained"] == 3


def test_release_waits_for_inflight_work():
    g = with_tenant(guard())
    g.register("i1", "t1")
    g.attach_range("i1", 0, PAGE)
    g.spawn_handler("i1", "w1")
    g.enqueue_event("i1", "e1")
    with pytest.raises(ug.UffdError) as excinfo:
        g.release("i1")
    assert excinfo.value.code == "UFFD_RELEASE_BUSY"
    assert excinfo.value.detail == {"queued": 1, "threads": 1}
    assert g.describe("i1").state == "open"
    view = g.release("i1", force=True, now=10)
    assert view.state == "released"
    assert view.ranges == ()
    assert view.threads == ()
    assert view.queued == 0
    assert g.stats()["forced_discards"] == 1
    with pytest.raises(ug.UffdError) as excinfo:
        g.release("i1")
    assert excinfo.value.code == "UFFD_STATE_INVALID"


def test_recover_reaps_instances_left_open_after_restart():
    g = guard(idle_timeout=30)
    with_tenant(g)
    g.register("i1", "t1", now=0)
    g.register("i2", "t1", now=0)
    g.release("i2", now=5)
    state = g.snapshot()
    fresh = guard(idle_timeout=30)
    fresh.restore(state)
    assert fresh.describe("i1").state == "open"
    assert fresh.recover(now=100) == {"marked": 1, "reaped": 0}
    assert fresh.describe("i1").state == "stale"
    assert fresh.describe("i2").state == "released"
    assert fresh.recover(now=131) == {"marked": 0, "reaped": 1}
    assert fresh.describe("i1").state == "released"
    assert guard().recover(now=200) == {"marked": 0, "reaped": 0}


def test_snapshot_restore_round_trip_is_deep():
    g = with_tenant(guard())
    g.register("i1", "t1")
    g.attach_range("i1", 0, PAGE)
    g.enqueue_event("i1", "e1")
    state = g.snapshot()
    fresh = guard()
    fresh.restore(state)
    view = fresh.describe("i1")
    assert (view.tenant, view.state) == ("t1", "open")
    assert view.ranges == ((0, PAGE),)
    assert view.queued == 1
    assert fresh.drain("i1") == ["e1"]
    state["instances"]["i1"]["queued"] = 99
    assert fresh.describe("i1").queued == 0
    with pytest.raises(ug.UffdError) as excinfo:
        fresh.restore({"instances": {}})
    assert excinfo.value.code == "UFFD_SNAPSHOT_INVALID"
    assert fresh.describe("i1").state == "open"
