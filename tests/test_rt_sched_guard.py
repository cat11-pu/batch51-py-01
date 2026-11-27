import copy
import threading

import pytest

import rt_sched_guard as rt


def guard(**kwargs):
    return rt.RtSchedGuard(**kwargs)


def test_create_group_reports_limits_and_child_budget():
    inst = guard()
    root = inst.create_group("root", budget_us=100)
    assert isinstance(root, rt.GroupBudget)
    assert (root.name, root.limit_us, root.used_us, root.available_us,
            root.over_us) == ("root", 100, 0, 100, 0)
    inst.create_group("leaf", parent="root", budget_us=60)
    leaf = inst.group_budget("leaf")
    assert (leaf.limit_us, leaf.used_us, leaf.available_us, leaf.over_us) == (
        60, 0, 60, 0)
    assert inst.group_budget("root").available_us == 100


def test_create_group_rejects_duplicates_unknown_parents_and_bad_limits():
    inst = guard()
    inst.create_group("root", budget_us=100)
    with pytest.raises(rt.RtSchedError) as dup:
        inst.create_group("root", budget_us=50)
    assert dup.value.code == "RT_GROUP_EXISTS"
    with pytest.raises(rt.RtSchedError) as orphan:
        inst.create_group("child", parent="missing", budget_us=10)
    assert orphan.value.code == "RT_GROUP_UNKNOWN"
    with pytest.raises(rt.RtSchedError) as bad:
        inst.create_group("zero", budget_us=0)
    assert bad.value.code == "RT_INVALID_BUDGET"
    with pytest.raises(rt.RtSchedError) as unknown:
        inst.group_budget("nope")
    assert unknown.value.code == "RT_GROUP_UNKNOWN"
    assert inst.stats()["groups"] == 1


def test_admit_charges_group_budget_and_records_sequence():
    inst = guard()
    inst.create_group("root", budget_us=100)
    first = inst.admit(1001, group="root", policy="fifo", budget_us=40, now_us=0)
    assert (first.pid, first.group, first.policy, first.budget_us,
            first.status, first.sequence) == (1001, "root", "fifo", 40,
                                              "admitted", 1)
    assert inst.reservation_of(1001) == first
    budget = inst.group_budget("root")
    assert (budget.used_us, budget.available_us, budget.over_us) == (40, 60, 0)

    second = inst.admit(1002, group="root", policy="rr", budget_us=60, now_us=0)
    assert second.status == "admitted"
    assert second.sequence == 2
    assert inst.group_budget("root").available_us == 0
    assert [row.pid for row in inst.admissions()] == [1001, 1002]


def test_admit_over_group_budget_is_refused_without_charge():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=80, now_us=0)
    with pytest.raises(rt.RtSchedError) as exc:
        inst.admit(2, group="root", policy="fifo", budget_us=30, now_us=0)
    assert exc.value.code == "RT_QUOTA_EXCEEDED"
    assert exc.value.detail == {"group": "root", "requested": 30,
                                "available": 20}
    assert inst.reservation_of(2) is None
    assert inst.group_budget("root").used_us == 80
    assert inst.stats()["rejected"] == 1


def test_child_group_is_bounded_by_parent_remaining_budget():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.create_group("a", parent="root", budget_us=80)
    inst.create_group("b", parent="root", budget_us=80)
    inst.admit(1, group="a", policy="rr", budget_us=70, now_us=0)
    assert inst.group_budget("a").available_us == 10
    assert inst.group_budget("root").available_us == 30
    assert inst.group_budget("root").used_us == 70
    with pytest.raises(rt.RtSchedError) as exc:
        inst.admit(2, group="b", policy="rr", budget_us=40, now_us=0)
    assert exc.value.code == "RT_QUOTA_EXCEEDED"
    assert inst.admit(3, group="b", policy="rr", budget_us=30,
                      now_us=0).status == "admitted"
    assert inst.group_budget("b").available_us == 50
    assert inst.group_budget("root").available_us == 0


def test_release_frees_budget_exactly_once():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(7, group="root", policy="fifo", budget_us=40, now_us=0)
    assert inst.release(7, now_us=10) == 40
    assert inst.release(7, now_us=20) == 0
    assert inst.release(999, now_us=30) == 0
    assert inst.reservation_of(7) is None
    assert inst.group_budget("root").used_us == 0
    assert inst.stats()["released"] == 1


def test_watchdog_demotes_and_opens_cooldown_window():
    inst = guard(watchdog_cooldown_us=5000)
    inst.create_group("root", budget_us=100)
    inst.admit(7, group="root", policy="fifo", budget_us=40, now_us=1000)
    demo = inst.watchdog(7, now_us=2000)
    assert isinstance(demo, rt.Demotion)
    assert (demo.pid, demo.policy, demo.reason, demo.released_us,
            demo.cooldown_until_us) == (7, "other", "overrun", 40, 7000)
    assert inst.cooldown_until(7) == 7000
    assert inst.cooldown_until(8) == 0
    assert inst.reservation_of(7) is None
    assert inst.group_budget("root").used_us == 0
    assert inst.stats()["demotions"] == 1


def test_overflow_is_queued_and_promoted_in_fifo_order():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=80, now_us=0)
    first = inst.admit(2, group="root", policy="fifo", budget_us=60,
                       now_us=0, allow_queue=True)
    second = inst.admit(3, group="root", policy="rr", budget_us=10,
                        now_us=0, allow_queue=True)
    assert (first.status, second.status) == ("queued", "queued")
    assert [row.pid for row in inst.queued()] == [2, 3]
    assert inst.group_budget("root").used_us == 80
    assert inst.stats()["queued"] == 2

    assert inst.release(1, now_us=10) == 80
    promoted = inst.pump(now_us=20)
    assert [row.pid for row in promoted] == [2, 3]
    assert [row.status for row in promoted] == ["admitted", "admitted"]
    assert inst.queued() == ()
    assert inst.group_budget("root").used_us == 70
    assert inst.stats()["admitted"] == 3


def test_pump_skips_requests_that_do_not_fit_and_keeps_their_order():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=50, now_us=0)
    inst.admit(2, group="root", policy="fifo", budget_us=60, now_us=0,
               allow_queue=True)
    inst.admit(3, group="root", policy="rr", budget_us=5, now_us=0,
               allow_queue=True)
    promoted = inst.pump(now_us=10)
    assert [row.pid for row in promoted] == [3]
    assert [row.pid for row in inst.queued()] == [2]
    assert inst.group_budget("root").used_us == 55
    assert inst.pump(now_us=20) == ()


def test_invalid_policy_and_budget_are_refused():
    inst = guard()
    inst.create_group("root", budget_us=100)
    for policy in ("other", "batch", ""):
        with pytest.raises(rt.RtSchedError) as exc:
            inst.admit(1, group="root", policy=policy, budget_us=10, now_us=0)
        assert exc.value.code == "RT_INVALID_POLICY"
    for amount in (0, -5, 1.5, "10"):
        with pytest.raises(rt.RtSchedError) as exc:
            inst.admit(1, group="root", policy="fifo", budget_us=amount,
                       now_us=0)
        assert exc.value.code == "RT_INVALID_BUDGET"
    assert inst.group_budget("root").used_us == 0
    assert inst.stats()["admitted"] == 0


def test_set_group_budget_raises_the_ceiling():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=90, now_us=0)
    raised = inst.set_group_budget("root", 200)
    assert (raised.limit_us, raised.used_us, raised.available_us) == (200, 90, 110)
    assert inst.admit(2, group="root", policy="rr", budget_us=100,
                      now_us=0).status == "admitted"
    assert inst.group_budget("root").available_us == 10
    with pytest.raises(rt.RtSchedError) as exc:
        inst.set_group_budget("missing", 10)
    assert exc.value.code == "RT_GROUP_UNKNOWN"


def test_snapshot_is_detached_and_restore_roundtrips():
    inst = guard(watchdog_cooldown_us=5000)
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=20, now_us=0)
    inst.watchdog(1, now_us=1000)
    inst.admit(3, group="root", policy="rr", budget_us=40, now_us=2000)
    inst.admit(2, group="root", policy="fifo", budget_us=70, now_us=2000,
               allow_queue=True)

    state = inst.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"groups", "reservations", "queue", "cooldown",
                             "sequence", "stats"}

    state["groups"].clear()
    state["stats"]["admitted"] = 99
    assert inst.group_budget("root").used_us == 40
    assert inst.stats()["admitted"] == 2

    clone = guard(watchdog_cooldown_us=5000)
    clone.restore(pristine)
    assert clone.group_budget("root").used_us == 40
    assert [row.pid for row in clone.queued()] == [2]
    assert clone.cooldown_until(1) == 6000
    assert clone.stats()["admitted"] == 2
    assert clone.stats()["demotions"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=40, now_us=0)
    good_stats = {"groups": 1, "admitted": 1, "queued": 0, "rejected": 0,
                  "released": 0, "demotions": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"groups": {}, "reservations": {}, "queue": [], "cooldown": {},
         "sequence": 0, "stats": {}},
        {"groups": [], "reservations": {}, "queue": [], "cooldown": {},
         "sequence": 0, "stats": good_stats},
        {"groups": {}, "reservations": {}, "queue": [], "cooldown": {},
         "sequence": "0", "stats": good_stats},
    ]
    for bad in bad_states:
        with pytest.raises(rt.RtSchedError) as exc:
            inst.restore(bad)
        assert exc.value.code == "RT_SNAPSHOT_INVALID"
    assert inst.group_budget("root").used_us == 40
    assert inst.stats()["admitted"] == 1


def test_concurrent_admissions_never_overcommit_the_group():
    inst = guard()
    inst.create_group("root", budget_us=100)
    barrier = threading.Barrier(20)
    admitted = []
    rejected = []
    errors = []

    def worker(pid):
        try:
            barrier.wait(5)
            admitted.append(inst.admit(pid, group="root", policy="fifo",
                                       budget_us=30, now_us=0))
        except rt.RtSchedError as exc:
            rejected.append(exc.code)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert errors == []
    assert len(admitted) == 3
    assert len(rejected) == 17
    assert set(rejected) == {"RT_QUOTA_EXCEEDED"}
    assert inst.group_budget("root").used_us == 90
    assert sorted(row.pid for row in inst.admissions()) == sorted(
        row.pid for row in admitted)


def test_stats_track_each_operation_exactly():
    inst = guard()
    inst.create_group("root", budget_us=100)
    inst.admit(1, group="root", policy="fifo", budget_us=20, now_us=0)
    inst.admit(2, group="root", policy="fifo", budget_us=200, now_us=0,
               allow_queue=True)
    with pytest.raises(rt.RtSchedError):
        inst.admit(3, group="root", policy="fifo", budget_us=200, now_us=0)
    inst.release(1, now_us=10)
    assert inst.stats() == {"groups": 1, "admitted": 1, "queued": 1,
                            "rejected": 1, "released": 1, "demotions": 0,
                            "restores": 0}
