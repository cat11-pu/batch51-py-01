import pytest

import sched_affinity_warden as sw


def warden(**kwargs):
    return sw.SchedAffinityWarden(**kwargs)


def tenant(w, name="t1", cpus=(0, 1, 2, 3)):
    w.set_allowed(name, list(cpus))
    return w


def test_set_allowed_normalises_and_drops_offline_cpus():
    w = warden(cpus=(0, 1, 2, 3))
    w.set_online((0, 1, 2))
    assert w.set_allowed("t1", [3, 2, 2, 0]) == (0, 2)
    assert w.allowed_for("t1") == (0, 2)
    assert w.stats()["hotplug"] == 1


def test_set_allowed_rejects_empty_and_unknown_cpu():
    w = warden(cpus=(0, 1, 2, 3))
    with pytest.raises(sw.SchedError) as excinfo:
        w.set_allowed("t1", [])
    assert excinfo.value.code == "SCHED_EMPTY_SET"
    with pytest.raises(sw.SchedError) as excinfo:
        w.set_allowed("t1", [9])
    assert excinfo.value.code == "SCHED_CPU_UNKNOWN"
    with pytest.raises(sw.SchedError) as excinfo:
        w.allowed_for("t1")
    assert excinfo.value.code == "SCHED_UNKNOWN_TENANT"


def test_register_intersects_tenant_and_online():
    w = tenant(warden(cpus=(0, 1, 2, 3)), cpus=(0, 1, 2))
    view = w.register_process(700, "t1", [1, 2, 3])
    assert view.pid == 700
    assert view.tenant == "t1"
    assert view.desired == frozenset({1, 2, 3})
    assert view.effective == frozenset({1, 2})
    assert view.epoch == 0
    assert w.effective_set(700) == frozenset({1, 2})


def test_register_requires_known_tenant():
    w = warden()
    with pytest.raises(sw.SchedError) as excinfo:
        w.register_process(701, "t9", [0])
    assert excinfo.value.code == "SCHED_UNKNOWN_TENANT"
    assert w.stats()["registered"] == 0


def test_duplicate_pid_is_refused():
    w = tenant(warden(), cpus=(0, 1, 2, 3))
    w.register_process(702, "t1", [2])
    with pytest.raises(sw.SchedError) as excinfo:
        w.register_process(702, "t1", [3])
    assert excinfo.value.code == "SCHED_DUPLICATE_PID"
    assert w.effective_set(702) == frozenset({2})


def test_apply_with_empty_intersection_keeps_previous():
    w = tenant(warden(), cpus=(0, 1))
    w.register_process(703, "t1", [0, 1])
    with pytest.raises(sw.SchedError) as excinfo:
        w.apply(703, [2, 3])
    assert excinfo.value.code == "SCHED_EMPTY_SET"
    assert w.effective_set(703) == frozenset({0, 1})
    assert w.history(703) == []
    assert w.stats()["rejected"] == 1


def test_apply_intersects_and_records_history():
    w = tenant(warden(), cpus=(0, 1))
    w.register_process(704, "t1", [0])
    view = w.apply(704, [1, 2])
    assert view.effective == frozenset({1})
    assert view.desired == frozenset({1, 2})
    assert view.epoch == 1
    entries = w.history(704)
    assert len(entries) == 1
    assert entries[0]["desired"] == (1, 2)
    assert entries[0]["effective"] == (1,)
    assert entries[0]["reason"] == "apply"
    assert w.stats()["applied"] == 1


def test_apply_rejects_unknown_pid_and_cpu():
    w = tenant(warden(), cpus=(0, 1))
    with pytest.raises(sw.SchedError) as excinfo:
        w.apply(999, [0])
    assert excinfo.value.code == "SCHED_UNKNOWN_PID"
    w.register_process(705, "t1", [0])
    with pytest.raises(sw.SchedError) as excinfo:
        w.apply(705, [0, 8])
    assert excinfo.value.code == "SCHED_CPU_UNKNOWN"
    assert w.effective_set(705) == frozenset({0})


def test_offline_cpu_migrates_registered_processes():
    w = tenant(warden(cpus=(0, 1, 2, 3)))
    w.register_process(706, "t1", [1, 2])
    w.register_process(707, "t1", [3])
    assert w.set_online((0, 1, 3)) == (0, 1, 3)
    out = w.reconcile()
    assert out == {"checked": 2, "migrated": 1, "fallback": 0, "failed": 0}
    assert w.effective_set(706) == frozenset({1})
    assert w.effective_set(707) == frozenset({3})
    assert w.stats()["migrated"] == 1


def test_reconcile_restores_when_cpu_returns_online():
    w = tenant(warden(cpus=(0, 1, 2, 3)))
    w.register_process(708, "t1", [1, 2])
    w.set_online((0, 1, 3))
    w.reconcile()
    assert w.effective_set(708) == frozenset({1})
    assert w.set_online((0, 1, 2, 3)) == (0, 1, 2, 3)
    out = w.reconcile()
    assert out["migrated"] == 1
    assert w.effective_set(708) == frozenset({1, 2})


def test_unregister_process_reports_first_and_second_call():
    w = tenant(warden())
    w.register_process(709, "t1", [0])
    assert w.unregister_process(709) is True
    assert w.unregister_process(709) is False
    with pytest.raises(sw.SchedError) as excinfo:
        w.effective_set(709)
    assert excinfo.value.code == "SCHED_UNKNOWN_PID"


def test_snapshot_restore_round_trip_is_deep():
    w = tenant(warden(cpus=(0, 1, 2, 3)), cpus=(0, 1, 2))
    w.register_process(710, "t1", [1, 2])
    w.apply(710, [2, 3])
    state = w.snapshot()
    fresh = warden(cpus=(0, 1, 2, 3))
    fresh.restore(state)
    assert fresh.allowed_for("t1") == (0, 1, 2)
    assert fresh.effective_set(710) == frozenset({2})
    assert fresh.stats()["applied"] == 1
    state["stats"]["applied"] = 99
    assert fresh.stats()["applied"] == 1


def test_restore_rejects_broken_state():
    w = tenant(warden())
    w.register_process(711, "t1", [0, 1])
    with pytest.raises(sw.SchedError) as excinfo:
        w.restore({"tenants": {}, "processes": {"711": {"pid": 711}}})
    assert excinfo.value.code == "SCHED_SNAPSHOT_INVALID"
    assert w.effective_set(711) == frozenset({0, 1})


def test_stats_count_hotplug_and_apply():
    w = tenant(warden(cpus=(0, 1, 2, 3)))
    w.register_process(712, "t1", [2, 3])
    w.apply(712, [1, 2])
    assert w.set_online((0, 1, 2, 3)) == (0, 1, 2, 3)
    out = w.reconcile()
    stats = w.stats()
    assert stats["registered"] == 1
    assert stats["applied"] == 1
    assert stats["hotplug"] == 1
    assert out["checked"] == 1
    assert w.effective_set(712) == frozenset({1, 2})


def test_empty_warden_reconciles_to_zero():
    w = warden()
    assert w.reconcile() == {"checked": 0, "migrated": 0, "fallback": 0,
                             "failed": 0}
    with pytest.raises(sw.SchedError) as excinfo:
        w.effective_set(1)
    assert excinfo.value.code == "SCHED_UNKNOWN_PID"
