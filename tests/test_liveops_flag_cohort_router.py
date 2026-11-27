import copy
import threading

import pytest

import liveops_flag_cohort_router as lf


def router(**kwargs):
    return lf.FlagCohortRouter(**kwargs)


def test_define_flag_returns_increasing_config_version():
    rt = router()
    assert rt.config_version() == 0
    first = rt.define_flag("new-ui", enabled=True, rollout_bps=1000,
                           regions=("cn",), platforms=("ios",),
                           whitelist=("vip-1",))
    second = rt.define_flag("promo")
    assert (first, second) == (1, 2)
    assert rt.config_version() == 2
    spec = rt.spec_of("new-ui")
    assert (spec.name, spec.enabled, spec.rollout_bps) == ("new-ui", True, 1000)
    assert spec.regions == ("cn",)
    assert spec.platforms == ("ios",)
    assert spec.whitelist == ("vip-1",)
    assert spec.depends_on == ()
    assert spec.version == 1


def test_define_flag_rejects_bad_names_duplicates_and_overflow():
    rt = router(max_flags=1)
    for bad in ("", "   "):
        with pytest.raises(lf.FlagError) as exc:
            rt.define_flag(bad)
        assert exc.value.code == "FLAG_INVALID_NAME"
    assert rt.define_flag("first") == 1
    with pytest.raises(lf.FlagError) as exc:
        rt.define_flag("first")
    assert exc.value.code == "FLAG_ALREADY_DEFINED"
    with pytest.raises(lf.FlagError) as exc:
        rt.define_flag("second")
    assert exc.value.code == "FLAG_CAPACITY_EXCEEDED"
    assert rt.config_version() == 1


def test_unknown_flag_is_reported_on_every_entry_point():
    rt = router()
    with pytest.raises(lf.FlagError) as exc:
        rt.evaluate("acc-1", "ghost")
    assert exc.value.code == "FLAG_UNKNOWN"
    with pytest.raises(lf.FlagError) as exc:
        rt.bulk_evaluate("acc-1", ["ghost"])
    assert exc.value.code == "FLAG_UNKNOWN"
    with pytest.raises(lf.FlagError) as exc:
        rt.set_rollout("ghost", 100)
    assert exc.value.code == "FLAG_UNKNOWN"
    with pytest.raises(lf.FlagError) as exc:
        rt.remove_flag("ghost")
    assert exc.value.code == "FLAG_UNKNOWN"
    with pytest.raises(lf.FlagError) as exc:
        rt.spec_of("ghost")
    assert exc.value.code == "FLAG_UNKNOWN"


def test_rollout_edges_decide_every_account():
    rt = router()
    rt.define_flag("new-ui", enabled=True, rollout_bps=0)
    for index in range(5):
        decision = rt.evaluate(f"acc-{index}", "new-ui")
        assert (decision.enabled, decision.reason) == (False, "COHORT_MISS")
    rt.set_rollout("new-ui", 10000)
    for index in range(5):
        decision = rt.evaluate(f"acc-{index}", "new-ui")
        assert (decision.enabled, decision.reason) == (True, "COHORT_HIT")


def test_whitelist_overrides_rollout_and_reports_source():
    rt = router()
    rt.define_flag("beta", enabled=True, rollout_bps=0, whitelist=("vip-1",))
    decision = rt.evaluate("vip-1", "beta")
    assert decision.enabled is True
    assert decision.reason == "WHITELIST"
    assert decision.source == "whitelist"
    other = rt.evaluate("vip-2", "beta")
    assert other.enabled is False
    assert other.reason == "COHORT_MISS"


def test_targeting_sets_gate_region_platform_and_version():
    rt = router()
    rt.define_flag("promo", enabled=True, rollout_bps=10000,
                   regions=("cn",), platforms=("ios",),
                   versions=("1.2.0",))
    miss_region = rt.evaluate("acc-1", "promo", region="us", platform="ios",
                              version="1.2.0")
    assert (miss_region.enabled, miss_region.reason) == (False, "TARGET_MISS")
    assert miss_region.source == "target"
    miss_platform = rt.evaluate("acc-1", "promo", region="cn", platform="android",
                                version="1.2.0")
    assert (miss_platform.enabled, miss_platform.reason) == (False, "TARGET_MISS")
    miss_version = rt.evaluate("acc-1", "promo", region="cn", platform="ios",
                               version="1.0.0")
    assert (miss_version.enabled, miss_version.reason) == (False, "TARGET_MISS")
    hit = rt.evaluate("acc-1", "promo", region="cn", platform="ios", version="1.2.0")
    assert (hit.enabled, hit.reason) == (True, "COHORT_HIT")
    assert hit.source == "rollout"


def test_decision_carries_the_configuration_version_it_used():
    rt = router()
    rt.define_flag("f", enabled=True, rollout_bps=10000)
    before = rt.evaluate("acc-1", "f")
    assert before.version == 1
    assert before.version == rt.config_version()
    assert rt.set_rollout("f", 5000) == 2
    after = rt.evaluate("acc-1", "f")
    assert after.version == 2
    assert after.version == rt.config_version()


def test_set_rollout_validates_range_and_audits_the_change():
    rt = router()
    rt.define_flag("f", enabled=True, rollout_bps=0)
    for bad in (-1, 10001):
        with pytest.raises(lf.FlagError) as exc:
            rt.set_rollout("f", bad)
        assert exc.value.code == "FLAG_INVALID_ROLLOUT"
    rt.set_rollout("f", 4000)
    rows = rt.audit_of("f")
    assert rows[-1]["kind"] == "rollout"
    assert rows[-1]["detail"] == {"from": 0, "to": 4000}
    assert rt.config_version() == 2


def test_bulk_evaluate_returns_topological_order():
    rt = router()
    rt.define_flag("a", enabled=True, rollout_bps=10000)
    rt.define_flag("b", enabled=True, rollout_bps=10000, depends_on=("a",))
    rt.define_flag("c", enabled=True, rollout_bps=10000, depends_on=("b",))
    results = rt.bulk_evaluate("acc-1", ["c", "b", "a"])
    assert [row.flag for row in results] == ["a", "b", "c"]
    assert [row.enabled for row in results] == [True, True, True]
    assert rt.stats()["evaluations"] == 3


def test_dependency_edges_refuse_unknown_parents_and_cycles():
    rt = router()
    with pytest.raises(lf.FlagError) as exc:
        rt.define_flag("x", depends_on=("missing",))
    assert exc.value.code == "FLAG_UNKNOWN_DEPENDENCY"
    with pytest.raises(lf.FlagError) as exc:
        rt.spec_of("x")
    assert exc.value.code == "FLAG_UNKNOWN"
    rt.define_flag("a")
    rt.define_flag("b", depends_on=("a",))
    with pytest.raises(lf.FlagError) as exc:
        rt.set_dependencies("a", ["b"])
    assert exc.value.code == "FLAG_DEPENDENCY_CYCLE"
    assert rt.spec_of("a").depends_on == ()
    assert rt.config_version() == 2


def test_remove_flag_drops_definitions_and_versions():
    rt = router()
    rt.define_flag("f", enabled=True, rollout_bps=10000)
    assert rt.evaluate("acc-1", "f").enabled is True
    assert rt.remove_flag("f") == 2
    assert rt.config_version() == 2
    with pytest.raises(lf.FlagError) as exc:
        rt.evaluate("acc-1", "f")
    assert exc.value.code == "FLAG_UNKNOWN"
    assert rt.stats()["flags"] == 0


def test_audit_keeps_newest_entries_in_sequence_order():
    rt = router(max_audit=3)
    rt.define_flag("f1")
    rt.define_flag("f2")
    rt.set_rollout("f1", 1000)
    rt.define_flag("f3")
    rt.remove_flag("f2")
    rows = rt.audit_of()
    assert [row["seq"] for row in rows] == [3, 4, 5]
    assert [row["kind"] for row in rows] == ["rollout", "define", "remove"]
    assert [row["flag"] for row in rows] == ["f1", "f3", "f2"]
    assert rt.stats()["audit"] == 3


def test_snapshot_is_detached_and_restore_roundtrips():
    rt = router()
    rt.define_flag("f", enabled=True, rollout_bps=10000, whitelist=("vip-1",))
    rt.evaluate("acc-1", "f")
    state = rt.snapshot()
    assert set(state) == {"version", "flags", "audit", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["flags"].clear()
    state["stats"]["evaluations"] = 99
    assert rt.evaluate("acc-1", "f").enabled is True
    clone = router()
    clone.restore(pristine)
    assert clone.config_version() == rt.config_version()
    assert clone.evaluate("acc-1", "f").enabled is True
    assert len(clone.audit_of()) == len(rt.audit_of())
    assert clone.stats() == rt.stats()


def test_restore_rejects_malformed_state():
    rt = router()
    rt.define_flag("f", enabled=True, rollout_bps=10000)
    bad_states = [
        None,
        {},
        {"version": 1, "flags": [], "audit": [], "counters": {}, "stats": {}},
        {"version": 1, "flags": {}, "audit": {}, "counters": {}, "stats": {}},
        {"version": 1, "flags": {}, "audit": [], "counters": [], "stats": {}},
        {"version": 1, "flags": {}, "audit": [], "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(lf.FlagError) as exc:
            rt.restore(bad)
        assert exc.value.code == "FLAG_SNAPSHOT_INVALID"
    assert rt.config_version() == 1
    assert rt.evaluate("acc-1", "f").enabled is True


def test_concurrent_rollout_changes_bump_versions_exactly_once_each():
    rt = router()
    rt.define_flag("f", enabled=True, rollout_bps=0)
    failures = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            rt.set_rollout("f", 100 * (index + 1))
        except Exception as exc:  # pragma: no cover - surfaced through failures
            failures.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert rt.config_version() == 9
    versions = [row["version"] for row in rt.audit_of("f")]
    assert versions == list(range(1, 10))
    assert rt.stats()["version"] == 9
