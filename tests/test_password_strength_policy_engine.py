import copy

import pytest

import password_strength_policy_engine as pw

BASELINE = {"min_length": 12, "min_classes": 3, "max_repeats": 2, "min_score": 60}


def engine(**kwargs):
    return pw.StrengthPolicyEngine(**kwargs)


def test_strong_password_passes_with_full_score():
    eng = engine()
    result = eng.evaluate("Abcd1234!xyz", tenant="t1")
    assert result.passed is True
    assert result.score == 100
    assert result.failed == ()
    assert result.exempted == ()
    assert result.version == 1


def test_short_password_fails_length_with_penalty():
    eng = engine()
    result = eng.evaluate("Ab1!", tenant="t1")
    assert result.passed is False
    assert result.failed == ("length",)
    assert result.score == 75
    assert eng.stats()["evaluations"] == 1
    assert eng.stats()["failures"] == 1


def test_password_with_too_few_character_classes_fails():
    eng = engine()
    result = eng.evaluate("abcdefghijklm", tenant="t1")
    assert result.passed is False
    assert result.failed == ("classes",)
    assert result.score == 80


def test_repeated_run_above_limit_fails():
    eng = engine()
    result = eng.evaluate("Aaaaaaaa1234!", tenant="t1")
    assert result.passed is False
    assert result.failed == ("repeat",)
    assert result.score == 85


def test_dictionary_substring_blocks_case_insensitively():
    eng = engine()
    result = eng.evaluate("XxPasswordYy12!", tenant="t1")
    assert result.passed is False
    assert result.failed == ("dictionary",)
    assert result.score == 70


def test_tenant_policy_can_only_tighten_the_baseline():
    eng = engine()
    version = eng.set_tenant_policy("t1", {"min_length": 8, "min_classes": 4,
                                           "max_repeats": 1})
    assert version == 2
    policy = eng.compose("t1")
    assert policy.min_length == 12
    assert policy.min_classes == 4
    assert policy.max_repeats == 1
    assert policy.version == 2
    result = eng.evaluate("Ab3!xyZ9", tenant="t1")
    assert result.passed is False
    assert result.failed == ("length",)
    assert result.score == 75


def test_scenario_exception_can_relax_an_explicit_key():
    eng = engine()
    eng.set_tenant_policy("t1", {})
    version = eng.register_exception("t1", "kiosk", {"min_length": 8})
    assert version == 3
    policy = eng.compose("t1", scenario="kiosk")
    assert policy.min_length == 8
    assert policy.version == 3
    result = eng.evaluate("Ab3!xyZ9", tenant="t1", scenario="kiosk")
    assert result.passed is True
    assert result.score == 100
    assert result.failed == ()
    described = eng.explain("t1", scenario="kiosk")
    assert described["min_length"] == 8
    assert described["version"] == 3
    assert described["exempted"] == []


def test_exception_registration_rejects_unknown_keys_and_blank_names():
    eng = engine()
    bad_calls = [
        dict(tenant="t1", scenario="kiosk", overrides={"teleport": 1}),
        dict(tenant="", scenario="kiosk", overrides={"min_length": 8}),
        dict(tenant="t1", scenario="", overrides={"min_length": 8}),
    ]
    for kwargs in bad_calls:
        with pytest.raises(pw.PolicyError) as exc:
            eng.register_exception(exempt=(), **kwargs)
        assert exc.value.code == "POLICY_INVALID_REQUEST"
    with pytest.raises(pw.PolicyError) as exc:
        eng.register_exception("t1", "kiosk", {"min_length": 8},
                               exempt=("teleport",))
    assert exc.value.code == "POLICY_INVALID_REQUEST"
    assert eng.policy_version() == 1


def test_unknown_scenario_and_blank_tenant_are_refused():
    eng = engine()
    with pytest.raises(pw.PolicyError) as exc:
        eng.compose("t1", scenario="night-shift")
    assert exc.value.code == "POLICY_SCENARIO_UNKNOWN"
    with pytest.raises(pw.PolicyError) as exc:
        eng.compose("")
    assert exc.value.code == "POLICY_INVALID_REQUEST"
    with pytest.raises(pw.PolicyError) as exc:
        eng.evaluate("Abcd1234!xyz", tenant="")
    assert exc.value.code == "POLICY_INVALID_REQUEST"


def test_multiple_failed_rules_stack_penalties():
    eng = engine()
    result = eng.evaluate("aaa", tenant="t1")
    assert result.passed is False
    assert set(result.failed) == {"length", "classes", "repeat"}
    assert len(result.failed) == 3
    assert result.score == 40


def test_explicit_exemption_skips_only_the_named_rule():
    eng = engine()
    eng.set_tenant_policy("t1", {})
    eng.register_exception("t1", "legacy", {}, exempt=("repeat",))
    allowed = eng.evaluate("Aaaaaaaa1234!", tenant="t1", scenario="legacy")
    assert allowed.passed is True
    assert allowed.failed == ()
    assert allowed.exempted == ("repeat",)
    assert allowed.score == 100
    strict = eng.evaluate("Aaaaaaaa1234!", tenant="t1")
    assert strict.failed == ("repeat",)
    assert strict.score == 85


def test_reload_swaps_every_layer_and_bumps_version():
    eng = engine()
    eng.set_tenant_policy("t1", {})
    old = eng.compose("t1")
    new_version = eng.reload({
        "baseline": {"min_length": 16, "min_classes": 3,
                     "max_repeats": 2, "min_score": 70},
        "tenants": {"t1": {"min_length": 18}},
        "exceptions": [{"tenant": "t1", "scenario": "kiosk",
                        "overrides": {"min_length": 10}, "exempt": ["repeat"]}],
    })
    assert new_version == old.version + 1
    assert old.min_length == 12
    assert old.version == 2
    fresh = eng.compose("t1")
    assert fresh.min_length == 18
    assert fresh.version == new_version
    assert fresh.min_score == 70
    assert eng.compose("t1", scenario="kiosk").min_length == 10
    assert eng.policy_version() == new_version
    assert eng.stats()["reloads"] == 1


def test_reload_rejects_malformed_payload_and_keeps_old_policy():
    eng = engine()
    eng.set_tenant_policy("t1", {})
    version = eng.policy_version()
    bad_payloads = [
        {},
        {"baseline": {"min_length": 16, "min_classes": 3, "max_repeats": 2},
         "tenants": {}, "exceptions": []},
        {"baseline": dict(BASELINE), "tenants": [], "exceptions": []},
        {"baseline": dict(BASELINE), "tenants": {}, "exceptions": "nope"},
        {"baseline": {"min_length": "long", "min_classes": 3,
                      "max_repeats": 2, "min_score": 60},
         "tenants": {}, "exceptions": []},
        {"baseline": dict(BASELINE), "tenants": {"t1": {"teleport": 1}},
         "exceptions": []},
    ]
    for bad in bad_payloads:
        with pytest.raises(pw.PolicyError) as exc:
            eng.reload(bad)
        assert exc.value.code == "POLICY_PAYLOAD_INVALID"
    assert eng.policy_version() == version
    assert eng.compose("t1").min_length == 12


def test_snapshot_is_detached_and_restore_roundtrips():
    eng = engine()
    eng.set_tenant_policy("t1", {"min_classes": 4})
    eng.register_exception("t1", "travel", {"min_length": 10},
                           exempt=("repeat",))
    state = eng.snapshot()
    assert set(state) == {"version", "baseline", "tenants", "exceptions", "stats"}
    pristine = copy.deepcopy(state)
    state["baseline"]["min_length"] = 99
    state["stats"]["evaluations"] = 42
    live = eng.compose("t1", scenario="travel")
    assert live.min_length == 10
    assert eng.compose("t1").min_length == 12
    assert eng.stats()["evaluations"] == 0

    clone = engine()
    clone.restore(pristine)
    assert clone.policy_version() == 3
    assert clone.compose("t1", scenario="travel") == live
    assert clone.compose("t1") == eng.compose("t1")
    assert clone.stats() == eng.stats()


def test_restore_rejects_malformed_state_without_touching_live_data():
    eng = engine()
    eng.set_tenant_policy("t1", {"min_classes": 4})
    bad_states = [
        None,
        {},
        {"version": 2, "baseline": dict(BASELINE), "tenants": {},
         "exceptions": []},
        {"version": 0, "baseline": dict(BASELINE), "tenants": {},
         "exceptions": [], "stats": {}},
        {"version": 2, "baseline": {"min_length": 12}, "tenants": {},
         "exceptions": [], "stats": {}},
        {"version": 2, "baseline": dict(BASELINE), "tenants": [],
         "exceptions": [], "stats": {}},
        {"version": 2, "baseline": dict(BASELINE), "tenants": {},
         "exceptions": [{"tenant": "t1"}], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(pw.PolicyError) as exc:
            eng.restore(bad)
        assert exc.value.code == "POLICY_SNAPSHOT_INVALID"
    assert eng.policy_version() == 2
    assert eng.compose("t1").min_classes == 4
