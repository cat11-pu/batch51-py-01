import copy

import pytest

import cors_policy_evaluator as cpe

ORIGIN = "https://app.example.com"


def evaluator(**kwargs):
    return cpe.CorsPolicyEvaluator(**kwargs)


def api_policy(instance, **kwargs):
    options = dict(origins=[ORIGIN], methods=["GET", "POST"],
                   headers=["Content-Type", "X-Token"], max_age=300)
    options.update(kwargs)
    return instance.register_policy("/api", **options)


def test_policy_registration_normalizes_methods_and_headers():
    gate = evaluator()
    policy = gate.register_policy("/api", origins=[ORIGIN],
                                  methods=["get", "POST", "get"],
                                  headers=["Content-Type", "X-Token"],
                                  max_age=300)
    assert policy.route == "/api"
    assert policy.origins == (ORIGIN,)
    assert policy.methods == ("GET", "POST")
    assert policy.headers == ("content-type", "x-token")
    assert policy.allow_credentials is False
    assert policy.max_age == 300
    assert gate.stats()["policies"] == 1


def test_exact_origin_is_allowed():
    gate = evaluator()
    api_policy(gate)
    decision = gate.evaluate("/api", ORIGIN, method="GET", now=0.0)
    assert decision.allowed is True
    assert decision.allow_origin == ORIGIN
    assert decision.allow_methods == ("GET", "POST")
    assert decision.reason == "ok"
    assert gate.stats()["evaluations"] == 1


def test_wildcard_origin_accepts_any_origin_without_credentials():
    gate = evaluator()
    gate.register_policy("/pub", origins=["*"], methods=["GET"])
    decision = gate.evaluate("/pub", "https://any.example.net", now=0.0)
    assert decision.allowed is True
    assert decision.allow_origin == "*"


def test_unknown_origin_is_denied():
    gate = evaluator()
    api_policy(gate)
    decision = gate.evaluate("/api", "https://evil.example", now=0.0)
    assert decision.allowed is False
    assert decision.allow_origin is None
    assert decision.reason == "origin-not-allowed"
    assert gate.stats()["denied"] == 1


def test_scheme_mismatch_is_a_different_origin():
    gate = evaluator()
    api_policy(gate)
    decision = gate.evaluate("/api", "http://app.example.com", now=0.0)
    assert decision.allowed is False
    assert decision.reason == "origin-not-allowed"


def test_route_without_policy_is_not_allowed():
    gate = evaluator()
    decision = gate.evaluate("/missing", ORIGIN, now=0.0)
    assert decision.allowed is False
    assert decision.allow_origin is None
    assert decision.reason == "no-policy"


def test_preflight_returns_methods_headers_and_cache_key():
    gate = evaluator()
    api_policy(gate)
    decision = gate.preflight("/api", ORIGIN, method="POST",
                              headers=["X-Token", "Content-Type"], now=0.0)
    assert decision.allowed is True
    assert decision.allow_origin == ORIGIN
    assert decision.allow_methods == ("GET", "POST")
    assert decision.allow_headers == ("content-type", "x-token")
    assert decision.max_age == 300
    assert decision.cacheable is True
    assert decision.cache_key == gate.cache_key("/api", ORIGIN, method="POST",
                                                headers=["Content-Type", "X-Token"])
    assert gate.stats()["preflights"] == 1


def test_preflight_rejects_headers_outside_the_policy():
    gate = evaluator()
    api_policy(gate)
    decision = gate.preflight("/api", ORIGIN, method="POST",
                              headers=["X-Token", "X-Evil"], now=0.0)
    assert decision.allowed is False
    assert decision.cacheable is False
    assert decision.reason == "header-not-allowed"
    assert gate.stats()["denied"] == 1


def test_cache_key_ignores_header_order_and_case():
    gate = evaluator()
    api_policy(gate)
    first = gate.cache_key("/api", ORIGIN, method="post",
                           headers=["X-Token", "content-type"])
    second = gate.cache_key("/api", ORIGIN, method="POST",
                            headers=["Content-Type", "X-Token"])
    third = gate.cache_key("/api", ORIGIN, method="GET",
                           headers=["Content-Type", "X-Token"])
    assert first == second
    assert first != third


def test_remember_lookup_and_invalidate():
    gate = evaluator()
    api_policy(gate)
    decision = gate.preflight("/api", ORIGIN, method="POST",
                              headers=["Content-Type"], now=0.0)
    key = gate.remember(decision, now=0.0)
    assert key == decision.cache_key
    hit = gate.lookup_cache(key, now=1.0)
    assert hit is not None
    assert hit.allow_origin == ORIGIN
    assert gate.stats()["cache_hits"] == 1
    assert gate.invalidate("/api") == 1
    assert gate.lookup_cache(key, now=2.0) is None


def test_preflight_cache_is_bounded_and_evicts_oldest():
    gate = evaluator(max_cache_entries=2)
    gate.register_policy("/pub", origins=["*"], methods=["GET"])
    keys = []
    for index, origin in enumerate(("https://a.example", "https://b.example",
                                    "https://c.example")):
        decision = gate.preflight("/pub", origin, method="GET", now=float(index))
        keys.append(gate.remember(decision, now=float(index)))
    assert gate.cache_size() == 2
    assert gate.lookup_cache(keys[0], now=10.0) is None
    assert gate.lookup_cache(keys[1], now=10.0) is not None
    assert gate.stats()["cache_evictions"] == 1


def test_invalid_policy_input_is_rejected():
    gate = evaluator()
    with pytest.raises(cpe.CorsError) as exc:
        gate.register_policy("", origins=[ORIGIN])
    assert exc.value.code == "CORS_INVALID_POLICY"
    with pytest.raises(cpe.CorsError) as exc:
        gate.register_policy("/api", origins=[])
    assert exc.value.code == "CORS_INVALID_POLICY"
    with pytest.raises(cpe.CorsError) as exc:
        gate.register_policy("/api", origins=[ORIGIN], methods=[""])
    assert exc.value.code == "CORS_INVALID_POLICY"
    with pytest.raises(cpe.CorsError) as exc:
        gate.register_policy("/api", origins=[ORIGIN], headers=["ok", 5])
    assert exc.value.code == "CORS_INVALID_POLICY"


def test_snapshot_is_detached_and_restore_roundtrips():
    gate = evaluator()
    api_policy(gate)
    decision = gate.preflight("/api", ORIGIN, method="POST",
                              headers=["Content-Type"], now=0.0)
    key = gate.remember(decision, now=0.0)
    state = gate.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "policies", "cache", "stats"}

    state["policies"].clear()
    state["stats"]["policies"] = 99
    assert gate.policy_for("/api") is not None
    assert gate.stats()["policies"] == 1

    clone = evaluator()
    clone.restore(pristine)
    assert clone.evaluate("/api", ORIGIN, now=1.0).allowed is True
    assert clone.lookup_cache(key, now=1.0) is not None
    assert clone.stats()["policies"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    gate = evaluator()
    api_policy(gate)
    good = gate.snapshot()
    bad_states = [
        None,
        {},
        dict(good, version=2),
        dict(good, policies=[]),
        dict(good, cache="nope"),
        dict(good, stats={"policies": 1}),
    ]
    for bad in bad_states:
        with pytest.raises(cpe.CorsError) as exc:
            gate.restore(bad)
        assert exc.value.code == "CORS_SNAPSHOT_INVALID"

    assert gate.policy_for("/api") is not None
    assert gate.stats()["policies"] == 1


def test_stats_track_evaluation_preflight_and_cache():
    gate = evaluator()
    api_policy(gate)
    gate.evaluate("/api", ORIGIN, method="GET", now=0.0)
    gate.evaluate("/api", "https://evil.example", now=0.0)
    decision = gate.preflight("/api", ORIGIN, method="POST",
                              headers=["Content-Type"], now=0.0)
    key = gate.remember(decision, now=0.0)
    gate.lookup_cache(key, now=1.0)
    assert gate.stats() == {
        "policies": 1,
        "evaluations": 2,
        "preflights": 1,
        "denied": 1,
        "cache_hits": 1,
        "cache_evictions": 0,
    }
