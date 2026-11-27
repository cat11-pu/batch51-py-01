import pytest

import cors_policy_evaluator_p2 as cors


def evaluator(**kwargs):
    return cors.CorsPolicyEvaluatorP2(**kwargs)


def test_add_route_dedupes_and_counts():
    svc = evaluator()
    count = svc.add_route(
        "api",
        allow_origins=["*", "https://app.example.com", "https://app.example.com"],
    )
    assert count == 2
    assert svc.list_routes() == ("api",)
    assert svc.describe_route("api")["allow_origins"] == (
        "https://app.example.com",
        "*",
    )


def test_invalid_pattern_rejects_route():
    svc = evaluator()
    with pytest.raises(cors.CorsError) as excinfo:
        svc.add_route("api", allow_origins=["https://ok.example.com", "app.example.com"])
    assert excinfo.value.code == "CORS_INVALID_PATTERN"
    with pytest.raises(cors.CorsError) as missing:
        svc.match_origin("api", "https://ok.example.com")
    assert missing.value.code == "CORS_UNKNOWN_ROUTE"


def test_exact_match_is_case_insensitive():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://app.example.com"])
    assert svc.match_origin("api", "https://app.example.com") == "https://app.example.com"
    assert svc.match_origin("api", "https://APP.example.com") == "https://app.example.com"
    assert svc.match_origin("api", "https://other.example.com") is None


def test_suffix_matches_subdomain_only():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://*.example.com"])
    assert svc.match_origin("api", "https://api.example.com") == "https://*.example.com"
    assert svc.match_origin("api", "https://example.com") is None
    assert svc.match_origin("api", "http://api.example.com") is None


def test_longest_pattern_wins():
    svc = evaluator(max_age_cap=600)
    svc.add_route(
        "api",
        allow_origins=["*", "https://*.example.com", "https://app.example.com"],
    )
    assert svc.match_origin("api", "https://api.example.com") == "https://*.example.com"
    assert svc.match_origin("api", "https://elsewhere.test") == "*"
    assert svc.match_origin("api", "https://app.example.com") == "https://app.example.com"


def test_wildcard_echoes_star_without_credentials():
    svc = evaluator()
    svc.add_route("api", allow_origins=["*"])
    out = svc.evaluate("api", origin="https://anywhere.test")
    assert out["allowed"] is True
    assert out["pattern"] == "*"
    assert out["echo_origin"] == "*"
    assert out["reason"] == "allowed"


def test_exact_match_echoes_concrete_origin():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://app.example.com"])
    out = svc.evaluate("api", origin="https://app.example.com")
    assert out["allowed"] is True
    assert out["echo_origin"] == "https://app.example.com"


def test_credentials_require_route_flag():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://app.example.com"])
    out = svc.evaluate("api", origin="https://app.example.com", credentials=True)
    assert out["allowed"] is False
    assert out["echo_origin"] is None
    assert out["reason"] == "credentials-not-allowed"
    assert svc.check_credentials(
        "api", "https://app.example.com", credentials=True
    ) is False


def test_credentials_with_wildcard_rejected():
    svc = evaluator()
    svc.add_route("api", allow_origins=["*"], allow_credentials=True)
    out = svc.evaluate("api", origin="https://anywhere.test", credentials=True)
    assert out["allowed"] is False
    assert out["echo_origin"] is None
    assert out["reason"] == "wildcard-credentials"


def test_credentials_with_suffix_echoes_origin():
    svc = evaluator()
    svc.add_route(
        "api",
        allow_origins=["https://*.example.com"],
        allow_credentials=True,
    )
    out = svc.evaluate("api", origin="https://api.example.com", credentials=True)
    assert out["allowed"] is True
    assert out["pattern"] == "https://*.example.com"
    assert out["echo_origin"] == "https://api.example.com"
    assert svc.check_credentials(
        "api", "https://api.example.com", credentials=True
    ) is True


def test_preflight_ttl_respects_cap_and_request():
    svc = evaluator(max_age_cap=90, default_max_age=120)
    svc.add_route("api", allow_origins=["https://app.example.com"], max_age=300)
    assert svc.preflight_ttl("api") == 90
    assert svc.preflight_ttl("api", requested_max_age=30) == 30
    svc.add_route("plain", allow_origins=["https://app.example.com"])
    assert svc.preflight_ttl("plain") == 90


def test_preflight_ttl_rejects_negative_request():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://app.example.com"])
    with pytest.raises(cors.CorsError) as excinfo:
        svc.preflight_ttl("api", requested_max_age=-5)
    assert excinfo.value.code == "CORS_INVALID_REQUEST"


def test_remove_origin_affects_matching():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://app.example.com", "https://api.example.com"])
    assert svc.remove_origin("api", "https://app.example.com") is True
    assert svc.remove_origin("api", "https://app.example.com") is False
    assert svc.match_origin("api", "https://app.example.com") is None
    assert svc.match_origin("api", "https://api.example.com") == "https://api.example.com"


def test_snapshot_restore_roundtrip():
    svc = evaluator(max_age_cap=120)
    svc.add_route("api", allow_origins=["https://app.example.com"], allow_credentials=True)
    svc.evaluate("api", origin="https://app.example.com")
    before = svc.stats()["evaluations"]
    snap = svc.snapshot()

    svc.add_route("admin", allow_origins=["*"], allow_credentials=True)
    svc.remove_origin("api", "https://app.example.com")

    svc.restore(snap)
    assert svc.list_routes() == ("api",)
    assert svc.stats()["evaluations"] == before
    out = svc.evaluate("api", origin="https://app.example.com", credentials=True)
    assert out["allowed"] is True
    assert svc.describe_route("api")["allow_origins"] == ("https://app.example.com",)
    snap["stats"]["evaluations"] = 999
    assert svc.stats()["evaluations"] != 999


def test_restore_rejects_malformed_state():
    svc = evaluator()
    svc.add_route("api", allow_origins=["https://app.example.com"])
    with pytest.raises(cors.CorsError) as excinfo:
        svc.restore({"routes": {"api": {"allow_origins": "https://app.example.com"}}})
    assert excinfo.value.code == "CORS_SNAPSHOT_INVALID"
    assert svc.match_origin("api", "https://app.example.com") == "https://app.example.com"
