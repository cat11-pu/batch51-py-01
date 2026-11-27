import pytest

import host_header_probe_planner as hp


def planner(**kwargs):
    return hp.HostHeaderProbePlanner(**kwargs)


def test_add_target_plans_default_variants():
    p = planner()
    count = p.add_target("shop", host="app.example.com")
    assert count == 6
    probes = p.plan_probes("shop")
    assert len(probes) == 6
    assert probes[0].variant == "plain"
    assert probes[0].target_id == "shop"
    assert probes[0].host_header == "app.example.com"
    assert probes[0].port == 443
    assert "case" not in tuple(probe.variant for probe in probes)
    assert p.describe_target("shop")["ports"] == (443,)


def test_duplicate_target_rejected():
    p = planner()
    p.add_target("shop", host="app.example.com")
    with pytest.raises(hp.HostError) as excinfo:
        p.add_target("shop", host="other.example.com")
    assert excinfo.value.code == "HOST_DUPLICATE_TARGET"


def test_invalid_host_rejected():
    p = planner()
    for bad in ("", "https://app.example.com", "app.example.com:8443", "app example.com"):
        with pytest.raises(hp.HostError) as excinfo:
            p.add_target("shop", host=bad)
        assert excinfo.value.code == "HOST_INVALID_HOST"


def test_invalid_port_rejected():
    p = planner()
    with pytest.raises(hp.HostError) as excinfo:
        p.add_target("shop", host="app.example.com", ports=(0,))
    assert excinfo.value.code == "HOST_INVALID_PORT"
    with pytest.raises(hp.HostError) as empty:
        p.add_target("shop", host="app.example.com", ports=())
    assert empty.value.code == "HOST_INVALID_PORT"


def test_plan_probes_respects_limit():
    p = planner(per_target_limit=3)
    p.add_target("shop", host="app.example.com")
    probes = p.plan_probes("shop")
    assert len(probes) == 3
    assert tuple(probe.variant for probe in probes) == ("plain", "trailing-dot", "port")
    assert p.stats()["suppressed"] == 3


def test_dedupe_keeps_first_occurrence():
    p = planner()
    p.add_target("shop", host="app.example.com")
    probes = (
        hp.Probe("shop", "plain", "app.example.com", 443),
        hp.Probe("shop", "case", "APP.EXAMPLE.COM", 443),
        hp.Probe("shop", "port", "app.example.com:443", 443),
        hp.Probe("shop", "plain-again", " app.example.com ", 443),
    )
    out = p.dedupe("shop", probes)
    assert tuple(probe.variant for probe in out) == ("plain", "port")


def test_detect_cache_key_from_vary():
    p = planner()
    assert p.detect_cache_key({"Vary": "Accept-Encoding, Host"}) is True
    assert p.detect_cache_key({"vary": "accept"}) is False
    assert p.detect_cache_key({}) is False


def test_detect_cache_key_from_explicit_key():
    p = planner()
    assert p.detect_cache_key({"X-Cache-Key": "host|path|query"}) is True
    assert p.detect_cache_key({"X-Cache-Key": "path|query"}) is False


def test_body_echo_on_business_page_is_medium():
    p = planner()
    out = p.classify_reflection(
        {
            "target_id": "shop",
            "variant": "absolute",
            "body_contains_host": True,
            "redirect_contains_host": False,
            "page_kind": "business",
            "response_headers": {"vary": "accept"},
        }
    )
    assert out["channel"] == "body"
    assert out["cache_key"] is False
    assert out["risk"] == "medium"


def test_body_echo_with_cache_key_is_high():
    p = planner()
    out = p.classify_reflection(
        {
            "target_id": "shop",
            "variant": "absolute",
            "body_contains_host": True,
            "redirect_contains_host": False,
            "page_kind": "business",
            "response_headers": {"Vary": "Host, Accept"},
        }
    )
    assert out["cache_key"] is True
    assert out["risk"] == "high"


def test_redirect_echo_is_medium():
    p = planner()
    out = p.classify_reflection(
        {
            "target_id": "shop",
            "variant": "prefixed",
            "body_contains_host": False,
            "redirect_contains_host": True,
            "page_kind": "business",
            "response_headers": {},
        }
    )
    assert out["channel"] == "redirect"
    assert out["risk"] == "medium"


def test_no_echo_is_none():
    p = planner()
    out = p.classify_reflection(
        {
            "target_id": "shop",
            "variant": "plain",
            "body_contains_host": False,
            "redirect_contains_host": False,
            "page_kind": "business",
            "response_headers": {},
        }
    )
    assert out["channel"] == "none"
    assert out["risk"] == "none"


def test_remove_target():
    p = planner()
    p.add_target("shop", host="app.example.com")
    assert p.remove_target("shop") is True
    assert p.remove_target("shop") is False
    with pytest.raises(hp.HostError) as excinfo:
        p.plan_probes("shop")
    assert excinfo.value.code == "HOST_UNKNOWN_TARGET"


def test_snapshot_restore_roundtrip():
    p = planner(per_target_limit=6)
    p.add_target("shop", host="app.example.com")
    p.plan_probes("shop")
    before = p.stats()["planned"]
    snap = p.snapshot()

    p.add_target("blog", host="blog.example.com")
    p.remove_target("shop")
    p.plan_probes("blog")

    p.restore(snap)
    assert p.list_targets() == ("shop",)
    assert p.stats()["planned"] == before
    assert len(p.plan_probes("shop")) == 6
    with pytest.raises(hp.HostError):
        p.plan_probes("blog")
    snap["stats"]["planned"] = 999
    assert p.stats()["planned"] != 999


def test_restore_rejects_malformed_state():
    p = planner()
    p.add_target("shop", host="app.example.com")
    with pytest.raises(hp.HostError) as excinfo:
        p.restore({"targets": [("shop", "app.example.com")]})
    assert excinfo.value.code == "HOST_SNAPSHOT_INVALID"
    assert p.list_targets() == ("shop",)
