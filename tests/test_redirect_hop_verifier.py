import copy

import pytest

import redirect_hop_verifier as rv


def verifier(**kwargs):
    return rv.RedirectHopVerifier(**kwargs)


def test_normalize_target_lowercases_and_drops_default_port():
    ver = verifier()
    assert ver.normalize_target("HTTPS://API.Example.com:443/v1/x") == "https://api.example.com/v1/x"
    assert ver.normalize_target("http://shop.example.com:80/a?b=1") == "http://shop.example.com/a?b=1"
    assert ver.normalize_target("https://shop.example.com:8443/a") == "https://shop.example.com:8443/a"
    assert ver.stats()["deduped"] == 0


def test_normalize_target_resolves_protocol_relative_against_base():
    ver = verifier()
    base = "https://shop.example.com/page/detail"
    assert ver.normalize_target("//cdn.example.com/a.js", base=base) == "https://cdn.example.com/a.js"
    assert ver.normalize_target("//CDN.Example.com:443/a.js", base=base) == "https://cdn.example.com/a.js"
    assert ver.normalize_target("https://cdn.example.com/x", base=base) == "https://cdn.example.com/x"


def test_normalize_target_folds_backslashes_and_double_slashes():
    ver = verifier()
    assert ver.normalize_target("https:\\api.example.com\\v1") == "https://api.example.com/v1"
    assert ver.normalize_target("https://api.example.com//v1///x") == "https://api.example.com/v1/x"
    assert ver.normalize_target("https:\\\\api.example.com\\v1") == "https://api.example.com/v1"


def test_normalize_target_resolves_dot_segments():
    ver = verifier()
    assert ver.normalize_target("https://api.example.com/a/b/../c/./d") == "https://api.example.com/a/c/d"
    assert ver.normalize_target("https://api.example.com/a/../../b") == "https://api.example.com/b"


def test_normalize_target_decodes_percent_encoded_host():
    ver = verifier()
    assert ver.normalize_target("https://%61pi.example.com/x") == "https://api.example.com/x"
    assert ver.normalize_target("https://%65XAMPLE.%63om/x") == "https://example.com/x"


def test_normalize_target_rejects_blank_and_schemeless():
    ver = verifier()
    for bad in ["", "   ", None, "//cdn.example.com/a", "cdn.example.com/a"]:
        with pytest.raises(rv.RedirectError) as exc:
            ver.normalize_target(bad)
        assert exc.value.code == "REDIRECT_TARGET_INVALID"


def test_check_scheme_accepts_http_family():
    ver = verifier()
    assert ver.check_scheme("HTTPS://api.example.com/x") == "https"
    assert ver.check_scheme("http://api.example.com/x") == "http"
    assert ver.normalize_target("HTTP://api.example.com/x") == "http://api.example.com/x"


def test_check_scheme_rejects_dangerous_schemes():
    ver = verifier()
    for bad in ["javascript:alert(1)", "data:text/html,<b>x</b>", "file:///etc/passwd"]:
        with pytest.raises(rv.RedirectError) as exc:
            ver.check_scheme(bad)
        assert exc.value.code == "REDIRECT_SCHEME_DENIED"
    https_only = verifier(allowed_schemes=("https",))
    with pytest.raises(rv.RedirectError) as exc:
        https_only.check_scheme("http://api.example.com/x")
    assert exc.value.code == "REDIRECT_SCHEME_DENIED"


def test_is_allowed_matches_exact_host_only():
    ver = verifier(allowed_hosts=("example.com",))
    assert ver.is_allowed("https://example.com/x") is True
    assert ver.is_allowed("https://EXAMPLE.com:443/x") is True
    assert ver.is_allowed("https://a.example.com/x") is False
    assert ver.is_allowed("https://example.com.evil.net/x") is False
    assert ver.allowed_hosts() == ["example.com"]


def test_verify_hops_accepts_fully_allowed_chain():
    ver = verifier(allowed_hosts=("example.com", "cdn.example.com"), max_hops=4)
    chain = [
        "https://example.com/start",
        "HTTPS://CDN.Example.com:443/mid",
        "https://example.com/end",
    ]
    out = ver.verify_hops(chain)
    assert out == {
        "ok": True,
        "reason": None,
        "count": 3,
        "denied": None,
        "hops": [
            "https://example.com/start",
            "https://cdn.example.com/mid",
            "https://example.com/end",
        ],
    }
    assert ver.hop_chain() == out["hops"]
    assert ver.stats()["verifications"] == 1
    assert ver.stats()["hops_checked"] == 3


def test_verify_hops_stops_at_offlist_host():
    ver = verifier(allowed_hosts=("example.com",), max_hops=4)
    out = ver.verify_hops([
        "https://example.com/a",
        "https://evil.example.net/b",
        "https://example.com/c",
    ])
    assert out["ok"] is False
    assert out["reason"] == "REDIRECT_HOST_DENIED"
    assert out["count"] == 1
    assert out["denied"] == "https://evil.example.net/b"
    assert out["hops"] == ["https://example.com/a"]
    assert ver.stats()["hop_denied"] == 1
    assert ver.stats()["chains_failed"] == 1


def test_verify_hops_enforces_max_hops():
    ver = verifier(allowed_hosts=("example.com",), max_hops=2)
    out = ver.verify_hops([
        "https://example.com/1",
        "https://example.com/2",
        "https://example.com/3",
        "https://example.com/4",
    ])
    assert out["ok"] is False
    assert out["reason"] == "REDIRECT_HOP_LIMIT"
    assert out["count"] == 2
    assert out["hops"] == ["https://example.com/1", "https://example.com/2"]
    assert out["denied"] == "https://example.com/3"
    assert ver.stats()["chains_failed"] == 1


def test_verify_hops_detects_cycle():
    ver = verifier(allowed_hosts=("example.com",), max_hops=6)
    out = ver.verify_hops([
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/a",
    ])
    assert out["ok"] is False
    assert out["reason"] == "REDIRECT_LOOP"
    assert out["count"] == 2
    assert out["denied"] == "https://example.com/a"
    assert len(out["hops"]) == 2


def test_dedupe_collapses_equivalent_forms():
    ver = verifier()
    rows = ver.dedupe([
        "https://Example.com:443/a",
        "https://example.com/a",
        "HTTP://example.com/b",
        "https://example.com/b",
        "https://example.com/a/",
    ])
    assert rows == [
        "https://example.com/a",
        "http://example.com/b",
        "https://example.com/a/",
    ]
    assert ver.stats()["deduped"] == 2


def test_snapshot_restore_and_stats():
    ver = verifier(allowed_hosts=("example.com",), max_hops=3)
    ver.verify_hops(["https://example.com/a", "https://example.com/b"])
    state = ver.snapshot()
    assert set(state) == {"version", "allowed_hosts", "allowed_schemes",
                          "max_hops", "chain", "stats"}
    pristine = copy.deepcopy(state)
    assert pristine["allowed_hosts"] == ["example.com"]
    assert pristine["chain"] == ["https://example.com/a", "https://example.com/b"]
    assert pristine["stats"]["hops_checked"] == 2

    state["chain"].clear()
    state["stats"]["hops_checked"] = 99
    assert ver.hop_chain() == ["https://example.com/a", "https://example.com/b"]
    assert ver.stats()["hops_checked"] == 2

    clone = verifier()
    clone.restore(pristine)
    assert clone.allowed_hosts() == ["example.com"]
    assert clone.hop_chain() == ["https://example.com/a", "https://example.com/b"]
    assert clone.stats()["restores"] == 1
    assert clone.stats()["hops_checked"] == 2

    for bad in [None, [], {"version": 2, "allowed_hosts": [], "allowed_schemes": [],
                           "max_hops": 3, "chain": [], "stats": {}}]:
        with pytest.raises(rv.RedirectError) as exc:
            clone.restore(bad)
        assert exc.value.code == "REDIRECT_SNAPSHOT_INVALID"
    assert clone.hop_chain() == ["https://example.com/a", "https://example.com/b"]
    assert clone.stats()["restores"] == 1
