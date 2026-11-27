import copy

import pytest

import ssrf_rebind_filter as sf

RESOLUTION = {
    "api.example.com": ("93.184.216.34",),
    "evil.example.net": ("203.0.113.9",),
}


def build(**kwargs):
    kwargs.setdefault("resolver", lambda host: RESOLUTION.get(host, ()))
    return sf.SsrfRebindFilter(**kwargs)


def test_normalize_strips_userinfo_and_resolves_dot_segments():
    guard = build()
    target = guard.normalize("HTTP://User:Pw@Example.COM:8080/a/../b/./c")

    assert target.scheme == "http"
    assert target.host == "example.com"
    assert target.port == 8080
    assert target.path == "/b/c"
    assert target.normalized == "http://example.com:8080/b/c"


def test_normalize_rejects_malformed_urls():
    guard = build()
    for raw in ("example.com/x", "http://example.com:99999/", "http:///nohost"):
        with pytest.raises(sf.SsrfError) as exc:
            guard.normalize(raw)
        assert exc.value.code == "SSRF_URL_INVALID"

    with pytest.raises(sf.SsrfError) as exc:
        guard.normalize("ftp://example.com/x")
    assert exc.value.code == "SSRF_SCHEME_REJECTED"


def test_numeric_host_forms_normalize_to_dotted_quad():
    guard = build()

    assert guard.normalize("http://2130706433/").host == "127.0.0.1"
    assert guard.normalize("http://0x7f.1/").host == "127.0.0.1"
    assert guard.normalize("http://0177.0.0.1/").host == "127.0.0.1"
    assert guard.normalize("http://2130706433/").normalized == "http://127.0.0.1/"
    assert guard.normalize("http://0x7f.1:80/x").normalized == "http://127.0.0.1:80/x"

    decision = guard.decide("http://2130706433/")
    assert decision.verdict == "deny"
    assert decision.hops[0].addresses == ("127.0.0.1",)


def test_classify_address_scopes():
    guard = build()
    cases = {
        "10.1.2.3": "private",
        "172.16.5.4": "private",
        "192.168.0.9": "private",
        "127.0.0.1": "loopback",
        "::1": "loopback",
        "169.254.169.254": "metadata",
        "100.100.100.200": "metadata",
        "fe80::1": "link_local",
        "fd00::1": "private",
        "8.8.8.8": "public",
        "not-an-ip": "invalid",
    }
    for address, expected in cases.items():
        assert guard.classify(address) == expected


def test_loopback_target_denied_at_first_hop():
    guard = build()
    decision = guard.decide("http://127.0.0.1/admin")

    assert decision.verdict == "deny"
    assert decision.reason == "SSRF_ADDRESS_DENIED"
    assert decision.failed_hop == 0
    assert len(decision.hops) == 1
    assert decision.hops[0].addresses == ("127.0.0.1",)


def test_metadata_address_has_its_own_reason():
    guard = build()
    decision = guard.decide("http://169.254.169.254/latest/meta-data/")

    assert decision.verdict == "deny"
    assert decision.reason == "SSRF_METADATA_DENIED"
    assert decision.hops[0].addresses == ("169.254.169.254",)
    assert decision.target.host == "169.254.169.254"


def test_unresolved_host_is_denied():
    guard = build()
    decision = guard.decide("https://nowhere.example.org/v1")

    assert decision.verdict == "deny"
    assert decision.reason == "SSRF_UNRESOLVED"
    assert decision.target.host == "nowhere.example.org"
    assert decision.hops[0].addresses == ()


def test_allowlist_is_exact_host_match():
    guard = build(allow_hosts=("API.Example.com.",))
    assert guard.allowed_hosts() == ("api.example.com",)

    allowed = guard.decide("https://api.example.com/v1")
    assert allowed.verdict == "allow"

    for raw in ("https://evil-api.example.com/v1", "https://api.example.com.evil.net/v1"):
        denied = guard.decide(raw)
        assert denied.verdict == "deny"
        assert denied.reason == "SSRF_HOST_NOT_ALLOWED"


def test_public_target_allowed_and_audited():
    guard = build()
    decision = guard.decide("https://api.example.com/v1/items")

    assert decision.verdict == "allow"
    assert decision.reason == "SSRF_OK"
    assert decision.target.port == 443
    assert decision.hops[0].verdict == "allow"
    assert decision.hops[0].addresses == ("93.184.216.34",)

    entry = guard.audit_log()[-1]
    assert entry["code"] == "SSRF_OK"
    assert entry["host"] == "api.example.com"
    assert guard.stats()["allowed"] == 1
    assert guard.stats()["denied"] == 0


def test_redirect_hop_is_checked_per_target():
    guard = build()
    first = guard.decide("https://api.example.com/v1")
    assert first.verdict == "allow"

    second = guard.follow_redirect(first, "http://10.0.0.5/internal")
    assert second.verdict == "deny"
    assert second.reason == "SSRF_ADDRESS_DENIED"
    assert len(second.hops) == 2
    assert [hop.verdict for hop in second.hops] == ["allow", "deny"]
    assert second.hops[1].addresses == ("10.0.0.5",)


def test_redirect_limit_rejects_chain():
    guard = build(max_redirects=2)
    decision = guard.decide("https://api.example.com/v1")

    decision = guard.follow_redirect(decision, "https://api.example.com/v2")
    assert decision.verdict == "allow"
    decision = guard.follow_redirect(decision, "https://api.example.com/v3")
    assert decision.verdict == "allow"

    over = guard.follow_redirect(decision, "https://api.example.com/v4")
    assert over.verdict == "deny"
    assert over.reason == "SSRF_REDIRECT_LIMIT"
    assert len(over.hops) == 4
    assert over.hops[-1].reason == "SSRF_REDIRECT_LIMIT"
    assert over.failed_hop == 3


def test_redirect_to_unsupported_scheme_denied():
    guard = build()
    decision = guard.decide("https://api.example.com/v1")

    out = guard.follow_redirect(decision, "gopher://api.example.com:70/_")
    assert out.verdict == "deny"
    assert out.reason == "SSRF_SCHEME_REJECTED"
    assert len(out.hops) == 2
    assert out.hops[-1].verdict == "deny"


def test_port_restriction_applies_after_normalization():
    guard = build(allow_ports=(443,))

    denied = guard.decide("http://api.example.com/v1")
    assert denied.verdict == "deny"
    assert denied.reason == "SSRF_PORT_REJECTED"

    assert guard.decide("https://api.example.com/v1").verdict == "allow"
    assert guard.decide("https://api.example.com:443/v1").verdict == "allow"


def test_snapshot_detached_and_restore_roundtrip():
    guard = build(allow_hosts=("api.example.com",))
    guard.decide("https://api.example.com/v1")

    state = guard.snapshot()
    assert set(state) == {"version", "allow_hosts", "bindings", "audit", "stats"}
    pristine = copy.deepcopy(state)

    state["allow_hosts"].clear()
    state["stats"]["allowed"] = 42
    assert guard.stats()["allowed"] == 1
    assert guard.allowed_hosts() == ("api.example.com",)

    clone = sf.SsrfRebindFilter()
    clone.restore(pristine)
    assert clone.allowed_hosts() == ("api.example.com",)
    assert clone.stats()["allowed"] == 1
    assert clone.stats()["restores"] == 1

    with pytest.raises(sf.SsrfError) as exc:
        clone.restore({"version": 1, "allow_hosts": [], "bindings": {}, "audit": [],
                       "stats": {}})
    assert exc.value.code == "SSRF_SNAPSHOT_INVALID"
    assert clone.stats()["allowed"] == 1


def test_counters_track_each_decision():
    guard = build(max_redirects=2)

    guard.decide("https://api.example.com/v1")
    guard.decide("http://10.0.0.5/x")
    guard.decide("not a url")
    first = guard.decide("https://api.example.com/v1")
    guard.follow_redirect(first, "https://api.example.com/v2")

    assert guard.stats() == {"allowed": 2, "denied": 2, "hops": 4,
                             "redirects": 1, "restores": 0}
