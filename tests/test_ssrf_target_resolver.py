import copy

import pytest

import ssrf_target_resolver as sr


def resolver(**kwargs):
    return sr.SsrfTargetResolver(**kwargs)


def test_normalize_splits_scheme_host_port_and_path():
    res = resolver()
    out = res.normalize("HTTPS://API.Example.COM:8443/V1/Items?q=1")
    assert out["scheme"] == "https"
    assert out["host"] == "api.example.com"
    assert out["port"] == 8443
    assert out["path"] == "/V1/Items?q=1"
    assert out["canonical"] == "https://api.example.com:8443/V1/Items?q=1"
    default = res.normalize("http://example.com")
    assert default["port"] == 80
    assert default["path"] == "/"
    assert default["canonical"] == "http://example.com/"
    assert res.stats()["normalized"] == 2


def test_normalize_rejects_missing_scheme_and_blank():
    res = resolver()
    for bad in ["", "   ", "example.com/path", None]:
        with pytest.raises(sr.SsrfError) as exc:
            res.normalize(bad)
        assert exc.value.code == "SSRF_INVALID_TARGET"
    assert res.stats()["normalized"] == 0


def test_normalize_rejects_non_http_schemes():
    res = resolver()
    for bad in ["ftp://example.com/x", "file:///etc/passwd", "gopher://example.com:70/"]:
        with pytest.raises(sr.SsrfError) as exc:
            res.normalize(bad)
        assert exc.value.code == "SSRF_SCHEME_DENIED"
    https_only = resolver(schemes=("https",))
    with pytest.raises(sr.SsrfError) as exc:
        https_only.normalize("http://example.com/")
    assert exc.value.code == "SSRF_SCHEME_DENIED"


def test_normalize_rewrites_decimal_and_octal_ipv4():
    res = resolver()
    decimal = res.normalize("http://2130706433/admin")
    assert decimal["host"] == "127.0.0.1"
    assert decimal["canonical"] == "http://127.0.0.1/admin"
    octal = res.normalize("http://0177.0.0.1/admin")
    assert octal["host"] == "127.0.0.1"
    assert octal["canonical"] == "http://127.0.0.1/admin"


def test_normalize_rewrites_hex_and_strips_trailing_dot():
    res = resolver()
    assert res.normalize("http://0x7f.0.0.1/x")["host"] == "127.0.0.1"
    assert res.normalize("http://0x7f.0.0.1/x")["canonical"] == "http://127.0.0.1/x"
    assert res.normalize("http://Example.COM./x")["host"] == "example.com"
    assert res.normalize("http://Example.COM./x")["canonical"] == "http://example.com/x"


def test_classify_scope_maps_address_families():
    res = resolver()
    assert res.classify_scope("8.8.8.8") == sr.SCOPE_PUBLIC
    assert res.classify_scope("10.0.0.5") == sr.SCOPE_PRIVATE
    assert res.classify_scope("172.16.9.9") == sr.SCOPE_PRIVATE
    assert res.classify_scope("192.168.1.1") == sr.SCOPE_PRIVATE
    assert res.classify_scope("127.0.0.1") == sr.SCOPE_LOOPBACK
    assert res.classify_scope("169.254.1.1") == sr.SCOPE_LINK_LOCAL
    assert res.classify_scope("169.254.169.254") == sr.SCOPE_METADATA
    assert res.classify_scope("not-an-address") == sr.SCOPE_INVALID


def test_classify_scope_handles_ipv6_forms():
    res = resolver()
    assert res.classify_scope("::1") == sr.SCOPE_LOOPBACK
    assert res.classify_scope("::ffff:127.0.0.1") == sr.SCOPE_LOOPBACK
    assert res.classify_scope("fd00::1") == sr.SCOPE_PRIVATE
    assert res.classify_scope("fe80::1") == sr.SCOPE_LINK_LOCAL
    assert res.classify_scope("2606:4700::1111") == sr.SCOPE_PUBLIC


def test_decide_denies_internal_scopes_and_denylist():
    res = resolver(deny_cidrs=("8.8.8.0/24",))
    loop = res.decide("http://127.0.0.1/admin")
    assert loop["verdict"] == "deny"
    assert loop["reason"] == "SSRF_SCOPE_DENIED"
    assert loop["scope"] == sr.SCOPE_LOOPBACK
    denied = res.decide("http://8.8.8.8/x")
    assert denied["verdict"] == "deny"
    assert denied["reason"] == "SSRF_HOST_DENIED"
    assert denied["scope"] == sr.SCOPE_PUBLIC
    assert res.stats()["denied"] == 2


def test_decide_allowlist_overrides_private_resolution():
    res = resolver(allow_hosts=("api.example.com",))
    out = res.decide("https://api.example.com/v1", addresses=["10.0.0.7"])
    assert out["verdict"] == "allow"
    assert out["reason"] == "allowlisted"
    assert out["target"] == "https://api.example.com/v1"
    assert res.allowed_hosts() == ["api.example.com"]
    assert res.stats()["allowed"] == 1


def test_decide_denies_host_resolving_into_private_range():
    res = resolver()
    out = res.decide("https://internal.example.com/x",
                     addresses=["10.1.2.3", "93.184.216.34"])
    assert out["verdict"] == "deny"
    assert out["reason"] == "SSRF_RESOLVED_PRIVATE"
    assert out["scope"] == sr.SCOPE_PRIVATE
    assert res.stats()["bindings"] == 1


def test_bind_resolution_sorts_dedupes_and_rejects_empty():
    res = resolver()
    out = res.bind_resolution("API.Example.com.",
                              ["93.184.216.34", "10.0.0.1", "93.184.216.34"],
                              now=1000)
    assert out["host"] == "api.example.com"
    assert out["addresses"] == ["10.0.0.1", "93.184.216.34"]
    assert out["bound_at"] == 1000
    with pytest.raises(sr.SsrfError) as exc:
        res.bind_resolution("api.example.com", [])
    assert exc.value.code == "SSRF_RESOLUTION_EMPTY"
    assert res.stats()["bindings"] == 1


def test_follow_redirect_normalizes_and_records_chain():
    res = resolver(allow_hosts=("api.example.com", "cdn.example.com"), max_redirects=3)
    start = "https://api.example.com/start"
    assert res.follow_redirect(start, "HTTPS://CDN.Example.com:443/next") == "https://cdn.example.com/next"
    assert res.hops_for(start) == [
        "https://api.example.com/start",
        "https://cdn.example.com/next",
    ]
    assert res.targets() == ["https://api.example.com/start"]
    assert res.follow_redirect(start, "https://api.example.com/end") == "https://api.example.com/end"
    assert res.hops_for(start) == [
        "https://api.example.com/start",
        "https://cdn.example.com/next",
        "https://api.example.com/end",
    ]
    assert res.stats()["redirects"] == 2


def test_follow_redirect_enforces_hop_limit():
    res = resolver(allow_hosts=("api.example.com",), max_redirects=2)
    start = "https://api.example.com/0"
    for step in range(2):
        res.follow_redirect(start, "https://api.example.com/{0}".format(step + 1))
    with pytest.raises(sr.SsrfError) as exc:
        res.follow_redirect(start, "https://api.example.com/last")
    assert exc.value.code == "SSRF_REDIRECT_LIMIT"
    assert len(res.hops_for(start)) == 3
    assert res.stats()["redirect_limits"] == 1


def test_follow_redirect_denies_private_hop_and_detects_loop():
    res = resolver(allow_hosts=("api.example.com",), max_redirects=4)
    start = "https://api.example.com/a"
    with pytest.raises(sr.SsrfError) as exc:
        res.follow_redirect(start, "http://127.0.0.1/admin")
    assert exc.value.code == "SSRF_HOP_DENIED"
    assert exc.value.detail == {"hop": 2, "target": "http://127.0.0.1/admin"}
    assert len(res.hops_for(start)) == 1
    res.follow_redirect(start, "https://api.example.com/b")
    with pytest.raises(sr.SsrfError) as exc:
        res.follow_redirect(start, "https://api.example.com/a")
    assert exc.value.code == "SSRF_REDIRECT_LOOP"
    assert len(res.hops_for(start)) == 2
    assert res.stats()["hops_denied"] == 1


def test_snapshot_restore_and_stats():
    res = resolver(allow_hosts=("api.example.com",), deny_cidrs=("10.0.0.0/8",),
                   max_redirects=2)
    res.decide("http://127.0.0.1/x")
    res.decide("https://api.example.com/x", addresses=["93.184.216.34"])
    res.follow_redirect("https://api.example.com/a", "https://api.example.com/b")
    state = res.snapshot()
    assert set(state) == {"version", "schemes", "allow_hosts", "deny_cidrs",
                          "max_redirects", "targets", "chains", "bindings", "stats"}
    pristine = copy.deepcopy(state)
    before = dict(res.stats())
    assert before["denied"] == 1
    assert before["allowed"] == 1
    assert before["bindings"] == 1

    state["chains"].clear()
    state["stats"]["allowed"] = 99
    assert len(res.hops_for("https://api.example.com/a")) == 2
    assert res.stats()["allowed"] == 1

    clone = resolver()
    clone.restore(pristine)
    assert clone.allowed_hosts() == ["api.example.com"]
    assert clone.stats()["bindings"] == 1
    assert clone.stats()["restores"] == 1
    assert clone.hops_for("https://api.example.com/a") == [
        "https://api.example.com/a",
        "https://api.example.com/b",
    ]
    for bad in [None, [], {"version": 2}]:
        with pytest.raises(sr.SsrfError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SSRF_SNAPSHOT_INVALID"
    assert clone.stats()["bindings"] == 1
    assert clone.allowed_hosts() == ["api.example.com"]
