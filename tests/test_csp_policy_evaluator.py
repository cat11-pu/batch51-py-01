import copy

import pytest

import csp_policy_evaluator as csp

ORIGIN = "https://app.example.com"
SCRIPT_URL = "https://cdn.example.com/assets/app.js"


def evaluator(**kwargs):
    kwargs.setdefault("origin", ORIGIN)
    return csp.CspPolicyEvaluator(**kwargs)


def parsed(text, **kwargs):
    return evaluator().parse_policy(text, **kwargs)


def test_parse_normalizes_names_and_keeps_source_order():
    policy = parsed("IMG-SRC *; SCRIPT-SRC 'self' https://cdn.example.com", name="main")
    assert policy.name == "main"
    assert policy.mode == "enforce"
    assert tuple(policy.directives) == ("img-src", "script-src")
    assert policy.directives["img-src"] == ("*",)
    assert policy.directives["script-src"] == ("'self'", "https://cdn.example.com")
    assert parsed(";; script-src 'none' ;;").directives == {"script-src": ("'none'",)}


def test_parse_rejects_empty_oversized_too_many_and_bad_mode():
    ev = evaluator()
    for text, code in (
        ("", "CSP_POLICY_EMPTY"),
        ("  ; ; ", "CSP_POLICY_EMPTY"),
        ("a" * (csp.MAX_POLICY_CHARS + 1), "CSP_POLICY_TOO_LARGE"),
    ):
        with pytest.raises(csp.CspError) as exc:
            ev.parse_policy(text)
        assert exc.value.code == code

    names = [
        "default-src", "script-src", "script-src-elem", "script-src-attr",
        "style-src", "style-src-elem", "style-src-attr", "img-src",
        "connect-src", "font-src", "media-src", "object-src", "frame-src",
        "worker-src", "child-src", "manifest-src", "prefetch-src", "base-uri",
        "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to",
        "require-trusted-types-for", "trusted-types", "upgrade-insecure-requests",
        "block-all-mixed-content", "navigate-to", "plugin-types", "reflected-xss",
        "referrer", "require-sri-for", "wasm-unsafe-eval",
    ]
    assert len(names) == csp.MAX_DIRECTIVES + 1
    with pytest.raises(csp.CspError) as exc:
        ev.parse_policy("; ".join(f"{name} 'none'" for name in names))
    assert exc.value.code == "CSP_TOO_MANY_DIRECTIVES"

    with pytest.raises(csp.CspError) as exc:
        ev.parse_policy("script-src 'self'", mode="audit")
    assert exc.value.code == "CSP_MODE_INVALID"


def test_parse_duplicate_directive_keeps_first_and_none_conflict():
    policy = parsed("script-src 'self'; script-src *")
    assert policy.directives["script-src"] == ("'self'",)
    assert len(policy.directives) == 1

    with pytest.raises(csp.CspError) as exc:
        parsed("script-src 'none' 'self'")
    assert exc.value.code == "CSP_DIRECTIVE_INVALID"

    with pytest.raises(csp.CspError) as exc:
        parsed("script-src^ 'self'")
    assert exc.value.code == "CSP_DIRECTIVE_INVALID"


def test_self_and_scheme_source_matching():
    ev = evaluator()
    policy = ev.parse_policy("script-src 'self' https:")
    same_origin = ev.evaluate(policy, url="https://app.example.com/js/a.js")
    assert same_origin.allowed is True
    assert same_origin.directive == "script-src"
    assert same_origin.matched == "'self'"
    assert same_origin.violations == ()

    blocked = ev.evaluate(policy, url="http://app.example.com/js/a.js")
    assert blocked.allowed is False
    assert blocked.directive == "script-src"
    assert blocked.matched is None
    assert len(blocked.violations) == 1
    violation = blocked.violations[0]
    assert (violation.policy, violation.directive, violation.blocked_uri,
            violation.reason) == ("policy", "script-src",
                                  "http://app.example.com/js/a.js", "source")

    assert ev.evaluate(policy, url="https://other.example.net/x.js").allowed is True
    assert ev.evaluate(policy, url="http://other.example.net/x.js").allowed is False


def test_wildcard_source_does_not_cross_hosts():
    assert csp.source_matches("*.example.com", "https://a.example.com/x") is True
    assert csp.source_matches("*.example.com", "https://a.b.example.com/x") is True
    assert csp.source_matches("*.example.com", "https://example.com/x") is False
    assert csp.source_matches("*.example.com", "https://a.example.com.evil.net/x") is False
    assert csp.source_matches("*.example.com", "https://evilexample.com/x") is False
    assert csp.source_matches("example.com", "https://example.com/x") is True
    assert csp.source_matches("example.com", "https://deep.example.com/x") is False
    assert csp.source_matches("https://*.example.com", "http://a.example.com/x") is False
    assert csp.source_matches("*", "https://any.example/x") is True
    assert csp.source_matches("*", "data:text/html,hi") is False


def test_host_source_port_and_path_prefix():
    assert csp.source_matches("https://cdn.example.com:8443/assets",
                              "https://cdn.example.com:8443/assets/app.js") is True
    assert csp.source_matches("https://cdn.example.com:8443/assets",
                              "https://cdn.example.com:8443/other/app.js") is False
    assert csp.source_matches("https://cdn.example.com:8443/assets",
                              "https://cdn.example.com/assets/app.js") is False
    assert csp.source_matches("https://cdn.example.com",
                              "https://cdn.example.com/a.js") is True
    assert csp.source_matches("https://cdn.example.com",
                              "https://cdn.example.com:9000/a.js") is False
    assert csp.source_matches("https://cdn.example.com/",
                              "https://cdn.example.com/deep/a.js") is True


def test_directive_fallback_chain_per_kind():
    ev = evaluator()
    policy = ev.parse_policy(
        "script-src-elem https://elem.example.com; "
        "script-src https://script.example.com; default-src 'none'"
    )
    elem = ev.evaluate(policy, url="https://elem.example.com/a.js")
    assert (elem.allowed, elem.matched, elem.directive) == (
        True, "https://elem.example.com", "script-src-elem")
    script_blocked = ev.evaluate(policy, url="https://script.example.com/a.js")
    assert script_blocked.allowed is False
    assert script_blocked.directive == "script-src-elem"

    style_policy = ev.parse_policy("style-src https://css.example.com; default-src 'none'")
    style_ok = ev.evaluate(style_policy, url="https://css.example.com/site.css", kind="style")
    assert (style_ok.allowed, style_ok.directive) == (True, "style-src")
    default_blocked = ev.evaluate(style_policy, url="https://cdn.example.com/a.js")
    assert (default_blocked.allowed, default_blocked.directive,
            default_blocked.violations[0].reason) == (False, "default-src", "none")

    assert csp.effective_directive({"script-src": ("*",)}, "script") == "script-src"
    assert csp.effective_directive({"img-src": ("*",)}, "script") is None
    with pytest.raises(csp.CspError) as exc:
        ev.evaluate(style_policy, url="https://cdn.example.com/x", kind="frame")
    assert exc.value.code == "CSP_KIND_INVALID"


def test_missing_directive_does_not_inherit_across_kinds():
    ev = evaluator()
    policy = ev.parse_policy("style-src 'self'")
    script = ev.evaluate(policy, url=SCRIPT_URL, kind="script")
    assert script.allowed is True
    assert script.directive is None
    assert script.matched is None
    assert script.violations == ()
    assert ev.evaluate(policy, url=SCRIPT_URL, kind="style").allowed is False


def test_nonce_allows_and_unsafe_inline_is_ignored():
    ev = evaluator()
    policy = ev.parse_policy("script-src 'unsafe-inline' 'nonce-abc123'")
    inline_blocked = ev.evaluate(policy, url="inline:alert(1)")
    assert inline_blocked.allowed is False
    assert inline_blocked.violations[0].reason == "inline"

    inline_nonce = ev.evaluate(policy, url="inline:alert(1)", nonce="abc123")
    assert (inline_nonce.allowed, inline_nonce.matched) == (True, "'nonce-abc123'")

    external_nonce = ev.evaluate(policy, url=SCRIPT_URL, nonce="abc123")
    assert external_nonce.allowed is True
    assert ev.evaluate(policy, url=SCRIPT_URL).allowed is False

    assert ev.check_nonce(policy, directive="script-src", nonce="abc123") is True
    assert ev.check_nonce(policy, directive="script-src", nonce="nope") is False


def test_hash_allows_and_unsafe_inline_is_ignored():
    ev = evaluator()
    policy = ev.parse_policy("script-src 'unsafe-inline' 'sha256-AAA'")
    assert ev.evaluate(policy, url="inline:run()").allowed is False
    inline_hash = ev.evaluate(policy, url="inline:run()", hashes=("sha256-AAA",))
    assert inline_hash.allowed is True
    assert inline_hash.matched == "'sha256-AAA'"
    assert ev.evaluate(policy, url=SCRIPT_URL, hashes=("sha256-AAA",)).allowed is True
    assert ev.evaluate(policy, url=SCRIPT_URL).allowed is False


def test_strict_dynamic_ignores_host_allowlist_for_scripts():
    ev = evaluator()
    policy = ev.parse_policy(
        "script-src 'strict-dynamic' 'nonce-abc' https://cdn.example.com")
    assert ev.evaluate(policy, url=SCRIPT_URL).allowed is False
    assert ev.evaluate(policy, url=SCRIPT_URL, nonce="abc").allowed is True
    assert ev.evaluate(policy, url="inline:x()", nonce="abc").allowed is True

    style_policy = ev.parse_policy(
        "style-src 'strict-dynamic' https://cdn.example.com")
    style = ev.evaluate(style_policy, url="https://cdn.example.com/a.css", kind="style")
    assert style.allowed is True
    assert style.matched == "https://cdn.example.com"


def test_merge_policies_splits_modes_and_digest():
    ev = evaluator()
    first = ev.parse_policy("script-src 'self'", name="a")
    second = ev.parse_policy("default-src 'none'", name="b", mode="report-only")
    third = ev.parse_policy("default-src https:", name="c")
    merged = ev.merge_policies([first, second, third])
    assert tuple(policy.name for policy in merged.enforce) == ("a", "c")
    assert tuple(policy.name for policy in merged.report_only) == ("b",)
    assert merged.digest == "a:enforce,c:enforce;b:report-only"
    assert ev.merge_policies([first]).digest == "a:enforce;"
    with pytest.raises(csp.CspError) as exc:
        ev.merge_policies([first, "script-src *"])
    assert exc.value.code == "CSP_POLICY_INVALID"


def test_policy_set_intersection_and_report_only_records():
    ev = evaluator()
    allow = ev.parse_policy("script-src https://cdn.example.com", name="allow")
    deny = ev.parse_policy("script-src 'none'", name="deny")
    blocked = ev.evaluate(ev.merge_policies([allow, deny]), url=SCRIPT_URL)
    assert blocked.allowed is False
    assert blocked.blocked_by == ("deny",)
    assert len(blocked.violations) == 1
    assert blocked.violations[0].policy == "deny"

    allowed = ev.evaluate(ev.merge_policies([allow]), url=SCRIPT_URL)
    assert allowed.allowed is True
    assert allowed.blocked_by == ()

    report_only = ev.parse_policy("script-src 'none'", name="ro", mode="report-only")
    recorded = ev.evaluate(report_only, url=SCRIPT_URL)
    assert recorded.allowed is True
    assert recorded.blocked_by == ()
    assert len(recorded.violations) == 1


def test_report_counts_by_directive_and_policy():
    ev = evaluator()
    deny_script = ev.parse_policy("script-src 'none'", name="a")
    deny_default = ev.parse_policy("default-src 'none'", name="b")
    allow_script = ev.parse_policy("script-src *", name="ok")
    decisions = [
        ev.evaluate(deny_script, url="https://x.example/a.js"),
        ev.evaluate(deny_default, url="https://x.example/i.png", kind="img"),
        ev.evaluate(allow_script, url="https://x.example/a.js"),
    ]
    assert ev.report(decisions) == {
        "total": 3,
        "allowed": 1,
        "blocked": 2,
        "violations": 2,
        "by_directive": {"default-src": 1, "script-src": 1},
        "by_policy": {"a": 1, "b": 1},
    }
    assert ev.stats() == {"evaluated": 3, "allowed": 1, "blocked": 2, "violations": 2}


def test_snapshot_is_detached_and_restore_roundtrips():
    ev = evaluator()
    policy = ev.parse_policy("script-src 'none'", name="a")
    assert ev.register_policy(policy) == 1
    ev.evaluate(policy, url="https://app.example.com/a.js")
    ev.evaluate(policy, url="https://app.example.com/b.js")

    state = ev.snapshot()
    assert state["revision"] == 1
    assert state["policies"] == {
        "a": {"mode": "enforce", "directives": {"script-src": ("'none'",)}}
    }
    assert state["counters"] == {
        "evaluated": 2, "allowed": 0, "blocked": 2, "violations": 2}

    pristine = copy.deepcopy(state)
    state["policies"]["a"]["mode"] = "report-only"
    state["counters"]["blocked"] = 99
    assert ev.stats()["blocked"] == 2

    clone = evaluator()
    clone.restore(pristine)
    assert clone.revision == 1
    assert clone.stats() == {"evaluated": 2, "allowed": 0, "blocked": 2,
                             "violations": 2}

    for bad in (None, {}, {"revision": 1, "policies": [], "counters": {}}):
        with pytest.raises(csp.CspError) as exc:
            clone.restore(bad)
        assert exc.value.code == "CSP_SNAPSHOT_INVALID"
    assert clone.stats()["evaluated"] == 2
