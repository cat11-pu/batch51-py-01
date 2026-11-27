import copy
import threading

import pytest

import ssti_context_guard as sg

NOW = "2026-11-27T09:00:00+00:00"

POLICY = {
    "roots": {"user": ("name", "email"), "site": ("title",), "page": ("blocks",)},
    "filters": ("upper", "lower", "escape"),
    "template_root": "templates",
    "max_depth": 8,
    "max_tokens": 64,
    "max_include_depth": 4,
}


def make_guard(policy=None):
    return sg.SstiContextGuard(policy=copy.deepcopy(policy if policy is not None else POLICY))


def test_tokenize_splits_names_and_pipes():
    guard = make_guard()
    tokens = guard.tokenize("user.name|upper")
    assert [(tok.kind, tok.value) for tok in tokens] == [
        ("name", "user"),
        ("dot", "."),
        ("name", "name"),
        ("pipe", "|"),
        ("name", "upper"),
    ]
    assert [tok.offset for tok in tokens] == [0, 4, 5, 9, 10]


def test_tokenize_rejects_unknown_character():
    guard = make_guard()
    with pytest.raises(sg.SstiError) as exc:
        guard.tokenize("user?name")
    assert exc.value.code == "SSTI_LEX_ERROR"
    assert exc.value.detail["offset"] == 4


def test_tokenize_keeps_string_and_number_literals():
    guard = make_guard()
    tokens = guard.tokenize("'a.b' 42")
    assert [(tok.kind, tok.value) for tok in tokens] == [("string", "a.b"), ("number", "42")]
    assert tokens[1].offset == 6


def test_analyze_expression_reports_root_attributes_and_filters():
    guard = make_guard()
    analysis = guard.analyze_expression("user.name|upper|escape")
    assert analysis.root == "user"
    assert analysis.attributes == ("name",)
    assert analysis.filters == ("upper", "escape")
    assert analysis.depth == 4


def test_depth_over_limit_is_denied_with_numbers():
    policy = copy.deepcopy(POLICY)
    policy["roots"] = {"user": ("a", "b", "c", "d", "e", "f", "g")}
    guard = make_guard(policy)
    verdict = guard.adjudicate("user.a.b.c.d.e.f.g|upper")
    assert verdict.status == "deny"
    assert verdict.code == "SSTI_DEPTH_EXCEEDED"
    assert verdict.detail == {"depth": 9, "max_depth": 8}


def test_unknown_root_is_denied():
    guard = make_guard()
    verdict = guard.adjudicate("admin.panel")
    assert verdict.status == "deny"
    assert verdict.code == "SSTI_UNKNOWN_ROOT"
    assert verdict.detail == {"root": "admin"}
    assert guard.stats()["denied"] == 1


def test_attribute_outside_whitelist_is_denied_at_index():
    guard = make_guard()
    verdict = guard.adjudicate("user.name.secret")
    assert verdict.status == "deny"
    assert verdict.code == "SSTI_ATTRIBUTE_DENIED"
    assert verdict.detail == {"segment": "secret", "index": 1}


def test_dunder_segment_is_denied_even_when_listed():
    policy = copy.deepcopy(POLICY)
    policy["roots"]["user"] = ("name", "__class__")
    guard = make_guard(policy)
    verdict = guard.adjudicate("user.__class__")
    assert verdict.status == "deny"
    assert verdict.code == "SSTI_DUNDER_DENIED"
    assert verdict.detail["segment"] == "__class__"


def test_unknown_filter_is_denied_with_position():
    guard = make_guard()
    verdict = guard.adjudicate("user.name|attr")
    assert verdict.status == "deny"
    assert verdict.code == "SSTI_FILTER_DENIED"
    assert verdict.detail == {"filter": "attr", "position": 0}


def test_allowed_expression_renders_context_value():
    guard = make_guard()
    assert guard.render("page.html", "user.name|upper", {"user": {"name": "ada"}}) == "ADA"
    assert guard.render("page.html", "user.name|escape", {"user": {"name": "<b>"}}) == "&lt;b&gt;"
    assert guard.stats()["rendered"] == 2


def test_render_refuses_before_reading_context():
    guard = make_guard()

    class Boom(dict):
        def __getitem__(self, key):
            raise AssertionError("context must not be read for a denied expression")

        def get(self, key, default=None):
            raise AssertionError("context must not be read for a denied expression")

    with pytest.raises(sg.SstiError) as exc:
        guard.render("page.html", "user.name|attr", Boom(user={"name": "ada"}))
    assert exc.value.code == "SSTI_FILTER_DENIED"
    assert guard.stats()["rendered"] == 0
    assert guard.audit_log()[-1].verdict == "deny"


def test_include_paths_normalize_within_template_root():
    guard = make_guard()
    assert guard.resolve_include("partials/../base.html") == "base.html"
    assert guard.resolve_include("./a//b.html") == "a/b.html"
    assert guard.resolve_include("partials/header.html") == "partials/header.html"
    assert guard.stats()["includes"] == 3


def test_include_escape_is_denied():
    guard = make_guard()
    for bad in ("../etc/passwd", "/etc/passwd", "partials/../../outside.html"):
        with pytest.raises(sg.SstiError) as exc:
            guard.resolve_include(bad)
        assert exc.value.code == "SSTI_INCLUDE_ESCAPE"
    assert guard.stats()["includes"] == 0
    assert guard.stats()["denied"] == 3


def test_snapshot_detaches_and_restore_roundtrips():
    guard = make_guard()
    guard.adjudicate("user.name")
    state = guard.snapshot()
    assert set(state) == {"version", "policy", "templates", "audit", "counters", "seq"}
    pristine = copy.deepcopy(state)

    state["audit"].clear()
    state["counters"]["allowed"] = 99
    assert guard.stats()["allowed"] == 1

    clone = make_guard()
    clone.restore(pristine)
    assert clone.stats()["allowed"] == 1
    assert clone.stats()["restored"] == 1
    with pytest.raises(sg.SstiError) as exc:
        clone.restore({"version": 1})
    assert exc.value.code == "SSTI_SNAPSHOT_INVALID"
    assert clone.stats()["allowed"] == 1
    assert clone.stats()["restored"] == 1
    assert clone.adjudicate("user.name").status == "allow"
    assert clone.stats()["allowed"] == 2


def test_concurrent_adjudication_keeps_audit_sequence_unique():
    guard = make_guard()
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            verdict = guard.adjudicate("site.title")
            assert verdict.status == "allow"
            assert verdict.code is None
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert [entry.seq for entry in guard.audit_log()] == list(range(1, 9))
    assert guard.stats()["analyzed"] == 8
    assert guard.stats()["allowed"] == 8
    assert guard.stats()["denied"] == 0
