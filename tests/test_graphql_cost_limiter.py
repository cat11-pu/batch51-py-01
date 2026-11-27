import copy

import pytest

import graphql_cost_limiter as gq


def limiter(**kwargs):
    return gq.GraphqlCostLimiter(**kwargs)


def test_parse_document_reports_operation_and_root_fields():
    limiter_one = limiter()
    doc = limiter_one.parse("query Hero { hero { name friends { name } } }")
    assert doc.operation == "query"
    assert doc.name == "Hero"
    assert len(doc.selections) == 1

    shorthand = limiter().parse("{ a b }")
    assert shorthand.operation == "query"
    assert shorthand.name is None
    assert len(shorthand.selections) == 2


def test_parse_error_carries_offset():
    with pytest.raises(gq.GraphqlError) as exc:
        limiter().parse("query Q { hero { name }")
    assert exc.value.code == "GRAPHQL_PARSE_ERROR"
    assert isinstance(exc.value.detail, dict)
    assert "offset" in exc.value.detail


def test_duplicate_fragment_name_is_rejected():
    with pytest.raises(gq.GraphqlError) as exc:
        limiter().parse(
            "query Q { x } fragment F on T { a } fragment F on T { b }"
        )
    assert exc.value.code == "GRAPHQL_DUPLICATE_FRAGMENT"
    assert exc.value.detail == {"name": "F"}


def test_unknown_fragment_is_rejected():
    limiter_one = limiter()
    doc = limiter_one.parse("query Q { hero { ...Missing } }")
    with pytest.raises(gq.GraphqlError) as exc:
        limiter_one.resolve_fragments(doc)
    assert exc.value.code == "GRAPHQL_UNKNOWN_FRAGMENT"
    assert exc.value.detail == {"name": "Missing"}


def test_fragment_cycle_is_reported_with_path():
    limiter_one = limiter()
    doc = limiter_one.parse(
        "query { a { ...A } } "
        "fragment A on T { ...B } "
        "fragment B on T { ...A }"
    )
    with pytest.raises(gq.GraphqlError) as exc:
        limiter_one.resolve_fragments(doc)
    assert exc.value.code == "GRAPHQL_FRAGMENT_CYCLE"
    assert exc.value.detail["path"] == ["A", "B", "A"]


def test_cost_counts_each_field_occurrence():
    report = limiter().compute_cost(limiter().parse("{ a { b c } d }"))
    assert report.fields == 4
    assert report.cost == 4
    assert report.depth == 2
    assert report.aliases == 0
    assert report.introspection == 0


def test_aliased_occurrence_costs_double():
    report = limiter().compute_cost(limiter().parse("{ hero { name } other: hero { name } }"))
    assert report.fields == 4
    assert report.aliases == 1
    assert report.cost == 5


def test_depth_counts_selection_set_nesting():
    limiter_one = limiter()
    assert limiter_one.compute_depth(limiter_one.parse("{ a }")) == 1
    assert limiter_one.compute_depth(limiter_one.parse("{ a { b { c } } d }")) == 3


def test_depth_limit_denies_query():
    limiter_one = limiter(max_depth=2)
    admission = limiter_one.admit("{ a { b { c } } }")
    assert admission.allowed is False
    assert admission.reason == "GRAPHQL_DEPTH_EXCEEDED"
    assert admission.report.depth == 3
    assert admission.report.cost == 3
    assert limiter_one.stats()["denied"] == 1


def test_cost_limit_denies_query():
    limiter_one = limiter(max_cost=3)
    admission = limiter_one.admit("{ a b c d }")
    assert admission.allowed is False
    assert admission.reason == "GRAPHQL_COST_EXCEEDED"
    assert admission.report.cost == 4
    assert admission.report.depth == 1


def test_alias_limit_denies_query():
    limiter_one = limiter(max_aliases=1)
    admission = limiter_one.admit("{ a: x b: y }")
    assert admission.allowed is False
    assert admission.reason == "GRAPHQL_ALIAS_EXCEEDED"
    assert admission.report.aliases == 2
    assert admission.report.cost == 4


def test_introspection_has_its_own_budget():
    limiter_one = limiter(introspection_budget=2)
    allowed = limiter_one.admit("{ __typename user }")
    assert allowed.allowed is True
    assert allowed.report.fields == 2
    assert allowed.report.cost == 2
    assert allowed.report.introspection == 0

    denied = limiter_one.admit("{ __schema { types { name } } }")
    assert denied.allowed is False
    assert denied.reason == "GRAPHQL_INTROSPECTION_EXCEEDED"
    assert denied.report.fields == 3
    assert denied.report.cost == 0
    assert denied.report.introspection == 3


def test_single_fragment_spread_contributes_its_fields():
    limiter_one = limiter()
    doc = limiter_one.parse(
        "query { hero { ...Info } } fragment Info on Hero { name age }"
    )
    report = limiter_one.compute_cost(doc)
    assert report.fields == 3
    assert report.cost == 3
    assert report.aliases == 0
    assert report.introspection == 0


def test_per_client_limits_override_global_defaults():
    limiter_one = limiter(max_cost=100)
    assert limiter_one.client_limits("mobile")["max_cost"] == 100
    limiter_one.set_client_limits("mobile", max_cost=2)
    assert limiter_one.client_limits("mobile")["max_cost"] == 2

    assert limiter_one.admit("{ a b }", client="mobile").allowed is True
    denied = limiter_one.admit("{ a b c }", client="mobile")
    assert denied.allowed is False
    assert denied.reason == "GRAPHQL_COST_EXCEEDED"
    assert denied.limits["max_cost"] == 2
    assert limiter_one.admit("{ a b c }").allowed is True
    assert limiter_one.stats()["denied"] == 1
    assert limiter_one.stats()["admitted"] == 2


def test_snapshot_restore_roundtrip_and_invalid_state():
    limiter_one = limiter(max_cost=2)
    limiter_one.set_client_limits("mobile", max_cost=1)
    state = limiter_one.snapshot()
    assert set(state) == {"version", "limits", "clients", "counters"}
    pristine = copy.deepcopy(state)

    state["clients"].clear()
    assert limiter_one.client_limits("mobile")["max_cost"] == 1

    clone = limiter()
    clone.restore(pristine)
    assert clone.client_limits("mobile")["max_cost"] == 1
    assert clone.admit("{ a b }", client="mobile").allowed is False
    assert clone.stats()["denied"] == 1

    with pytest.raises(gq.GraphqlError) as exc:
        clone.restore(None)
    assert exc.value.code == "GRAPHQL_SNAPSHOT_INVALID"
    assert clone.stats()["denied"] == 1
    assert clone.stats()["restored"] == 1
