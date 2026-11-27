import copy

import pytest

import api_schema_security_diff as api


def doc(paths, *, global_security=None):
    data = {"openapi": "3.0.0", "info": {"title": "svc", "version": "1"}, "paths": paths}
    if global_security is not None:
        data["security"] = global_security
    return data


def op(**extra):
    data = {"responses": {"200": {"description": "ok"}}}
    data.update(extra)
    return data


def param(name="q", location="query", required=False, type_="string", enum=None):
    schema = {"type": type_}
    if enum is not None:
        schema["enum"] = list(enum)
    return {"name": name, "in": location, "required": required, "schema": schema}


def new(ev=None):
    return ev or api.ApiSchemaSecurityDiff()


def test_load_spec_normalizes_paths_and_methods():
    ev = new()
    spec = ev.load_spec(doc({
        "/users/{id}/": {"get": op()},
        "/users//{userId}": {"POST": op()},
    }), name="base")
    assert spec.name == "base"
    assert tuple(sorted(spec.operations)) == (("/users/{}", "get"), ("/users/{}", "post"))
    assert spec.operations[("/users/{}", "get")].template == ("id",)
    assert spec.operations[("/users/{}", "post")].template == ("userId",)
    assert ev.revision == 1
    assert ev.baseline == "base"
    assert ev.stats() == {"loads": 1, "security_changes": 0, "parameter_changes": 0}


def test_load_spec_rejects_oversize_too_many_and_malformed():
    ev = new()
    with pytest.raises(api.SchemaError) as exc:
        ev.load_spec("x" * (api.MAX_DOC_CHARS + 1))
    assert exc.value.code == "SCHEMA_TOO_LARGE"

    many = {f"/p{index}": {"get": op()} for index in range(api.MAX_OPERATIONS + 1)}
    with pytest.raises(api.SchemaError) as exc:
        ev.load_spec(doc(many))
    assert exc.value.code == "SCHEMA_TOO_MANY_OPERATIONS"

    for bad in ("not json", {"openapi": "3.0.0"}, {"paths": []}):
        with pytest.raises(api.SchemaError) as exc:
            ev.load_spec(bad)
        assert exc.value.code == "SCHEMA_INVALID"

    with pytest.raises(api.SchemaError) as exc:
        ev.load_spec(doc({"/a": {"get": op()}}, global_security="oauth"))
    assert exc.value.code == "SCHEMA_INVALID"
    assert ev.stats()["loads"] == 0
    assert ev.revision == 0


def test_load_spec_resolves_internal_refs_and_rejects_external_or_cyclic():
    ev = new()
    resolved = ev.load_spec({
        "openapi": "3.0.0",
        "info": {"title": "svc", "version": "1"},
        "components": {"parameters": {"Page": param("page", required=False,
                                                     type_="integer")}},
        "paths": {"/a": {"get": op(parameters=[
            {"$ref": "#/components/parameters/Page"}])}},
    })
    params = resolved.operations[("/a", "get")].parameters
    assert [(p.name, p.location, p.required, p.schema_type, p.enum)
            for p in params] == [("page", "query", False, "integer", ())]

    with pytest.raises(api.SchemaError) as exc:
        ev.load_spec(doc({"/a": {"get": op(parameters=[
            {"$ref": "https://x.example/schema.yaml#/components/parameters/P"}])}}))
    assert exc.value.code == "SCHEMA_EXTERNAL_REF"

    with pytest.raises(api.SchemaError) as exc:
        ev.load_spec({
            "openapi": "3.0.0",
            "info": {"title": "svc", "version": "1"},
            "components": {"parameters": {
                "A": {"$ref": "#/components/parameters/B"},
                "B": {"$ref": "#/components/parameters/A"},
            }},
            "paths": {"/a": {"get": op(parameters=[
                {"$ref": "#/components/parameters/A"}])}},
        })
    assert exc.value.code == "SCHEMA_REF_CYCLE"


def test_effective_security_inherits_global_and_allows_override():
    ev = new()
    spec = ev.load_spec(doc({
        "/a": {"get": op()},
        "/b": {"get": op(security=[{"key": []}])},
    }, global_security=[{"oauth": []}]))
    assert spec.operations[("/a", "get")].security is None
    assert spec.operations[("/b", "get")].security == (("key",),)
    assert ev.effective_security(spec, "/a", "get") == (("oauth",),)
    assert ev.effective_security(spec, "/b", "get") == (("key",),)


def test_security_normalization_and_unknown_operation():
    ev = new()
    spec = ev.load_spec(doc({"/a": {"get": op(
        security=[{"b": [], "a": []}, {"c": []}])}}))
    assert ev.effective_security(spec, "/a", "get") == (("a", "b"), ("c",))
    assert api.normalize_security([{"z": [], "y": []}]) == (("y", "z"),)
    assert api.normalize_path("/a//b/{x}/") == "/a/b/{}"
    assert api.normalize_path("/") == "/"

    with pytest.raises(api.SchemaError) as exc:
        ev.effective_security(spec, "/missing", "get")
    assert exc.value.code == "SCHEMA_OPERATION_UNKNOWN"


def test_diff_security_flags_removed_authentication():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op()}},
                            global_security=[{"oauth": []}]), name="base")
    head = ev.load_spec(doc({"/a": {"get": op()}}, global_security=[]), name="head")
    changes = ev.diff_security(base, head)
    assert len(changes) == 1
    change = changes[0]
    assert (change.change, change.path, change.method, change.severity) == (
        "removed", "/a", "get", "high")
    assert change.before == (("oauth",),)
    assert change.after == ()
    assert ev.stats()["security_changes"] == 1


def test_diff_security_grades_weakened_and_strengthened():
    ev = new()
    strong = ev.load_spec(doc({"/a": {"get": op(
        security=[{"oauth": [], "mtls": []}])}}), name="strong")
    weak = ev.load_spec(doc({"/a": {"get": op(security=[{"oauth": []}])}}), name="weak")
    weakened = ev.diff_security(strong, weak)
    assert [(c.change, c.before, c.after, c.severity) for c in weakened] == [
        ("weakened", (("mtls", "oauth"),), (("oauth",),), "medium")]
    strengthened = ev.diff_security(weak, strong)
    assert [(c.change, c.severity) for c in strengthened] == [("strengthened", "info")]


def test_diff_security_flags_new_unauthenticated_operation():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op()}}), name="base")
    head = ev.load_spec(doc({"/a": {"get": op()}, "/b": {"post": op()}}), name="head")
    changes = ev.diff_security(base, head)
    assert [(c.change, c.path, c.method, c.before, c.after, c.severity)
            for c in changes] == [
        ("unauthenticated", "/b", "post", (), (), "high")]

    guarded = ev.load_spec(doc({"/a": {"get": op()}},
                               global_security=[{"oauth": []}]), name="gbase")
    guarded_head = ev.load_spec(doc({"/a": {"get": op()}, "/b": {"post": op()}},
                                    global_security=[{"oauth": []}]), name="ghead")
    assert ev.diff_security(guarded, guarded_head) == ()


def test_diff_security_identical_specs_produce_no_change():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op()}}, global_security=[{"oauth": []}]),
                        name="base")
    head = ev.load_spec(doc({"/b": {"get": op()}, "/a": {"get": op()}},
                            global_security=[{"oauth": []}]), name="head")
    assert ev.diff_security(base, head) == ()
    assert ev.stats()["security_changes"] == 0


def test_diff_parameters_enum_widened_and_narrowed():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op(
        parameters=[param(enum=["a", "b"])])}}), name="base")
    head = ev.load_spec(doc({"/a": {"get": op(
        parameters=[param(enum=["a", "b", "c"])])}}), name="head")
    widened = ev.diff_parameters(base, head)
    assert [(c.change, c.parameter, c.severity) for c in widened] == [
        ("enum_widened", "q", "medium")]
    narrowed = ev.diff_parameters(head, base)
    assert [(c.change, c.parameter, c.severity) for c in narrowed] == [
        ("enum_narrowed", "q", "low")]


def test_diff_parameters_required_relaxed_and_tightened():
    ev = new()
    strict = ev.load_spec(doc({"/a": {"get": op(
        parameters=[param(required=True)])}}), name="strict")
    loose = ev.load_spec(doc({"/a": {"get": op(
        parameters=[param(required=False)])}}), name="loose")
    relaxed = ev.diff_parameters(strict, loose)
    assert [(c.change, c.parameter, c.severity) for c in relaxed] == [
        ("required_relaxed", "q", "high")]
    tightened = ev.diff_parameters(loose, strict)
    assert [(c.change, c.parameter, c.severity) for c in tightened] == [
        ("required_tightened", "q", "low")]


def test_diff_parameters_added_removed_and_type_loosened():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op(parameters=[
        param("a"), param("b", required=True), param("t", type_="integer")])}}),
        name="base")
    head = ev.load_spec(doc({"/a": {"get": op(parameters=[
        param("a"), param("c"), param("d", required=True),
        param("t", type_="string")])}}), name="head")
    changes = ev.diff_parameters(base, head)
    assert [(c.change, c.parameter, c.severity) for c in changes] == [
        ("parameter_removed", "b", "medium"),
        ("optional_added", "c", "low"),
        ("required_added", "d", "high"),
        ("type_loosened", "t", "medium"),
    ]
    assert ev.stats()["parameter_changes"] == 4


def test_diff_parameters_path_rename_is_reported_by_position():
    ev = new()
    base = ev.load_spec(doc({"/users/{id}": {"get": op(parameters=[
        param("id", "path", True, "integer")])}}), name="base")
    head = ev.load_spec(doc({"/users/{userId}": {"get": op(parameters=[
        param("userId", "path", True, "integer")])}}), name="head")
    changes = ev.diff_parameters(base, head)
    assert [(c.change, c.parameter, c.severity) for c in changes] == [
        ("renamed", "id->userId", "info")]


def test_classify_and_report_aggregate_severities():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op()}}, global_security=[{"oauth": []}]),
                        name="base")
    head = ev.load_spec(doc({"/a": {"get": op(parameters=[param("c")])}}),
                        name="head")
    security = ev.diff_security(base, head)
    parameters = ev.diff_parameters(base, head)
    assert len(security) == 1 and len(parameters) == 1

    assert ev.classify(security + parameters) == {
        "high": 1, "medium": 0, "low": 1, "info": 0, "verdict": "high"}
    assert ev.report(security, parameters) == {
        "security": {"total": 1, "by_change": {"removed": 1}},
        "parameters": {"total": 1, "by_change": {"optional_added": 1}},
        "verdict": "high",
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    ev = new()
    base = ev.load_spec(doc({"/a": {"get": op()}, "/b": {"post": op()}},
                            global_security=[{"oauth": []}]), name="base")
    head = ev.load_spec(doc({"/a": {"get": op()}, "/b": {"post": op()}},
                            global_security=[]), name="head")
    ev.diff_security(base, head)
    ev.diff_parameters(base, head)

    state = ev.snapshot()
    assert state == {
        "baseline": "head",
        "revision": 2,
        "operation_count": 2,
        "counters": {"loads": 2, "security_changes": 2, "parameter_changes": 0},
    }
    pristine = copy.deepcopy(state)
    state["counters"]["loads"] = 99
    assert ev.stats()["loads"] == 2

    clone = new()
    clone.restore(pristine)
    assert clone.snapshot() == pristine
    for bad in (None, [], {"baseline": "x"}):
        with pytest.raises(api.SchemaError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SCHEMA_SNAPSHOT_INVALID"
    assert clone.stats()["loads"] == 2
