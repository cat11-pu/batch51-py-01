import copy

import pytest

import param_pollution_scanner as pp


def scanner(**kwargs):
    return pp.ParamPollutionScanner(**kwargs)


def add(sc, endpoint_id="ep", path="/search", params=(("q", "base"),)):
    sc.add_endpoint(endpoint_id, path=path, params=params)
    return endpoint_id


def test_add_endpoint_validates_path_params_and_duplicates():
    sc = scanner(max_params=2)
    add(sc)
    with pytest.raises(pp.ParamError) as exc:
        add(sc)
    assert exc.value.code == "PARAM_DUPLICATE_ENDPOINT"

    for bad_path in ("", "search", "/search?q=1"):
        with pytest.raises(pp.ParamError) as exc:
            sc.add_endpoint("ep-2", path=bad_path, params=())
        assert exc.value.code == "PARAM_INVALID_ENDPOINT"

    with pytest.raises(pp.ParamError) as exc:
        sc.add_endpoint("ep-3", path="/a",
                        params=(("a", "1"), ("b", "2"), ("c", "3")))
    assert exc.value.code == "PARAM_TOO_MANY_PARAMS"

    with pytest.raises(pp.ParamError) as exc:
        sc.add_endpoint("ep-4", path="/a", params=(("a", "1", "2"),))
    assert exc.value.code == "PARAM_INVALID_ENDPOINT"


def test_build_matrix_emits_fixed_variants_per_param():
    sc = scanner()
    add(sc)
    probes = sc.build_matrix("ep")
    assert [(p.kind, p.query) for p in probes] == [
        ("duplicate_first", (("q", "base"), ("q", "probe"))),
        ("duplicate_last", (("q", "probe"), ("q", "base"))),
        ("bracket_dup", (("q[]", "base"), ("q[]", "probe"))),
        ("scalar_then_array", (("q", "base"), ("q[]", "probe"))),
        ("encoded_sep", (("q", "base%26q=probe"),)),
        ("semicolon_sep", (("q", "base;q=probe"),)),
    ]
    assert [p.probe_id for p in probes] == [
        "ep:q:duplicate_first",
        "ep:q:duplicate_last",
        "ep:q:bracket_dup",
        "ep:q:scalar_then_array",
        "ep:q:encoded_sep",
        "ep:q:semicolon_sep",
    ]


def test_build_matrix_enforces_combo_cap():
    sc = scanner(max_combos=4)
    add(sc, params=(("q", "base"), ("page", "1")))
    probes = sc.build_matrix("ep")
    assert len(probes) == 4
    assert [p.probe_id for p in probes] == [
        "ep:page:duplicate_first",
        "ep:page:duplicate_last",
        "ep:page:bracket_dup",
        "ep:page:scalar_then_array",
    ]
    assert sc.stats()["suppressed"] == 8


def test_build_matrix_and_describe_reject_unknown_endpoint():
    sc = scanner()
    with pytest.raises(pp.ParamError) as exc:
        sc.build_matrix("ghost")
    assert exc.value.code == "PARAM_UNKNOWN_ENDPOINT"
    with pytest.raises(pp.ParamError) as exc:
        sc.describe_endpoint("ghost")
    assert exc.value.code == "PARAM_UNKNOWN_ENDPOINT"


def test_classify_parser_reports_resolution_dialect():
    sc = scanner()
    assert sc.classify_parser(("base", "probe"), "base") == "first"
    assert sc.classify_parser(("base", "probe"), "probe") == "last"
    assert sc.classify_parser(("base", "probe"), ("base", "probe")) == "array"
    assert sc.classify_parser(("base", "probe"), "base,probe") == "joined"
    assert sc.classify_parser(("base",), None) == "none"
    assert sc.classify_parser(("base",), "other") == "other"


def test_classify_parser_rejects_bad_values():
    sc = scanner()
    for values in ((), ("base", 2), "base"):
        with pytest.raises(pp.ParamError) as exc:
            sc.classify_parser(values, "base")
        assert exc.value.code == "PARAM_INVALID_VALUES"


def test_compare_backends_flags_pollution_and_missing_side():
    sc = scanner()
    assert sc.compare_backends("base", "base") == "consistent"
    assert sc.compare_backends("base", "probe") == "polluted"
    assert sc.compare_backends(("base",), "base") == "polluted"
    assert sc.compare_backends(None, None) == "consistent"
    assert sc.compare_backends("base", None) == "divergent_missing"
    assert sc.compare_backends(None, "base") == "divergent_missing"


def test_merge_keeps_strongest_verdict_per_key():
    sc = scanner()
    add(sc)
    sc.build_matrix("ep")
    sc.record("ep:q:duplicate_first", source="query",
              frontend="base", backend="base")
    sc.record("ep:q:duplicate_first", source="query",
              frontend="base", backend="probe")
    sc.record("ep:q:duplicate_first", source="query",
              frontend="base", backend="base")
    report = sc.merge()
    assert len(report.rows) == 1
    assert report.rows[0].verdict == "polluted"
    assert report.rows[0].observations == 3
    assert report.merged == 2


def test_merge_sorts_rows_and_counts_each_key_once():
    sc = scanner()
    add(sc)
    sc.build_matrix("ep")
    sc.record("ep:q:duplicate_last", source="query",
              frontend="base", backend="probe")
    sc.record("ep:q:duplicate_first", source="query",
              frontend="base", backend="base")
    report = sc.merge()
    assert [(row.kind, row.verdict, row.observations) for row in report.rows] == [
        ("duplicate_first", "consistent", 1),
        ("duplicate_last", "polluted", 1),
    ]
    assert report.merged == 0


def test_merge_without_results_is_empty():
    sc = scanner()
    add(sc)
    empty = sc.merge()
    assert empty.rows == ()
    assert empty.merged == 0
    sc.build_matrix("ep")
    assert sc.merge().rows == ()


def test_record_rejects_unknown_probe_and_bad_source():
    sc = scanner()
    add(sc)
    sc.build_matrix("ep")
    with pytest.raises(pp.ParamError) as exc:
        sc.record("ghost", source="query", frontend="a", backend="a")
    assert exc.value.code == "PARAM_UNKNOWN_PROBE"
    with pytest.raises(pp.ParamError) as exc:
        sc.record("ep:q:duplicate_first", source="header",
                  frontend="a", backend="a")
    assert exc.value.code == "PARAM_INVALID_SOURCE"


def test_describe_endpoint_reports_matrix_shape():
    sc = scanner(max_combos=5)
    add(sc, params=(("q", "base"), ("page", "1")))
    sc.build_matrix("ep")
    info = sc.describe_endpoint("ep")
    assert info["endpoint_id"] == "ep"
    assert info["path"] == "/search"
    assert info["params"] == (("page", "1"), ("q", "base"))
    assert info["probes"] == 5


def test_stats_count_matrix_records_and_merges():
    sc = scanner()
    add(sc)
    sc.build_matrix("ep")
    sc.build_matrix("ep")
    sc.record("ep:q:duplicate_first", source="query",
              frontend="base", backend="probe")
    sc.merge()
    assert sc.stats() == {
        "endpoints": 1,
        "probes": 12,
        "suppressed": 0,
        "results": 1,
        "merged": 0,
        "restores": 0,
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    sc = scanner()
    add(sc)
    sc.build_matrix("ep")
    sc.record("ep:q:duplicate_first", source="body",
              frontend="base", backend="probe")
    state = sc.snapshot()
    assert set(state) == {"version", "endpoints", "probes", "results", "stats"}
    pristine = copy.deepcopy(state)
    state["endpoints"].clear()
    state["stats"]["results"] = 99
    assert sc.stats()["results"] == 1
    assert sc.describe_endpoint("ep")["path"] == "/search"

    clone = scanner()
    clone.restore(pristine)
    assert clone.describe_endpoint("ep")["path"] == "/search"
    assert clone.merge().rows[0].verdict == "polluted"
    assert clone.stats()["results"] == 1
    assert clone.stats()["restores"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    sc = scanner()
    add(sc)
    sc.build_matrix("ep")
    stats = {"endpoints": 1, "probes": 6, "suppressed": 0, "results": 0,
             "merged": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"version": 7, "endpoints": [], "probes": [], "results": [],
         "stats": stats},
        {"version": 1, "endpoints": "nope", "probes": [], "results": [],
         "stats": stats},
        {"version": 1, "endpoints": [], "probes": [], "results": [],
         "stats": {"results": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(pp.ParamError) as exc:
            sc.restore(bad)
        assert exc.value.code == "PARAM_SNAPSHOT_INVALID"
    assert sc.stats() == stats
    assert sc.describe_endpoint("ep")["path"] == "/search"
