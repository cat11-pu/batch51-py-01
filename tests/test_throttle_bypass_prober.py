import copy

import pytest

import throttle_bypass_prober as tp


def prober(**kwargs):
    return tp.ThrottleBypassProber(**kwargs)


def add(pr, endpoint_id="ep", path="/api/v1/report",
        params=(("page", "1"), ("size", "20"))):
    pr.add_endpoint(endpoint_id, path=path, params=params)


def test_add_endpoint_validates_path_params_and_duplicates():
    pr = prober()
    add(pr)
    with pytest.raises(tp.ThrottleError) as exc:
        add(pr)
    assert exc.value.code == "THROTTLE_DUPLICATE_ENDPOINT"

    for bad_path in ("", "api/v1", "/api/v1?x=1", "/api/v1#frag"):
        with pytest.raises(tp.ThrottleError) as exc:
            pr.add_endpoint("ep-2", path=bad_path, params=())
        assert exc.value.code == "THROTTLE_INVALID_ENDPOINT"

    with pytest.raises(tp.ThrottleError) as exc:
        pr.add_endpoint("ep-3", path="/a", params=(("k",),))
    assert exc.value.code == "THROTTLE_INVALID_ENDPOINT"
    assert pr.describe_endpoint("ep")["path"] == "/api/v1/report"


def test_plan_variants_emits_five_fixed_kinds():
    pr = prober()
    add(pr)
    variants = pr.plan_variants("ep")
    assert [(v.kind, v.raw_path, v.query) for v in variants] == [
        ("plain", "/api/v1/report", "page=1&size=20"),
        ("case", "/API/V1/REPORT", "page=1&size=20"),
        ("trailing_slash", "/api/v1/report/", "page=1&size=20"),
        ("encoding", "/api/v1/%72eport", "page=1&size=20"),
        ("param_order", "/api/v1/report", "size=20&page=1"),
    ]
    assert [v.variant_id for v in variants] == [
        "ep#plain", "ep#case", "ep#trailing_slash", "ep#encoding",
        "ep#param_order",
    ]


def test_plan_variants_rejects_unknown_endpoint():
    pr = prober()
    with pytest.raises(tp.ThrottleError) as exc:
        pr.plan_variants("ghost")
    assert exc.value.code == "THROTTLE_UNKNOWN_ENDPOINT"
    with pytest.raises(tp.ThrottleError) as exc:
        pr.describe_endpoint("ghost")
    assert exc.value.code == "THROTTLE_UNKNOWN_ENDPOINT"


def test_dedupe_drops_trailing_slash_duplicate_and_keeps_first():
    pr = prober()
    add(pr)
    plain, _case, slash, _enc, _order = pr.plan_variants("ep")
    assert [v.variant_id for v in pr.dedupe((slash, plain, slash))] == [
        "ep#trailing_slash"]
    unique = pr.dedupe(pr.plan_variants("ep"))
    assert [v.variant_id for v in unique] == [
        "ep#plain", "ep#case", "ep#encoding", "ep#param_order"]
    assert [v.kind for v in unique] == [
        "plain", "case", "encoding", "param_order"]
    assert pr.dedupe(()) == ()


def test_classify_counter_marks_shared_buckets_protected():
    pr = prober()
    add(pr)
    verdicts = pr.classify_counter("ep", [
        ("ep#plain", "bucket-a"),
        ("ep#case", "bucket-a"),
        ("ep#encoding", "bucket-b"),
        ("ep#trailing_slash", "bucket-a"),
    ])
    assert [(row.variant_id, row.verdict) for row in verdicts] == [
        ("ep#plain", "protected"),
        ("ep#case", "protected"),
        ("ep#encoding", "bypass"),
        ("ep#trailing_slash", "protected"),
    ]
    assert verdicts[0].counter_key == "bucket-a"
    assert verdicts[2].counter_key == "bucket-b"


def test_classify_counter_requires_plain_and_known_variants():
    pr = prober()
    add(pr)
    with pytest.raises(tp.ThrottleError) as exc:
        pr.classify_counter("ep", [("ep#case", "bucket-a")])
    assert exc.value.code == "THROTTLE_INVALID_OBSERVATION"
    with pytest.raises(tp.ThrottleError) as exc:
        pr.classify_counter("ep", [("ep#plain", "bucket-a"),
                                   ("ep#ghost", "bucket-a")])
    assert exc.value.code == "THROTTLE_UNKNOWN_VARIANT"


def test_measure_window_counts_responses_and_limited_variants():
    pr = prober()
    add(pr)
    report = pr.measure_window("ep", 0, [
        ("ep#plain", 200), ("ep#plain", 429), ("ep#case", 429),
        ("ep#encoding", 200), ("ep#param_order", 200),
        ("ep#param_order", 200),
    ])
    assert report.endpoint_id == "ep"
    assert report.window_index == 0
    assert report.counts == {"ep#plain": 2, "ep#case": 1,
                             "ep#encoding": 1, "ep#param_order": 2}
    assert report.exhausted == ("ep#case", "ep#plain")
    assert report.total == 6


def test_measure_window_rejects_bad_window_and_unknown_targets():
    pr = prober()
    add(pr)
    with pytest.raises(tp.ThrottleError) as exc:
        pr.measure_window("ep", -1, [])
    assert exc.value.code == "THROTTLE_INVALID_WINDOW"
    with pytest.raises(tp.ThrottleError) as exc:
        pr.measure_window("ghost", 0, [])
    assert exc.value.code == "THROTTLE_UNKNOWN_ENDPOINT"
    with pytest.raises(tp.ThrottleError) as exc:
        pr.measure_window("ep", 0, [("ep#ghost", 200)])
    assert exc.value.code == "THROTTLE_UNKNOWN_VARIANT"


def test_compare_windows_lists_unstable_variants():
    pr = prober()
    add(pr)
    first = pr.measure_window("ep", 0, [
        ("ep#plain", 429), ("ep#case", 200)])
    second = pr.measure_window("ep", 1, [
        ("ep#plain", 429), ("ep#case", 429)])
    assert pr.compare_windows(first, second) == ("ep#case",)
    third = pr.measure_window("ep", 2, [
        ("ep#plain", 429), ("ep#case", 429)])
    assert pr.compare_windows(second, third) == ()

    other = prober()
    add(other, "ep-2", path="/other", params=())
    foreign = other.measure_window("ep-2", 0, [])
    with pytest.raises(tp.ThrottleError) as exc:
        pr.compare_windows(first, foreign)
    assert exc.value.code == "THROTTLE_WINDOW_MISMATCH"


def test_reserve_probe_enforces_per_window_rate():
    pr = prober(window_rate=2, total_budget=10, window_seconds=10)
    add(pr)
    assert [pr.reserve_probe("ep", at=0).allowed for _ in range(2)] == [
        True, True]
    denied = pr.reserve_probe("ep", at=5)
    assert denied.allowed is False
    assert denied.reason == "window_exhausted"
    assert denied.window_left == 0
    nxt = pr.reserve_probe("ep", at=10)
    assert nxt.allowed is True
    assert nxt.window_index == 1
    assert nxt.total_left == 7


def test_reserve_probe_enforces_total_budget():
    pr = prober(window_rate=5, total_budget=3, window_seconds=10)
    add(pr)
    results = [pr.reserve_probe("ep", at=0) for _ in range(3)]
    assert [row.allowed for row in results] == [True, True, True]
    denied = pr.reserve_probe("ep", at=10)
    assert denied.allowed is False
    assert denied.reason == "budget_exhausted"
    assert denied.total_left == 0


def test_reserve_probe_rejects_unknown_endpoint_and_negative_time():
    pr = prober()
    with pytest.raises(tp.ThrottleError) as exc:
        pr.reserve_probe("ghost", at=0)
    assert exc.value.code == "THROTTLE_UNKNOWN_ENDPOINT"
    add(pr)
    with pytest.raises(tp.ThrottleError) as exc:
        pr.reserve_probe("ep", at=-1)
    assert exc.value.code == "THROTTLE_INVALID_WINDOW"
    assert pr.reserve_probe("ep", at=0).allowed is True
    assert pr.stats()["reserved"] == 1
    assert pr.stats()["denied"] == 0


def test_snapshot_is_detached_and_restore_roundtrips():
    pr = prober()
    add(pr)
    pr.plan_variants("ep")
    pr.reserve_probe("ep", at=3)
    pr.measure_window("ep", 0, [("ep#plain", 429)])
    state = pr.snapshot()
    assert set(state) == {"version", "endpoints", "budget", "windows", "stats"}
    pristine = copy.deepcopy(state)
    state["endpoints"].clear()
    state["stats"]["reserved"] = 99
    assert pr.stats()["reserved"] == 1
    assert len(pr.plan_variants("ep")) == 5

    clone = prober()
    clone.restore(pristine)
    assert clone.describe_endpoint("ep")["path"] == "/api/v1/report"
    assert clone.reserve_probe("ep", at=3).total_left == 22
    assert clone.stats()["reserved"] == 1
    assert clone.stats()["measurements"] == 1
    assert clone.stats()["restores"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    pr = prober()
    add(pr)
    pr.plan_variants("ep")
    stats = {"endpoints": 1, "planned": 5, "reserved": 0, "denied": 0,
             "measurements": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"version": 4, "endpoints": [], "budget": {}, "windows": [],
         "stats": stats},
        {"version": 1, "endpoints": "nope", "budget": {}, "windows": [],
         "stats": stats},
        {"version": 1, "endpoints": [], "budget": {}, "windows": [],
         "stats": {"reserved": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(tp.ThrottleError) as exc:
            pr.restore(bad)
        assert exc.value.code == "THROTTLE_SNAPSHOT_INVALID"
    assert pr.stats() == stats
    assert pr.describe_endpoint("ep")["path"] == "/api/v1/report"


def test_stats_count_prober_activity():
    pr = prober()
    add(pr)
    pr.plan_variants("ep")
    pr.plan_variants("ep")
    pr.reserve_probe("ep", at=0)
    pr.measure_window("ep", 0, [("ep#plain", 200)])
    assert pr.stats() == {
        "endpoints": 1,
        "planned": 10,
        "reserved": 1,
        "denied": 0,
        "measurements": 1,
        "restores": 0,
    }
