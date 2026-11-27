import copy

import pytest

import smart_reframe_tracker as rf


def tracker(**kwargs):
    return rf.SmartReframeTracker(**kwargs)


def prepared(**kwargs):
    tr = rf.SmartReframeTracker(**kwargs)
    tr.set_source(1920, 1080)
    return tr


def test_set_source_validates_and_is_fixed():
    tr = tracker()
    for width, height in ((0, 1080), (-1, 1080), (1920, 0)):
        with pytest.raises(rf.ReframeError) as exc:
            tr.set_source(width, height)
        assert exc.value.code == "RF_INVALID_SOURCE"

    info = tr.set_source(1920, 1080)
    assert (info.width, info.height, info.window_width) == (1920, 1080, 608)
    assert tr.set_source(1920, 1080) == info

    with pytest.raises(rf.ReframeError) as exc:
        tr.set_source(1080, 1920)
    assert exc.value.code == "RF_INVALID_SOURCE"


def test_observe_requires_increasing_timestamps():
    tr = prepared()
    tr.observe(0, [("p1", 800, 500, 1.0)])
    with pytest.raises(rf.ReframeError) as exc:
        tr.observe(0, [("p1", 800, 500, 1.0)])
    assert exc.value.code == "RF_DUPLICATE_TIME"

    with pytest.raises(rf.ReframeError) as exc:
        tr.observe(-1, [("p1", 800, 500, 1.0)])
    assert exc.value.code == "RF_INVALID_TIME"

    tr.observe(50, [("p1", 810, 500, 1.0)])
    with pytest.raises(rf.ReframeError) as exc:
        tr.observe(40, [("p1", 820, 500, 1.0)])
    assert exc.value.code == "RF_OUT_OF_ORDER"
    assert tr.stats()["samples"] == 2


def test_observe_rejects_bad_subjects():
    tr = prepared()
    cases = [
        [("", 800, 500, 1.0)],
        [("p1", 1920, 500, 1.0)],
        [("p1", 800, 1080, 1.0)],
        [("p1", -1, 500, 1.0)],
        [("p1", 800, 500, 0.0)],
        [("p1", 800, 500, -0.5)],
        [("p1", 800.5, 500, 1.0)],
    ]
    for subjects in cases:
        with pytest.raises(rf.ReframeError) as exc:
            tr.observe(0, subjects)
        assert exc.value.code == "RF_INVALID_SUBJECT"
    assert tr.stats()["samples"] == 0


def test_track_cap_decimates_evenly():
    tr = prepared(max_track=4)
    for ts in (0, 100, 200, 300, 400, 500):
        tr.observe(ts, [("p1", 800, 500, 1.0)])

    stats = tr.stats()
    assert (stats["samples"], stats["dropped"]) == (4, 2)
    assert tr.primary_at(0) == "p1"
    assert tr.primary_at(500) == "p1"


def test_primary_and_confidence_follow_subjects():
    tr = prepared()
    first = tr.observe(0, [("p1", 800, 500, 1.0)])
    assert (first.subject_id, first.x, first.y, first.confidence) == (
        "p1", 800, 500, 1.0)

    lost = tr.observe(40, [])
    assert (lost.subject_id, lost.x, lost.y, lost.confidence) == (
        None, 800, 500, 0.75)
    again = tr.observe(80, [])
    assert again.confidence == 0.5

    assert tr.primary_at(40) is None
    assert tr.primary_at(0) == "p1"
    assert tr.stats()["lost"] == 2


def test_add_keyframe_validates():
    tr = prepared()
    for ts, center, code in ((-1, 600, "RF_INVALID_TIME"),
                             (0, -1, "RF_WINDOW_OUT_OF_BOUNDS"),
                             (0, 1921, "RF_WINDOW_OUT_OF_BOUNDS"),
                             (0, 600.5, "RF_WINDOW_OUT_OF_BOUNDS")):
        with pytest.raises(rf.ReframeError) as exc:
            tr.add_keyframe(ts, center)
        assert exc.value.code == code

    keyframe = tr.add_keyframe(0, 600)
    assert (keyframe.timestamp_ms, keyframe.center_x) == (0, 600)
    with pytest.raises(rf.ReframeError) as exc:
        tr.add_keyframe(0, 700)
    assert exc.value.code == "RF_DUPLICATE_TIME"
    assert len(tr.keyframes()) == 1


def test_keyframe_cap_is_hard():
    tr = prepared(max_keyframes=2)
    tr.add_keyframe(0, 600)
    tr.add_keyframe(100, 700)
    with pytest.raises(rf.ReframeError) as exc:
        tr.add_keyframe(200, 800)
    assert exc.value.code == "RF_KEYFRAME_LIMIT"
    assert len(tr.keyframes()) == 2


def test_window_width_from_aspect():
    tr = prepared()
    window = tr.window_at(0)
    assert (window.width, window.x) == (608, 656)
    assert window.center == 960.0


def test_window_at_endpoints_and_midpoint():
    tr = prepared()
    tr.add_keyframe(0, 600)
    tr.add_keyframe(1000, 1000)

    assert tr.window_at(0).center == 600.0
    assert tr.window_at(1000).center == 1000.0
    assert (tr.window_at(0).x, tr.window_at(1000).x) == (296, 696)

    mid = tr.window_at(500)
    assert mid.center == 800.0
    assert mid.x == 496


def test_window_holds_outside_keyframe_range():
    tr = prepared()
    tr.add_keyframe(200, 620)
    tr.add_keyframe(800, 700)

    assert tr.window_at(0).center == 620.0
    assert tr.window_at(199).center == 620.0
    assert tr.window_at(800).center == 700.0
    assert tr.window_at(1500).center == 700.0

    with pytest.raises(rf.ReframeError) as exc:
        tr.window_at(-1)
    assert exc.value.code == "RF_INVALID_TIME"


def test_render_plan_validates_and_matches_window_at():
    tr = prepared()
    tr.add_keyframe(0, 600)
    tr.add_keyframe(1000, 1000)

    cases = [{"step_ms": 0}, {"step_ms": -40}, {"start_ms": -1},
             {"start_ms": 500, "end_ms": 500}, {"start_ms": 600, "end_ms": 500}]
    for kwargs in cases:
        with pytest.raises(rf.ReframeError) as exc:
            tr.render_plan(**kwargs)
        assert exc.value.code == "RF_INVALID_RANGE"

    plan = tr.render_plan(start_ms=0, end_ms=200, step_ms=50)
    assert [window.timestamp_ms for window in plan] == [0, 50, 100, 150, 200]
    assert plan[0].center == 600.0
    for window in plan:
        assert window == tr.window_at(window.timestamp_ms)
        assert 0 <= window.x <= 1920 - 608


def test_remove_keyframe_updates_grid():
    tr = prepared()
    tr.add_keyframe(0, 600)
    tr.add_keyframe(500, 700)

    removed = tr.remove_keyframe(500)
    assert (removed.timestamp_ms, removed.center_x) == (500, 700)
    assert len(tr.keyframes()) == 1
    assert tr.window_at(900).center == 600.0

    with pytest.raises(rf.ReframeError) as exc:
        tr.remove_keyframe(500)
    assert exc.value.code == "RF_UNKNOWN_KEYFRAME"


def test_snapshot_restore_round_trip():
    tr = prepared()
    tr.observe(0, [("p1", 800, 500, 1.0)])
    tr.observe(40, [])
    tr.add_keyframe(0, 600)
    tr.add_keyframe(1000, 1000)

    state = tr.snapshot()
    pristine = copy.deepcopy(state)
    state["keyframes"].clear()
    state["stats"]["keyframes"] = 99
    assert len(tr.keyframes()) == 2

    clone = tracker()
    clone.restore(pristine)
    assert clone.stats() == tr.stats()
    assert clone.keyframes() == tr.keyframes()
    assert clone.window_at(500).center == 800.0
    assert clone.primary_at(0) == "p1"

    fresh = tracker()
    bad_states = [
        None,
        {},
        {"version": 9, "source": None, "samples": [], "keyframes": [],
         "stats": {"samples": 0, "subjects": 0, "keyframes": 0, "lost": 0,
                   "dropped": 0, "plans": 0, "rejected": 0}},
        {"version": 1, "source": "nope", "samples": [],
         "keyframes": [], "stats": {"samples": 0, "subjects": 0,
                                    "keyframes": 0, "lost": 0, "dropped": 0,
                                    "plans": 0, "rejected": 0}},
        {"version": 1, "source": None, "samples": [],
         "keyframes": [{"timestamp_ms": 0}],
         "stats": {"samples": 0, "subjects": 0, "keyframes": 1, "lost": 0,
                   "dropped": 0, "plans": 0, "rejected": 0}},
        {"version": 1, "source": None, "samples": [], "keyframes": [],
         "stats": {"samples": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(rf.ReframeError) as exc:
            fresh.restore(bad)
        assert exc.value.code == "RF_SNAPSHOT_INVALID"
    assert fresh.stats()["samples"] == 0


def test_stats_track_counters():
    tr = prepared()
    tr.observe(0, [("p1", 800, 500, 1.0)])
    tr.observe(40, [("p2", 900, 500, 0.5), ("p1", 800, 500, 1.0)])
    tr.observe(80, [])
    tr.add_keyframe(0, 600)
    tr.render_plan(start_ms=0, end_ms=80, step_ms=40)

    stats = tr.stats()
    assert (stats["samples"], stats["subjects"], stats["keyframes"],
            stats["lost"], stats["plans"]) == (3, 2, 1, 1, 1)
    assert stats["dropped"] == 0
    assert stats["rejected"] == 0


def test_primary_at_returns_latest_sample():
    tr = prepared()
    tr.observe(0, [("p1", 800, 500, 1.0)])
    tr.observe(100, [("p2", 900, 500, 2.0)])

    assert tr.primary_at(0) == "p1"
    assert tr.primary_at(99) == "p1"
    assert tr.primary_at(100) == "p2"
    assert tr.primary_at(1000) == "p2"
    assert tr.confidence_at(100) == 1.0

    with pytest.raises(rf.ReframeError) as exc:
        tr.primary_at(-1)
    assert exc.value.code == "RF_INVALID_TIME"

    empty = prepared()
    assert empty.primary_at(0) is None
