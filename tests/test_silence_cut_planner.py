import copy

import pytest

import silence_cut_planner as sc


def planner(**kwargs):
    return sc.SilenceCutPlanner(**kwargs)


def frames(*runs):
    out = []
    for db, zcr, count in runs:
        out.extend([(db, zcr)] * count)
    return out


def case_a():
    return frames((-20.0, 0.1, 20), (-60.0, 0.1, 15), (-20.0, 0.1, 15))


def case_b():
    return frames((-20.0, 0.1, 20), (-60.0, 0.1, 10),
                  (-20.0, 0.1, 10), (-60.0, 0.1, 10))


def case_d():
    return frames((-60.0, 0.1, 15), (-20.0, 0.1, 5),
                  (-60.0, 0.1, 15), (-20.0, 0.1, 15))


def test_analyze_rejects_bad_frames():
    p = planner()
    with pytest.raises(sc.SilenceError) as exc:
        p.analyze([])
    assert exc.value.code == "SIL_EMPTY_BUFFER"

    for frame in ((-20.0,), (-20.0, 0.1, 0.2), ("loud", 0.1),
                  (float("nan"), 0.1), (-20.0, 1.5), (-20.0, -0.1)):
        with pytest.raises(sc.SilenceError) as exc:
            p.analyze([frame])
        assert exc.value.code == "SIL_INVALID_FRAME"
    assert p.stats()["frames"] == 0


def test_analyze_rejects_sample_rate_mismatch():
    p = planner(sample_rate=48000)
    with pytest.raises(sc.SilenceError) as exc:
        p.analyze([(-20.0, 0.1)], sample_rate=44100)
    assert exc.value.code == "SIL_SAMPLE_RATE"
    assert p.stats()["frames"] == 0

    assert p.analyze([(-20.0, 0.1)], sample_rate=48000) == 1
    assert p.stats()["frames"] == 1


def test_analyze_respects_caps_atomically():
    small = planner(max_frames=4)
    assert small.analyze([(-20.0, 0.1)] * 4) == 4
    with pytest.raises(sc.SilenceError) as exc:
        small.analyze([(-20.0, 0.1)])
    assert exc.value.code == "SIL_CAPACITY"
    assert small.stats()["frames"] == 4

    narrow = planner(max_ranges=1)
    two_silences = frames((-60.0, 0.1, 15), (-20.0, 0.1, 15),
                          (-60.0, 0.1, 15), (-20.0, 0.1, 15))
    with pytest.raises(sc.SilenceError) as exc:
        narrow.analyze(two_silences)
    assert exc.value.code == "SIL_CAPACITY"
    assert narrow.stats()["frames"] == 0


def test_silence_ranges_basic():
    p = planner()
    p.analyze(case_a())
    assert p.silence_ranges() == ((400, 700),)
    assert p.voiced_ranges() == ((0, 400), (700, 1000))
    assert p.stats()["duration_ms"] == 1000


def test_short_silence_is_filtered():
    p = planner()
    p.analyze(case_b())
    assert p.silence_ranges() == ()
    assert p.voiced_ranges() == ((0, 1000),)

    plan = p.plan_cuts()
    assert plan.kept == (sc.Segment(0, 1000, 0, 0),)
    assert plan.removed_ms == 0


def test_zero_crossing_rule():
    noisy = planner()
    noisy.analyze([(-60.0, 0.9)] * 50)
    assert noisy.silence_ranges() == ()

    p = planner()
    p.analyze(frames((-60.0, 0.9, 20), (-60.0, 0.1, 15), (-20.0, 0.1, 15)))
    assert p.silence_ranges() == ((400, 700),)


def test_merge_gaps_merges_close_silences():
    p = planner()
    p.analyze(case_d())
    assert p.silence_ranges() == ((0, 300), (400, 700))

    assert p.merge_gaps() == 1
    assert p.silence_ranges() == ((0, 700),)
    assert p.stats()["merged"] == 1
    assert p.merge_gaps() == 0


def test_merge_gaps_validates_threshold():
    p = planner()
    p.analyze(case_d())
    for bad in (-1, -100):
        with pytest.raises(sc.SilenceError) as exc:
            p.merge_gaps(bad)
        assert exc.value.code == "SIL_INVALID_ARG"
    assert p.silence_ranges() == ((0, 300), (400, 700))


def test_plan_cuts_keeps_complement():
    p = planner()
    p.analyze(case_a())

    plan = p.plan_cuts()
    assert plan.cuts == (sc.FrameRange(400, 700),)
    assert plan.kept == (sc.Segment(0, 400, 0, 10),
                         sc.Segment(700, 1000, 10, 0))
    assert plan.removed_ms == 300
    assert p.cuts() == (sc.FrameRange(400, 700),)


def test_apply_padding_extends_and_clamps():
    p = planner()
    p.analyze(case_a())
    assert p.apply_padding(100, 50) == (sc.FrameRange(300, 750),)
    assert p.plan_cuts(pad_lead_ms=100, pad_tail_ms=50).kept == (
        sc.Segment(0, 300, 0, 10), sc.Segment(750, 1000, 10, 0))

    lead = planner()
    lead.analyze(frames((-60.0, 0.1, 15), (-20.0, 0.1, 35)))
    assert lead.apply_padding(100, 50) == (sc.FrameRange(0, 350),)


def test_plan_cuts_rejects_negative_padding():
    p = planner()
    p.analyze(case_a())
    for lead, tail in ((-1, 0), (0, -1)):
        with pytest.raises(sc.SilenceError) as exc:
            p.plan_cuts(pad_lead_ms=lead, pad_tail_ms=tail)
        assert exc.value.code == "SIL_INVALID_PAD"

    with pytest.raises(sc.SilenceError) as exc:
        p.apply_padding(-5, 0)
    assert exc.value.code == "SIL_INVALID_PAD"
    assert p.cuts() == ()


def test_padded_cuts_stay_disjoint():
    p = planner()
    p.analyze(case_d())
    assert p.apply_padding(100, 100) == (sc.FrameRange(0, 350),
                                         sc.FrameRange(350, 800))
    assert p.plan_cuts(pad_lead_ms=100, pad_tail_ms=100).kept == (
        sc.Segment(350, 1000, 10, 0),)


def test_preview_reports_durations():
    p = planner()
    p.analyze(case_a())

    preview = p.preview()
    assert preview["source_duration_ms"] == 1000
    assert preview["output_duration_ms"] == 700
    assert [(seg.start_ms, seg.end_ms) for seg in preview["kept"]] == [
        (0, 400), (700, 1000)]
    assert [(cut.start_ms, cut.end_ms) for cut in preview["cuts"]] == [
        (400, 700)]


def test_snapshot_restore_round_trip():
    p = planner()
    p.analyze(case_a())
    p.plan_cuts()

    state = p.snapshot()
    pristine = copy.deepcopy(state)
    state["frames"].clear()
    state["stats"]["frames"] = 0
    assert p.stats()["frames"] == 50

    clone = planner()
    clone.restore(pristine)
    assert clone.stats() == p.stats()
    assert clone.silence_ranges() == p.silence_ranges()
    assert clone.plan_cuts() == p.plan_cuts()

    fresh = planner()
    bad_states = [
        None,
        {},
        {"version": 9, "sample_rate": 48000, "frame_ms": 20, "frames": [],
         "ranges": [], "stats": {}},
        {"version": 1, "sample_rate": 48000, "frame_ms": 20,
         "frames": "nope", "ranges": [], "stats": {}},
        {"version": 1, "sample_rate": 48000, "frame_ms": 20, "frames": [],
         "ranges": [(0, "x")], "stats": {}},
        {"version": 1, "sample_rate": 48000, "frame_ms": 20, "frames": [],
         "ranges": [], "stats": {"frames": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(sc.SilenceError) as exc:
            fresh.restore(bad)
        assert exc.value.code == "SIL_SNAPSHOT_INVALID"
    assert fresh.stats()["frames"] == 0


def test_stats_track_counters():
    p = planner()
    p.analyze(case_d())

    stats = p.stats()
    assert (stats["frames"], stats["duration_ms"],
            stats["silences"]) == (50, 1000, 2)
    assert stats["merged"] == 0

    p.merge_gaps()
    p.plan_cuts()
    stats = p.stats()
    assert (stats["merged"], stats["cuts"], stats["kept"]) == (1, 1, 1)
    assert stats["plans"] == 1
    assert stats["rejected"] == 0
