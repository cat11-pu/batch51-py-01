import copy

import pytest

import beat_grid_analyzer as bg


def analyzer(**kwargs):
    return bg.BeatGridAnalyzer(**kwargs)


def clicks(*indices, total, height=1.0):
    frames = [0.0] * total
    for index in indices:
        frames[index] = height
    return frames


def shapes(al):
    return [(seg.source, seg.start, seg.end, seg.bpm) for seg in al.grid_segments()]


def test_feed_rejects_empty_rate_and_bad_frames():
    al = analyzer(frame_hz=100.0)
    for bad in (0, -1, 0.0):
        with pytest.raises(bg.BeatError) as exc:
            bg.BeatGridAnalyzer(frame_hz=bad)
        assert exc.value.code == "BEAT_INVALID"

    with pytest.raises(bg.BeatError) as exc:
        al.feed([])
    assert exc.value.code == "BEAT_EMPTY_BUFFER"

    with pytest.raises(bg.BeatError) as exc:
        al.feed([0.0, 1.0], frame_hz=50.0)
    assert exc.value.code == "BEAT_FRAME_RATE"

    for bad in (-0.5, float("nan"), "loud"):
        with pytest.raises(bg.BeatError) as exc:
            al.feed([bad])
        assert exc.value.code == "BEAT_INVALID"

    assert al.stats()["frames"] == 0


def test_feed_detects_onsets_by_threshold_and_rise():
    al = analyzer(frame_hz=100.0, onset_threshold=0.4, rise_ratio=3.0)
    assert al.feed(clicks(0, 10, 20, total=30)) == 30
    assert al.onsets() == (0.0, 0.1, 0.2)

    quiet = analyzer(frame_hz=100.0, onset_threshold=0.4, rise_ratio=3.0)
    quiet.feed([1.0, 0.5, 0.0, 1.5, 0.0])
    assert quiet.onsets() == (0.0, 0.03)


def test_feed_respects_frame_cap_atomically():
    al = analyzer(max_frames=100)
    assert al.feed([0.0] * 100) == 100
    with pytest.raises(bg.BeatError) as exc:
        al.feed([1.0])
    assert exc.value.code == "BEAT_CAPACITY"
    assert al.stats()["frames"] == 100
    assert al.stats()["rejected"] == 1


def test_onset_cap_rejects_before_state_change():
    al = analyzer(max_onsets=2)
    al.feed([1.0, 0.0])
    al.feed([1.0, 0.0])
    assert al.onsets() == (0.0, 0.02)
    with pytest.raises(bg.BeatError) as exc:
        al.feed([1.0, 0.0])
    assert exc.value.code == "BEAT_CAPACITY"
    assert al.stats()["frames"] == 4
    assert al.onsets() == (0.0, 0.02)


def test_estimate_tempo_uses_median_interval():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    assert al.estimate_tempo() == 120.0
    assert al.estimate_tempo(min_bpm=100.0, max_bpm=140.0) == 120.0
    with pytest.raises(bg.BeatError) as exc:
        al.estimate_tempo(min_bpm=200.0)
    assert exc.value.code == "BEAT_TEMPO_RANGE"

    empty = analyzer()
    with pytest.raises(bg.BeatError) as exc:
        empty.estimate_tempo()
    assert exc.value.code == "BEAT_EMPTY_GRID"


def test_estimate_tempo_validates_bounds():
    al = analyzer()
    al.feed(clicks(0, 50, total=100))
    for kwargs in ({"min_bpm": 0.0}, {"min_bpm": -1.0}, {"max_bpm": 40.0},
                   {"min_bpm": 100.0, "max_bpm": 100.0}):
        with pytest.raises(bg.BeatError) as exc:
            al.estimate_tempo(**kwargs)
        assert exc.value.code == "BEAT_INVALID"


def test_beat_times_cover_window_from_phase():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    times = al.beat_times()
    assert times == (0.0, 0.5, 1.0, 1.5, 2.0)
    assert list(times) == sorted(set(times))


def test_beat_at_validates_index():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    first = al.beat_at(0)
    assert (first.index, first.time, first.bpm) == (0, 0.0, 120.0)
    third = al.beat_at(2)
    assert (third.index, third.time) == (2, 1.0)
    for bad in (-1, 5, 99):
        with pytest.raises(bg.BeatError) as exc:
            al.beat_at(bad)
        assert exc.value.code == "BEAT_INDEX"


def test_snap_returns_nearest_beat_within_tolerance():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    hit = al.snap(0.51)
    assert (hit.index, hit.time) == (1, 0.5)
    assert al.snap(0.26, tolerance=0.1) is None
    tie = al.snap(0.25, tolerance=0.3)
    assert tie.time == 0.0
    with pytest.raises(bg.BeatError) as exc:
        al.snap(-0.1)
    assert exc.value.code == "BEAT_INVALID"


def test_tap_correct_overrides_automatic_grid():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    tap = al.tap_correct(0.5, 1.5, bpm=90.0)
    assert (tap.start, tap.end, tap.bpm, tap.anchor) == (0.5, 1.5, 90.0, 0.5)
    assert shapes(al) == [("auto", 0.0, 0.5, 120.0),
                          ("manual", 0.5, 1.5, 90.0),
                          ("auto", 1.5, 2.0, 120.0)]
    assert al.tempo_at(1.0) == 90.0
    assert al.tempo_at(0.2) == 120.0


def test_tap_correct_validates_arguments():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    cases = [
        ((-0.1, 1.0), {"bpm": 90.0}),
        ((1.0, 1.0), {"bpm": 90.0}),
        ((1.5, 1.0), {"bpm": 90.0}),
        ((0.5, 1.5), {"bpm": 10.0}),
        ((0.5, 1.5), {"bpm": 400.0}),
        ((0.5, 1.5), {"bpm": 90.0, "anchor": 0.2}),
    ]
    for args, kwargs in cases:
        with pytest.raises(bg.BeatError) as exc:
            al.tap_correct(*args, **kwargs)
        assert exc.value.code == "BEAT_INVALID"
    assert al.stats()["taps"] == 0


def test_overlapping_tap_replaces_previous():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    al.tap_correct(0.5, 1.5, bpm=90.0)
    al.tap_correct(1.0, 2.0, bpm=150.0)
    assert shapes(al) == [("auto", 0.0, 0.5, 120.0),
                          ("manual", 0.5, 1.0, 90.0),
                          ("manual", 1.0, 2.0, 150.0)]
    assert al.stats()["taps"] == 2


def test_tempo_at_and_clear_taps():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    assert al.tempo_at(0.2) == 120.0
    with pytest.raises(bg.BeatError) as exc:
        al.tempo_at(-0.1)
    assert exc.value.code == "BEAT_INVALID"

    al.tap_correct(0.5, 1.5, bpm=90.0)
    assert al.clear_taps() == 1
    assert al.stats()["taps"] == 0
    assert shapes(al) == [("auto", 0.0, 2.0, 120.0)]


def test_snapshot_restore_round_trip():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    al.tap_correct(0.5, 1.5, bpm=90.0)

    state = al.snapshot()
    pristine = copy.deepcopy(state)
    state["taps"].clear()
    state["stats"]["taps"] = 99
    assert al.stats()["taps"] == 1

    clone = analyzer()
    clone.restore(pristine)
    assert clone.stats() == al.stats()
    assert clone.beat_times() == al.beat_times()
    assert shapes(clone) == shapes(al)

    bad_states = [
        None,
        {},
        {"version": 2, "frame_hz": 100.0, "onset_threshold": 0.5,
         "rise_ratio": 2.0, "frames": 0, "onsets": [], "taps": [], "stats": {}},
        {"version": 1, "frame_hz": 100.0, "onset_threshold": 0.5,
         "rise_ratio": 2.0, "frames": -1, "onsets": [], "taps": [], "stats": {}},
        {"version": 1, "frame_hz": 100.0, "onset_threshold": 0.5,
         "rise_ratio": 2.0, "frames": 0, "onsets": "nope", "taps": [], "stats": {}},
        {"version": 1, "frame_hz": 100.0, "onset_threshold": 0.5,
         "rise_ratio": 2.0, "frames": 0, "onsets": [], "taps": [{"start": 0.0}],
         "stats": {}},
        {"version": 1, "frame_hz": 100.0, "onset_threshold": 0.5,
         "rise_ratio": 2.0, "frames": 0, "onsets": [], "taps": [],
         "stats": {"frames": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(bg.BeatError) as exc:
            clone.restore(bad)
        assert exc.value.code == "BEAT_SNAPSHOT_INVALID"

    assert clone.stats() == al.stats()
    assert shapes(clone) == shapes(al)


def test_stats_track_analysis_counters():
    al = analyzer()
    al.feed(clicks(0, 50, 100, 150, total=200))
    al.tap_correct(0.5, 1.5, bpm=90.0)

    stats = al.stats()
    assert (stats["frames"], stats["onsets"], stats["taps"],
            stats["beats"], stats["segments"]) == (200, 4, 1, 5, 3)
    assert stats["rejected"] == 0

    with pytest.raises(bg.BeatError) as exc:
        al.feed([])
    assert exc.value.code == "BEAT_EMPTY_BUFFER"
    assert al.stats()["rejected"] == 1
