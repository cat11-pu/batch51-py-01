import copy

import pytest

import freeze_frame_detector as ff


def detector(**kwargs):
    return ff.FreezeFrameDetector(**kwargs)


def feed(det, stream="cam1", pts=0, fp=7, luma=0.5, epoch=1):
    return det.feed(stream, pts_ms=pts, fingerprint=fp, luma=luma, epoch=epoch)


def test_feed_rejects_non_monotonic_pts():
    det = detector()
    feed(det, pts=100)
    for bad in (100, 99):
        with pytest.raises(ff.FreezeError) as exc:
            feed(det, pts=bad)
        assert exc.value.code == "FREEZE_PTS_NON_MONOTONIC"
    assert det.stats()["frames"] == 1

    feed(det, pts=101)
    assert det.stats()["frames"] == 2


def test_feed_rejects_invalid_arguments():
    det = detector()
    bad_calls = [
        dict(stream="   ", pts=0, fp=1, luma=0.5, epoch=1),
        dict(stream="cam1", pts=-1, fp=1, luma=0.5, epoch=1),
        dict(stream="cam1", pts=0, fp=-1, luma=0.5, epoch=1),
        dict(stream="cam1", pts=0, fp=1, luma=1.5, epoch=1),
        dict(stream="cam1", pts=0, fp=1, luma=-0.1, epoch=1),
        dict(stream="cam1", pts=0, fp=1, luma=0.5, epoch=0),
    ]
    for call in bad_calls:
        with pytest.raises(ff.FreezeError) as exc:
            det.feed(call["stream"], pts_ms=call["pts"], fingerprint=call["fp"],
                     luma=call["luma"], epoch=call["epoch"])
        assert exc.value.code == "FREEZE_INVALID"
    assert det.stats()["frames"] == 0
    assert det.streams() == ()


def test_freeze_run_is_closed_at_last_frame():
    det = detector(min_freeze_ms=200)
    assert feed(det, pts=0) == ()
    assert feed(det, pts=100) == ()
    assert feed(det, pts=200) == ()
    assert feed(det, pts=300) == ()

    closed = feed(det, pts=400, fp=8)
    assert len(closed) == 1
    row = closed[0]
    assert (row.stream, row.kind) == ("cam1", "freeze")
    assert (row.start_ms, row.end_ms, row.frames) == (0, 300, 4)
    assert det.ranges() == (row,)
    assert det.stats()["freeze_ranges"] == 1


def test_short_freeze_run_is_discarded():
    det = detector(min_freeze_ms=200)
    feed(det, pts=0)
    feed(det, pts=100)
    assert feed(det, pts=150, fp=8) == ()
    assert det.ranges() == ()
    assert det.stats()["discarded"] == 1
    assert det.stats()["freeze_ranges"] == 0


def test_distinct_fingerprints_never_freeze():
    det = detector(min_freeze_ms=200)
    for index, pts in enumerate((0, 100, 200, 300)):
        assert feed(det, pts=pts, fp=index) == ()
    assert det.ranges() == ()
    assert det.stats()["freeze_ranges"] == 0
    assert det.stats()["discarded"] == 3


def test_black_run_is_closed_at_last_frame():
    det = detector(min_black_ms=300)
    for index, pts in enumerate((0, 100, 200, 300)):
        assert feed(det, pts=pts, fp=index, luma=0.0) == ()

    closed = feed(det, pts=400, fp=9, luma=0.5)
    assert len(closed) == 1
    row = closed[0]
    assert (row.stream, row.kind) == ("cam1", "black")
    assert (row.start_ms, row.end_ms, row.frames) == (0, 300, 4)
    assert det.stats()["black_ranges"] == 1


def test_bright_frames_never_go_black():
    det = detector(min_black_ms=300)
    for index, pts in enumerate((0, 100, 200, 300, 400)):
        feed(det, pts=pts, fp=index, luma=0.5)
    assert det.ranges() == ()
    assert det.stats()["black_ranges"] == 0


def test_flush_closes_open_run_and_clears_window():
    det = detector(min_freeze_ms=200)
    feed(det, pts=0)
    feed(det, pts=100)
    feed(det, pts=200)

    closed = det.flush("cam1")
    assert len(closed) == 1
    assert (closed[0].start_ms, closed[0].end_ms, closed[0].frames) == (0, 200, 3)

    opened = det.open_range("cam1")
    assert opened["freeze_start"] is None
    assert opened["freeze_frames"] == 0
    assert opened["last_pts"] == 200

    assert feed(det, pts=300) == ()
    assert det.open_range("cam1")["freeze_frames"] == 1
    assert len(det.ranges()) == 1

    with pytest.raises(ff.FreezeError) as exc:
        det.flush("cam9")
    assert exc.value.code == "FREEZE_UNKNOWN_STREAM"


def test_ranges_are_stream_scoped():
    det = detector(min_freeze_ms=200)
    feed(det, "cam1", pts=0, fp=1)
    feed(det, "cam2", pts=0, fp=5)
    feed(det, "cam1", pts=100, fp=1)
    feed(det, "cam2", pts=100, fp=6)
    feed(det, "cam1", pts=200, fp=1)
    feed(det, "cam2", pts=150, fp=7)
    det.flush("cam1")

    assert len(det.ranges("cam1")) == 1
    assert det.ranges("cam2") == ()
    assert len(det.ranges()) == 1
    assert det.streams() == ("cam1", "cam2")
    assert det.stats()["frames"] == 6


def test_confidence_uses_double_threshold_formula():
    det = detector(min_freeze_ms=200)
    for pts in (0, 100, 200, 300):
        feed(det, pts=pts)
    det.flush("cam1")
    assert det.confidence_of("cam1", 0) == pytest.approx(0.75)

    for pts in (1000, 1100, 1200, 1300, 1400):
        feed(det, pts=pts)
    det.flush("cam1")
    assert det.confidence_of("cam1", 1000) == pytest.approx(1.0)
    assert det.ranges()[0].confidence == pytest.approx(0.75)

    with pytest.raises(ff.FreezeError) as exc:
        det.confidence_of("cam1", 99999)
    assert exc.value.code == "FREEZE_RANGE_UNKNOWN"

    with pytest.raises(ff.FreezeError) as exc:
        det.confidence_of("cam1", 0, kind="black")
    assert exc.value.code == "FREEZE_RANGE_UNKNOWN"


def test_set_threshold_is_per_stream_and_validated():
    det = detector()
    feed(det, "cam1", pts=0, fp=1)
    previous = det.set_threshold("cam1", min_freeze_ms=100)
    assert previous == {"min_freeze_ms": 200, "min_black_ms": 300, "black_luma": 0.08}

    feed(det, "cam1", pts=100, fp=1)
    closed = feed(det, "cam1", pts=150, fp=2)
    assert len(closed) == 1
    assert (closed[0].start_ms, closed[0].end_ms) == (0, 100)

    global_previous = det.set_threshold(min_black_ms=500)
    assert global_previous["min_black_ms"] == 300
    assert det.open_range("cam2") is None

    for bad in ({"min_freeze_ms": -1}, {"min_black_ms": -5}, {"black_luma": 1.5}):
        with pytest.raises(ff.FreezeError) as exc:
            det.set_threshold("cam1", **bad)
        assert exc.value.code == "FREEZE_INVALID"

    with pytest.raises(ff.FreezeError) as exc:
        det.set_threshold("cam9", min_freeze_ms=50)
    assert exc.value.code == "FREEZE_UNKNOWN_STREAM"


def test_range_cap_evicts_oldest():
    det = detector(min_freeze_ms=200, max_ranges=2)
    script = [
        (0, 1), (100, 1), (200, 1), (300, 2),
        (400, 2), (500, 2), (600, 3),
        (700, 3), (800, 3), (900, 4),
    ]
    for pts, fp in script:
        feed(det, pts=pts, fp=fp)

    kept = det.ranges()
    assert [(row.start_ms, row.end_ms) for row in kept] == [(300, 500), (600, 800)]
    assert det.stats()["evicted"] == 1
    assert det.stats()["freeze_ranges"] == 3


def test_reset_stream_drops_only_that_stream():
    det = detector(min_freeze_ms=200)
    for pts, fp in ((0, 1), (100, 1), (200, 1), (300, 2), (400, 2), (500, 2)):
        feed(det, "cam1", pts=pts, fp=fp)
    feed(det, "cam1", pts=600, fp=9)
    for pts in (0, 100, 200):
        feed(det, "cam2", pts=pts, fp=3)
    det.flush("cam2")
    assert len(det.ranges()) == 3

    assert det.reset_stream("cam1") == 2
    assert len(det.ranges()) == 1
    assert det.ranges()[0].stream == "cam2"
    assert det.stats()["resets"] == 1
    assert det.streams() == ("cam1", "cam2")


def test_snapshot_restore_continues_open_run():
    det = detector(min_freeze_ms=200)
    feed(det, pts=0)
    feed(det, pts=100)

    state = det.snapshot()
    pristine = copy.deepcopy(state)
    state["streams"].clear()
    state["stats"]["frames"] = 99
    assert det.stats()["frames"] == 2

    clone = detector()
    clone.restore(pristine)
    assert clone.stats() == det.stats()
    assert clone.open_range("cam1")["freeze_frames"] == 2

    clone.feed("cam1", pts_ms=200, fingerprint=7, luma=0.5, epoch=1)
    closed = clone.flush("cam1")
    assert len(closed) == 1
    assert (closed[0].start_ms, closed[0].end_ms, closed[0].frames) == (0, 200, 3)


def test_restore_rejects_malformed_state_without_mutating():
    det = detector()
    feed(det, pts=0)
    bad_states = [
        None,
        {},
        {"version": 2, "streams": [], "ranges": [], "stats": {}},
        {"version": 1, "streams": "nope", "ranges": [], "stats": {}},
        {"version": 1, "streams": [{"stream": "cam1"}], "ranges": [], "stats": {}},
        {"version": 1, "streams": [], "ranges": [{"stream": "cam1"}], "stats": {}},
        {"version": 1, "streams": [{"stream": "cam1", "kind": "freeze"}],
         "ranges": [], "stats": {}},
    ]
    for state in bad_states:
        with pytest.raises(ff.FreezeError) as exc:
            det.restore(state)
        assert exc.value.code == "FREEZE_SNAPSHOT_INVALID"

    assert det.stats()["frames"] == 1
    assert det.open_range("cam1")["freeze_frames"] == 1
