import copy

import pytest

import encode_quality_gate as qg


def gate(**kwargs):
    return qg.EncodeQualityGate(**kwargs)


def frame(pts, *pixels):
    return (pts, tuple(pixels))


def good(pts=0):
    return frame(pts, 10, 245, 10, 245)


def source(pts=0):
    return frame(pts, 0, 255, 0, 255)


def poor(pts=0):
    return frame(pts, 51, 204, 51, 204)


def test_set_threshold_returns_previous_and_validates():
    g = gate()
    assert g.set_threshold(0.8) == 0.95
    assert g.set_threshold(1.0) == 0.8
    for bad in (-0.01, 1.01, "high"):
        with pytest.raises(qg.GateError) as exc:
            g.set_threshold(bad)
        assert exc.value.code == "QG_INVALID_THRESHOLD"
    assert g.report()["threshold"] == 1.0


def test_set_budget_and_budget_left():
    g = gate(budget=5)
    assert g.budget_left() == 5
    assert g.set_budget(2) == 5
    assert g.budget_left() == 2
    for bad in (-1, 1.5):
        with pytest.raises(qg.GateError) as exc:
            g.set_budget(bad)
        assert exc.value.code == "QG_INVALID_BUDGET"
    assert g.budget_left() == 2


def test_submit_rejects_frame_count_mismatch():
    g = gate()
    with pytest.raises(qg.GateError) as exc:
        g.submit_segment("s1", decoded=[frame(0, 0, 0)],
                         source=[frame(0, 0, 0), frame(1, 0, 0)])
    assert exc.value.code == "QG_FRAME_COUNT"

    with pytest.raises(qg.GateError) as exc:
        g.submit_segment("s1", decoded=[], source=[])
    assert exc.value.code == "QG_FRAME_COUNT"
    assert g.segments() == ()


def test_submit_rejects_duplicate_pts():
    g = gate()
    with pytest.raises(qg.GateError) as exc:
        g.submit_segment("s1", decoded=[frame(0, 1, 2), frame(0, 1, 2)],
                         source=[frame(0, 1, 2), frame(1, 1, 2)])
    assert exc.value.code == "QG_DUPLICATE_PTS"
    assert g.segments() == ()


def test_submit_rejects_bad_pixels():
    g = gate()
    for decoded in ([frame(0)], [frame(0, 300, 0)], [frame(0, -1, 0)],
                    [frame(0, 1.5, 0)]):
        with pytest.raises(qg.GateError) as exc:
            g.submit_segment("s1", decoded=decoded, source=[frame(0, 1, 0)])
        assert exc.value.code == "QG_INVALID_FRAME"

    with pytest.raises(qg.GateError) as exc:
        g.submit_segment("s1", decoded=[frame(0, 1, 2), frame(1, 1, 2, 3)],
                         source=[frame(0, 1, 2), frame(1, 1, 2, 3)])
    assert exc.value.code == "QG_INVALID_FRAME"
    assert g.segments() == ()


def test_submit_duplicate_and_capacity():
    g = gate(max_segments=2)
    g.submit_segment("a", decoded=[frame(0, 1)], source=[frame(0, 1)])
    with pytest.raises(qg.GateError) as exc:
        g.submit_segment("a", decoded=[frame(0, 1)], source=[frame(0, 1)])
    assert exc.value.code == "QG_SEGMENT_EXISTS"

    g.submit_segment("b", decoded=[frame(0, 1)], source=[frame(0, 1)])
    with pytest.raises(qg.GateError) as exc:
        g.submit_segment("c", decoded=[frame(0, 1)], source=[frame(0, 1)])
    assert exc.value.code == "QG_CAPACITY"
    assert g.segments() == ("a", "b")

    tight = gate(max_frames_per_segment=1)
    with pytest.raises(qg.GateError) as exc:
        tight.submit_segment("x", decoded=[frame(0, 1), frame(1, 1)],
                             source=[frame(0, 1), frame(1, 1)])
    assert exc.value.code == "QG_CAPACITY"
    assert tight.segments() == ()


def test_score_uses_mean_absolute_error():
    g = gate()
    g.submit_segment("s1", decoded=[good()], source=[source()])
    assert g.score("s1") == 0.960784
    with pytest.raises(qg.GateError) as exc:
        g.score("ghost")
    assert exc.value.code == "QG_UNKNOWN_SEGMENT"


def test_decide_accepts_high_score():
    g = gate()
    g.submit_segment("s1", decoded=[good()], source=[source()])
    assert g.decide("s1") == "accept"
    assert g.budget_left() == 8
    with pytest.raises(qg.GateError) as exc:
        g.decide("ghost")
    assert exc.value.code == "QG_UNKNOWN_SEGMENT"


def test_decide_reencodes_and_charges_budget():
    g = gate(budget=2)
    g.submit_segment("s1", decoded=[poor()], source=[source()])
    assert g.score("s1") == 0.8
    assert g.decide("s1") == "reencode"
    assert g.budget_left() == 1
    assert g.report()["budget_spent"] == 1


def test_decide_is_idempotent():
    g = gate(budget=1)
    g.submit_segment("s1", decoded=[poor()], source=[source()])
    assert g.decide("s1") == "reencode"
    assert g.budget_left() == 0
    assert g.decide("s1") == "reencode"
    assert g.budget_left() == 0
    assert g.report()["budget_spent"] == 1


def test_evaluate_all_matches_individual_decisions():
    g = gate(budget=2)
    g.submit_segment("good", decoded=[frame(0, 1, 254, 1, 254)],
                     source=[source()])
    g.submit_segment("bad1", decoded=[poor()], source=[source()])
    g.submit_segment("bad2", decoded=[poor()], source=[source()])
    result = g.evaluate_all(workers=3)
    assert result == {"good": "accept", "bad1": "reencode",
                      "bad2": "reencode"}
    assert g.budget_left() == 0
    assert g.evaluate_all() == result
    assert g.budget_left() == 0


def test_report_counts():
    g = gate(budget=2)
    g.submit_segment("good", decoded=[good()], source=[source()])
    g.submit_segment("bad", decoded=[poor()], source=[source()])
    g.decide("good")
    g.decide("bad")

    report = g.report()
    assert (report["segments"], report["accepted"], report["reencode"],
            report["budget_spent"]) == (2, 1, 1, 1)
    assert report["budget_left"] == 1
    assert report["threshold"] == 0.95


def test_segment_info_reports_state():
    g = gate()
    info = g.submit_segment("s1",
                            decoded=[frame(0, 10, 245, 10, 245),
                                     frame(1, 10, 245, 10, 245)],
                            source=[source(0), source(1)])
    assert (info.segment_id, info.frames, info.decision,
            info.evaluated) == ("s1", 2, "pending", False)
    assert info.score is None

    g.decide("s1")
    after = g.segment_info("s1")
    assert (after.score, after.decision, after.evaluated) == (
        0.960784, "accept", True)
    with pytest.raises(qg.GateError) as exc:
        g.segment_info("ghost")
    assert exc.value.code == "QG_UNKNOWN_SEGMENT"


def test_snapshot_restore_round_trip():
    g = gate(budget=3)
    g.submit_segment("good", decoded=[good()], source=[source()])
    g.submit_segment("bad", decoded=[poor()], source=[source()])
    g.decide("good")
    g.decide("bad")

    state = g.snapshot()
    pristine = copy.deepcopy(state)
    state["segments"].clear()
    state["counters"]["accepted"] = 99
    assert g.segments() == ("good", "bad")

    clone = gate()
    clone.restore(pristine)
    assert clone.report() == g.report()
    assert clone.budget_left() == g.budget_left()
    assert clone.segments() == g.segments()
    assert clone.score("bad") == g.score("bad")
    assert clone.decide("bad") == "reencode"
    assert clone.budget_left() == g.budget_left()

    fresh = gate()
    bad_states = [
        None,
        {},
        {"version": 9, "threshold": 0.95, "budget_left": 8, "segments": [],
         "counters": {"submitted": 0, "accepted": 0, "reencode": 0,
                      "unevaluated": 0, "budget_spent": 0, "rejected": 0}},
        {"version": 1, "threshold": 1.5, "budget_left": 8, "segments": [],
         "counters": {"submitted": 0, "accepted": 0, "reencode": 0,
                      "unevaluated": 0, "budget_spent": 0, "rejected": 0}},
        {"version": 1, "threshold": 0.95, "budget_left": 8,
         "segments": "nope", "counters": {"submitted": 0, "accepted": 0,
                                          "reencode": 0, "unevaluated": 0,
                                          "budget_spent": 0, "rejected": 0}},
        {"version": 1, "threshold": 0.95, "budget_left": 8,
         "segments": [{"segment_id": "x", "frames": 1, "score": 0.9,
                       "decision": "accept", "evaluated": True}],
         "counters": {"submitted": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(qg.GateError) as exc:
            fresh.restore(bad)
        assert exc.value.code == "QG_SNAPSHOT_INVALID"
    assert fresh.segments() == ()


def test_segments_preserve_submit_order():
    g = gate()
    for name in ("zulu", "alpha", "mike"):
        g.submit_segment(name, decoded=[frame(0, 1, 254, 1, 254)],
                         source=[source()])
    assert g.segments() == ("zulu", "alpha", "mike")
    assert [info.segment_id for info in
            (g.segment_info("zulu"), g.segment_info("alpha"),
             g.segment_info("mike"))] == ["zulu", "alpha", "mike"]
