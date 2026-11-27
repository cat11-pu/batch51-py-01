import pytest

import late_latch_reprojector as lr

LEFT_POS = (0.0, 0.0, 1.0)
RIGHT_POS = (0.06, 0.0, 1.0)
IDENTITY = (0.0, 0.0, 0.0, 1.0)


def rig(**kwargs):
    return lr.LateLatchReprojector(**kwargs)


def submit(r, frame, eye, *, timestamp_ms=1000.0):
    position = LEFT_POS if eye == "left" else RIGHT_POS
    return r.submit_pose(frame, eye=eye, position=position,
                         orientation=IDENTITY, timestamp_ms=timestamp_ms)


def test_submit_pose_records_render_pose():
    r = rig()
    assert submit(r, 10, "left", timestamp_ms=1000.0) is True
    pose = r.pose_for(10, eye="left")
    assert pose == lr.Pose(frame=10, eye="left", position=(0.0, 0.0, 1.0),
                           orientation=(0.0, 0.0, 0.0, 1.0),
                           timestamp_ms=1000.0)
    assert r.pose_for(10, eye="right") is None
    assert r.stats()["poses"] == 1


def test_submit_pose_rejects_unknown_eye():
    r = rig()
    with pytest.raises(lr.ReprojectError) as exc:
        r.submit_pose(10, eye="center", position=(0.0, 0.0, 0.0),
                      orientation=IDENTITY, timestamp_ms=1.0)
    assert exc.value.code == "REPROJECT_INVALID_EYE"


def test_horizon_inside_range_returns_requested():
    plan = rig().prediction_horizon(render_time_ms=1000.0,
                                    compose_time_ms=1012.0)
    assert plan.requested_ms == pytest.approx(12.0)
    assert plan.used_ms == pytest.approx(12.0)
    assert plan.clipped is False


def test_horizon_above_max_is_clipped():
    plan = rig(max_horizon_ms=40.0).prediction_horizon(render_time_ms=1000.0,
                                                      compose_time_ms=1200.0)
    assert plan.requested_ms == pytest.approx(200.0)
    assert plan.clipped is True


def test_horizon_below_min_is_clipped():
    plan = rig(min_horizon_ms=4.0).prediction_horizon(render_time_ms=1000.0,
                                                      compose_time_ms=1001.0)
    assert plan.requested_ms == pytest.approx(1.0)
    assert plan.clipped is True


def test_reproject_counts_finite_samples():
    r = rig()
    submit(r, 20, "left")
    plan = r.reproject(20, eye="left", depths=[1.0, 2.0, 4.0])
    assert plan.frame == 20
    assert plan.eye == "left"
    assert plan.total_samples == 3
    assert plan.low_confidence == 0
    assert plan.reprojected is True
    assert r.stats()["reprojects"] == 1


def test_reproject_flags_missing_depth_as_low_confidence():
    r = rig()
    submit(r, 20, "left")
    plan = r.reproject(20, eye="left", depths=[1.0, None, 0.0, 2.0])
    assert plan.total_samples == 4
    assert plan.low_confidence == 2


def test_reproject_without_pose_raises():
    r = rig()
    with pytest.raises(lr.ReprojectError) as exc:
        r.reproject(20, eye="left", depths=[1.0])
    assert exc.value.code == "REPROJECT_NO_POSE"


def test_late_latch_shares_predicted_time_across_eyes():
    r = rig()
    submit(r, 30, "left", timestamp_ms=2000.0)
    submit(r, 30, "right", timestamp_ms=2000.0)
    plans = r.late_latch(30, compose_time_ms=2010.0,
                         depths={"left": [1.0, 2.0], "right": [1.0, None]})
    assert set(plans) == {"left", "right"}
    assert plans["left"].predicted_at_ms == pytest.approx(2010.0)
    assert plans["right"].predicted_at_ms == pytest.approx(2010.0)
    assert plans["left"].used_horizon_ms == pytest.approx(10.0)
    assert plans["right"].used_horizon_ms == pytest.approx(10.0)
    assert plans["left"].low_confidence == 0
    assert plans["right"].low_confidence == 1
    assert r.stats()["latches"] == 1


def test_late_latch_requires_both_eyes():
    r = rig()
    submit(r, 30, "left")
    with pytest.raises(lr.ReprojectError) as exc:
        r.late_latch(30, compose_time_ms=1010.0,
                     depths={"left": [1.0], "right": [1.0]})
    assert exc.value.code == "REPROJECT_MISSING_EYE"


def test_mark_low_confidence_accumulates():
    r = rig()
    submit(r, 40, "left")
    r.reproject(40, eye="left", depths=[1.0, None])
    total = r.mark_low_confidence(40, eye="left", count=3)
    assert total == 4
    assert r.frame_state(40, eye="left").low_confidence == 4
    assert r.stats()["low_confidence"] == 3
    with pytest.raises(lr.ReprojectError) as exc:
        r.mark_low_confidence(40, eye="left", count=-1)
    assert exc.value.code == "REPROJECT_INVALID_COUNT"


def test_drop_frame_removes_both_eyes():
    r = rig()
    submit(r, 50, "left")
    submit(r, 50, "right")
    r.reproject(50, eye="left", depths=[1.0])
    assert r.drop_frame(50) == 2
    assert r.frame_state(50) == {}
    assert r.pose_for(50, eye="left") is None
    assert r.stats()["dropped"] == 2


def test_snapshot_restore_round_trip():
    r = rig()
    submit(r, 60, "left")
    submit(r, 60, "right")
    r.reproject(60, eye="left", depths=[1.0, None])
    snap = r.snapshot()
    r.mark_low_confidence(60, eye="left", count=5)
    other = rig()
    other.restore(snap)
    assert other.pose_for(60, eye="right") == r.pose_for(60, eye="right")
    restored = other.frame_state(60, eye="left")
    assert restored.total_samples == 2
    assert restored.low_confidence == 1
    assert other.stats()["poses"] == 2


def test_restore_rejects_unknown_snapshot():
    r = rig()
    submit(r, 70, "left")
    with pytest.raises(lr.ReprojectError) as exc:
        r.restore({"version": 999, "poses": {}})
    assert exc.value.code == "REPROJECT_SNAPSHOT_INVALID"
    assert r.pose_for(70, eye="left") is not None


def test_stats_reports_all_counters():
    r = rig()
    submit(r, 80, "left")
    submit(r, 80, "right")
    r.reproject(80, eye="left", depths=[1.0, None, None])
    r.late_latch(80, compose_time_ms=1010.0,
                 depths={"left": [1.0], "right": [None]})
    r.mark_low_confidence(80, eye="left", count=4)
    assert r.stats() == {"poses": 2, "late_poses": 0, "reprojects": 1,
                         "latches": 1, "dropped": 0, "low_confidence": 4}
