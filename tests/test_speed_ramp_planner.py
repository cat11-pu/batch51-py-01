import threading

import pytest

import speed_ramp_planner as sp

PLAN = [(0, 1.0), (10, 2.0)]


def planner(**kwargs):
    return sp.SpeedRampPlanner(**kwargs)


def test_set_keyframes_orders_and_reports_speed():
    p = planner()
    assert p.set_keyframes(PLAN) == 2
    frames = p.keyframes()
    assert [(k.output_frame, k.speed) for k in frames] == [(0, 1.0), (10, 2.0)]
    assert p.speed_at(0) == 1.0
    assert p.speed_at(9) == 1.0
    assert p.speed_at(10) == 2.0
    assert p.speed_at(1000) == 2.0


def test_map_time_advances_by_segment_speed():
    p = planner()
    p.set_keyframes(PLAN)
    assert [p.map_time(n) for n in (0, 5, 10, 15, 20, 25)] == [0, 5, 10, 20, 30, 40]


def test_map_time_floors_slow_motion():
    p = planner()
    p.set_keyframes([(0, 0.5)])
    values = [p.map_time(n) for n in range(1, 13)]
    assert values == [0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6]
    assert values == sorted(values)


def test_unmap_time_is_frame_level_inverse():
    p = planner()
    p.set_keyframes(PLAN)
    assert p.unmap_time(0) == 0
    assert p.unmap_time(5) == 5
    assert p.unmap_time(10) == 10
    assert p.unmap_time(20) == 15
    assert p.unmap_time(31) == 21
    for n in range(30):
        assert p.unmap_time(p.map_time(n)) <= n


def test_output_frames_and_frame_budget():
    p = planner()
    p.set_keyframes(PLAN)
    assert p.set_source_duration(30) == 30
    assert p.output_frames() == 20
    assert p.frame_budget() == {"output_frames": 20, "source_frames": 30,
                                "freeze_frames": 0, "budget": 100000}
    with pytest.raises(sp.SpeedRampError) as exc:
        p.set_source_duration(0)
    assert exc.value.code == "SPEED_RAMP_INVALID"


def test_audio_segments_align_with_video_segments():
    p = planner(frame_rate=25)
    p.set_keyframes(PLAN)
    p.set_source_duration(30)
    segments = p.audio_segments()
    assert len(segments) == 2
    first, second = segments
    assert (first.index, first.output_start, first.output_frames) == (0, 0, 10)
    assert (first.source_start, first.source_frames) == (0, 10)
    assert first.ratio == 1.0
    assert (second.index, second.output_start, second.output_frames) == (1, 10, 10)
    assert (second.source_start, second.source_frames) == (10, 20)
    assert second.ratio == 0.5
    assert sum(s.output_frames for s in segments) == 20


def test_validate_flags_acceleration_jump():
    p = planner()
    assert p.validate() == ()
    p.set_keyframes([(0, 1.0), (10, 4.0)])
    issues = p.validate()
    assert len(issues) == 1
    assert issues[0].code == "ACCEL_LIMIT"
    assert issues[0].at_frame == 10
    p.set_source_duration(30)
    with pytest.raises(sp.SpeedRampError) as exc:
        p.frame_budget()
    assert exc.value.code == "SPEED_RAMP_ACCEL_LIMIT"


def test_invalid_keyframes_are_rejected():
    p = planner()
    bad_batches = [
        [],
        [(5, 1.0)],
        [(0, 1.0), (0, 2.0)],
        [(10, 1.0), (0, 2.0)],
        [(0, -1.0)],
        [(0, 1.0), (5, 9.0)],
    ]
    for batch in bad_batches:
        with pytest.raises(sp.SpeedRampError) as exc:
            p.set_keyframes(batch)
        assert exc.value.code == "SPEED_RAMP_INVALID"
    assert p.keyframes() == ()


def test_keyframe_limit_rejects_whole_batch():
    p = planner(max_keyframes=2)
    with pytest.raises(sp.SpeedRampError) as exc:
        p.set_keyframes([(0, 1.0), (1, 1.0), (2, 1.0)])
    assert exc.value.code == "SPEED_RAMP_LIMIT"
    assert p.keyframes() == ()


def test_budget_exceeded_is_refused():
    p = planner(max_output_frames=10)
    p.set_keyframes([(0, 0.5)])
    p.set_source_duration(30)
    with pytest.raises(sp.SpeedRampError) as exc:
        p.frame_budget()
    assert exc.value.code == "SPEED_RAMP_BUDGET_EXCEEDED"


def test_stats_reports_curve_shape():
    p = planner()
    assert p.stats() == {"keyframes": 0, "intervals": 0,
                         "max_speed": 0.0, "min_speed": 0.0}
    p.set_keyframes(PLAN)
    assert p.stats() == {"keyframes": 2, "intervals": 2,
                         "max_speed": 2.0, "min_speed": 1.0}


def test_snapshot_is_deep_copy_and_restores():
    p = planner()
    p.set_keyframes(PLAN)
    p.set_source_duration(30)
    snap = p.snapshot()
    assert snap["version"] == 1
    assert snap["keyframes"] == [[0, 1.0], [10, 2.0]]
    snap["keyframes"].append([99, 1.0])
    snap["source_frames"] = 999
    assert len(p.keyframes()) == 2
    assert p.output_frames() == 20
    q = planner()
    q.restore(p.snapshot())
    assert [q.map_time(n) for n in (0, 10, 20)] == [0, 10, 30]
    assert q.output_frames() == 20


def test_restore_rejects_bad_state_without_change():
    p = planner()
    p.set_keyframes(PLAN)
    p.set_source_duration(30)
    before = p.snapshot()
    bad_states = [
        {"version": 2},
        {"version": 1, "frame_rate": 30, "max_speed": 8.0,
         "max_keyframes": 32, "max_accel": 0.5, "max_output_frames": 100000,
         "source_frames": 30, "keyframes": [[0, 1.0], [10, -2.0]], "plans": 0},
        None,
    ]
    for bad in bad_states:
        with pytest.raises(sp.SpeedRampError) as exc:
            p.restore(bad)
        assert exc.value.code == "SPEED_RAMP_SNAPSHOT_INVALID"
    assert p.snapshot() == before


def test_reset_clears_plan():
    p = planner()
    p.set_keyframes(PLAN)
    p.set_source_duration(30)
    p.reset()
    assert p.keyframes() == ()
    assert p.stats() == {"keyframes": 0, "intervals": 0,
                         "max_speed": 0.0, "min_speed": 0.0}
    with pytest.raises(sp.SpeedRampError) as exc:
        p.output_frames()
    assert exc.value.code == "SPEED_RAMP_STATE"


def test_reads_are_consistent_under_threads():
    p = planner()
    p.set_keyframes(PLAN)
    p.set_source_duration(30)
    expected = tuple(list(range(11)) + [10 + 2 * (i - 10) for i in range(11, 25)])
    results = []

    def worker():
        results.append(tuple(p.map_time(i) for i in range(25)))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 4
    assert all(r == expected for r in results)
    assert p.output_frames() == 20
