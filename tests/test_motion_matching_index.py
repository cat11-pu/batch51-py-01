import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

import motion_matching_index as mm


def index(**kwargs):
    return mm.MotionMatchingIndex(**kwargs)


def clip(poses, trajectories=None):
    if trajectories is None:
        trajectories = [((0.0, 0.0),)] * len(poses)
    return [{"time_ms": 100 * position, "pose": pose, "trajectory": traj}
            for position, (pose, traj) in enumerate(zip(poses, trajectories))]


def state(pose, trajectory=((0.0, 0.0),)):
    return {"pose": pose, "trajectory": trajectory}


def cooked(**kwargs):
    m = index(**kwargs)
    m.set_weights(1.0, 0.0)
    return m


def test_add_clip_validates_frames_and_identifiers():
    m = index()
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("run", [])
    assert exc.value.code == "MOTION_EMPTY_CLIP"
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("", clip([(0.0, 0.0)]))
    assert exc.value.code == "MOTION_INVALID_CLIP"
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("run", [{"pose": (0.0, 0.0)}])
    assert exc.value.code == "MOTION_INVALID_CLIP"

    flat = clip([(0.0, 0.0), (1.0, 0.0)])
    flat[1]["time_ms"] = 0
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("run", flat)
    assert exc.value.code == "MOTION_INVALID_FRAMES"

    broken = clip([(0.0, 0.0)])
    broken[0]["pose"] = (float("nan"), 0.0)
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("run", broken)
    assert exc.value.code == "MOTION_INVALID_FRAMES"

    assert m.add_clip("run", clip([(0.0, 0.0), (1.0, 0.0)])) == 2
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("run", clip([(0.0, 0.0)]))
    assert exc.value.code == "MOTION_DUPLICATE_CLIP"
    assert m.stats()["clips"] == 1
    assert m.stats()["frames"] == 2


def test_clip_dimensions_must_agree():
    m = index()
    m.add_clip("run", clip([(0.0, 0.0)]))
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("wide", clip([(0.0, 0.0, 0.0)]))
    assert exc.value.code == "MOTION_DIM_MISMATCH"
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("long", clip([(0.0, 0.0)],
                                trajectories=[((0.0, 0.0), (1.0, 0.0))]))
    assert exc.value.code == "MOTION_DIM_MISMATCH"
    with pytest.raises(mm.MotionError) as exc:
        m.add_clip("thin", clip([(0.0, 0.0)], trajectories=[((0.0,),)]))
    assert exc.value.code == "MOTION_DIM_MISMATCH"
    assert m.stats()["clips"] == 1


def test_build_index_reuses_an_unchanged_index():
    m = index()
    m.add_clip("run", clip([(0.0, 0.0), (1.0, 0.0)]))
    first = m.build_index()
    assert (first.clips, first.frames, first.version, first.rebuilt) == \
        (1, 2, 1, True)

    second = m.build_index()
    assert (second.version, second.rebuilt) == (1, False)
    assert m.index_version() == 1
    assert m.stats()["builds"] == 1
    assert m.stats()["reused"] == 1


def test_query_requires_a_current_index_and_matching_state():
    m = cooked()
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0)))
    assert exc.value.code == "MOTION_INDEX_NOT_BUILT"

    m.add_clip("run", clip([(0.0, 0.0)]))
    m.build_index()
    m.add_clip("walk", clip([(0.0, 0.0)]))
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0)))
    assert exc.value.code == "MOTION_INDEX_NOT_BUILT"

    m.build_index()
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0, 0.0)))
    assert exc.value.code == "MOTION_DIM_MISMATCH"
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0)), limit=0)
    assert exc.value.code == "MOTION_INVALID_LIMIT"


def test_pose_cost_orders_candidates():
    m = cooked()
    m.add_clip("run", clip([(0.0, 0.0), (3.0, 4.0)]))
    m.build_index()

    result = m.query(state((0.0, 0.0)))
    assert [(c.clip_id, c.frame_index, c.cost) for c in result.candidates] == \
        [("run", 0, 0.0), ("run", 1, 5.0)]
    assert result.index_version == 1
    assert m.stats()["queries"] == 1


def test_trajectory_cost_uses_future_samples():
    m = index()
    m.set_weights(0.0, 1.0)
    m.add_clip("run", clip([(0.0, 0.0), (9.0, 9.0)],
                           trajectories=[((2.0, 0.0),), ((0.0, 8.0),)]))
    m.build_index()

    result = m.query(state((0.0, 0.0), ((0.0, 0.0),)))
    assert [(c.frame_index, c.cost) for c in result.candidates] == \
        [(0, 2.0), (1, 8.0)]


def test_cost_combines_pose_and_trajectory_weights():
    m = index()
    m.add_clip("run", clip([(0.0, 0.0), (0.0, 0.0)],
                           trajectories=[((1.0, 2.0),), ((4.0, 6.0),)]))
    m.set_weights(2.0, 3.0)
    m.build_index()

    result = m.query(state((0.0, 0.0), ((1.0, 2.0),)))
    assert [(c.frame_index, c.cost) for c in result.candidates] == \
        [(0, 0.0), (1, 15.0)]

    m.set_weights(0.0, 1.0)
    m.build_index()
    assert [c.cost for c in m.query(
        state((0.0, 0.0), ((1.0, 2.0),))).candidates] == [0.0, 5.0]


def test_equal_costs_fall_back_to_clip_and_frame_order():
    m = cooked()
    m.add_clip("alpha", clip([(1.0, 0.0)]))
    m.add_clip("beta", clip([(0.5, 0.0)]))
    m.add_clip("gamma", clip([(0.5, 0.0)]))
    m.build_index()
    assert [(c.clip_id, c.cost) for c in m.query(state((0.0, 0.0))).candidates] \
        == [("beta", 0.5), ("gamma", 0.5), ("alpha", 1.0)]

    tie = cooked()
    tie.add_clip("run", clip([(0.5, 0.0), (0.5, 0.0)]))
    tie.build_index()
    assert [(c.clip_id, c.frame_index) for c in
            tie.query(state((0.0, 0.0))).candidates] == [("run", 0), ("run", 1)]


def test_query_limit_and_counter():
    m = cooked()
    for name, pose in (("a", (1.0, 0.0)), ("b", (2.0, 0.0)),
                       ("c", (3.0, 0.0))):
        m.add_clip(name, clip([pose]))
    m.build_index()

    result = m.query(state((0.0, 0.0)), limit=2)
    assert len(result.candidates) == 2
    assert [c.clip_id for c in result.candidates] == ["a", "b"]
    assert len(m.query(state((0.0, 0.0)), limit=10).candidates) == 3
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0)), limit=-1)
    assert exc.value.code == "MOTION_INVALID_LIMIT"
    assert m.stats()["queries"] == 2


def test_set_weights_invalidates_and_recomputes_cost():
    m = index()
    m.add_clip("run", clip([(3.0, 4.0)]))
    m.build_index()
    assert m.query(state((0.0, 0.0))).candidates[0].cost == 5.0

    assert m.set_weights(2.0, 1.0) == (2.0, 1.0)
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0)))
    assert exc.value.code == "MOTION_INDEX_NOT_BUILT"

    report = m.build_index()
    assert report.version == 2
    assert m.query(state((0.0, 0.0))).candidates[0].cost == 10.0
    with pytest.raises(mm.MotionError) as exc:
        m.set_weights(-1.0, 1.0)
    assert exc.value.code == "MOTION_INVALID_WEIGHTS"
    with pytest.raises(mm.MotionError) as exc:
        m.set_weights(0.0, 0.0)
    assert exc.value.code == "MOTION_INVALID_WEIGHTS"


def test_commit_choice_validates_and_records_the_playhead():
    m = cooked()
    m.add_clip("run", clip([(0.0, 0.0), (1.0, 0.0)]))
    with pytest.raises(mm.MotionError) as exc:
        m.commit_choice("run", 0)
    assert exc.value.code == "MOTION_INDEX_NOT_BUILT"

    m.build_index()
    assert m.current_choice() is None
    with pytest.raises(mm.MotionError) as exc:
        m.commit_choice("run", 5)
    assert exc.value.code == "MOTION_UNKNOWN_FRAME"
    with pytest.raises(mm.MotionError) as exc:
        m.commit_choice("walk", 0)
    assert exc.value.code == "MOTION_UNKNOWN_FRAME"

    chosen = m.commit_choice("run", 1)
    assert (chosen.clip_id, chosen.frame_index, chosen.cost) == \
        ("run", 1, 1.0)
    assert m.current_choice() == ("run", 1)
    assert m.stats()["commits"] == 1


def test_remove_clip_marks_the_index_dirty():
    m = cooked()
    m.add_clip("alpha", clip([(0.0, 0.0)]))
    m.add_clip("beta", clip([(1.0, 0.0), (2.0, 0.0)]))
    m.build_index()
    m.commit_choice("beta", 0)

    with pytest.raises(mm.MotionError) as exc:
        m.remove_clip("gamma")
    assert exc.value.code == "MOTION_UNKNOWN_CLIP"

    assert m.remove_clip("beta") == 2
    assert m.stats()["clips"] == 1
    assert m.stats()["frames"] == 1
    assert m.current_choice() is None
    with pytest.raises(mm.MotionError) as exc:
        m.query(state((0.0, 0.0)))
    assert exc.value.code == "MOTION_INDEX_NOT_BUILT"

    report = m.build_index()
    assert (report.clips, report.frames, report.version) == (1, 1, 2)


def test_parallel_queries_are_deterministic():
    m = cooked()
    for position, pose in enumerate(((1.0, 0.0), (2.0, 0.0),
                                     (0.5, 0.0), (3.0, 0.0))):
        m.add_clip("c%d" % position, clip([pose]))
    m.build_index()

    expected = [(c.clip_id, c.cost)
                for c in m.query(state((0.0, 0.0))).candidates]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: m.query(state((0.0, 0.0))),
                                range(8)))
    for result in results:
        assert [(c.clip_id, c.cost) for c in result.candidates] == expected
    assert m.stats()["queries"] == 9


def test_queries_only_see_complete_index_versions():
    m = cooked()
    m.add_clip("run", clip([(3.0, 4.0)]))
    m.build_index()

    def rebuild():
        for weight in (2.0, 1.0, 2.0, 1.0):
            m.set_weights(weight, 0.0)
            m.build_index()

    def querier():
        found = []
        for _ in range(30):
            try:
                found.append(m.query(state((0.0, 0.0))))
            except mm.MotionError as exc:
                assert exc.code == "MOTION_INDEX_NOT_BUILT"
        return found

    with ThreadPoolExecutor(max_workers=4) as pool:
        changing = pool.submit(rebuild)
        futures = [pool.submit(querier) for _ in range(3)]
        results = [item for future in futures for item in future.result()]
        changing.result()

    assert results
    for result in results:
        assert result.index_version in (1, 2, 3, 4, 5)
        assert result.candidates[0].cost in (5.0, 10.0)


def test_snapshot_restore_roundtrip_and_malformed_state():
    m = index()
    m.set_weights(2.0, 0.5)
    m.add_clip("run", clip([(1.0, 0.0), (2.0, 0.0)]))
    m.build_index()
    m.commit_choice("run", 1)
    cost = m.query(state((0.0, 0.0))).candidates[0].cost
    assert cost == 2.0

    saved = m.snapshot()
    assert set(saved) == {"version", "clips", "pose_weight",
                          "trajectory_weight", "exclusion_window",
                          "index_version", "dirty", "current", "stats"}
    pristine = copy.deepcopy(saved)
    saved["stats"]["queries"] = 99
    saved["clips"].clear()
    assert m.stats()["queries"] == 1
    assert m.stats()["clips"] == 1

    clone = index()
    clone.restore(pristine)
    assert clone.index_version() == 1
    assert clone.current_choice() == ("run", 1)
    assert clone.query(state((0.0, 0.0))).candidates[0].cost == cost
    assert clone.stats()["frames"] == 2

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(mm.MotionError) as exc:
            m.restore(broken)
        assert exc.value.code == "MOTION_SNAPSHOT_INVALID"
    assert m.stats()["queries"] == 1
