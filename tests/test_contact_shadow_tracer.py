import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

import contact_shadow_tracer as cs


def tracer(**kwargs):
    return cs.ContactShadowTracer(**kwargs)


def scene(size=4, depth=10.0, occluder_at=None):
    surface = [[depth] * size for _ in range(size)]
    occluders = [[[] for _ in range(size)] for _ in range(size)]
    if occluder_at is not None:
        (x, y), depths = occluder_at
        occluders[y][x] = list(depths)
    return surface, occluders


def load(tr, size=4, depth=10.0, occluder_at=None):
    surface, occluders = scene(size, depth, occluder_at)
    return tr.load_scene(surface=surface, occluders=occluders)


def test_configure_validates_steps_thickness_and_weight():
    tr = tracer()
    config = tr.configure(max_steps=4, thickness=2.0)
    assert config["max_steps"] == 4
    assert config["thickness"] == 2.0
    assert config["step_size"] == 1.0

    for broken in (dict(max_steps=0), dict(thickness=0.0),
                   dict(step_size=-1.0), dict(history_weight=1.5),
                   dict(far_plane=0.0)):
        with pytest.raises(cs.ShadowTraceError) as exc:
            tr.configure(**broken)
        assert exc.value.code == "SHADOW_INVALID_CONFIG"
    assert tr.configure()["max_steps"] == 4


def test_load_scene_validates_shape():
    tr = tracer(width=3, height=2)
    good = [[5.0] * 3 for _ in range(2)]
    assert tr.load_scene(surface=good,
                         occluders=[[[]] * 3 for _ in range(2)]) == 6

    with pytest.raises(cs.ShadowTraceError) as exc:
        tr.load_scene(surface=[[5.0] * 3], occluders=[[[]] * 3])
    assert exc.value.code == "SHADOW_INVALID_SCENE"
    with pytest.raises(cs.ShadowTraceError):
        tr.load_scene(surface=[[5.0] * 3, [5.0, 5.0]],
                      occluders=[[[]] * 3, [[]] * 3])
    with pytest.raises(cs.ShadowTraceError):
        tr.load_scene(surface=good, occluders=[[[]] * 2 for _ in range(2)])


def test_queries_need_a_traced_scene():
    tr = tracer(width=4, height=4)
    with pytest.raises(KeyError):
        tr.sample_occlusion(0, 0)
    with pytest.raises(cs.ShadowTraceError) as exc:
        tr.trace_tile(0, 0, 1, 1)
    assert exc.value.code == "SHADOW_NO_SCENE"

    load(tr)
    with pytest.raises(KeyError):
        tr.sample_occlusion(0, 0)
    with pytest.raises(cs.ShadowTraceError) as exc:
        tr.sample_occlusion(9, 0)
    assert exc.value.code == "SHADOW_OUT_OF_RANGE"


def test_single_occluder_produces_contact_shadow():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0, step_size=1.0)
    load(tr, occluder_at=((1, 1), [7.5]))
    result = tr.trace_tile(0, 0, 3, 3)

    assert (result.x0, result.y0, result.x1, result.y1) == (0, 0, 3, 3)
    assert result.pixels == 16
    assert 0 < result.steps <= 16 * 4
    assert tr.sample_occlusion(1, 1) == pytest.approx(0.75)
    assert tr.sample_occlusion(0, 0) == 0.0


def test_without_occluders_pixels_stay_lit():
    tr = tracer(width=3, height=3, max_steps=4, thickness=2.0)
    load(tr, size=3)
    tr.trace_tile(0, 0, 2, 2)
    values = [tr.sample_occlusion(x, y) for y in range(3) for x in range(3)]
    assert values == [0.0] * 9


def test_occluder_beyond_thickness_is_ignored():
    tr = tracer(width=2, height=2, max_steps=4, thickness=0.5, step_size=1.0)
    load(tr, size=2, occluder_at=((0, 0), [8.4]))
    tr.trace_tile(0, 0, 1, 1)
    assert tr.sample_occlusion(0, 0) == 0.0


def test_trace_tile_rejects_inverted_or_out_of_range_rects():
    tr = tracer(width=4, height=4)
    load(tr)
    for rect in ((2, 0, 1, 0), (0, 2, 0, 1), (0, 0, 4, 0),
                 (0, 0, 0, 4), (-1, 0, 0, 0)):
        with pytest.raises(cs.ShadowTraceError) as exc:
            tr.trace_tile(*rect)
        assert exc.value.code == "SHADOW_TILE_INVALID"
    assert tr.stats()["tiles"] == 0


def test_tile_result_and_samples_agree():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0, step_size=1.0)
    load(tr, occluder_at=((1, 1), [7.5]))
    surface, occluders = scene(4, 10.0)
    occluders[2][2] = [8.8]
    tr.load_scene(surface=surface, occluders=occluders)

    result = tr.trace_tile(1, 1, 2, 2)
    assert (result.x0, result.y0, result.x1, result.y1, result.pixels) == \
        (1, 1, 2, 2, 4)
    assert tr.sample_occlusion(1, 1) == pytest.approx(0.75)
    assert tr.sample_occlusion(2, 2) == pytest.approx(0.95)
    assert tr.sample_occlusion(1, 2) == 0.0


def test_occlusion_map_only_covers_traced_pixels():
    tr = tracer(width=4, height=4)
    load(tr)
    tr.trace_tile(1, 1, 2, 2)
    grid = tr.occlusion_map()
    assert len(grid) == 4
    assert [len(row) for row in grid] == [4, 4, 4, 4]
    assert grid[1][1] == 0.0
    assert grid[2][2] == 0.0
    assert grid[0][0] is None
    assert grid[3][3] is None
    assert tr.stats()["tiles"] == 1
    assert tr.stats()["pixels"] == 4


def test_accumulate_blends_with_history_weight():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0,
                history_weight=0.5)
    load(tr, occluder_at=((0, 0), [7.5]))
    tr.trace_tile(0, 0, 3, 3)
    assert tr.accumulate() == 16
    assert tr.sample_occlusion(0, 0) == pytest.approx(0.75)

    load(tr)
    tr.trace_tile(0, 0, 3, 3)
    assert tr.sample_occlusion(0, 0) == pytest.approx(0.75)
    assert tr.accumulate() == 16
    assert tr.sample_occlusion(0, 0) == pytest.approx(0.375)
    assert tr.stats()["accumulations"] == 2


def test_reset_history_returns_to_the_current_frame():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0)
    load(tr, occluder_at=((0, 0), [7.5]))
    tr.trace_tile(0, 0, 3, 3)
    tr.accumulate()
    assert tr.reset_history("lighting-change") == 16
    assert tr.sample_occlusion(0, 0) == pytest.approx(0.75)
    assert tr.stats()["resets"] == 1


def test_camera_change_clears_traced_frame_but_keeps_scene():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0)
    load(tr, occluder_at=((0, 0), [7.5]))
    tr.trace_tile(0, 0, 3, 3)
    tr.accumulate()

    tr.configure(camera_id="cam-1")
    with pytest.raises(KeyError):
        tr.sample_occlusion(0, 0)
    assert tr.stats()["resets"] == 1

    tr.trace_tile(0, 0, 1, 1)
    assert tr.sample_occlusion(0, 0) == pytest.approx(0.75)


def test_resolution_change_requires_a_new_scene():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0)
    load(tr)
    tr.trace_tile(0, 0, 3, 3)

    tr.configure(width=8)
    assert tr.configure()["width"] == 8
    with pytest.raises(cs.ShadowTraceError) as exc:
        tr.trace_tile(0, 0, 1, 1)
    assert exc.value.code == "SHADOW_NO_SCENE"
    assert tr.stats()["resets"] == 1


def test_parallel_tiles_match_single_threaded_results():
    surface = [[10.0] * 8 for _ in range(8)]
    occluders = [[[] for _ in range(8)] for _ in range(8)]
    for index in range(8):
        occluders[index][index] = [9.5 + index * 0.05]

    serial = tracer(width=8, height=8, max_steps=4, thickness=2.0)
    serial.load_scene(surface=surface, occluders=occluders)
    serial.trace_tile(0, 0, 7, 7)

    parallel = tracer(width=8, height=8, max_steps=4, thickness=2.0)
    parallel.load_scene(surface=surface, occluders=occluders)
    rects = [(0, 0, 3, 3), (4, 0, 7, 3), (0, 4, 3, 7), (4, 4, 7, 7)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda rect: parallel.trace_tile(*rect), rects))

    assert parallel.occlusion_map() == serial.occlusion_map()
    assert parallel.stats()["pixels"] == 64
    assert parallel.stats()["tiles"] == 4


def test_snapshot_restore_roundtrip_and_malformed_state():
    tr = tracer(width=4, height=4, max_steps=4, thickness=2.0)
    load(tr, occluder_at=((0, 0), [7.5]))
    tr.trace_tile(0, 0, 3, 3)
    tr.accumulate()

    state = tr.snapshot()
    assert set(state) == {"version", "config", "surface", "occluders",
                          "current", "history", "stats"}
    pristine = copy.deepcopy(state)
    state["current"].clear()
    state["stats"]["tiles"] = 99
    assert tr.stats()["tiles"] == 1
    assert tr.sample_occlusion(0, 0) == pytest.approx(0.75)

    clone = tracer()
    clone.restore(pristine)
    assert clone.stats()["tiles"] == 1
    assert clone.occlusion_map() == tr.occlusion_map()
    assert clone.sample_occlusion(0, 0) == pytest.approx(0.75)

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(cs.ShadowTraceError) as exc:
            tr.restore(broken)
        assert exc.value.code == "SHADOW_SNAPSHOT_INVALID"
    assert tr.stats()["tiles"] == 1
