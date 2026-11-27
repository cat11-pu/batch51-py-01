import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

import procedural_scatter_planner as ps


def planner(**kwargs):
    kwargs.setdefault("chunk_size", 8)
    return ps.ProceduralScatterPlanner(**kwargs)


def flat(x, y):
    return 0.0


def seeded(**kwargs):
    p = planner(**kwargs)
    p.set_seed(7)
    p.set_terrain(flat)
    return p


def test_set_seed_validates_and_clears_cache():
    p = planner()
    for bad in (-1, "7", None):
        with pytest.raises(ps.ScatterError) as exc:
            p.set_seed(bad)
        assert exc.value.code == "SCATTER_INVALID_SEED"

    assert p.set_seed(11) == 11
    p.set_terrain(flat)
    p.add_layer("grass", density=0.0625)
    p.place_chunk(0, 0)
    assert p.stats()["cached"] == 1

    assert p.set_seed(12) == 12
    assert p.cached_chunks() == ()
    assert p.stats()["seed"] == 12
    assert p.stats()["cached"] == 0


def test_add_layer_validates_density_and_exclusion():
    p = planner()
    for bad in (0.0, -0.25, 1.5):
        with pytest.raises(ps.ScatterError) as exc:
            p.add_layer("grass", density=bad)
        assert exc.value.code == "SCATTER_INVALID_DENSITY"
    with pytest.raises(ps.ScatterError) as exc:
        p.add_layer("", density=0.25)
    assert exc.value.code == "SCATTER_INVALID_LAYER"
    with pytest.raises(ps.ScatterError) as exc:
        p.add_layer("bush", density=0.25, exclusion=(4.0, 0.0, 0.0, 4.0))
    assert exc.value.code == "SCATTER_INVALID_LAYER"

    p.add_layer("grass", density=0.25)
    with pytest.raises(ps.ScatterError) as exc:
        p.add_layer("grass", density=0.0625)
    assert exc.value.code == "SCATTER_DUPLICATE_LAYER"
    with pytest.raises(ps.ScatterError) as exc:
        p.add_layer("wide-gap", density=0.04)
    assert exc.value.code == "SCATTER_INVALID_DENSITY"

    spec = p.add_layer("rock", density=0.0625, seed_offset=3, max_slope=20.0)
    assert spec["density"] == 0.0625
    assert spec["seed_offset"] == 3
    assert p.stats()["layers"] == 2
    with pytest.raises(ps.ScatterError) as exc:
        p.remove_layer("missing")
    assert exc.value.code == "SCATTER_UNKNOWN_LAYER"


def test_place_chunk_requires_terrain_and_layers():
    p = planner()
    p.add_layer("grass", density=0.25)
    with pytest.raises(ps.ScatterError) as exc:
        p.place_chunk(0, 0)
    assert exc.value.code == "SCATTER_NO_TERRAIN"

    bare = planner()
    bare.set_terrain(flat)
    with pytest.raises(ps.ScatterError) as exc:
        bare.place_chunk(0, 0)
    assert exc.value.code == "SCATTER_NO_LAYERS"

    with pytest.raises(ps.ScatterError) as exc:
        bare.set_terrain(None)
    assert exc.value.code == "SCATTER_INVALID_TERRAIN"


def test_chunk_coordinates_are_validated():
    p = planner()
    p.set_terrain(flat)
    p.add_layer("grass", density=0.0625)
    for bad in ((1.5, 0), ("a", 0), (0, None), (1_000_001, 0),
                (0, -1_000_001)):
        with pytest.raises(ps.ScatterError) as exc:
            p.place_chunk(*bad)
        assert exc.value.code == "SCATTER_INVALID_CHUNK"

    assert p.chunk_of(0.0, 0.0) == (0, 0)
    assert p.chunk_of(-0.5, 7.9) == (-1, 0)
    assert p.chunk_of(8.0, 16.5) == (1, 2)

    assert p.set_cache_limit(3) == 3
    with pytest.raises(ps.ScatterError) as exc:
        p.set_cache_limit(0)
    assert exc.value.code == "SCATTER_INVALID_CACHE_LIMIT"


def test_candidate_count_follows_density_stride():
    full = seeded()
    full.add_layer("grass", density=1.0)
    result = full.place_chunk(0, 0)
    assert len(result.points) == 64
    assert all(point.z == 0.0 for point in result.points)
    assert full.points_in_chunk(0, 0) == result.points

    quarter = seeded()
    quarter.add_layer("grass", density=0.25)
    assert len(quarter.place_chunk(0, 0).points) == 16

    sparse = seeded()
    sparse.add_layer("moss", density=0.0625)
    assert len(sparse.place_chunk(0, 0).points) == 4


def test_height_band_filters_points():
    p = seeded()
    p.set_terrain(lambda x, y: x)
    p.add_layer("grass", density=1.0, min_height=0.0, max_height=4.0)
    result = p.place_chunk(0, 0)
    assert len(result.points) == 32
    assert result.filtered == 32
    assert all(point.z < 4.0 for point in result.points)

    high = seeded()
    high.set_terrain(lambda x, y: x)
    high.add_layer("grass", density=1.0, min_height=6.0)
    upper = high.place_chunk(0, 0)
    assert len(upper.points) == 16
    assert all(point.z >= 6.0 for point in upper.points)


def test_slope_filter_rejects_steep_points():
    p = seeded()
    p.set_terrain(lambda x, y: 0.0, lambda x, y: x)
    p.add_layer("grass", density=1.0, max_slope=2.5)
    result = p.place_chunk(0, 0)
    assert len(result.points) == 24
    assert result.filtered == 40
    assert all(point.cell_x < 3 for point in result.points)


def test_water_level_excludes_low_points():
    p = seeded()
    p.set_terrain(lambda x, y: x)
    p.add_layer("reed", density=1.0, water_level=4.0)
    result = p.place_chunk(0, 0)
    assert len(result.points) == 32
    assert all(point.z >= 4.0 for point in result.points)
    assert p.stats()["filtered"] == 32


def test_exclusion_rect_removes_points():
    p = seeded()
    p.add_layer("grass", density=1.0, exclusion=(0.0, 0.0, 4.0, 8.0))
    result = p.place_chunk(0, 0)
    assert len(result.points) == 32
    assert all(point.x >= 4.0 for point in result.points)
    assert result.filtered == 32


def test_seed_determinism_across_instances():
    first = seeded()
    first.add_layer("grass", density=0.25)
    one = first.place_chunk(2, -1)

    second = seeded()
    second.add_layer("grass", density=0.25)
    two = second.place_chunk(2, -1)
    assert one == two
    assert len(one.points) == 16

    other = seeded()
    other.set_seed(999)
    other.set_terrain(flat)
    other.add_layer("grass", density=0.25)
    assert other.place_chunk(2, -1).points != one.points


def test_chunk_order_does_not_change_points():
    first = seeded()
    first.add_layer("grass", density=0.25)
    chunk_zero = first.place_chunk(0, 0).points
    first.place_chunk(1, 0)
    assert first.points_in_chunk(0, 0) == chunk_zero

    second = seeded()
    second.add_layer("grass", density=0.25)
    second.place_chunk(1, 0)
    second.place_chunk(0, 0)
    assert second.points_in_chunk(0, 0) == chunk_zero
    assert second.points_in_chunk(1, 0) == first.points_in_chunk(1, 0)


def test_cache_limit_evicts_least_recent_chunk():
    p = planner(cache_limit=2)
    p.set_seed(7)
    p.set_terrain(flat)
    p.add_layer("grass", density=0.0625)

    p.place_chunk(0, 0)
    expected = p.place_chunk(1, 0).points
    p.points_in_chunk(0, 0)
    p.place_chunk(2, 0)
    assert p.cached_chunks() == ((1, 0), (2, 0))
    assert p.stats()["evicted"] == 1

    with pytest.raises(ps.ScatterError) as exc:
        p.points_in_chunk(0, 0)
    assert exc.value.code == "SCATTER_NOT_CACHED"
    with pytest.raises(ps.ScatterError) as exc:
        p.evict_chunk(0, 0)
    assert exc.value.code == "SCATTER_NOT_CACHED"

    assert p.evict_chunk(1, 0) is True
    assert p.cached_chunks() == ((2, 0),)
    assert p.place_chunk(1, 0).points == expected


def test_chunk_point_cap_clips_deterministically():
    p = seeded(chunk_point_cap=10)
    p.add_layer("grass", density=1.0)
    result = p.place_chunk(0, 0)
    assert len(result.points) == 10
    assert result.clipped == 54
    assert p.stats()["clipped"] == 54
    assert p.points_in_chunk(0, 0) == result.points


def test_parallel_placement_matches_serial():
    coords = [(cx, cy) for cx in range(4) for cy in range(2)]

    serial = seeded()
    serial.add_layer("grass", density=0.25)
    expected = {coord: serial.place_chunk(*coord).points for coord in coords}

    parallel = seeded()
    parallel.add_layer("grass", density=0.25)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda coord: parallel.place_chunk(*coord),
                                coords))
    assert {coord: result.points for coord, result in zip(coords, results)} \
        == expected
    assert parallel.stats()["placed"] == 8
    assert len(parallel.cached_chunks()) == 8


def test_snapshot_restore_roundtrip_and_malformed_state():
    p = seeded()
    p.set_terrain(lambda x, y: x)
    p.add_layer("grass", density=0.25, min_height=0.0)
    p.place_chunk(0, 0)
    points = p.points_in_chunk(0, 0)

    state = p.snapshot()
    assert set(state) == {"version", "seed", "chunk_size", "cache_limit",
                          "chunk_point_cap", "layers", "terrain", "chunks",
                          "stats"}
    pristine = copy.deepcopy(state)
    state["stats"]["placed"] = 99
    state["chunks"].clear()
    assert p.stats()["placed"] == 1
    assert p.points_in_chunk(0, 0) == points

    clone = planner()
    clone.restore(pristine)
    assert clone.stats()["seed"] == 7
    assert clone.stats()["layers"] == 1
    assert clone.points_in_chunk(0, 0) == points
    assert clone.place_chunk(0, 0).points == points

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(ps.ScatterError) as exc:
            p.restore(broken)
        assert exc.value.code == "SCATTER_SNAPSHOT_INVALID"
    assert p.stats()["placed"] == 1
