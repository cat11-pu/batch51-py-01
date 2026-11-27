import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

import terrain_splat_composer as ts


def composer(**kwargs):
    return ts.TerrainSplatComposer(**kwargs)


def ready(**kwargs):
    c = composer(**kwargs)
    c.set_layers(("grass", "rock", "sand", "mud", "snow"))
    return c


def pairs(samples):
    return [(sample.layer, sample.index, sample.weight) for sample in samples]


def test_set_layers_validates_count_duplicates_and_empties():
    c = composer(max_layers=3)
    with pytest.raises(ts.SplatError) as exc:
        c.set_layers(("a", "b", "c", "d"))
    assert exc.value.code == "SPLAT_LAYER_LIMIT"
    with pytest.raises(ts.SplatError) as exc:
        c.set_layers(())
    assert exc.value.code == "SPLAT_INVALID_LAYERS"
    with pytest.raises(ts.SplatError) as exc:
        c.set_layers(("a", ""))
    assert exc.value.code == "SPLAT_INVALID_LAYERS"
    with pytest.raises(ts.SplatError) as exc:
        c.set_layers(("a", "a"))
    assert exc.value.code == "SPLAT_DUPLICATE_LAYER"

    assert c.set_layers(("a", "b")) == ("a", "b")
    assert c.stats()["layers"] == 2


def test_write_weight_validates_layer_and_weight():
    c = ready()
    with pytest.raises(ts.SplatError) as exc:
        c.write_weight(0, 0, "lava", 1.0)
    assert exc.value.code == "SPLAT_UNKNOWN_LAYER"
    with pytest.raises(ts.SplatError) as exc:
        c.write_weight(0, 0, "grass", -0.5)
    assert exc.value.code == "SPLAT_NEGATIVE_WEIGHT"
    for broken in (float("nan"), float("inf")):
        with pytest.raises(ts.SplatError) as exc:
            c.write_weight(0, 0, "grass", broken)
        assert exc.value.code == "SPLAT_INVALID_WEIGHT"
    with pytest.raises(ts.SplatError) as exc:
        c.write_weight(-1, 0, "grass", 1.0)
    assert exc.value.code == "SPLAT_OUT_OF_RANGE"

    assert c.write_weight(0, 0, "grass", 1.0) == 1.0
    assert c.stats()["pixels"] == 1
    assert c.write_weight(0, 0, "grass", 0.0) == 0.0
    assert c.stats()["pixels"] == 0


def test_stored_pixel_cap_is_enforced():
    c = ready(max_stored_pixels=2)
    c.write_weight(0, 0, "grass", 1.0)
    c.write_weight(1, 0, "grass", 1.0)
    with pytest.raises(ts.SplatError) as exc:
        c.write_weight(2, 0, "grass", 1.0)
    assert exc.value.code == "SPLAT_CAPACITY_EXCEEDED"

    c.write_weight(0, 0, "rock", 1.0)
    assert c.stats()["pixels"] == 2


def test_tile_bounds_and_sampling_require_a_composed_tile():
    c = ready()
    for rect in ((1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1024, 0), (-1, 0, 0, 0)):
        with pytest.raises(ts.SplatError) as exc:
            c.compose_tile(*rect)
        assert exc.value.code == "SPLAT_TILE_INVALID"

    with pytest.raises(ts.SplatError) as exc:
        c.sample_layers(1024, 0)
    assert exc.value.code == "SPLAT_OUT_OF_RANGE"
    with pytest.raises(ts.SplatError) as exc:
        c.sample_layers(0, 0)
    assert exc.value.code == "SPLAT_NOT_COMPOSED"


def test_weights_are_normalized_and_sorted():
    c = ready()
    c.write_weight(0, 0, "grass", 1.0)
    c.write_weight(0, 0, "rock", 3.0)
    result = c.compose_tile(0, 0, 0, 0)

    assert result.pixels == 1
    assert result.residency_version == 1
    samples = c.sample_layers(0, 0)
    assert [(s.layer, round(s.weight, 6)) for s in samples] == \
        [("rock", 0.75), ("grass", 0.25)]
    assert sum(s.weight for s in samples) == pytest.approx(1.0, abs=1e-12)


def test_layers_beyond_the_pixel_limit_are_clipped():
    c = composer(max_layers=8, max_layers_per_pixel=4)
    c.set_layers(("a", "b", "c", "d", "e"))
    for name, weight in zip("abcde", (5.0, 4.0, 3.0, 2.0, 1.0)):
        c.write_weight(0, 0, name, weight)
    result = c.compose_tile(0, 0, 0, 0)

    samples = c.sample_layers(0, 0)
    assert [s.layer for s in samples] == ["a", "b", "c", "d"]
    assert [round(s.weight, 6) for s in samples] == \
        [0.357143, 0.285714, 0.214286, 0.142857]
    assert sum(s.weight for s in samples) == pytest.approx(1.0, abs=1e-12)
    assert result.clipped == 1
    assert c.stats()["clipped_pixels"] == 1


def test_rounding_residual_keeps_the_sum_at_one():
    c = ready()
    for name in ("grass", "rock", "sand"):
        c.write_weight(0, 0, name, 1.0)
    c.compose_tile(0, 0, 0, 0)

    samples = c.sample_layers(0, 0)
    assert [round(s.weight, 6) for s in samples] == \
        [0.333334, 0.333333, 0.333333]
    assert samples[0].weight == pytest.approx(1.0 - samples[1].weight -
                                              samples[2].weight, abs=1e-12)
    assert abs(sum(s.weight for s in samples) - 1.0) < 1e-12


def test_writing_a_weight_invalidates_composed_tiles():
    c = ready()
    c.write_weight(1, 1, "grass", 2.0)
    c.compose_tile(0, 0, 2, 2)
    assert pairs(c.sample_layers(1, 1)) == [("grass", 0, 1.0)]
    with pytest.raises(ts.SplatError) as exc:
        c.sample_layers(3, 3)
    assert exc.value.code == "SPLAT_OUT_OF_RANGE"

    c.write_weight(1, 1, "rock", 1.0)
    for coords in ((1, 1), (2, 2)):
        with pytest.raises(ts.SplatError) as exc:
            c.sample_layers(*coords)
        assert exc.value.code == "SPLAT_NOT_COMPOSED"


def test_multiple_tiles_are_tracked_separately():
    c = ready()
    c.write_weight(0, 0, "grass", 1.0)
    c.write_weight(5, 5, "rock", 1.0)
    c.compose_tile(0, 0, 1, 1)
    c.compose_tile(4, 4, 6, 6)

    assert c.stats()["tiles"] == 2
    assert c.stats()["composed_pixels"] == 13
    assert pairs(c.sample_layers(0, 0)) == [("grass", 0, 1.0)]
    assert pairs(c.sample_layers(5, 5)) == [("rock", 1, 1.0)]
    with pytest.raises(ts.SplatError) as exc:
        c.sample_layers(2, 2)
    assert exc.value.code == "SPLAT_NOT_COMPOSED"


def test_residency_keeps_slots_and_reuses_freed_ones():
    c = composer(max_slots=4)
    c.set_layers(("a", "b", "c", "d"))
    assert c.residency_map() == {"a": 0, "b": 1, "c": 2, "d": 3}
    assert c.stats()["residency_version"] == 1

    assert c.set_residency(("b", "c", "d")) == {"b": 1, "c": 2, "d": 0}
    assert c.residency_map() == {"b": 1, "c": 2, "d": 0}
    assert c.stats()["residency_version"] == 2

    with pytest.raises(ts.SplatError) as exc:
        c.set_residency(("missing",))
    assert exc.value.code == "SPLAT_UNKNOWN_LAYER"
    with pytest.raises(ts.SplatError) as exc:
        c.set_residency(("a", "b", "c", "d", "grass"))
    assert exc.value.code == "SPLAT_SLOT_LIMIT"


def test_compose_records_the_residency_snapshot():
    c = ready()
    c.write_weight(0, 0, "rock", 1.0)
    first = c.compose_tile(0, 0, 0, 0)
    assert first.residency_version == 1
    assert first.slots == (("grass", 0), ("rock", 1), ("sand", 2),
                           ("mud", 3), ("snow", 4))

    c.set_residency(("rock", "grass"))
    second = c.compose_tile(0, 0, 0, 0)
    assert second.residency_version == 2
    assert second.slots == (("rock", 0), ("grass", 1))
    assert pairs(c.sample_layers(0, 0)) == [("rock", 1, 1.0)]


def test_concurrent_compose_sees_one_residency_snapshot():
    c = ready()
    for x in range(4):
        c.write_weight(x, 0, "grass", 1.0)
        c.write_weight(x, 0, "rock", 3.0)
    mapping_a = (("grass", 0), ("rock", 1))
    mapping_b = (("rock", 0), ("grass", 1))

    def flip():
        for i in range(20):
            c.set_residency(("rock", "grass") if i % 2 == 0
                            else ("grass", "rock"))

    def compose():
        return [c.compose_tile(0, 0, 3, 0) for _ in range(20)]

    with ThreadPoolExecutor(max_workers=5) as pool:
        flipping = pool.submit(flip)
        futures = [pool.submit(compose) for _ in range(4)]
        flipping.result()
        results = [item for future in futures for item in future.result()]

    assert len(results) == 80
    for result in results:
        assert result.pixels == 4
        assert result.slots in (mapping_a, mapping_b)
        assert result.residency_version >= 2


def test_parallel_tiles_match_a_serial_compose():
    def build():
        c = ready()
        for x in range(4):
            c.write_weight(x, 0, "grass", float(x + 1))
        return c

    serial = build()
    serial.compose_tile(0, 0, 3, 0)
    expected = tuple(pairs(serial.sample_layers(x, 0)) for x in range(4))

    parallel = build()
    rects = [(0, 0, 0, 0), (1, 0, 1, 0), (2, 0, 2, 0), (3, 0, 3, 0)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda rect: parallel.compose_tile(*rect), rects))
    assert tuple(pairs(parallel.sample_layers(x, 0)) for x in range(4)) == \
        expected


def test_snapshot_restore_roundtrip_and_malformed_state():
    c = ready()
    c.write_weight(0, 0, "grass", 1.0)
    c.write_weight(0, 0, "rock", 1.0)
    c.compose_tile(0, 0, 1, 1)

    state = c.snapshot()
    assert set(state) == {"version", "layers", "weights", "tiles",
                          "composed", "residency", "residency_version",
                          "config", "stats"}
    pristine = copy.deepcopy(state)
    state["stats"]["tiles"] = 99
    state["weights"].clear()
    assert c.stats()["tiles"] == 1
    assert c.sample_layers(0, 0)[0].weight == pytest.approx(0.5)

    clone = composer()
    clone.restore(pristine)
    assert clone.stats()["tiles"] == 1
    assert pairs(clone.sample_layers(0, 0)) == pairs(c.sample_layers(0, 0))
    assert clone.residency_map() == c.residency_map()

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(ts.SplatError) as exc:
            c.restore(broken)
        assert exc.value.code == "SPLAT_SNAPSHOT_INVALID"
    assert c.stats()["tiles"] == 1


def test_set_layers_resets_weights_tiles_and_residency():
    c = ready()
    c.write_weight(0, 0, "grass", 1.0)
    c.compose_tile(0, 0, 0, 0)
    c.set_residency(("rock", "grass"))

    assert c.set_layers(("dirt", "water")) == ("dirt", "water")
    assert c.stats()["pixels"] == 0
    assert c.residency_map() == {"dirt": 0, "water": 1}
    assert c.stats()["residency_version"] == 3
    with pytest.raises(ts.SplatError) as exc:
        c.sample_layers(0, 0)
    assert exc.value.code == "SPLAT_NOT_COMPOSED"
