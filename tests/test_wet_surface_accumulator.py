import threading

import pytest

import wet_surface_accumulator as wa


def accumulator(**kwargs):
    return wa.WetSurfaceAccumulator(**kwargs)


def rainy(acc, intensity=1.0):
    acc.set_precipitation("rain", intensity=intensity)
    return acc


def test_register_surface_validates_and_starts_dry():
    acc = accumulator()
    state = acc.register_surface("roof-01", exposure=1.0)
    assert state.surface_id == "roof-01"
    assert state.wetness == 0.0
    assert state.sheltered is False
    assert state.exposure == 1.0
    assert state.frame == 0
    assert acc.surface_of("roof-01") == state

    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.register_surface("roof-01")
    assert exc.value.code == "WET_SURFACE_EXISTS"
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.register_surface("")
    assert exc.value.code == "WET_INVALID_ARGUMENT"
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.register_surface("wall-02", exposure=0.0)
    assert exc.value.code == "WET_INVALID_ARGUMENT"
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.register_surface("wall-03", exposure=1.5)
    assert exc.value.code == "WET_INVALID_ARGUMENT"


def test_surface_capacity_is_hard_limited():
    acc = accumulator(max_surfaces=2)
    acc.register_surface("a")
    acc.register_surface("b")
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.register_surface("c")
    assert exc.value.code == "WET_CAPACITY_EXCEEDED"
    assert acc.stats()["surfaces"] == 2
    assert acc.stats()["rejected"] == 1
    with pytest.raises(wa.WetSurfaceError):
        acc.surface_of("c")


def test_set_precipitation_validates_kind_and_intensity():
    acc = accumulator()
    assert acc.set_precipitation("rain", intensity=0.5) == {"kind": "rain",
                                                            "intensity": 0.5}
    assert acc.set_precipitation("snow", intensity=0.25) == {"kind": "snow",
                                                             "intensity": 0.25}
    for kind in ("hail", "", None):
        with pytest.raises(wa.WetSurfaceError) as exc:
            acc.set_precipitation(kind)
        assert exc.value.code == "WET_INVALID_ARGUMENT"
    for intensity in (-0.1, 1.5):
        with pytest.raises(wa.WetSurfaceError) as exc:
            acc.set_precipitation("rain", intensity=intensity)
        assert exc.value.code == "WET_INVALID_ARGUMENT"


def test_rain_accumulates_gain_minus_evaporation():
    acc = rainy(accumulator())
    acc.register_surface("road")
    assert acc.accumulate("road", 2.0) == pytest.approx(0.8)
    assert acc.wetness_of("road") == 0.0
    assert acc.publish() == 1
    assert acc.wetness_of("road") == pytest.approx(0.8)


def test_exposure_scales_the_gain():
    acc = rainy(accumulator())
    acc.register_surface("ledge", exposure=0.5)
    assert acc.accumulate("ledge", 2.0) == pytest.approx(0.3)
    acc.publish()
    assert acc.wetness_of("ledge") == pytest.approx(0.3)


def test_sheltered_surface_gains_no_precipitation():
    acc = rainy(accumulator())
    acc.register_surface("under-eave", sheltered=True)
    assert acc.accumulate("under-eave", 5.0) == pytest.approx(0.0)
    acc.publish()
    assert acc.wetness_of("under-eave") == pytest.approx(0.0)


def test_evaporate_reduces_wetness_and_floors_at_zero():
    acc = rainy(accumulator())
    acc.register_surface("deck")
    assert acc.accumulate("deck", 2.0) == pytest.approx(0.8)
    assert acc.evaporate("deck", 2.0) == pytest.approx(0.6)
    assert acc.evaporate("deck", 100.0) == pytest.approx(0.0)
    assert acc.evaporate("deck", 1.0) == pytest.approx(0.0)


def test_wetness_caps_at_one():
    acc = rainy(accumulator())
    acc.register_surface("pier")
    assert acc.accumulate("pier", 10.0) == pytest.approx(1.0)
    assert acc.accumulate("pier", 1.0) == pytest.approx(1.0)
    acc.publish()
    assert acc.puddle_mask("pier").depth == pytest.approx(1.0)


def test_publish_isolates_working_state_from_readers():
    acc = rainy(accumulator())
    acc.register_surface("walkway")
    acc.accumulate("walkway", 1.0)
    assert acc.wetness_of("walkway") == 0.0
    assert acc.surface_of("walkway").wetness == 0.0
    assert acc.publish() == 1
    assert acc.wetness_of("walkway") == pytest.approx(0.4)
    assert acc.surface_of("walkway").frame == 1
    assert acc.publish(frame=7) == 7
    assert acc.surface_of("walkway").frame == 7


def test_material_roughness_and_albedo_move_together():
    acc = rainy(accumulator())
    acc.register_surface("slab")
    acc.accumulate("slab", 1.0)
    acc.publish()
    damp = acc.material_of("slab")
    assert damp.blended is False
    assert damp.roughness == pytest.approx(0.61)
    assert damp.albedo_scale == pytest.approx(0.888)

    acc.accumulate("slab", 1.0)
    acc.publish()
    soaked = acc.material_of("slab")
    assert soaked.blended is True
    assert soaked.roughness == pytest.approx(0.37)
    assert soaked.albedo_scale == pytest.approx(0.776)
    assert soaked.roughness < damp.roughness
    assert soaked.albedo_scale < damp.albedo_scale


def test_puddle_mask_follows_the_threshold():
    acc = rainy(accumulator())
    acc.register_surface("yard")
    acc.accumulate("yard", 1.0)
    acc.publish()
    dry = acc.puddle_mask("yard")
    assert dry.blended is False
    assert dry.depth == pytest.approx(0.0)
    assert dry.threshold == pytest.approx(0.6)

    acc.accumulate("yard", 1.0)
    acc.publish()
    wet = acc.puddle_mask("yard")
    assert wet.blended is True
    assert wet.depth == pytest.approx(0.5)


def test_invalid_arguments_and_unknown_surfaces_are_rejected():
    acc = rainy(accumulator())
    acc.register_surface("step")
    for seconds in (-1.0, "2", None):
        with pytest.raises(wa.WetSurfaceError) as exc:
            acc.accumulate("step", seconds)
        assert exc.value.code == "WET_INVALID_ARGUMENT"
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.evaporate("step", -0.5)
    assert exc.value.code == "WET_INVALID_ARGUMENT"
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.accumulate("ghost", 1.0)
    assert exc.value.code == "WET_NO_SUCH_SURFACE"
    with pytest.raises(wa.WetSurfaceError) as exc:
        acc.puddle_mask("ghost")
    assert exc.value.code == "WET_NO_SUCH_SURFACE"


def test_snapshot_restore_roundtrip_and_malformed():
    acc = rainy(accumulator())
    acc.register_surface("court", exposure=0.5)
    acc.register_surface("shed", sheltered=True)
    acc.accumulate("court", 2.0)
    acc.publish()
    acc.accumulate("court", 2.0)
    state = acc.snapshot()
    assert set(state) == {"version", "surfaces", "published", "frame",
                          "config", "counters"}

    state["surfaces"].clear()
    state["published"].clear()
    assert acc.wetness_of("court") == pytest.approx(0.3)

    pristine = acc.snapshot()
    clone = accumulator()
    clone.restore(pristine)
    assert clone.wetness_of("court") == pytest.approx(0.3)
    assert clone.surface_of("court").exposure == pytest.approx(0.5)
    assert clone.publish() == 2
    assert clone.wetness_of("court") == pytest.approx(0.6)

    for bad in (None, {},
                {"version": 2, "surfaces": {}, "published": {}, "frame": 0,
                 "config": {}, "counters": {}},
                {"version": 1, "surfaces": {}, "published": {}, "frame": 0,
                 "config": {}}):
        with pytest.raises(wa.WetSurfaceError) as exc:
            clone.restore(bad)
        assert exc.value.code == "WET_SNAPSHOT_INVALID"
    assert clone.surface_of("court").exposure == pytest.approx(0.5)


def test_stats_track_updates_and_publishes():
    acc = rainy(accumulator(max_surfaces=8))
    acc.register_surface("a")
    acc.register_surface("b")
    acc.accumulate("a", 0.5)
    acc.accumulate("a", 0.5)
    acc.accumulate("b", 0.5)
    acc.evaporate("b", 0.5)
    acc.publish()
    acc.publish()
    with pytest.raises(wa.WetSurfaceError):
        acc.accumulate("ghost", 1.0)
    assert acc.stats() == {"surfaces": 2, "accumulates": 3, "evaporates": 1,
                           "publishes": 2, "puddle_events": 0, "rejected": 1}


def test_concurrent_updates_reach_readers_after_one_publish():
    acc = rainy(accumulator(max_surfaces=16))
    names = [f"patch-{index:02d}" for index in range(8)]
    for name in names:
        acc.register_surface(name)

    errors = []
    barrier = threading.Barrier(len(names))

    def worker(name):
        try:
            barrier.wait(timeout=5)
            acc.accumulate(name, 1.0)
        except Exception as exc:  # pragma: no cover - surfaced through assertions
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    acc.publish()
    assert [acc.wetness_of(name) for name in names] == [pytest.approx(0.4)] * 8
    assert acc.stats()["accumulates"] == 8
