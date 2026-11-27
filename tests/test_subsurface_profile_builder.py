import math
import threading

import pytest

import subsurface_profile_builder as sp

COLOR = (1.0, 0.8, 0.7)


def builder(**kwargs):
    return sp.SubsurfaceProfile(**kwargs)


def spec(name="skin", radius=0.8, resolution=32, **kwargs):
    return sp.ProfileSpec(name=name, radius=radius, color=COLOR,
                          ior=1.4, resolution=resolution, **kwargs)


def test_define_profile_stores_spec_and_version():
    profiles = builder()
    assert profiles.define_profile(spec()) == 1
    assert profiles.profile_versions() == {"skin": 1}
    assert profiles.stats()["profiles"] == 1
    assert profiles.stats()["defined"] == 1


def test_redefine_bumps_version_and_invalidates_lut_cache():
    profiles = builder()
    profiles.define_profile(spec(radius=0.8))
    first = profiles.build_lut("skin")
    assert first.version == 1
    assert first.cached is False
    assert profiles.define_profile(spec(radius=0.5)) == 2
    second = profiles.build_lut("skin")
    assert second.version == 2
    assert second.cached is False
    assert profiles.stats()["lut_builds"] == 2


def test_define_rejects_invalid_profile():
    profiles = builder()
    bad = [
        sp.ProfileSpec(name="", radius=0.8, color=COLOR),
        sp.ProfileSpec(name="wax", radius=0.0, color=COLOR),
        sp.ProfileSpec(name="wax", radius=0.8, color=COLOR, resolution=0),
        sp.ProfileSpec(name="wax", radius=0.8, color=(1.0, 0.5)),
    ]
    for candidate in bad:
        with pytest.raises(sp.SubsurfaceError) as exc:
            profiles.define_profile(candidate)
        assert exc.value.code == "SUBSURFACE_INVALID_PROFILE"
    assert profiles.profile_versions() == {}


def test_build_lut_clamps_resolution():
    profiles = builder(max_resolution=256)
    profiles.define_profile(spec(name="skin", resolution=32))
    profiles.define_profile(spec(name="wax", radius=0.2, resolution=4096))
    assert profiles.build_lut("skin").resolution == 32
    assert profiles.build_lut("wax").resolution == 256


def test_build_lut_caches_same_version():
    profiles = builder()
    profiles.define_profile(spec())
    first = profiles.build_lut("skin")
    second = profiles.build_lut("skin")
    assert first.cached is False
    assert second.cached is True
    assert second.version == first.version
    assert profiles.stats()["lut_builds"] == 1
    assert profiles.stats()["lut_cache_hits"] == 1


def test_sample_profile_normalizes_at_zero_and_decays():
    profiles = builder()
    profiles.define_profile(spec(radius=0.8))
    assert profiles.sample_profile("skin", 0.0) == pytest.approx(1.0)
    assert profiles.sample_profile("skin", 0.8) == pytest.approx(math.exp(-1.0))
    assert profiles.sample_profile("skin", 1.6) == pytest.approx(math.exp(-2.0))
    assert profiles.stats()["samples"] == 3


def test_sample_profile_rejects_negative_distance():
    profiles = builder()
    profiles.define_profile(spec())
    with pytest.raises(sp.SubsurfaceError) as exc:
        profiles.sample_profile("skin", -0.1)
    assert exc.value.code == "SUBSURFACE_INVALID_DISTANCE"


def test_thickness_from_uses_map_sample():
    profiles = builder()
    profiles.define_profile(spec())
    sample = profiles.thickness_from("skin", thickness_map={0.25: 0.12, 0.5: 0.4},
                                     uv=0.25)
    assert sample.profile == "skin"
    assert sample.value == pytest.approx(0.12)
    assert sample.degraded is False


def test_thickness_from_without_map_degrades():
    profiles = builder(default_thickness=0.75)
    profiles.define_profile(spec())
    sample = profiles.thickness_from("skin")
    assert sample.value == pytest.approx(0.75)
    assert sample.degraded is True


def test_transmission_backlit_falls_off_with_thickness():
    profiles = builder()
    profiles.define_profile(spec(radius=0.8))
    thin = profiles.transmission("skin", light_dot_normal=-1.0, thickness=0.0)
    mid = profiles.transmission("skin", light_dot_normal=-0.7, thickness=0.8)
    thick = profiles.transmission("skin", light_dot_normal=-0.3, thickness=1.6)
    assert thin.transmittance == pytest.approx(1.0)
    assert mid.transmittance == pytest.approx(math.exp(-1.0))
    assert thick.transmittance == pytest.approx(math.exp(-2.0))
    assert thin.backlit is True
    assert thin.fallback is False
    assert thin.transmittance > mid.transmittance > thick.transmittance


def test_transmission_rejects_negative_thickness():
    profiles = builder()
    profiles.define_profile(spec())
    with pytest.raises(sp.SubsurfaceError) as exc:
        profiles.transmission("skin", light_dot_normal=-1.0, thickness=-0.2)
    assert exc.value.code == "SUBSURFACE_INVALID_THICKNESS"


def test_snapshot_restore_round_trip():
    profiles = builder()
    profiles.define_profile(spec(radius=0.8))
    profiles.build_lut("skin")
    profiles.build_lut("skin")
    expected = profiles.sample_profile("skin", 0.4)
    snap = profiles.snapshot()
    profiles.define_profile(spec(name="wax", radius=0.2))
    other = builder()
    other.restore(snap)
    assert other.profile_versions() == {"skin": 1}
    assert other.sample_profile("skin", 0.4) == pytest.approx(expected)
    assert other.build_lut("skin").cached is True


def test_restore_rejects_unknown_snapshot():
    profiles = builder()
    profiles.define_profile(spec())
    with pytest.raises(sp.SubsurfaceError) as exc:
        profiles.restore({"version": 999, "profiles": {}})
    assert exc.value.code == "SUBSURFACE_SNAPSHOT_INVALID"
    assert profiles.profile_versions() == {"skin": 1}


def test_concurrent_build_and_sample_stay_consistent():
    profiles = builder()
    profiles.define_profile(spec(radius=1.0, resolution=64))
    failures = []

    def reader():
        try:
            for _ in range(30):
                handle = profiles.build_lut("skin")
                assert handle.name == "skin"
                assert 1 <= handle.resolution <= 256
                value = profiles.sample_profile("skin", 0.5)
                assert 0.0 < value <= 1.0
        except BaseException as exc:  # noqa: BLE001 - collected for assertion
            failures.append(exc)

    def writer():
        try:
            for _ in range(10):
                profiles.define_profile(spec(radius=1.0, resolution=32))
        except BaseException as exc:  # noqa: BLE001 - collected for assertion
            failures.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(3)]
    threads.append(threading.Thread(target=writer))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert profiles.profile_versions() == {"skin": 11}


def test_stats_reports_all_counters():
    profiles = builder()
    profiles.define_profile(spec())
    profiles.build_lut("skin")
    profiles.build_lut("skin")
    profiles.sample_profile("skin", 0.25)
    profiles.thickness_from("skin")
    assert profiles.stats() == {"profiles": 1, "defined": 1, "removed": 0,
                                "lut_builds": 1, "lut_cache_hits": 1,
                                "samples": 1, "fallbacks": 0}
