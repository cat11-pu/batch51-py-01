import pytest

import volumetric_cloudscape as cl

ORIGIN = (0.0, 0.0, 50.0)
UP = (0.0, 0.0, 1.0)


def scene(**kwargs):
    return cl.Cloudscape(**kwargs)


def weather(version=1, coverage=0.6, base=100.0, top=300.0):
    return cl.WeatherMap(version=version, coverage=coverage,
                         base_height=base, top_height=top)


def march(clouds, frame, *, budget=None):
    return clouds.integrate(frame, ray_origin=ORIGIN, ray_dir=UP,
                            step_budget=budget)


def test_set_weather_reports_version_and_state():
    clouds = scene()
    assert clouds.set_weather(weather(version=3)) == 3
    current = clouds.current_weather()
    assert current.version == 3
    assert current.coverage == pytest.approx(0.6)
    assert current.base_height == pytest.approx(100.0)
    assert clouds.stats()["weather_sets"] == 1


def test_set_weather_rejects_stale_version():
    clouds = scene()
    clouds.set_weather(weather(version=4))
    with pytest.raises(cl.CloudError) as exc:
        clouds.set_weather(weather(version=4))
    assert exc.value.code == "CLOUD_WEATHER_STALE"
    with pytest.raises(cl.CloudError) as exc2:
        clouds.set_weather(weather(version=2))
    assert exc2.value.code == "CLOUD_WEATHER_STALE"
    assert clouds.current_weather().version == 4


def test_sample_density_profile():
    clouds = scene()
    clouds.set_weather(weather(coverage=0.6, base=100.0, top=300.0))
    assert clouds.sample_density(0.0, 0.0, 50.0) == pytest.approx(0.0)
    assert clouds.sample_density(0.0, 0.0, 200.0) == pytest.approx(0.6)
    assert clouds.sample_density(0.0, 0.0, 400.0) == pytest.approx(0.0)


def test_integrate_respects_step_budget():
    clouds = scene(max_steps=64)
    clouds.set_weather(weather())
    frame = march(clouds, 1, budget=16)
    assert frame.steps == 16
    assert frame.frame == 1


def test_integrate_clamps_to_max_steps():
    clouds = scene(max_steps=64)
    clouds.set_weather(weather())
    assert march(clouds, 1).steps == 64
    assert march(clouds, 2, budget=500).steps == 64


def test_integrate_holds_min_steps():
    clouds = scene(min_steps=8)
    clouds.set_weather(weather())
    assert march(clouds, 1, budget=2).steps == 8


def test_integrate_clear_sky_has_no_density():
    clouds = scene()
    clouds.set_weather(weather(coverage=0.0))
    frame = march(clouds, 1)
    assert frame.density == pytest.approx(0.0)
    assert frame.transmittance == pytest.approx(1.0)


def test_integrate_cloud_band_attenuates():
    clouds = scene()
    clouds.set_weather(weather(coverage=1.0))
    frame = march(clouds, 1)
    assert frame.density > 0.0
    assert 0.0 < frame.transmittance < 1.0


def test_resolve_without_history_returns_raw_frame():
    clouds = scene()
    clouds.set_weather(weather())
    raw = march(clouds, 1)
    resolved = clouds.resolve()
    assert resolved.history_valid is False
    assert resolved.history_weight == pytest.approx(0.0)
    assert resolved.density == pytest.approx(raw.density)
    assert resolved.transmittance == pytest.approx(raw.transmittance)


def test_resolve_blends_identical_frames():
    clouds = scene()
    clouds.set_weather(weather())
    march(clouds, 1)
    first = clouds.resolve()
    march(clouds, 2)
    second = clouds.resolve()
    assert second.history_valid is True
    assert 0.0 < second.history_weight <= 1.0
    assert second.density == pytest.approx(first.density)
    assert second.transmittance == pytest.approx(first.transmittance)


def test_new_weather_version_invalidates_history():
    clouds = scene()
    clouds.set_weather(weather(version=1))
    march(clouds, 1)
    clouds.resolve()
    clouds.set_weather(weather(version=2))
    march(clouds, 2)
    resolved = clouds.resolve()
    assert resolved.history_valid is False
    assert resolved.weather_version == 2


def test_invalidate_history_drops_frames():
    clouds = scene()
    clouds.set_weather(weather())
    march(clouds, 1)
    clouds.resolve()
    march(clouds, 2)
    clouds.resolve()
    assert clouds.invalidate_history("weather reset") == 2
    assert clouds.frame_state(1) is None
    assert clouds.frame_state(2) is None
    assert clouds.stats()["invalidations"] == 1
    assert clouds.stats()["frames_dropped"] == 2
    march(clouds, 3)
    assert clouds.resolve().history_valid is False


def test_camera_error_scales_history_weight():
    clouds = scene(reprojection_threshold=0.35)
    assert clouds.set_camera(reprojection_error=0.0) == pytest.approx(1.0)
    assert clouds.set_camera(reprojection_error=0.175) == pytest.approx(0.5)
    assert clouds.stats()["camera_updates"] == 2


def test_snapshot_restore_round_trip():
    clouds = scene()
    clouds.set_weather(weather(version=2))
    march(clouds, 1)
    clouds.resolve()
    snap = clouds.snapshot()
    march(clouds, 2)
    other = scene()
    other.restore(snap)
    assert other.current_weather().version == 2
    assert other.frame_state(1) is not None
    assert other.frame_state(2) is None
    with pytest.raises(cl.CloudError) as exc:
        other.restore({"version": 999, "frames": []})
    assert exc.value.code == "CLOUD_SNAPSHOT_INVALID"
    assert other.frame_state(1) is not None


def test_stats_reports_all_counters():
    clouds = scene()
    clouds.set_weather(weather())
    march(clouds, 1)
    clouds.resolve()
    assert clouds.stats() == {"weather_sets": 1, "integrates": 1,
                              "resolves": 1, "invalidations": 0,
                              "frames_dropped": 0, "camera_updates": 0}
