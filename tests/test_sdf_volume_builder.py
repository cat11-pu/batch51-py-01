import threading

import pytest

import sdf_volume_builder as sv

NOW = "2026-11-27T10:00:00+00:00"
LATER = "2026-11-27T10:05:00+00:00"
BOUNDS = ((-4.0, -4.0, -4.0), (0.0, 0.0, 0.0))
ALL_BRICKS = 27


def plane(x, y, z):
    return x + 2.0


def builder(**kwargs):
    return sv.SdfVolumeBuilder(**kwargs)


def baked(**kwargs):
    volume = builder(**kwargs)
    volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane, content_hash="h1")
    volume.build("m1", now=NOW)
    return volume


def test_register_mesh_reports_version_and_pending_bricks():
    volume = builder()
    assert volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane,
                                content_hash="h1") == 1
    assert volume.version_of("m1") == 1
    assert volume.ready_bricks() == ()
    pending = volume.pending_bricks()
    assert len(pending) == ALL_BRICKS
    assert pending == tuple(sorted(pending))


def test_register_and_build_reject_bad_arguments():
    volume = builder()
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.register_mesh("", bounds=BOUNDS)
    assert exc.value.code == "SDF_INVALID_ARGUMENT"
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.register_mesh("m1", bounds=((0.0, 0.0, 0.0), (-4.0, -4.0, -4.0)))
    assert exc.value.code == "SDF_INVALID_ARGUMENT"
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.build("ghost", now=NOW)
    assert exc.value.code == "SDF_NO_SUCH_MESH"
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.version_of("ghost")
    assert exc.value.code == "SDF_NO_SUCH_MESH"


def test_register_with_new_content_hash_bumps_version_and_invalidates():
    volume = baked()
    assert len(volume.ready_bricks()) == ALL_BRICKS
    assert volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane,
                                content_hash="h2") == 2
    assert volume.version_of("m1") == 2
    assert volume.ready_bricks() == ()
    assert len(volume.pending_bricks()) == ALL_BRICKS


def test_build_bakes_every_brick_of_the_mesh():
    volume = builder()
    volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane, content_hash="h1")
    report = volume.build("m1", now=NOW)
    assert report.mesh_id == "m1"
    assert report.version == 1
    assert report.built_bricks == ALL_BRICKS
    assert report.pending_bricks == 0
    assert len(volume.ready_bricks()) == ALL_BRICKS
    assert volume.pending_bricks() == ()
    assert volume.rebuild_pending(now=LATER) == 0


def test_brick_of_handles_negative_and_face_aligned_points():
    volume = builder()
    assert volume.brick_of(0.0, -0.5, -2.0) == (0, -1, -1)
    assert volume.brick_of(-2.0, 0.0, 0.0) == (-1, 0, 0)
    assert volume.brick_of(-0.01, -0.01, -0.01) == (-1, -1, -1)
    assert volume.brick_of(-1.65, -3.1, -3.1) == (-1, -2, -2)
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.brick_of(float("nan"), 0.0, 0.0)
    assert exc.value.code == "SDF_INVALID_ARGUMENT"


def test_sample_interpolates_a_cross_brick_field():
    volume = baked()
    result = volume.sample(-1.65, -3.1, -3.1)
    assert result.ready is True
    assert result.truncated is False
    assert result.brick == (-1, -2, -2)
    assert result.distance == pytest.approx(0.35)


def test_sample_clamps_distance_outside_the_narrow_band():
    volume = baked(band_voxels=2.0)
    inside = volume.sample(-3.9, -3.1, -3.1)
    assert inside.distance == pytest.approx(-0.5)
    assert inside.truncated is True
    outside = volume.sample(-0.05, -3.1, -3.1)
    assert outside.distance == pytest.approx(0.5)
    assert outside.truncated is True


def test_brick_state_records_version_range_and_build_time():
    volume = baked()
    state = volume.brick_state((-2, -2, -2))
    assert state.brick == (-2, -2, -2)
    assert state.mesh_id == "m1"
    assert state.version == 1
    assert state.ready is True
    assert state.min_distance == pytest.approx(-0.5)
    assert state.max_distance == pytest.approx(0.0)
    assert state.built_at == NOW
    assert state.build_count == 1


def test_apply_edit_inside_one_brick_invalidates_only_that_brick():
    volume = baked()
    touched = volume.apply_edit("m1", bounds=((-1.2, -1.2, -1.2), (-1.1, -1.1, -1.1)))
    assert touched == ((-1, -1, -1),)
    assert volume.pending_bricks() == ((-1, -1, -1),)
    assert len(volume.ready_bricks()) == ALL_BRICKS - 1
    untouched = volume.brick_state((-2, -2, -2))
    assert untouched.ready is True
    assert untouched.built_at == NOW
    assert untouched.build_count == 1


def test_rebuild_pending_refreshes_only_invalidated_bricks():
    volume = baked()
    volume.apply_edit("m1", bounds=((-1.2, -1.2, -1.2), (-1.1, -1.1, -1.1)))
    assert volume.rebuild_pending(now=LATER) == 1
    rebuilt = volume.brick_state((-1, -1, -1))
    assert rebuilt.ready is True
    assert rebuilt.built_at == LATER
    assert rebuilt.build_count == 2
    stale = volume.brick_state((0, 0, 0))
    assert stale.built_at == NOW
    assert stale.build_count == 1


def test_invalidate_is_idempotent_and_rejects_unknown_bricks():
    volume = baked()
    assert volume.invalidate((0, 0, 0)) is True
    assert volume.invalidate((0, 0, 0)) is False
    assert volume.pending_bricks() == ((0, 0, 0),)
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.invalidate((9, 9, 9))
    assert exc.value.code == "SDF_UNKNOWN_BRICK"
    assert volume.stats()["invalidated"] == 1


def test_brick_capacity_rejects_oversized_mesh():
    volume = builder(max_bricks=8)
    with pytest.raises(sv.SdfVolumeError) as exc:
        volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane, content_hash="h1")
    assert exc.value.code == "SDF_CAPACITY_EXCEEDED"
    with pytest.raises(sv.SdfVolumeError) as missing:
        volume.version_of("m1")
    assert missing.value.code == "SDF_NO_SUCH_MESH"
    assert volume.stats()["rejected"] == 1


def test_concurrent_build_bakes_each_brick_once():
    volume = builder()
    volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane, content_hash="h1")
    reports = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            reports.append(volume.build("m1", now=NOW))
        except Exception as exc:  # pragma: no cover - surfaced through assertions
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sum(report.built_bricks for report in reports) == ALL_BRICKS
    assert len(volume.ready_bricks()) == ALL_BRICKS
    assert volume.pending_bricks() == ()


def test_snapshot_and_restore_keep_pending_state():
    volume = baked()
    volume.apply_edit("m1", bounds=((-1.2, -1.2, -1.2), (-1.1, -1.1, -1.1)))
    state = volume.snapshot()
    assert set(state) == {"version", "meshes", "bricks", "counters"}

    state["bricks"].clear()
    assert len(volume.ready_bricks()) == ALL_BRICKS - 1

    fresh = volume.snapshot()
    clone = builder()
    clone.restore(fresh)
    assert clone.version_of("m1") == 1
    assert clone.pending_bricks() == ((-1, -1, -1),)
    assert len(clone.ready_bricks()) == ALL_BRICKS - 1
    assert clone.rebuild_pending(now=LATER) == 1
    assert clone.sample(-1.65, -3.1, -3.1).distance == pytest.approx(0.35)

    for bad in (None, {}, {"version": 2, "meshes": {}, "bricks": {},
                           "counters": fresh["counters"]},
                {"version": 1, "meshes": [], "bricks": {},
                 "counters": fresh["counters"]},
                {"version": 1, "meshes": {}, "bricks": {}, "counters": {}}):
        with pytest.raises(sv.SdfVolumeError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SDF_SNAPSHOT_INVALID"
    assert clone.pending_bricks() == ()
    assert clone.sample(-1.65, -3.1, -3.1).ready is True


def test_stats_track_build_samples_and_invalidations():
    volume = builder()
    volume.register_mesh("m1", bounds=BOUNDS, sample_fn=plane, content_hash="h1")
    volume.build("m1", now=NOW)
    volume.sample(-1.65, -3.1, -3.1)
    volume.sample(-3.9, -3.1, -3.1)
    volume.apply_edit("m1", bounds=((-1.2, -1.2, -1.2), (-1.1, -1.1, -1.1)))
    volume.invalidate((0, 0, 0))
    assert volume.stats() == {"bricks": ALL_BRICKS, "ready": 25, "pending": 2,
                              "built": ALL_BRICKS, "reused": 0,
                              "invalidated": 2, "samples": 2, "rejected": 0}
