import pytest

import file_handle_resolver as fh


def build(*, cache_size=16, extra_objects=0, prefix="/"):
    r = fh.FileHandleResolver(cache_size=cache_size)
    r.add_mount("m1", "ns1", root="/srv")
    r.enter_namespace("svc", "ns1")
    r.grant("svc", "m1", path_prefix=prefix)
    r.add_object("fh-1", mount_id="m1", path="/srv/app/one.txt", inode=101)
    for index in range(extra_objects):
        r.add_object("fh-%d" % (index + 2), mount_id="m1",
                     path="/srv/app/extra%d.txt" % index, inode=200 + index)
    return r


def test_resolve_returns_current_path_and_identity():
    r = build()
    out = r.resolve("svc", "fh-1")
    assert out.handle_id == "fh-1"
    assert out.mount_id == "m1"
    assert out.namespace == "ns1"
    assert out.path == "/srv/app/one.txt"
    assert out.inode == 101
    assert out.generation == 1
    assert out.kind == "file"
    assert r.stats()["resolves"] == 1


def test_mount_outside_caller_namespace_is_hidden():
    r = build()
    r.enter_namespace("svc", "ns2")
    with pytest.raises(fh.FhError) as excinfo:
        r.resolve("svc", "fh-1")
    assert excinfo.value.code == "FILEHANDLE_MOUNT_HIDDEN"
    assert r.stats()["hidden"] == 1


def test_missing_capability_is_denied():
    r = fh.FileHandleResolver()
    r.add_mount("m1", "ns1", root="/srv")
    r.enter_namespace("svc", "ns1")
    r.add_object("fh-1", mount_id="m1", path="/srv/app/one.txt", inode=101)
    assert r.authorize("svc", "fh-1") is False
    with pytest.raises(fh.FhError) as excinfo:
        r.resolve("svc", "fh-1")
    assert excinfo.value.code == "FILEHANDLE_ACCESS_DENIED"
    assert r.stats()["denied"] == 1


def test_authorize_accepts_matching_capability():
    r = build(prefix="/srv/app")
    assert r.authorize("svc", "fh-1") is True
    assert r.stats()["authorized"] == 1


def test_unlinked_object_is_stale():
    r = build()
    r.unlink("fh-1")
    assert r.describe("fh-1")["deleted"] is True
    with pytest.raises(fh.FhError) as excinfo:
        r.resolve("svc", "fh-1")
    assert excinfo.value.code == "FILEHANDLE_STALE"
    assert r.stats()["stale"] == 1


def test_rename_changes_reported_path():
    r = build()
    r.resolve("svc", "fh-1")
    r.rename("fh-1", "/srv/app/sub/two.txt")
    out = r.resolve("svc", "fh-1")
    assert out.path == "/srv/app/sub/two.txt"
    assert out.generation == 1
    assert out.inode == 101


def test_repeated_resolve_is_served_from_cache():
    r = build()
    r.resolve("svc", "fh-1")
    r.resolve("svc", "fh-1")
    stats = r.stats()
    assert stats["cache_misses"] == 1
    assert stats["cache_hits"] == 1


def test_invalidate_drops_cached_entry():
    r = build()
    r.resolve("svc", "fh-1")
    r.resolve("svc", "fh-1")
    assert r.invalidate("fh-1") == 1
    assert r.invalidate("fh-1") == 0
    r.resolve("svc", "fh-1")
    stats = r.stats()
    assert stats["cache_hits"] == 1
    assert stats["cache_misses"] == 2
    assert stats["invalidations"] == 1


def test_object_registration_rejects_duplicates():
    r = build()
    with pytest.raises(fh.FhError) as excinfo:
        r.add_object("fh-1", mount_id="m1", path="/srv/app/new.txt", inode=301)
    assert excinfo.value.code == "FILEHANDLE_DUPLICATE"
    with pytest.raises(fh.FhError) as excinfo:
        r.add_object("fh-9", mount_id="m1", path="/srv/app/one.txt", inode=302)
    assert excinfo.value.code == "FILEHANDLE_DUPLICATE_PATH"
    with pytest.raises(fh.FhError) as excinfo:
        r.add_object("fh-9", mount_id="m1", path="app/relative.txt", inode=303)
    assert excinfo.value.code == "FILEHANDLE_PATH_INVALID"


def test_unknown_handle_is_refused_everywhere():
    r = build()
    with pytest.raises(fh.FhError) as excinfo:
        r.resolve("svc", "fh-77")
    assert excinfo.value.code == "FILEHANDLE_UNKNOWN"
    with pytest.raises(fh.FhError) as excinfo:
        r.describe("fh-77")
    assert excinfo.value.code == "FILEHANDLE_UNKNOWN"
    with pytest.raises(fh.FhError) as excinfo:
        r.authorize("svc", "fh-77")
    assert excinfo.value.code == "FILEHANDLE_UNKNOWN"


def test_prefix_matching_respects_path_segments():
    r = build(prefix="/srv/a")
    r.add_object("fh-2", mount_id="m1", path="/srv/ab/other.txt", inode=111)
    r.add_object("fh-3", mount_id="m1", path="/srv/a/inner.txt", inode=112)
    with pytest.raises(fh.FhError) as excinfo:
        r.resolve("svc", "fh-2")
    assert excinfo.value.code == "FILEHANDLE_ACCESS_DENIED"
    assert r.resolve("svc", "fh-3").path == "/srv/a/inner.txt"


def test_snapshot_restore_round_trip_is_deep():
    r = build()
    r.resolve("svc", "fh-1")
    state = r.snapshot()
    fresh = fh.FileHandleResolver()
    fresh.restore(state)
    out = fresh.resolve("svc", "fh-1")
    assert out.inode == 101
    assert out.path == "/srv/app/one.txt"
    assert fresh.stats()["resolves"] == 2
    state["stats"]["resolves"] = 99
    assert fresh.stats()["resolves"] == 2


def test_restore_rejects_broken_state():
    r = build()
    with pytest.raises(fh.FhError) as excinfo:
        r.restore({"mounts": {}, "objects": {"fh-1": {"handle_id": "fh-1"}}})
    assert excinfo.value.code == "FILEHANDLE_SNAPSHOT_INVALID"
    assert r.describe("fh-1")["path"] == "/srv/app/one.txt"


def test_cache_evicts_least_recently_used_entry():
    r = build(cache_size=2, extra_objects=2)
    r.resolve("svc", "fh-1")
    r.resolve("svc", "fh-2")
    r.resolve("svc", "fh-3")
    r.resolve("svc", "fh-1")
    stats = r.stats()
    assert stats["evictions"] == 2
    assert stats["cache_misses"] == 4
    assert stats["cache_hits"] == 0


def test_mount_registration_rejects_duplicates_and_unknown_mount():
    r = build()
    with pytest.raises(fh.FhError) as excinfo:
        r.add_mount("m1", "ns2", root="/srv")
    assert excinfo.value.code == "FILEHANDLE_DUPLICATE_MOUNT"
    with pytest.raises(fh.FhError) as excinfo:
        r.add_object("fh-5", mount_id="m9", path="/srv/x", inode=501)
    assert excinfo.value.code == "FILEHANDLE_UNKNOWN_MOUNT"
