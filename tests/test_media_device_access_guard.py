import copy

import pytest

import media_device_access_guard as md

NOW = "2026-11-27T08:00:00+00:00"
LATER = "2026-11-27T08:04:00+00:00"


def guard(**kwargs):
    return md.MediaDeviceAccessGuard(**kwargs)


def seeded(**kwargs):
    g = guard(**kwargs)
    g.register_device("cam0", md.CAMERA)
    g.register_device("cam1", md.CAMERA)
    g.register_device("mic0", md.MICROPHONE)
    return g


def test_enumerate_devices_sorted_by_kind_then_id():
    g = seeded()
    rows = g.enumerate_devices()
    assert [(row.kind, row.device_id) for row in rows] == [
        ("camera", "cam0"),
        ("camera", "cam1"),
        ("microphone", "mic0"),
    ]
    assert [row.present for row in rows] == [True, True, True]
    assert [row.device_id for row in g.enumerate_devices(kind=md.CAMERA)] == ["cam0", "cam1"]
    assert [row.device_id for row in g.enumerate_devices(kind=md.MICROPHONE)] == ["mic0"]


def test_request_access_defaults_to_present_devices_of_kind():
    g = seeded()
    camera = g.request_access("sess-a", md.CAMERA, now=NOW)
    assert camera.session == "sess-a"
    assert camera.kind == md.CAMERA
    assert camera.devices == ("cam0", "cam1")
    assert camera.revision == 1
    assert camera.granted_at == NOW

    mic = g.request_access("sess-a", md.MICROPHONE, ["mic0", "mic0"], now=NOW)
    assert mic.devices == ("mic0",)
    assert g.stats()["grants"] == 2


def test_request_access_rejects_malformed_requests():
    g = seeded()
    with pytest.raises(md.MediaAccessError) as exc:
        g.request_access("", md.CAMERA, ["cam0"], now=NOW)
    assert exc.value.code == "MEDIA_INVALID_REQUEST"
    with pytest.raises(md.MediaAccessError) as exc:
        g.request_access("sess-a", md.CAMERA, [], now=NOW)
    assert exc.value.code == "MEDIA_INVALID_REQUEST"
    with pytest.raises(md.MediaAccessError) as exc:
        g.request_access("sess-a", "speaker", ["cam0"], now=NOW)
    assert exc.value.code == "MEDIA_INVALID_REQUEST"
    with pytest.raises(md.MediaAccessError) as exc:
        g.request_access("sess-a", md.CAMERA, ["cam9"], now=NOW)
    assert exc.value.code == "MEDIA_DEVICE_UNKNOWN"
    assert exc.value.detail == "cam9"
    assert g.stats()["grants"] == 0


def test_request_access_repeat_is_idempotent_and_superset_unions():
    g = seeded()
    first = g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    repeat = g.request_access("sess-a", md.CAMERA, ["cam0"], now=LATER)
    assert repeat.devices == ("cam0",)
    assert repeat.revision == 1
    assert repeat.granted_at == NOW

    wider = g.request_access("sess-a", md.CAMERA, ["cam1", "cam0"], now=LATER)
    assert wider.devices == ("cam0", "cam1")
    assert wider.revision == 2
    assert wider.granted_at == LATER
    assert g.stats()["grants"] == 1


def test_open_stream_requires_matching_grant():
    g = seeded()
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-a", "cam0", now=NOW)
    assert exc.value.code == "MEDIA_ACCESS_DENIED"
    assert g.indicator_state() == {"active": False, "kinds": ()}

    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    handle = g.open_stream("sess-a", "cam0", now=NOW)
    assert handle.device_id == "cam0"
    assert handle.kind == md.CAMERA
    assert handle.mode == "read"
    assert handle.shared is False
    assert handle.live is True


def test_unplugged_device_must_be_granted_again_after_replug():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    assert g.unplug_device("cam0") == 0
    assert [row.present for row in g.enumerate_devices(kind=md.CAMERA)] == [False, True]
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-a", "cam0", now=NOW)
    assert exc.value.code == "MEDIA_DEVICE_ABSENT"

    g.register_device("cam0", md.CAMERA)
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-a", "cam0", now=NOW)
    assert exc.value.code == "MEDIA_ACCESS_DENIED"

    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    assert g.open_stream("sess-a", "cam0", now=NOW).live is True


def test_second_session_cannot_open_exclusive_device():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    g.request_access("sess-b", md.CAMERA, ["cam0"], now=NOW)
    g.open_stream("sess-a", "cam0", now=NOW)
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-b", "cam0", now=NOW)
    assert exc.value.code == "MEDIA_DEVICE_BUSY"
    assert g.stats()["streams_opened"] == 1


def test_unknown_mode_is_rejected_before_any_state_change():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-a", "cam0", mode="append", now=NOW)
    assert exc.value.code == "MEDIA_INVALID_REQUEST"
    assert g.stats()["streams_opened"] == 0
    assert g.indicator_state() == {"active": False, "kinds": ()}


def test_stream_ids_are_sequential_and_indicator_tracks_live_streams():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    g.request_access("sess-a", md.MICROPHONE, ["mic0"], now=NOW)
    first = g.open_stream("sess-a", "cam0", now=NOW)
    second = g.open_stream("sess-a", "mic0", now=NOW)
    assert (first.stream_id, second.stream_id) == ("cam0/s1", "mic0/s2")
    assert g.indicator_state() == {"active": True, "kinds": ("camera", "microphone")}

    assert g.close_stream(second.stream_id) is True
    assert g.indicator_state() == {"active": True, "kinds": ("camera",)}
    assert g.close_stream(first.stream_id) is True
    assert g.indicator_state() == {"active": False, "kinds": ()}


def test_close_stream_is_idempotent():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    handle = g.open_stream("sess-a", "cam0", now=NOW)
    assert g.close_stream(handle.stream_id) is True
    assert g.close_stream(handle.stream_id) is False
    assert g.close_stream("cam0/s99") is False
    assert g.stats()["streams_opened"] == 1
    assert g.stats()["streams_closed"] == 1
    assert g.stats()["streams_forced_closed"] == 0


def test_per_session_stream_limit():
    g = guard(max_streams_per_session=2)
    for device in ("cam0", "cam1", "cam2"):
        g.register_device(device, md.CAMERA)
    g.request_access("sess-a", md.CAMERA, ["cam0", "cam1", "cam2"], now=NOW)
    g.open_stream("sess-a", "cam0", now=NOW)
    g.open_stream("sess-a", "cam1", now=NOW)
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-a", "cam2", now=NOW)
    assert exc.value.code == "MEDIA_STREAM_LIMIT"
    assert g.stats()["streams_opened"] == 2


def test_total_stream_limit_releases_after_close():
    g = guard(max_streams_total=2)
    for device in ("cam0", "cam1", "cam2"):
        g.register_device(device, md.CAMERA)
    for session in ("sess-a", "sess-b", "sess-c"):
        g.request_access(session, md.CAMERA, ["cam0", "cam1", "cam2"], now=NOW)
    first = g.open_stream("sess-a", "cam0", now=NOW)
    g.open_stream("sess-b", "cam1", now=NOW)
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-c", "cam2", now=NOW)
    assert exc.value.code == "MEDIA_STREAM_LIMIT"

    g.close_stream(first.stream_id)
    assert g.open_stream("sess-c", "cam2", now=NOW).live is True
    assert g.stats()["streams_opened"] == 3


def test_revoke_forces_streams_closed_and_is_idempotent():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, now=NOW)
    first = g.open_stream("sess-a", "cam0", now=NOW)
    second = g.open_stream("sess-a", "cam1", now=NOW)
    assert (first.live, second.live) == (True, True)

    assert g.revoke("sess-a", md.CAMERA, now=NOW) == 2
    assert g.stats()["streams_forced_closed"] == 2
    assert g.indicator_state()["active"] is False
    with pytest.raises(md.MediaAccessError) as exc:
        g.open_stream("sess-a", "cam0", now=NOW)
    assert exc.value.code == "MEDIA_ACCESS_DENIED"
    assert g.revoke("sess-a", md.CAMERA, now=LATER) == 0


def test_end_session_reports_grant_and_stream_counts():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    g.request_access("sess-a", md.MICROPHONE, ["mic0"], now=NOW)
    g.request_access("sess-b", md.CAMERA, ["cam1"], now=NOW)
    g.open_stream("sess-a", "cam0", now=NOW)
    g.open_stream("sess-a", "mic0", now=NOW)

    assert g.end_session("sess-a", now=NOW) == {"grants": 2, "streams": 2}
    assert g.indicator_state()["active"] is False
    assert g.stats()["sessions_ended"] == 1
    assert g.stats()["grants"] == 3
    assert g.end_session("sess-a", now=LATER) == {"grants": 0, "streams": 0}
    assert g.open_stream("sess-b", "cam1", now=LATER).live is True


def test_snapshot_is_detached_and_restore_roundtrips():
    g = seeded()
    g.request_access("sess-a", md.CAMERA, ["cam0"], now=NOW)
    handle = g.open_stream("sess-a", "cam0", now=NOW)
    state = g.snapshot()
    assert set(state) == {"version", "devices", "grants", "streams", "counters"}
    pristine = copy.deepcopy(state)

    state["streams"].clear()
    state["counters"]["streams_opened"] = 999
    assert g.stats()["streams_opened"] == 1
    assert g.indicator_state() == {"active": True, "kinds": ("camera",)}

    clone = guard()
    clone.restore(pristine)
    assert clone.stats()["streams_opened"] == 1
    assert clone.indicator_state() == {"active": True, "kinds": ("camera",)}
    assert clone.close_stream(handle.stream_id) is True

    for bad in (None, {}, {"version": 1, "devices": [], "grants": {}, "streams": []},
                {"version": 1, "devices": [], "grants": [], "streams": [], "counters": {}}):
        with pytest.raises(md.MediaAccessError) as exc:
            g.restore(bad)
        assert exc.value.code == "MEDIA_SNAPSHOT_INVALID"
    assert g.stats()["streams_opened"] == 1
    assert g.indicator_state() == {"active": True, "kinds": ("camera",)}
