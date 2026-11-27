import copy

import pytest

import input_device_grab_guard as ig

POINTER_PATH = "/dev/input/by-path/pci-0000:00:1a.0-usb-0:1:1.0-event"
KEYBOARD_PATH = "/dev/input/by-path/pci-0000:00:1a.0-usb-0:2:1.0-event"


def guard(**kwargs):
    return ig.InputDeviceGrabGuard(**kwargs)


def pointer(g, path=POINTER_PATH, inode=1001):
    return g.register_device(path, event_nodes="event5", inode=inode,
                             capabilities=("EV_REL", "EV_SYN"))


def keyboard(g, path=KEYBOARD_PATH, inode=1002):
    return g.register_device(path, event_nodes=("event7",), inode=inode,
                             capabilities=("EV_KEY", "EV_SYN"),
                             keyboard=True)


def test_register_and_enumerate_devices():
    g = guard()
    first = pointer(g)
    second = keyboard(g)
    assert first.device_id == "input-1"
    assert second.device_id == "input-2"
    assert first.nodes == ("event5",)
    assert set(first.capabilities) == {"EV_REL", "EV_SYN"}
    assert first.present is True
    assert first.keyboard is False
    assert second.keyboard is True
    assert [device.device_id for device in g.enumerate()] == ["input-1",
                                                              "input-2"]
    assert g.stats()["registered"] == 2


def test_grab_rejects_unknown_device_and_missing_capability():
    g = guard()
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab("input-9", session="sess", pid=10, purpose="pointer-capture")
    assert exc.value.code == "INPUT_DEVICE_UNKNOWN"
    assert exc.value.detail["device"] == "input-9"

    device = pointer(g)
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(device.device_id, session="sess", pid=10,
               purpose="keyboard-capture")
    assert exc.value.code == "INPUT_CAPABILITY_MISSING"
    assert exc.value.detail["purpose"] == "keyboard-capture"
    assert g.grabs() == ()


def test_keyboard_grab_requires_higher_authorization():
    g = guard()
    device = keyboard(g)
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(device.device_id, session="sess", pid=11,
               purpose="keyboard-capture")
    assert exc.value.code == "INPUT_AUTH_REQUIRED"
    assert exc.value.detail["device"] == device.device_id

    handle = g.grab(device.device_id, session="sess", pid=11,
                    purpose="keyboard-capture", authorized=True)
    assert handle.grab_id == "grab-1"
    assert handle.purpose == "keyboard-capture"
    assert handle.stale is False
    assert handle.lease_expires == 30


def test_second_session_cannot_grab_a_busy_device():
    g = guard()
    device = pointer(g)
    first = g.grab(device.device_id, session="session-a", pid=100,
                   purpose="pointer-capture")
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(device.device_id, session="session-b", pid=200,
               purpose="pointer-capture")
    assert exc.value.code == "INPUT_DEVICE_BUSY"
    assert exc.value.detail["session"] == "session-a"
    assert g.device_state(device.device_id)["holder"] == "session-a"
    assert first.session == "session-a"


def test_repeated_grab_by_same_session_merges_and_renews_the_lease():
    g = guard()
    device = pointer(g)
    first = g.grab(device.device_id, session="session-a", pid=100,
                   purpose="pointer-capture", now=0)
    second = g.grab(device.device_id, session="session-a", pid=100,
                    purpose="pointer-capture", now=5)
    assert second.grab_id == first.grab_id
    assert second.lease_expires == 15
    assert len(g.grabs()) == 1
    assert g.stats()["grabbed"] == 1
    assert g.stats()["merged"] == 1


def test_grab_validates_purpose_and_session():
    g = guard()
    device = pointer(g)
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(device.device_id, session="", pid=10,
               purpose="pointer-capture")
    assert exc.value.code == "INPUT_INVALID_REQUEST"
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(device.device_id, session="sess", pid=10, purpose="raw")
    assert exc.value.code == "INPUT_INVALID_REQUEST"
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(device.device_id, session="sess", pid=10,
               purpose="hotkey-capture")
    assert exc.value.code == "INPUT_CAPABILITY_MISSING"
    assert g.grabs() == ()


def test_ungrab_enforces_ownership_and_reports_unknown_handles():
    g = guard()
    device = pointer(g)
    handle = g.grab(device.device_id, session="session-a", pid=100,
                    purpose="pointer-capture")
    with pytest.raises(ig.InputGrabError) as exc:
        g.ungrab(handle.grab_id, session="session-b")
    assert exc.value.code == "INPUT_NOT_OWNER"
    assert exc.value.detail["session"] == "session-b"
    assert g.device_state(device.device_id)["holder"] == "session-a"

    assert g.ungrab(handle.grab_id, session="session-a") is True
    assert g.device_state(device.device_id)["holder"] is None
    assert g.ungrab("grab-99") is False
    assert g.stats()["ungrabbed"] == 1


def test_session_grab_cap_refuses_the_next_device():
    g = guard(max_grabs_per_session=2)
    devices = [pointer(g, path=f"/dev/input/by-path/virtio-{index}-event",
                        inode=2000 + index) for index in range(3)]
    g.grab(devices[0].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    g.grab(devices[1].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(devices[2].device_id, session="session-a", pid=1,
               purpose="pointer-capture")
    assert exc.value.code == "INPUT_SESSION_LIMIT"
    assert exc.value.detail["session"] == "session-a"
    assert exc.value.detail["limit"] == 2


def test_total_grab_cap_refuses_another_session():
    g = guard(max_grabs=2)
    devices = [pointer(g, path=f"/dev/input/by-path/acpi-{index}-event",
                        inode=3000 + index) for index in range(3)]
    g.grab(devices[0].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    g.grab(devices[1].device_id, session="session-b", pid=2,
           purpose="pointer-capture")
    with pytest.raises(ig.InputGrabError) as exc:
        g.grab(devices[2].device_id, session="session-c", pid=3,
               purpose="pointer-capture")
    assert exc.value.code == "INPUT_CAPACITY"
    assert exc.value.detail["limit"] == 2


def test_unplug_marks_the_grab_stale_and_rebind_restores_the_holder():
    g = guard()
    device = pointer(g)
    g.grab(device.device_id, session="session-a", pid=100,
           purpose="pointer-capture", now=0)
    assert g.unplug(device.device_id) is True
    assert g.device_state(device.device_id)["present"] is False
    assert g.grabs()[0].stale is True

    info = g.rebind(device.device_id, event_node="event9", inode=4004,
                    session="session-a", now=10)
    assert info.nodes == ("event9",)
    assert info.inode == 4004
    assert info.present is True
    handle = g.grabs()[0]
    assert handle.stale is False
    assert handle.lease_expires == 40
    assert g.device_state(device.device_id)["holder"] == "session-a"


def test_rebind_without_a_grab_updates_node_and_inode():
    g = guard()
    device = pointer(g)
    g.unplug(device.device_id)
    info = g.rebind(device.device_id, event_node="event8", inode=5005,
                    session="session-b", now=1)
    assert info.nodes == ("event8",)
    assert info.inode == 5005
    assert info.present is True
    assert g.grabs() == ()
    assert g.device_state(device.device_id)["holder"] is None


def test_release_session_frees_every_grab_of_that_session():
    g = guard()
    devices = [pointer(g, path=f"/dev/input/by-path/usb-{index}-event",
                        inode=6000 + index) for index in range(3)]
    g.grab(devices[0].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    g.grab(devices[1].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    g.grab(devices[2].device_id, session="session-b", pid=2,
           purpose="pointer-capture")
    assert g.release_session("session-a") == 2
    assert g.device_state(devices[0].device_id)["holder"] is None
    assert g.device_state(devices[1].device_id)["holder"] is None
    assert g.device_state(devices[2].device_id)["holder"] == "session-b"
    assert g.release_session("session-a") == 0
    assert g.stats()["session_releases"] == 1
    assert len(g.grabs()) == 1


def test_lease_expiry_reclaims_a_crashed_grab():
    g = guard(lease_ttl=10)
    device = pointer(g)
    handle = g.grab(device.device_id, session="session-a", pid=100,
                    purpose="pointer-capture", now=0)
    assert handle.lease_expires == 10
    assert g.heartbeat(handle.grab_id, now=5) == 15
    assert g.expire(now=14) == 0
    assert g.expire(now=15) == 1
    assert g.device_state(device.device_id)["holder"] is None
    assert g.stats()["expired"] == 1


def test_grabs_are_ordered_and_filtered_per_session():
    g = guard()
    devices = [pointer(g, path=f"/dev/input/by-path/ps2-{index}-event",
                        inode=7000 + index) for index in range(3)]
    g.grab(devices[0].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    g.grab(devices[1].device_id, session="session-b", pid=2,
           purpose="pointer-capture")
    g.grab(devices[2].device_id, session="session-a", pid=1,
           purpose="pointer-capture")
    assert [handle.grab_id for handle in g.grabs()] == ["grab-1", "grab-2",
                                                       "grab-3"]
    assert [handle.grab_id for handle in g.grabs(session="session-a")] == \
        ["grab-1", "grab-3"]
    state = g.session_state("session-a")
    assert state["locked"] is False
    assert state["grabs"] == ("grab-1", "grab-3")


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard(lease_ttl=10)
    first = keyboard(g)
    second = pointer(g)
    g.grab(first.device_id, session="session-a", pid=100,
           purpose="keyboard-capture", authorized=True, now=0)
    g.grab(second.device_id, session="session-b", pid=200,
           purpose="pointer-capture", now=5)
    g.set_session_locked("session-b", True)

    state = g.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "devices", "grabs", "sessions",
                             "counters"}
    state["devices"].clear()
    state["counters"]["grabbed"] = 999
    assert len(g.enumerate()) == 2
    assert g.stats()["grabbed"] == 2

    clone = guard()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.enumerate() == g.enumerate()
    assert clone.grabs() == g.grabs()
    assert clone.device_state(first.device_id)["holder"] == "session-a"
    assert clone.session_state("session-b")["locked"] is True
    assert clone.grabs(session="session-a")[0].lease_expires == 10

    bad_states = [
        None,
        {},
        {"version": 2, "devices": [], "grabs": [], "sessions": {},
         "counters": dict(g.stats())},
        {"version": 1, "devices": {}, "grabs": [], "sessions": {},
         "counters": dict(g.stats())},
        {"version": 1, "devices": [], "grabs": [], "sessions": {},
         "counters": {"grabbed": 2}},
    ]
    for bad in bad_states:
        with pytest.raises(ig.InputGrabError) as exc:
            g.restore(bad)
        assert exc.value.code == "INPUT_SNAPSHOT_INVALID"
    assert len(g.grabs()) == 2
    assert g.session_state("session-b")["locked"] is True
