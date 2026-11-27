import pytest

import bfd_session_guard as bg

NOW = 1000


def guard(**kwargs):
    return bg.BfdSessionGuard(**kwargs)


def control(local=10, remote=20, state="up", auth_key=None, auth_seq=None):
    packet = {"local_discriminator": local, "remote_discriminator": remote,
              "state": state}
    if auth_key is not None:
        packet["auth_key"] = auth_key
        packet["auth_seq"] = auth_seq
    return packet


def live_session(g, session_id="s1", local=10, remote=20, **kwargs):
    return g.create_session(session_id, local, remote, now=kwargs.get("now", NOW))


def bring_up(g, session_id="s1", local=10, remote=20):
    live_session(g, session_id=session_id, local=local, remote=remote)
    g.receive(session_id, control(local, remote), now=NOW)
    return g.receive(session_id, control(local, remote), now=NOW + 50)


def test_create_session_starts_down_with_detection_time():
    g = guard()
    view = g.create_session("s1", 10, remote_discriminator=20, now=NOW)
    assert view.state == "down"
    assert view.local_discriminator == 10
    assert view.remote_discriminator == 20
    assert view.detection_time == 150
    assert view.next_timeout_at is None
    assert view.auth_sequence == 0
    assert g.session_view("s1") == view
    assert g.peer("s1") == 20
    assert g.timers("s1") == {"detection_time": 150, "next_timeout_at": None}


def test_duplicate_local_discriminator_is_refused():
    g = guard()
    live_session(g, session_id="s1", local=10)
    with pytest.raises(bg.BfdError) as exc:
        live_session(g, session_id="s2", local=10, remote=99)
    assert exc.value.code == "BFD_DISCRIMINATOR_TAKEN"
    assert g.session_state("s1") == "down"
    assert g.stats()["created"] == 1


def test_receive_from_down_moves_one_step_to_init():
    g = guard(auth_enabled=False)
    live_session(g)
    result = g.receive("s1", control(), now=NOW)
    assert result.accepted is True
    assert result.reason == "accepted"
    assert result.state == "init"
    assert g.session_state("s1") == "init"
    assert g.session_view("s1").next_timeout_at == NOW + 150


def test_receive_from_init_reaches_up_and_starts_timer():
    g = guard(auth_enabled=False)
    live_session(g)
    g.receive("s1", control(), now=NOW)
    result = g.receive("s1", control(), now=NOW + 50)
    assert (result.accepted, result.state) == (True, "up")
    view = g.session_view("s1")
    assert view.state == "up"
    assert view.next_timeout_at == NOW + 200
    assert g.stats()["transitioned"] == 2


def test_receive_in_up_keeps_state_and_refreshes_timer():
    g = guard(auth_enabled=False)
    bring_up(g)
    result = g.receive("s1", control(), now=NOW + 100)
    assert (result.accepted, result.state) == (True, "up")
    view = g.session_view("s1")
    assert view.next_timeout_at == NOW + 250
    assert g.stats()["transitioned"] == 2


def test_packet_for_another_discriminator_is_dropped():
    g = guard(auth_enabled=False)
    live_session(g)
    g.receive("s1", control(), now=NOW)
    result = g.receive("s1", control(local=77), now=NOW + 50)
    assert result.accepted is False
    assert result.reason == "local_discriminator_mismatch"
    assert result.state == "init"
    assert g.session_state("s1") == "init"
    assert g.session_view("s1").next_timeout_at == NOW + 150
    assert g.stats()["rejected"] == 1


def test_receive_on_unknown_session_raises():
    g = guard()
    with pytest.raises(bg.BfdError) as exc:
        g.receive("s9", control(), now=NOW)
    assert exc.value.code == "BFD_UNKNOWN_SESSION"
    assert g.stats()["rejected"] == 0


def test_authentication_accepts_increasing_sequence():
    g = guard(auth_enabled=True)
    live_session(g)
    g.set_auth_keys("s1", 1, "secret-one")
    assert g.authenticate("s1", {"auth_key": 1, "auth_seq": 5}) is True
    assert g.session_view("s1").auth_sequence == 5
    assert g.stats()["auth_failures"] == 0


def test_authentication_with_unknown_key_fails():
    g = guard(auth_enabled=True)
    live_session(g)
    g.set_auth_keys("s1", 1, "secret-one")
    assert g.authenticate("s1", {"auth_key": 2, "auth_seq": 5}) is False
    assert g.session_view("s1").auth_sequence == 0
    assert g.stats()["auth_failures"] == 1


def test_advance_before_deadline_does_not_time_out():
    g = guard(auth_enabled=False)
    bring_up(g)
    assert g.advance(NOW + 199) == ()
    assert g.session_state("s1") == "up"
    assert g.stats()["timeouts"] == 0


def test_advance_at_deadline_moves_session_down():
    g = guard(auth_enabled=False)
    bring_up(g)
    assert g.advance(NOW + 200) == ("s1",)
    assert g.session_state("s1") == "down"
    view = g.session_view("s1")
    assert view.next_timeout_at is None
    assert g.stats()["timeouts"] == 1
    assert g.stats()["transitioned"] == 3


def test_rebuild_keeps_local_discriminator_and_resets_state():
    g = guard(auth_enabled=False)
    bring_up(g)
    view = g.rebuild("s1", 44, now=NOW + 60)
    assert view.state == "down"
    assert view.local_discriminator == 10
    assert view.remote_discriminator == 44
    assert view.next_timeout_at is None
    assert view.auth_sequence == 0
    assert g.peer("s1") == 44
    assert g.stats()["rebuilds"] == 1


def test_stats_count_lifecycle_events():
    g = guard(auth_enabled=False)
    live_session(g)
    g.receive("s1", control(), now=NOW)
    g.receive("s1", control(), now=NOW + 50)
    g.receive("s1", control(local=77), now=NOW + 60)
    g.authenticate("s1", {"auth_key": 2, "auth_seq": 9})
    g.advance(NOW + 200)
    assert g.stats() == {
        "created": 1,
        "transitioned": 3,
        "timeouts": 1,
        "auth_failures": 1,
        "duplicates": 0,
        "rejected": 1,
        "rebuilds": 0,
    }


def test_snapshot_restore_keeps_detection_deadline():
    g = guard(auth_enabled=False)
    bring_up(g)
    state = g.snapshot()
    assert set(state) == {"version", "sessions", "stats"}
    state["sessions"].clear()
    assert g.session_state("s1") == "up"

    clone = guard(auth_enabled=False)
    clone.restore(g.snapshot())
    view = clone.session_view("s1")
    assert view.state == "up"
    assert view.next_timeout_at == NOW + 200
    assert clone.advance(NOW + 199) == ()
    assert clone.session_state("s1") == "up"
    assert clone.advance(NOW + 200) == ("s1",)
    assert clone.session_state("s1") == "down"
    assert clone.stats()["timeouts"] == 1


def test_restore_rejects_malformed_state_without_touching_live_state():
    g = guard(auth_enabled=False)
    bring_up(g)
    bad_states = [
        None,
        {},
        {"version": 2, "sessions": {}, "stats": {}},
        {"version": 1, "sessions": [], "stats": {}},
        {"version": 1, "sessions": {}},
    ]
    for bad in bad_states:
        with pytest.raises(bg.BfdError) as exc:
            g.restore(bad)
        assert exc.value.code == "BFD_SNAPSHOT_INVALID"
    assert g.session_state("s1") == "up"
    assert g.session_view("s1").next_timeout_at == NOW + 200
