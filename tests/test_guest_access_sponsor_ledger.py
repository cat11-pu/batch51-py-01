import copy
import threading

import pytest

import guest_access_sponsor_ledger as gl


def ledger(**kwargs):
    return gl.GuestAccessLedger(**kwargs)


def sponsor_and_guest(led, *, sponsor="s1", guest="g1",
                      grantable=("data:read", "data:write", "admin"),
                      scope=("data:read", "data:write"), now=0):
    led.register_sponsor(sponsor, list(grantable), now=now)
    led.invite_guest(guest, now=now)
    return led.bind_sponsor(guest, sponsor, list(scope), now=now)


def test_register_sponsor_normalizes_scope_and_rejects_duplicates():
    led = ledger()
    view = led.register_sponsor(
        "s1", ["Data:Write", " data:read ", "data:read"], now=0)
    assert view.sponsor_id == "s1"
    assert view.grantable == ("data:read", "data:write")
    assert view.guest_count == 0
    with pytest.raises(gl.GuestError) as exc:
        led.register_sponsor("s1", ["data:read"], now=10)
    assert exc.value.code == "GUEST_SPONSOR_EXISTS"
    with pytest.raises(gl.GuestError) as exc:
        led.register_sponsor("  ", ["data:read"], now=10)
    assert exc.value.code == "GUEST_INVALID_REQUEST"
    assert led.stats()["sponsors"] == 1


def test_invite_creates_pending_guest_without_window():
    led = ledger()
    guest = led.invite_guest("g1", now=0)
    assert guest.guest_id == "g1"
    assert guest.sponsor_id is None
    assert guest.state == "pending"
    assert guest.scope == ()
    assert guest.invited_at == 0
    assert guest.granted_at is None
    assert guest.expires_at is None
    assert guest.disabled_reason is None
    assert guest.renewal_pending is False
    with pytest.raises(gl.GuestError) as exc:
        led.invite_guest("g1", now=10)
    assert exc.value.code == "GUEST_ALREADY_EXISTS"
    with pytest.raises(gl.GuestError) as exc:
        led.invite_guest("", now=10)
    assert exc.value.code == "GUEST_INVALID_REQUEST"
    assert led.stats()["guests_invited"] == 1


def test_bind_sponsor_activates_guest_inside_grantable_scope():
    led = ledger()
    led.register_sponsor("s1", ["admin", "data:read", "data:write"], now=0)
    led.invite_guest("g1", now=0)
    view = led.bind_sponsor("g1", "s1",
                            ["data:write", "data:read", "DATA:READ"], now=50)
    assert view.state == "active"
    assert view.sponsor_id == "s1"
    assert view.scope == ("data:read", "data:write")
    assert view.granted_at == 50
    assert view.expires_at == 1050
    led.invite_guest("g2", now=60)
    with pytest.raises(gl.GuestError) as exc:
        led.bind_sponsor("g2", "s1", ["root"], now=60)
    assert exc.value.code == "GUEST_SCOPE_EXCEEDED"
    assert led.guest("g2").state == "pending"
    assert led.stats()["guests_bound"] == 1


def test_unknown_guest_and_sponsor_are_reported():
    led = ledger()
    led.register_sponsor("s1", ["data:read"], now=0)
    with pytest.raises(gl.GuestError) as exc:
        led.bind_sponsor("ghost", "s1", ["data:read"], now=0)
    assert exc.value.code == "GUEST_UNKNOWN"
    led.invite_guest("g1", now=0)
    with pytest.raises(gl.GuestError) as exc:
        led.bind_sponsor("g1", "ghost", ["data:read"], now=0)
    assert exc.value.code == "GUEST_SPONSOR_UNKNOWN"
    with pytest.raises(gl.GuestError) as exc:
        led.guest("nope")
    assert exc.value.code == "GUEST_UNKNOWN"
    with pytest.raises(gl.GuestError) as exc:
        led.guests_for("ghost")
    assert exc.value.code == "GUEST_SPONSOR_UNKNOWN"


def test_guests_for_is_sorted_and_scoped_to_one_sponsor():
    led = ledger()
    led.register_sponsor("s1", ["data:read"], now=0)
    led.register_sponsor("s2", ["data:read"], now=0)
    for guest in ("g2", "g1", "g3"):
        led.invite_guest(guest, now=0)
    led.bind_sponsor("g2", "s1", ["data:read"], now=10)
    led.bind_sponsor("g1", "s1", ["data:read"], now=10)
    led.bind_sponsor("g3", "s2", ["data:read"], now=10)
    assert [row.guest_id for row in led.guests_for("s1")] == ["g1", "g2"]
    assert [row.guest_id for row in led.guests_for("s2")] == ["g3"]


def test_renewal_must_be_requested_inside_the_renewal_window():
    led = ledger()
    sponsor_and_guest(led)
    with pytest.raises(gl.GuestError) as exc:
        led.request_renewal("g1", now=500)
    assert exc.value.code == "GUEST_RENEWAL_TOO_EARLY"
    view = led.request_renewal("g1", now=850)
    assert view.renewal_pending is True
    with pytest.raises(gl.GuestError) as exc:
        led.request_renewal("g1", now=860)
    assert exc.value.code == "GUEST_RENEWAL_PENDING"
    assert led.stats()["renewals_requested"] == 1


def test_approve_renewal_recomputes_window_from_approval_time():
    led = ledger()
    sponsor_and_guest(led)
    led.request_renewal("g1", now=850)
    view = led.approve_renewal("g1", now=900)
    assert view.state == "active"
    assert view.expires_at == 1900
    assert view.granted_at == 0
    assert view.renewal_pending is False
    assert led.stats()["renewals_approved"] == 1


def test_approve_without_pending_renewal_is_refused():
    led = ledger()
    sponsor_and_guest(led)
    with pytest.raises(gl.GuestError) as exc:
        led.approve_renewal("g1", now=900)
    assert exc.value.code == "GUEST_RENEWAL_MISSING"


def test_settle_expiry_disables_only_expired_active_guests():
    led = ledger()
    sponsor_and_guest(led, guest="g1")
    sponsor_and_guest(led, guest="g2")
    assert led.settle_expiry(now=999) == 0
    assert led.settle_expiry(now=1000) == 2
    for guest_id in ("g1", "g2"):
        view = led.guest(guest_id)
        assert view.state == "disabled"
        assert view.disabled_reason == "expired"
        assert view.expires_at == 1000
    assert led.settle_expiry(now=1001) == 0
    assert led.stats()["expired"] == 2


def test_current_sponsor_can_revoke_and_clears_renewal():
    led = ledger()
    sponsor_and_guest(led)
    led.request_renewal("g1", now=850)
    view = led.revoke_guest("g1", "s1", now=900)
    assert view.state == "disabled"
    assert view.disabled_reason == "revoked"
    assert view.renewal_pending is False
    assert led.stats()["revoked"] == 1


def test_other_sponsor_cannot_revoke_a_guest():
    led = ledger()
    sponsor_and_guest(led)
    led.register_sponsor("s2", ["data:read"], now=0)
    with pytest.raises(gl.GuestError) as exc:
        led.revoke_guest("g1", "s2", now=500)
    assert exc.value.code == "GUEST_NOT_SPONSOR"
    assert led.guest("g1").state == "active"


def test_transfer_moves_sponsor_and_shrinks_scope_to_new_grantable():
    led = ledger()
    sponsor_and_guest(led, grantable=["data:read", "data:write"],
                      scope=["data:read", "data:write"])
    led.register_sponsor("s2", ["data:read", "admin"], now=0)
    view = led.transfer_guest("g1", "s2", now=300)
    assert view.sponsor_id == "s2"
    assert view.scope == ("data:read",)
    assert view.expires_at == 1000
    assert view.state == "active"
    assert led.guests_for("s1") == []
    assert [row.guest_id for row in led.guests_for("s2")] == ["g1"]
    assert led.stats()["transferred"] == 1


def test_concurrent_renewal_and_expiry_leave_one_terminal_state():
    led = ledger()
    sponsor_and_guest(led)
    led.request_renewal("g1", now=990)
    errors = []
    barrier = threading.Barrier(2)

    def renewal():
        try:
            barrier.wait(timeout=5)
            led.approve_renewal("g1", now=1005)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    def expiry():
        try:
            barrier.wait(timeout=5)
            led.settle_expiry(now=1005)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=renewal), threading.Thread(target=expiry)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    view = led.guest("g1")
    assert view.state in {"active", "disabled"}
    if view.state == "active":
        assert view.expires_at == 2005
        assert view.renewal_pending is False
    else:
        assert view.disabled_reason == "expired"
    assert len(errors) <= 1
    assert led.stats()["expired"] <= 1
    assert led.stats()["renewals_approved"] <= 1


def test_snapshot_is_detached_and_restore_roundtrips():
    led = ledger()
    sponsor_and_guest(led, guest="g1")
    sponsor_and_guest(led, guest="g2", sponsor="s2",
                      grantable=["data:read"], scope=["data:read"])
    led.request_renewal("g1", now=850)
    state = led.snapshot()
    assert set(state) == {"version", "sponsors", "guests", "stats"}
    pristine = copy.deepcopy(state)
    state["sponsors"].clear()
    state["guests"].clear()
    state["stats"]["sponsors"] = 9
    live = led.guest("g1")
    assert live.state == "active"
    assert live.renewal_pending is True
    assert led.guest("g2").sponsor_id == "s2"
    assert led.stats()["sponsors"] == 2

    clone = ledger()
    clone.restore(pristine)
    assert clone.guest("g1") == live
    assert [row.guest_id for row in clone.guests_for("s1")] == ["g1"]
    assert clone.stats() == led.stats()


def test_restore_rejects_malformed_state_without_touching_live_data():
    led = ledger()
    sponsor_and_guest(led)
    bad_states = [
        None,
        {},
        {"version": 1, "sponsors": {}, "guests": {}, "stats": {}},
        {"version": 2, "sponsors": {}, "guests": {}, "stats": {}},
        {"version": 1, "sponsors": [], "guests": {}, "stats": {}},
        {"version": 1, "sponsors": {}, "guests": [], "stats": {}},
        {"version": 1, "sponsors": {}, "guests": {}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(gl.GuestError) as exc:
            led.restore(bad)
        assert exc.value.code == "GUEST_SNAPSHOT_INVALID"
    assert led.guest("g1").state == "active"
