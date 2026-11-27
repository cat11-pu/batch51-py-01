import copy
import threading

import pytest

import captive_portal_gate as cpg

MAC = "AA:BB:CC:DD:EE:01"
MAC_KEY = "aa:bb:cc:dd:ee:01"
ADDR = "192.0.2.10"


def gate(**kwargs):
    return cpg.CaptivePortalGate(**kwargs)


def registered(instance, *, now=0.0):
    instance.register_client(MAC, ADDR, now=now)
    return instance


def test_register_creates_preauth_session_with_limits():
    portal = gate(byte_budget=1000, session_ttl=60.0)
    session = portal.register_client(MAC, ADDR, now=0.0)
    assert session.mac == MAC_KEY
    assert session.addr == ADDR
    assert session.state == "preauth"
    assert session.started_at == 0.0
    assert session.expires_at == 60.0
    assert session.bytes_used == 0
    assert session.bytes_limit == 1000
    assert session.authenticated_at is None
    assert portal.session_for(MAC_KEY) == session
    assert portal.session_for("aa:bb:cc:dd:ee:02") is None
    assert portal.stats()["registered"] == 1


def test_invalid_registration_arguments_are_rejected():
    portal = gate()
    with pytest.raises(cpg.CaptiveError) as exc:
        portal.register_client("", ADDR, now=0.0)
    assert exc.value.code == "CAPTIVE_INVALID_ARGUMENT"
    with pytest.raises(cpg.CaptiveError) as exc:
        portal.register_client(MAC, "   ", now=0.0)
    assert exc.value.code == "CAPTIVE_INVALID_ARGUMENT"
    with pytest.raises(cpg.CaptiveError) as exc:
        cpg.CaptivePortalGate(byte_budget=-1)
    assert exc.value.code == "CAPTIVE_INVALID_ARGUMENT"
    registered(portal)
    with pytest.raises(cpg.CaptiveError) as exc:
        portal.consume_bytes(MAC_KEY, -3, now=1.0)
    assert exc.value.code == "CAPTIVE_INVALID_ARGUMENT"


def test_unknown_client_is_denied_before_authentication():
    portal = gate()
    decision = portal.authorize(MAC, ADDR, "intranet.example", now=0.0)
    assert decision.allowed is False
    assert decision.reason == "unregistered"
    assert decision.host == "intranet.example"
    assert portal.stats()["denied"] == 1


def test_unknown_client_may_reach_the_portal_itself():
    portal = gate(portal_hosts=("portal.example",))
    decision = portal.authorize(MAC, ADDR, "portal.example", now=0.0)
    assert decision.allowed is True
    assert decision.reason == "portal"
    assert portal.stats()["allowed"] == 1


def test_allowlisted_destination_is_open_but_others_stay_blocked():
    portal = gate(portal_hosts=("portal.example",))
    portal.update_allowlist("cdn.example", addresses=["203.0.113.5"], ttl=30.0, now=0.0)
    registered(portal)
    allowed = portal.authorize(MAC_KEY, ADDR, "203.0.113.5", now=1.0)
    assert allowed.allowed is True
    assert allowed.reason == "allowlist"
    blocked = portal.authorize(MAC_KEY, ADDR, "evil.example", now=1.0)
    assert blocked.allowed is False
    assert blocked.reason == "blocked"


def test_consume_bytes_reports_remaining_budget():
    portal = registered(gate(byte_budget=1000))
    assert portal.consume_bytes(MAC_KEY, 400, now=1.0) == 600
    session = portal.session_for(MAC_KEY)
    assert session.bytes_used == 400
    assert session.bytes_limit == 1000
    assert portal.stats()["bytes_consumed"] == 400


def test_exhausted_budget_degrades_preauth_traffic():
    portal = registered(gate(byte_budget=500))
    assert portal.consume_bytes(MAC_KEY, 500, now=1.0) == 0
    decision = portal.authorize(MAC_KEY, ADDR, "intranet.example", now=2.0)
    assert decision.allowed is False
    assert decision.reason == "quota_exhausted"


def test_completed_authentication_switches_to_normal_policy():
    portal = registered(gate(byte_budget=100))
    session = portal.complete_auth(MAC_KEY, now=5.0)
    assert session.state == "authorized"
    assert session.authenticated_at == 5.0
    decision = portal.authorize(MAC_KEY, ADDR, "anywhere.example", now=6.0)
    assert decision.allowed is True
    assert decision.reason == "authorized"
    assert portal.stats()["authorized"] == 1


def test_completing_authentication_for_unknown_client_raises():
    portal = gate()
    with pytest.raises(cpg.CaptiveError) as exc:
        portal.complete_auth("aa:bb:cc:dd:ee:09", now=0.0)
    assert exc.value.code == "CAPTIVE_UNKNOWN_CLIENT"


def test_expired_session_is_settled_and_then_denied():
    portal = registered(gate(session_ttl=60.0))
    assert portal.settle_expired(now=59.0) == 0
    assert portal.settle_expired(now=60.0) == 1
    assert portal.session_for(MAC_KEY).state == "expired"
    assert portal.stats()["expired"] == 1
    decision = portal.authorize(MAC_KEY, ADDR, "intranet.example", now=61.0)
    assert decision.allowed is False
    assert decision.reason == "expired"


def test_concurrent_byte_consumption_never_crosses_the_cap():
    portal = registered(gate(byte_budget=1000))
    errors = []
    barrier = threading.Barrier(20)

    def worker():
        try:
            barrier.wait(timeout=5)
            portal.consume_bytes(MAC_KEY, 100, now=1.0)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert portal.session_for(MAC_KEY).bytes_used == 1000
    assert portal.authorize(MAC_KEY, ADDR, "intranet.example", now=2.0).reason == "quota_exhausted"


def test_allowlist_update_publishes_new_addresses():
    portal = gate()
    result = portal.update_allowlist("files.example", addresses=["203.0.113.9"], ttl=30.0, now=0.0)
    assert tuple(result) == ("203.0.113.9",)
    assert tuple(portal.allowlist_addresses("files.example", now=1.0)) == ("203.0.113.9",)
    registered(portal)
    decision = portal.authorize(MAC_KEY, ADDR, "203.0.113.9", now=2.0)
    assert decision.allowed is True
    assert decision.reason == "allowlist"


def test_snapshot_is_detached_and_restore_roundtrips():
    portal = gate(portal_hosts=("portal.example",))
    registered(portal)
    portal.update_allowlist("files.example", addresses=["203.0.113.9"], ttl=30.0, now=0.0)
    portal.consume_bytes(MAC_KEY, 100, now=1.0)
    state = portal.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "sessions", "allowlist", "stats"}

    state["sessions"].clear()
    state["stats"]["registered"] = 99
    assert portal.session_for(MAC_KEY) is not None
    assert portal.stats()["registered"] == 1

    clone = gate(portal_hosts=("portal.example",))
    clone.restore(pristine)
    session = clone.session_for(MAC_KEY)
    assert session.bytes_used == 100
    assert tuple(clone.allowlist_addresses("files.example", now=2.0)) == ("203.0.113.9",)
    assert clone.stats()["registered"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    portal = registered(gate())
    good = portal.snapshot()
    bad_states = [
        None,
        {},
        dict(good, version=2),
        dict(good, sessions="nope"),
        dict(good, allowlist=[]),
        dict(good, stats={"registered": 1}),
    ]
    for bad in bad_states:
        with pytest.raises(cpg.CaptiveError) as exc:
            portal.restore(bad)
        assert exc.value.code == "CAPTIVE_SNAPSHOT_INVALID"

    assert portal.session_for(MAC_KEY).state == "preauth"
    assert portal.stats()["registered"] == 1


def test_stats_track_portal_activity():
    portal = gate(portal_hosts=("portal.example",))
    registered(portal)
    portal.authorize(MAC_KEY, ADDR, "portal.example", now=1.0)
    portal.authorize(MAC_KEY, ADDR, "evil.example", now=1.0)
    portal.consume_bytes(MAC_KEY, 100, now=2.0)
    portal.complete_auth(MAC_KEY, now=3.0)
    portal.authorize(MAC_KEY, ADDR, "anywhere.example", now=4.0)
    assert portal.stats() == {
        "registered": 1,
        "authorized": 1,
        "allowed": 2,
        "denied": 1,
        "expired": 0,
        "bytes_consumed": 100,
    }
