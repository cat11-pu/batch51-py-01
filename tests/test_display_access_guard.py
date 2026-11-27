import copy
import threading

import pytest

import display_access_guard as dg

NOW = 1000
LATER = 1001


def guard(**kwargs):
    return dg.DisplayAccessGuard(**kwargs)


def opened(**kwargs):
    options = dict(uid=1000, display=0, seat="seat0", now=NOW)
    options.update(kwargs)
    return options


def zero_counters():
    return {"sessions_opened": 0, "credentials_issued": 0, "credentials_rotated": 0,
            "denied": 0, "revoked": 0, "sessions_closed": 0}


def test_open_session_records_owner_and_rejects_duplicate():
    g = guard()
    record = g.open_session("seat0-s1", **opened())
    assert (record.session_id, record.uid, record.display, record.seat) == (
        "seat0-s1", 1000, 0, "seat0")
    assert record.opened_at == NOW
    assert record.closed is False

    with pytest.raises(dg.DisplayError) as exc:
        g.open_session("seat0-s1", **opened(now=LATER))
    assert exc.value.code == "DISPLAY_SESSION_EXISTS"

    assert [row.session_id for row in g.sessions()] == ["seat0-s1"]
    assert g.stats()["sessions_opened"] == 1


def test_issue_credential_binds_session_client_and_mode():
    g = guard()
    g.open_session("s1", **opened())
    cred = g.issue_credential("s1", client_addr="127.0.0.1:41000",
                              file_mode=0o600, now=NOW)
    assert (cred.session_id, cred.uid, cred.display) == ("s1", 1000, 0)
    assert cred.client_addr == "127.0.0.1:41000"
    assert cred.file_mode == 0o600
    assert cred.issued_at == NOW
    assert cred.expires_at == NOW + 300
    assert isinstance(cred.token, str) and len(cred.token) >= 16

    active = g.active_credential("s1")
    assert active is not None and active.token == cred.token
    assert g.credentials_for("s1") == (cred,)
    assert g.stats()["credentials_issued"] == 1


def test_issue_second_credential_replaces_active_one():
    g = guard()
    g.open_session("s1", **opened())
    first = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)
    second = g.issue_credential("s1", client_addr="cli-2", file_mode=0o600, now=LATER)

    assert first.token != second.token
    assert g.active_credential("s1").token == second.token
    assert [c.token for c in g.credentials_for("s1")] == [first.token, second.token]
    assert g.stats()["credentials_rotated"] == 1

    stale = g.authorize(first.token, client_addr="cli-1", session_id="s1",
                        action="screenshot", now=LATER)
    assert (stale.status, stale.code) == ("deny", "CREDENTIAL_REVOKED")


def test_authorize_requires_matching_client_address():
    g = guard()
    g.open_session("s1", **opened())
    g.grant_capability("s1", "screenshot", now=NOW)
    cred = g.issue_credential("s1", client_addr="127.0.0.1:41000",
                              file_mode=0o600, now=NOW)

    denied = g.authorize(cred.token, client_addr="127.0.0.1:41001",
                         session_id="s1", action="screenshot", now=NOW)
    assert (denied.status, denied.code) == ("deny", "CLIENT_MISMATCH")

    allowed = g.authorize(cred.token, client_addr="127.0.0.1:41000",
                          session_id="s1", action="screenshot", now=NOW)
    assert (allowed.status, allowed.code) == ("allow", "")


def test_authorize_rejects_unknown_and_expired_credential():
    g = guard()
    g.open_session("s1", **opened())
    unknown = g.authorize("no-such-token", client_addr="cli-1", session_id="s1",
                          action="screenshot", now=NOW)
    assert (unknown.status, unknown.code) == ("deny", "CREDENTIAL_UNKNOWN")

    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)
    expired = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                          action="screenshot", now=cred.expires_at)
    assert (expired.status, expired.code) == ("deny", "CREDENTIAL_EXPIRED")


def test_screenshot_capability_grants_only_that_action():
    g = guard()
    g.open_session("s1", **opened())
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)

    missing = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                          action="screenshot", now=NOW)
    assert (missing.status, missing.code) == ("deny", "CAPABILITY_MISSING")

    assert g.grant_capability("s1", "screenshot", now=NOW) == ("screenshot",)
    allowed = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                          action="screenshot", now=NOW)
    assert (allowed.status, allowed.code) == ("allow", "")
    assert (allowed.session_id, allowed.action, allowed.uid) == ("s1", "screenshot", 1000)


def test_input_capability_is_independent_from_screenshot():
    g = guard()
    g.open_session("s1", **opened())
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)
    g.grant_capability("s1", "input", now=NOW)

    injected = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                           action="input", now=NOW)
    assert (injected.status, injected.code) == ("allow", "")

    captured = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                           action="screenshot", now=NOW)
    assert (captured.status, captured.code) == ("deny", "CAPABILITY_MISSING")


def test_revoke_capability_takes_effect_immediately():
    g = guard()
    g.open_session("s1", **opened())
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)
    g.grant_capability("s1", "screenshot", now=NOW)

    assert g.revoke_capability("s1", "screenshot") is True
    assert g.revoke_capability("s1", "screenshot") is False
    assert g.capabilities("s1") == ()

    denied = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                         action="screenshot", now=NOW)
    assert (denied.status, denied.code) == ("deny", "CAPABILITY_MISSING")


def test_close_session_cascades_credentials_and_capabilities():
    g = guard()
    g.open_session("s1", **opened())
    g.open_session("s2", **opened(uid=1001, display=1, seat="seat1"))
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)
    g.grant_capability("s1", "screenshot", now=NOW)

    assert g.close_session("s1", now=LATER) == 1
    assert g.active_credential("s1") is None
    assert g.capabilities("s1") == ()

    denied = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                         action="screenshot", now=LATER)
    assert (denied.status, denied.code) == ("deny", "SESSION_CLOSED")

    assert [row.session_id for row in g.sessions()] == ["s2"]
    assert g.stats()["sessions_closed"] == 1


def test_capabilities_are_sorted_and_session_scoped():
    g = guard()
    g.open_session("s1", **opened())
    assert g.grant_capability("s1", "screenshot", now=NOW) == ("screenshot",)
    assert g.grant_capability("s1", "input", now=NOW) == ("input", "screenshot")
    assert g.capabilities("s1") == ("input", "screenshot")

    with pytest.raises(dg.DisplayError) as exc:
        g.grant_capability("s1", "clipboard", now=NOW)
    assert exc.value.code == "DISPLAY_CAPABILITY_UNKNOWN"

    with pytest.raises(dg.DisplayError) as exc:
        g.capabilities("s9")
    assert exc.value.code == "DISPLAY_SESSION_UNKNOWN"


def test_cross_session_authorization_is_denied():
    g = guard()
    g.open_session("s1", **opened())
    g.open_session("s2", **opened(uid=1001, display=1, seat="seat1"))
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)
    g.grant_capability("s1", "screenshot", now=NOW)
    g.grant_capability("s2", "screenshot", now=NOW)

    crossed = g.authorize(cred.token, client_addr="cli-1", session_id="s2",
                          action="screenshot", now=NOW)
    assert (crossed.status, crossed.code) == ("deny", "SESSION_MISMATCH")
    assert crossed.session_id == "s2"

    own = g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                      action="screenshot", now=NOW)
    assert own.status == "allow"


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    g.open_session("s1", **opened())
    g.grant_capability("s1", "screenshot", now=NOW)
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)

    state = g.snapshot()
    assert set(state) == {"version", "sessions", "credentials", "capabilities", "counters"}
    pristine = copy.deepcopy(state)
    state["sessions"].clear()
    state["counters"]["sessions_opened"] = 99
    assert len(g.sessions()) == 1
    assert g.stats()["sessions_opened"] == 1

    clone = guard()
    clone.restore(copy.deepcopy(pristine))
    assert clone.stats() == g.stats()
    assert clone.active_credential("s1").token == cred.token
    decision = clone.authorize(cred.token, client_addr="cli-1", session_id="s1",
                               action="screenshot", now=NOW)
    assert decision.status == "allow"


def test_restore_rejects_malformed_state_without_touching_live_data():
    g = guard()
    g.open_session("s1", **opened())
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)

    bad_states = [
        None,
        {},
        {"version": 1, "sessions": [], "credentials": {},
         "capabilities": {}, "counters": zero_counters()},
        {"version": 1, "sessions": {}, "credentials": [],
         "capabilities": {}, "counters": zero_counters()},
        {"version": 1, "sessions": {}, "credentials": {},
         "capabilities": {}, "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(dg.DisplayError) as exc:
            g.restore(bad)
        assert exc.value.code == "DISPLAY_SNAPSHOT_INVALID"

    assert g.active_credential("s1").token == cred.token
    assert g.stats()["sessions_opened"] == 1


def test_stats_track_each_operation_exactly():
    g = guard()
    g.open_session("s1", **opened())
    g.grant_capability("s1", "screenshot", now=NOW)
    cred = g.issue_credential("s1", client_addr="cli-1", file_mode=0o600, now=NOW)

    g.authorize("bogus", client_addr="cli-1", session_id="s1",
                action="screenshot", now=LATER)
    g.authorize(cred.token, client_addr="wrong", session_id="s1",
                action="screenshot", now=LATER)
    g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                action="screenshot", now=LATER)
    g.revoke_credential(cred.token, now=LATER)
    g.authorize(cred.token, client_addr="cli-1", session_id="s1",
                action="screenshot", now=LATER)
    assert g.close_session("s1", now=LATER) == 0

    assert g.stats() == {"sessions_opened": 1, "credentials_issued": 1,
                         "credentials_rotated": 0, "denied": 3,
                         "revoked": 1, "sessions_closed": 1}


def test_concurrent_issue_leaves_single_active_credential():
    g = guard()
    g.open_session("s1", **opened())
    workers = 12
    errors = []
    barrier = threading.Barrier(workers)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            g.issue_credential("s1", client_addr=f"cli-{index:02d}",
                               file_mode=0o600, now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(g.credentials_for("s1")) == workers
    assert g.active_credential("s1") is not None
    assert g.stats()["credentials_issued"] == workers
    assert g.stats()["credentials_rotated"] == workers - 1

    active_token = g.active_credential("s1").token
    stale = [c for c in g.credentials_for("s1") if c.token != active_token]
    assert len(stale) == workers - 1
    for cred in stale:
        decision = g.authorize(cred.token, client_addr=cred.client_addr,
                               session_id="s1", action="screenshot", now=NOW)
        assert decision.code == "CREDENTIAL_REVOKED"
