import copy
import re

import pytest

import session_fixation_guard as sf

NOW = "2026-11-27T10:00:00+00:00"
LATER = "2026-11-27T10:05:00+00:00"
SID = "0123456789abcdef0123456789abcdef"


def guard(**kwargs):
    return sf.SessionFixationGuard(**kwargs)


def test_create_session_issues_hex_identifier_and_defaults():
    gen = guard()
    sid = gen.create_session(now=NOW)
    assert re.fullmatch(r"[0-9a-f]{32}", sid)
    record = gen.session_record(sid, now=NOW)
    assert record.sid == sid
    assert record.user is None
    assert record.auth_level == 0
    assert record.generation == 0
    assert record.fingerprint is None
    assert record.created_at == NOW
    assert record.rotated_at == NOW
    assert gen.stats()["created"] == 1


def test_create_session_for_user_and_sessions_for_order():
    gen = guard()
    first = gen.create_session(user="u1", now="2026-11-27T10:00:00+00:00")
    second = gen.create_session(user="u1", now="2026-11-27T10:01:00+00:00")
    third = gen.create_session(user="u2", now="2026-11-27T10:02:00+00:00")
    rows = gen.sessions_for("u1")
    assert [row.sid for row in rows] == [first, second]
    assert gen.session_record(first, now=NOW).auth_level == 1
    assert gen.sessions_for("nobody") == ()
    assert [row.sid for row in gen.sessions()] == [first, second, third]


def test_total_session_cap_refuses_extra_session():
    gen = guard(max_sessions_total=2)
    gen.create_session(now=NOW)
    gen.create_session(now=NOW)
    with pytest.raises(sf.SessionError) as exc:
        gen.create_session(now=NOW)
    assert exc.value.code == "SESSION_LIMIT_EXCEEDED"
    assert gen.stats()["created"] == 2
    assert gen.stats()["rejected"] == 1
    assert len(gen.sessions()) == 2


def test_rotate_reissues_identifier_and_retires_old_one():
    gen = guard()
    sid = gen.create_session(now=NOW)
    new_sid = gen.rotate(sid, now=LATER)
    assert new_sid != sid
    assert re.fullmatch(r"[0-9a-f]{32}", new_sid)
    record = gen.session_record(new_sid, now=LATER)
    assert record.generation == 1
    assert record.created_at == NOW
    assert record.rotated_at == LATER
    with pytest.raises(sf.SessionError) as exc:
        gen.session_record(sid, now=LATER)
    assert exc.value.code == "SESSION_UNKNOWN"
    assert gen.stats()["rotated"] == 1
    assert gen.audit_log()[1].event == "rotate"


def test_unknown_identifier_is_refused_everywhere():
    gen = guard()
    calls = [
        lambda: gen.rotate("0" * 32, now=NOW),
        lambda: gen.login("0" * 32, user="u1", now=NOW),
        lambda: gen.elevate("0" * 32, level=2, now=NOW),
    ]
    for call in calls:
        with pytest.raises(sf.SessionError) as exc:
            call()
        assert exc.value.code == "SESSION_UNKNOWN"
    assert gen.stats()["rejected"] == 3


def test_elevate_raises_level_and_rotates_identifier():
    gen = guard()
    sid = gen.create_session(user="u1", now=NOW)
    new_sid = gen.elevate(sid, level=2, now=LATER)
    assert new_sid != sid
    record = gen.session_record(new_sid, now=LATER)
    assert record.auth_level == 2
    assert record.generation == 1
    assert record.user == "u1"
    with pytest.raises(sf.SessionError) as exc:
        gen.session_record(sid, now=LATER)
    assert exc.value.code == "SESSION_UNKNOWN"
    assert gen.stats()["elevated"] == 1


def test_elevate_rejects_non_increasing_and_out_of_range_levels():
    gen = guard()
    sid = gen.create_session(user="u1", now=NOW)
    with pytest.raises(sf.SessionError) as exc:
        gen.elevate(sid, level=1, now=NOW)
    assert exc.value.code == "SESSION_LEVEL_NOT_RAISED"
    with pytest.raises(sf.SessionError) as exc:
        gen.elevate(sid, level=0, now=NOW)
    assert exc.value.code == "SESSION_INVALID_LEVEL"
    with pytest.raises(sf.SessionError) as exc:
        gen.elevate(sid, level=4, now=NOW)
    assert exc.value.code == "SESSION_INVALID_LEVEL"
    assert gen.session_record(sid, now=NOW).generation == 0
    assert gen.stats()["rejected"] == 3


def test_logout_is_idempotent():
    gen = guard()
    sid = gen.create_session(user="u1", now=NOW)
    assert gen.logout(sid, now=NOW) is True
    assert gen.logout(sid, now=NOW) is False
    with pytest.raises(sf.SessionError) as exc:
        gen.session_record(sid, now=NOW)
    assert exc.value.code == "SESSION_UNKNOWN"
    assert gen.stats()["revoked"] == 1


def test_revoke_user_clears_only_that_users_sessions():
    gen = guard()
    gen.create_session(user="u1", now=NOW)
    gen.create_session(user="u1", now=NOW)
    survivor = gen.create_session(user="u2", now=NOW)
    assert gen.revoke_user("u1", now=NOW) == 2
    assert gen.sessions_for("u1") == ()
    assert [row.sid for row in gen.sessions_for("u2")] == [survivor]
    assert gen.revoke_user("u1", now=NOW) == 0
    assert gen.stats()["revoked"] == 2


def test_bound_fingerprint_mismatch_is_refused():
    gen = guard()
    sid = gen.create_session(user="u1", fingerprint="fp-a", now=NOW)
    with pytest.raises(sf.SessionError) as exc:
        gen.session_record(sid, fingerprint="fp-b", now=NOW)
    assert exc.value.code == "SESSION_FINGERPRINT_MISMATCH"
    assert gen.session_record(sid, fingerprint="fp-a", now=NOW).sid == sid
    assert gen.stats()["rejected"] == 1


def test_idle_session_expires_and_is_purged():
    gen = guard(idle_timeout=60)
    sid = gen.create_session(now=NOW)
    assert gen.revoke_expired(now="2026-11-27T10:00:30+00:00") == 0
    with pytest.raises(sf.SessionError) as exc:
        gen.session_record(sid, now="2026-11-27T10:02:00+00:00")
    assert exc.value.code == "SESSION_EXPIRED"
    assert gen.revoke_expired(now="2026-11-27T10:02:00+00:00") == 1
    assert gen.stats()["expired"] == 1
    assert gen.revoke_expired(now="2026-11-27T10:03:00+00:00") == 0


def test_issued_cookie_carries_host_prefix_defaults():
    gen = guard()
    sid = gen.create_session(now=NOW)
    spec = gen.issue_cookie(sid, now=NOW)
    assert spec.name == "__Host-SID"
    assert spec.value == sid
    assert spec.secure is True
    assert spec.http_only is True
    assert spec.path == "/"
    assert spec.domain is None
    assert spec.same_site == "Lax"


def test_validate_cookie_accepts_scoped_cookies():
    gen = guard()
    host = gen.validate_cookie("__Host-SID=" + SID + "; Secure; Path=/; HttpOnly; SameSite=Lax")
    assert (host.name, host.value, host.secure, host.http_only, host.path) == (
        "__Host-SID", SID, True, True, "/")
    assert host.domain is None
    assert host.same_site == "Lax"

    secure_prefix = gen.validate_cookie(
        "__Secure-SID=" + SID + "; Secure; Domain=example.com; Path=/app")
    assert secure_prefix.domain == "example.com"
    assert secure_prefix.path == "/app"
    assert secure_prefix.secure is True

    plain = gen.validate_cookie("SID=" + SID)
    assert plain.secure is False
    assert plain.http_only is False
    assert plain.domain is None
    assert plain.path == "/"
    assert plain.same_site == "Lax"


def test_validate_cookie_rejects_broken_attribute_sets():
    gen = guard()
    cases = [
        ("__Host-SID=" + SID + "; Path=/; HttpOnly", "COOKIE_INSECURE_PREFIX"),
        ("__Host-SID=" + SID + "; Secure; Path=/app", "COOKIE_INVALID_PATH"),
        ("__Secure-SID=" + SID + "; Domain=example.com; Path=/", "COOKIE_INSECURE_PREFIX"),
        ("SID=" + SID + "; SameSite=None", "COOKIE_SAMESITE_NONE_REQUIRES_SECURE"),
        ("SID=" + SID + "; Secure; Secure", "COOKIE_DUPLICATE_ATTRIBUTE"),
        ("SID=" + SID + "; Weird=1", "COOKIE_UNKNOWN_ATTRIBUTE"),
        ("SID", "COOKIE_MALFORMED"),
        ("SID=short; Secure", "COOKIE_INVALID_VALUE"),
    ]
    for raw, code in cases:
        with pytest.raises(sf.SessionError) as exc:
            gen.validate_cookie(raw)
        assert exc.value.code == code
    assert gen.stats()["rejected"] == len(cases)


def test_snapshot_restore_roundtrip_and_invalid_state():
    gen = guard()
    sid = gen.create_session(user="u1", now=NOW)
    new_sid = gen.elevate(sid, level=2, now=LATER)
    state = gen.snapshot()
    assert set(state) == {"version", "sessions", "audit", "counters", "seq"}
    pristine = copy.deepcopy(state)

    state["sessions"].clear()
    assert gen.session_record(new_sid, now=LATER).auth_level == 2

    clone = guard()
    clone.restore(pristine)
    assert clone.session_record(new_sid, now=LATER).auth_level == 2
    assert clone.stats()["created"] == 1
    assert clone.stats()["restored"] == 1

    with pytest.raises(sf.SessionError) as exc:
        clone.restore({"version": 1, "sessions": "nope"})
    assert exc.value.code == "SESSION_SNAPSHOT_INVALID"
    assert clone.stats()["created"] == 1
    assert clone.stats()["restored"] == 1
