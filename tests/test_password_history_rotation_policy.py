import copy
import threading

import pytest

import password_history_rotation_policy as php

NOW = 1_800_000_000
DAY = 86400


def policy(**kwargs):
    return php.PasswordHistoryPolicy(**kwargs)


def digest(tag):
    return f"{tag:016x}"


def test_enroll_creates_first_generation():
    pol = policy()
    entry = pol.enroll_account("u-1", digest=digest(1), now=NOW)
    assert entry.generation == 1
    assert entry.digest == digest(1)
    assert entry.created_at == NOW
    history = pol.history_of("u-1")
    assert [row.generation for row in history] == [1]
    state = pol.account_state("u-1", now=NOW)
    assert state.account == "u-1"
    assert state.generation == 1
    assert state.history_size == 1
    assert state.must_change is False
    assert state.expired is False
    assert state.grace_used == 0
    assert pol.stats() == {"enrolled": 1, "changed": 0, "reused": 0,
                           "resets": 0, "logins": 0, "trimmed": 0}


def test_change_to_current_digest_is_reused():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    out = pol.submit_change("u-1", digest=digest(1), now=NOW + 60)
    assert out.status == "rejected"
    assert out.code == "PWD_REUSED"
    assert out.generation == 1
    assert out.history_size == 1
    assert pol.stats()["reused"] == 1
    assert pol.stats()["changed"] == 0
    assert [row.generation for row in pol.history_of("u-1")] == [1]


def test_change_to_older_generation_is_reused():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    assert pol.submit_change("u-1", digest=digest(2), now=NOW + 60).status == "accepted"
    assert pol.submit_change("u-1", digest=digest(3), now=NOW + 120).status == "accepted"
    out = pol.submit_change("u-1", digest=digest(2), now=NOW + 180)
    assert out.code == "PWD_REUSED"
    assert out.generation == 3
    assert pol.account_state("u-1", now=NOW + 180).generation == 3
    assert pol.stats()["reused"] == 1


def test_accepted_change_bumps_generation_and_resets_flags():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    out = pol.submit_change("u-1", digest=digest(2), now=NOW + 60)
    assert out.status == "accepted"
    assert out.code == "PWD_CHANGED"
    assert out.generation == 2
    assert out.history_size == 2
    entries = pol.history_of("u-1")
    assert [(row.generation, row.digest) for row in entries] == [
        (1, digest(1)), (2, digest(2))]
    state = pol.account_state("u-1", now=NOW + 61)
    assert state.changed_at == NOW + 60
    assert state.must_change is False
    assert pol.stats()["changed"] == 1


def test_unknown_account_is_refused_everywhere():
    pol = policy()
    with pytest.raises(php.PasswordPolicyError) as exc:
        pol.submit_change("ghost", digest=digest(1), now=NOW)
    assert exc.value.code == "PWD_UNKNOWN_ACCOUNT"
    verdict = pol.check_login("ghost", now=NOW)
    assert verdict.action == "deny"
    assert verdict.reason == "PWD_UNKNOWN_ACCOUNT"
    assert verdict.entry_allowed is False
    assert verdict.grace_remaining == 0
    with pytest.raises(php.PasswordPolicyError) as exc:
        pol.admin_reset("ghost", digest=digest(1), now=NOW)
    assert exc.value.code == "PWD_UNKNOWN_ACCOUNT"


def test_invalid_digest_and_duplicate_account():
    pol = policy()
    for bad in ["", "short", "has space in it", "0123456789abcdef ", 12345678]:
        with pytest.raises(php.PasswordPolicyError) as exc:
            pol.enroll_account("u-1", digest=bad, now=NOW)
        assert exc.value.code == "PWD_INVALID_DIGEST"
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    with pytest.raises(php.PasswordPolicyError) as exc:
        pol.enroll_account("u-1", digest=digest(2), now=NOW)
    assert exc.value.code == "PWD_ACCOUNT_EXISTS"


def test_fresh_login_is_allowed():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    verdict = pol.check_login("u-1", now=NOW + DAY)
    assert verdict.action == "allow"
    assert verdict.reason == "PWD_FRESH"
    assert verdict.grace_remaining == 3
    assert verdict.entry_allowed is True
    assert pol.stats()["logins"] == 0


def test_expired_account_gets_grace_allowance():
    pol = policy(max_age_days=30, grace_logins=2)
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    verdict = pol.check_login("u-1", now=NOW + 30 * DAY + 5)
    assert verdict.action == "allow"
    assert verdict.reason == "PWD_EXPIRED_GRACE"
    assert verdict.grace_remaining == 2
    assert verdict.entry_allowed is True
    state = pol.account_state("u-1", now=NOW + 30 * DAY + 5)
    assert state.expired is True
    assert state.must_change is False


def test_record_login_only_consumes_grace_when_expired():
    pol = policy(max_age_days=30, grace_logins=2)
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    assert pol.record_login("u-1", now=NOW + DAY) == 2
    assert pol.account_state("u-1", now=NOW + DAY).grace_used == 0
    assert pol.record_login("u-1", now=NOW + 30 * DAY + 1) == 1
    assert pol.record_login("u-1", now=NOW + 30 * DAY + 2) == 0
    assert pol.account_state("u-1", now=NOW + 30 * DAY + 2).grace_used == 2
    assert pol.stats()["logins"] == 3


def test_admin_reset_sets_forced_change():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    entry = pol.admin_reset("u-1", digest=digest(9), now=NOW + 60)
    assert entry.generation == 2
    state = pol.account_state("u-1", now=NOW + 61)
    assert state.must_change is True
    assert state.generation == 2
    verdict = pol.check_login("u-1", now=NOW + 61)
    assert verdict.action == "change_required"
    assert verdict.reason == "PWD_RESET_REQUIRED"
    assert verdict.entry_allowed is True
    assert pol.stats()["resets"] == 1


def test_change_after_reset_clears_flag_and_keeps_history():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    pol.admin_reset("u-1", digest=digest(9), now=NOW + 60)
    out = pol.submit_change("u-1", digest=digest(2), now=NOW + 120)
    assert out.status == "accepted"
    assert out.generation == 3
    assert out.history_size == 3
    state = pol.account_state("u-1", now=NOW + 121)
    assert state.must_change is False
    assert [row.generation for row in pol.history_of("u-1")] == [1, 2, 3]


def test_policy_update_trims_history_to_new_depth():
    pol = policy(history_depth=12)
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    for index in range(2, 10):
        assert pol.submit_change("u-1", digest=digest(index),
                                 now=NOW + index * 60).status == "accepted"
    assert len(pol.history_of("u-1")) == 9
    settings = pol.update_policy(history_depth=4)
    assert settings == {"history_depth": 4, "max_age_days": 90, "grace_logins": 3}
    assert pol.history_depth == 4
    assert [row.generation for row in pol.history_of("u-1")] == [6, 7, 8, 9]
    assert pol.stats()["trimmed"] == 5


def test_snapshot_is_detached_and_restore_roundtrips():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    pol.submit_change("u-1", digest=digest(2), now=NOW + 60)
    pol.admin_reset("u-1", digest=digest(9), now=NOW + 120)
    state = pol.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "policy", "accounts", "stats"}
    state["accounts"].clear()
    state["stats"]["changed"] = 99
    assert pol.stats()["changed"] == 1
    assert pol.account_state("u-1", now=NOW + 121).must_change is True
    clone = policy()
    clone.restore(pristine)
    assert clone.stats() == pol.stats()
    assert [row.digest for row in clone.history_of("u-1")] == [
        digest(1), digest(2), digest(9)]
    assert clone.account_state("u-1", now=NOW + 121).must_change is True
    assert clone.check_login("u-1", now=NOW + 121).reason == "PWD_RESET_REQUIRED"


def test_restore_rejects_malformed_state():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "policy": {}, "accounts": {}, "stats": {}},
        {"version": 1, "policy": {"history_depth": 4}, "accounts": {}, "stats": {}},
        {"version": 1,
         "policy": {"history_depth": 4, "max_age_days": 90, "grace_logins": 3},
         "accounts": [], "stats": {}},
        {"version": 1,
         "policy": {"history_depth": 4, "max_age_days": 90, "grace_logins": 3},
         "accounts": {}, "stats": {"enrolled": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(php.PasswordPolicyError) as exc:
            pol.restore(bad)
        assert exc.value.code == "PWD_SNAPSHOT_INVALID"
    assert pol.stats()["enrolled"] == 1
    assert [row.generation for row in pol.history_of("u-1")] == [1]


def test_concurrent_change_same_digest_applies_once():
    pol = policy()
    pol.enroll_account("u-1", digest=digest(1), now=NOW)
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(pol.submit_change("u-1", digest=digest(7), now=NOW + 60))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert sum(1 for row in results if row.status == "accepted") == 1
    assert sum(1 for row in results if row.code == "PWD_REUSED") == 7
    assert pol.account_state("u-1", now=NOW + 61).generation == 2
    assert len(pol.history_of("u-1")) == 2
    assert pol.stats()["changed"] == 1
    assert pol.stats()["reused"] == 7
