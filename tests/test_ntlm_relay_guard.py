import copy
import hashlib
import threading

import pytest

import ntlm_relay_guard as ng

NOW = "2026-11-27T10:00:00+00:00"


def guard(**kwargs):
    return ng.NtlmRelayGuard(**kwargs)


def bound_guard(**kwargs):
    instance = guard(**kwargs)
    instance.register_target(service_id="svc-a", channel_id="ch-a",
                             epa_policy="optional")
    instance.register_target(service_id="svc-b", channel_id="ch-b",
                             epa_policy="optional")
    return instance


def response_digest(nonce, account, channel_id):
    return hashlib.sha256(f"{nonce}|{account}|{channel_id}".encode("utf-8")).hexdigest()


def test_register_target_and_unknown_target_is_refused():
    instance = guard()
    instance.register_target(service_id="svc-a", channel_id="ch-a",
                             epa_policy="required")
    info = instance.target_info("svc-a")
    assert (info.service_id, info.channel_id, info.epa_policy) == (
        "svc-a", "ch-a", "required")

    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.issue_challenge(account="u1", service_id="svc-x",
                                 channel_id="ch-x", now=NOW)
    assert exc.value.code == "NTLM_TARGET_UNKNOWN"

    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.register_target(service_id="", channel_id="ch-a")
    assert exc.value.code == "NTLM_REQUEST_INVALID"


def test_issue_challenge_binds_service_channel_and_expiry():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-1", now=NOW)
    assert challenge.challenge_id
    assert (challenge.account, challenge.service_id, challenge.channel_id) == (
        "u1", "svc-a", "ch-a")
    assert (challenge.nonce, challenge.state) == ("n-1", "pending")
    assert challenge.issued_at == NOW
    assert challenge.expires_at == "2026-11-27T10:02:00+00:00"
    assert [item.challenge_id for item in instance.pending_for("u1", now=NOW)] == [
        challenge.challenge_id]
    assert instance.stats()["issued"] == 1


def test_issue_challenge_rejects_channel_not_registered_for_target():
    instance = bound_guard()
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.issue_challenge(account="u1", service_id="svc-a",
                                 channel_id="ch-b", now=NOW)
    assert exc.value.code == "NTLM_CHANNEL_MISMATCH"
    assert instance.stats()["issued"] == 0
    assert instance.pending_for("u1", now=NOW) == []


def test_pending_limit_per_account_is_enforced_and_released():
    instance = bound_guard(max_pending_per_account=2)
    first = instance.issue_challenge(account="u1", service_id="svc-a",
                                     channel_id="ch-a", nonce="n-1", now=NOW)
    instance.issue_challenge(account="u1", service_id="svc-a",
                             channel_id="ch-a", nonce="n-2", now=NOW)
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.issue_challenge(account="u1", service_id="svc-a",
                                 channel_id="ch-a", nonce="n-3", now=NOW)
    assert exc.value.code == "NTLM_PENDING_LIMIT"

    instance.verify_response(challenge_id=first.challenge_id, account="u1",
                             channel_id="ch-a",
                             response_digest=response_digest("n-1", "u1", "ch-a"),
                             now=NOW)
    third = instance.issue_challenge(account="u1", service_id="svc-a",
                                     channel_id="ch-a", nonce="n-4", now=NOW)
    assert third.state == "pending"
    assert instance.stats()["issued"] == 3


def test_bind_target_moves_challenge_between_targets():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-7", now=NOW)
    moved = instance.bind_target(challenge_id=challenge.challenge_id,
                                 service_id="svc-b", channel_id="ch-b", now=NOW)
    assert (moved.service_id, moved.channel_id, moved.state) == (
        "svc-b", "ch-b", "pending")

    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.verify_response(
            challenge_id=challenge.challenge_id, account="u1", channel_id="ch-a",
            response_digest=response_digest("n-7", "u1", "ch-a"), now=NOW)
    assert exc.value.code == "NTLM_CHANNEL_MISMATCH"

    verdict = instance.verify_response(
        challenge_id=challenge.challenge_id, account="u1", channel_id="ch-b",
        response_digest=response_digest("n-7", "u1", "ch-b"), now=NOW)
    assert verdict.status == "accepted"
    assert verdict.service_id == "svc-b"
    assert verdict.channel_id == "ch-b"


def test_bind_target_refused_after_challenge_consumed():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-2", now=NOW)
    instance.verify_response(challenge_id=challenge.challenge_id, account="u1",
                             channel_id="ch-a",
                             response_digest=response_digest("n-2", "u1", "ch-a"),
                             now=NOW)
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.bind_target(challenge_id=challenge.challenge_id,
                             service_id="svc-b", channel_id="ch-b", now=NOW)
    assert exc.value.code == "NTLM_CHALLENGE_CONSUMED"


def test_verify_accepts_once_and_closes_challenge():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-3", now=NOW)
    verdict = instance.verify_response(
        challenge_id=challenge.challenge_id, account="u1", channel_id="ch-a",
        response_digest=response_digest("n-3", "u1", "ch-a"), now=NOW)
    assert verdict.status == "accepted"
    assert (verdict.challenge_id, verdict.account) == (
        challenge.challenge_id, "u1")
    assert instance.pending_for("u1", now=NOW) == []
    assert instance.stats() == {"issued": 1, "accepted": 1, "replayed": 0,
                               "mismatch": 0, "expired": 0, "epa_rejected": 0}


def test_second_submission_of_same_challenge_is_replay():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-4", now=NOW)
    digest = response_digest("n-4", "u1", "ch-a")
    instance.verify_response(challenge_id=challenge.challenge_id, account="u1",
                             channel_id="ch-a", response_digest=digest, now=NOW)
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.verify_response(challenge_id=challenge.challenge_id,
                                 account="u1", channel_id="ch-a",
                                 response_digest=digest, now=NOW)
    assert exc.value.code == "NTLM_REPLAY_DETECTED"
    assert instance.stats()["accepted"] == 1
    assert instance.stats()["replayed"] == 1


def test_verify_rejects_other_account_without_consuming():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-5", now=NOW)
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.verify_response(
            challenge_id=challenge.challenge_id, account="u2", channel_id="ch-a",
            response_digest=response_digest("n-5", "u2", "ch-a"), now=NOW)
    assert exc.value.code == "NTLM_ACCOUNT_MISMATCH"
    assert instance.stats()["mismatch"] == 1
    assert [item.challenge_id for item in instance.pending_for("u1", now=NOW)] == [
        challenge.challenge_id]


def test_verify_digest_mismatch_keeps_challenge_usable():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-6", now=NOW)
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.verify_response(challenge_id=challenge.challenge_id,
                                 account="u1", channel_id="ch-a",
                                 response_digest="0" * 64, now=NOW)
    assert exc.value.code == "NTLM_RESPONSE_MISMATCH"
    assert instance.stats()["mismatch"] == 1

    verdict = instance.verify_response(
        challenge_id=challenge.challenge_id, account="u1", channel_id="ch-a",
        response_digest=response_digest("n-6", "u1", "ch-a"), now=NOW)
    assert verdict.status == "accepted"


def test_expiry_boundary_and_expire_sweep():
    instance = bound_guard(challenge_ttl=60)
    accepted = instance.issue_challenge(account="u1", service_id="svc-a",
                                        channel_id="ch-a", nonce="n-8", now=NOW)
    verdict = instance.verify_response(
        challenge_id=accepted.challenge_id, account="u1", channel_id="ch-a",
        response_digest=response_digest("n-8", "u1", "ch-a"),
        now="2026-11-27T10:01:00+00:00")
    assert verdict.status == "accepted"

    late = instance.issue_challenge(account="u1", service_id="svc-a",
                                    channel_id="ch-a", nonce="n-9", now=NOW)
    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.verify_response(
            challenge_id=late.challenge_id, account="u1", channel_id="ch-a",
            response_digest=response_digest("n-9", "u1", "ch-a"),
            now="2026-11-27T10:01:01+00:00")
    assert exc.value.code == "NTLM_CHALLENGE_EXPIRED"

    instance.issue_challenge(account="u1", service_id="svc-a",
                             channel_id="ch-a", nonce="n-10", now=NOW)
    assert instance.expire_pending(now="2026-11-27T10:01:01+00:00") == 1
    assert instance.pending_for("u1", now="2026-11-27T10:01:01+00:00") == []
    assert instance.stats()["expired"] == 2
    assert instance.stats()["issued"] == 3


def test_concurrent_submissions_yield_single_acceptance():
    instance = bound_guard(max_pending_per_account=16)
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-11", now=NOW)
    digest = response_digest("n-11", "u1", "ch-a")
    accepted = []
    errors = []
    barrier = threading.Barrier(12)

    def worker():
        try:
            barrier.wait(timeout=5)
            verdict = instance.verify_response(
                challenge_id=challenge.challenge_id, account="u1",
                channel_id="ch-a", response_digest=digest, now=NOW)
            accepted.append(verdict.status)
        except ng.NtlmRelayError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert accepted == ["accepted"]
    assert errors.count("NTLM_REPLAY_DETECTED") == 11
    assert instance.stats()["accepted"] == 1
    assert instance.stats()["replayed"] == 11


def test_check_epa_reports_disabled_policy():
    instance = guard()
    instance.register_target(service_id="svc-a", channel_id="ch-a",
                             epa_policy="off")
    verdict = instance.check_epa(service_id="svc-a")
    assert (verdict.service_id, verdict.policy, verdict.status) == (
        "svc-a", "off", "disabled")
    assert verdict.bound is False

    with pytest.raises(ng.NtlmRelayError) as exc:
        instance.check_epa(service_id="svc-missing")
    assert exc.value.code == "NTLM_TARGET_UNKNOWN"


def test_snapshot_is_detached_and_restore_roundtrips():
    instance = bound_guard()
    challenge = instance.issue_challenge(account="u1", service_id="svc-a",
                                         channel_id="ch-a", nonce="n-12", now=NOW)
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "targets", "challenges", "stats"}

    state["stats"]["issued"] = 99
    state["challenges"].clear()
    assert instance.stats()["issued"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.target_info("svc-b").channel_id == "ch-b"
    verdict = clone.verify_response(
        challenge_id=challenge.challenge_id, account="u1", channel_id="ch-a",
        response_digest=response_digest("n-12", "u1", "ch-a"), now=NOW)
    assert verdict.status == "accepted"
    assert clone.pending_for("u1", now=NOW) == []


def test_restore_rejects_malformed_snapshot_without_mutating_live_state():
    instance = bound_guard()
    instance.issue_challenge(account="u1", service_id="svc-a",
                             channel_id="ch-a", nonce="n-13", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "targets": {}, "challenges": [], "stats": {}},
        {"version": 1, "targets": [], "challenges": [], "stats": {}},
        {"version": 1, "targets": {}, "challenges": "nope", "stats": {}},
        {"version": 1, "targets": {}, "challenges": [],
         "stats": {"issued": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ng.NtlmRelayError) as exc:
            instance.restore(bad)
        assert exc.value.code == "NTLM_SNAPSHOT_INVALID"

    assert instance.stats()["issued"] == 1
    assert len(instance.pending_for("u1", now=NOW)) == 1
