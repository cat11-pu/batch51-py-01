import copy
import threading

import pytest

import dns_cookie_guard as dcg

SECRET = bytes(range(32))
SRC = "192.0.2.10"
OTHER = "198.51.100.7"


def guard(**kwargs):
    return dcg.DnsCookieGuard(SECRET, **kwargs)


def test_client_cookie_is_source_bound_hex():
    gate = guard()
    first = gate.client_cookie(SRC)
    second = gate.client_cookie(SRC)
    assert first == second
    assert len(first) == 16
    assert all(char in "0123456789abcdef" for char in first)
    assert gate.client_cookie(OTHER) != first


def test_server_cookie_is_deterministic_per_generation():
    gate = guard()
    issued = gate.issue_server_cookie(SRC)
    assert len(issued) == 32
    assert all(char in "0123456789abcdef" for char in issued)
    assert gate.issue_server_cookie(SRC) == issued
    assert gate.issue_server_cookie(OTHER) != issued


def test_valid_client_and_server_cookie_is_answered():
    gate = guard()
    client = gate.client_cookie(SRC)
    server = gate.issue_server_cookie(SRC)
    verdict = gate.verify(f"{client} {server}", SRC, now=0.0)
    assert verdict.action == "answer"
    assert verdict.server_cookie is None
    assert gate.stats()["answered"] == 1
    assert gate.stats()["queries"] == 1


def test_missing_server_cookie_answers_with_fresh_cookie():
    gate = guard()
    client = gate.client_cookie(SRC)
    verdict = gate.verify(client, SRC, now=0.0)
    assert verdict.action == "answer_with_cookie"
    assert isinstance(verdict.server_cookie, str)
    assert len(verdict.server_cookie) == 32
    follow_up = gate.verify(f"{client} {verdict.server_cookie}", SRC, now=1.0)
    assert follow_up.action == "answer"


def test_missing_client_cookie_is_retried_with_cookie():
    gate = guard()
    verdict = gate.verify("", SRC, now=0.0)
    assert verdict.action == "retry_with_cookie"
    assert isinstance(verdict.server_cookie, str)
    assert gate.stats()["missing_client"] == 1
    assert gate.stats()["retried"] == 1


def test_missing_budget_exhaustion_drops_requests():
    gate = guard(default_missing_budget=2)
    actions = [gate.verify("", SRC, now=0.0).action for _ in range(3)]
    assert actions == ["retry_with_cookie", "retry_with_cookie", "drop"]
    assert gate.stats()["retried"] == 2
    assert gate.stats()["dropped"] == 1
    assert gate.stats()["missing_client"] == 3


def test_rotation_keeps_previous_generation_verifiable():
    gate = guard(generation=1, overlap_generations=1)
    client = gate.client_cookie(SRC)
    old_server = gate.issue_server_cookie(SRC)
    assert gate.rotate_key(now=10.0) == 2
    assert tuple(gate.active_generations()) == (1, 2)
    assert gate.verify(f"{client} {old_server}", SRC, now=11.0).action == "answer"
    fresh = gate.issue_server_cookie(SRC)
    assert fresh != old_server
    assert gate.verify(f"{client} {fresh}", SRC, now=11.0).action == "answer"


def test_sweep_retires_generations_beyond_overlap():
    gate = guard(generation=1, overlap_generations=1)
    gate.rotate_key(now=1.0)
    gate.rotate_key(now=2.0)
    assert tuple(gate.active_generations()) == (1, 2, 3)
    assert gate.sweep(now=3.0) == 1
    assert tuple(gate.active_generations()) == (2, 3)


def test_concurrent_rotation_at_same_moment_takes_effect_once():
    gate = guard(generation=1)
    errors = []
    results = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(gate.rotate_key(now=100.0))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert set(results) == {2}
    assert tuple(gate.active_generations()) == (2,)
    assert gate.stats()["rotations"] == 1


def test_source_policies_default_and_override():
    gate = guard()
    default = gate.policy_for(SRC)
    assert (default.source, default.cookie_required, default.missing_budget,
            default.amplification_budget) == (SRC, True, 3, 4096)
    updated = gate.set_source_policy(SRC, missing_budget=5, amplification_budget=512)
    assert updated.missing_budget == 5
    assert updated.amplification_budget == 512
    assert gate.policy_for(SRC).amplification_budget == 512
    assert gate.policy_for(OTHER).missing_budget == 3


def test_invalid_arguments_are_rejected():
    with pytest.raises(dcg.DnsCookieError) as exc:
        dcg.DnsCookieGuard(b"short")
    assert exc.value.code == "DNS_COOKIE_INVALID_ARGUMENT"
    gate = guard()
    with pytest.raises(dcg.DnsCookieError) as exc:
        gate.client_cookie("   ")
    assert exc.value.code == "DNS_COOKIE_INVALID_ARGUMENT"
    with pytest.raises(dcg.DnsCookieError) as exc:
        gate.set_source_policy(SRC, missing_budget=-1)
    assert exc.value.code == "DNS_COOKIE_INVALID_ARGUMENT"
    with pytest.raises(dcg.DnsCookieError) as exc:
        gate.note_amplification(SRC, -5, now=0.0)
    assert exc.value.code == "DNS_COOKIE_INVALID_ARGUMENT"


def test_amplification_quota_is_capped_and_isolated_per_source():
    gate = guard()
    gate.set_source_policy(SRC, amplification_budget=1000)
    assert gate.quota_remaining(SRC, now=0.0) == 1000
    assert gate.note_amplification(SRC, 400, now=0.0) == 400
    assert gate.quota_remaining(SRC, now=0.0) == 600
    assert gate.note_amplification(SRC, 9000, now=0.0) == 600
    assert gate.quota_remaining(SRC, now=1.0) == 0
    assert gate.quota_remaining(OTHER, now=0.0) == 4096


def test_stats_track_verdicts_and_rotations():
    gate = guard()
    client = gate.client_cookie(SRC)
    server = gate.issue_server_cookie(SRC)
    gate.verify(f"{client} {server}", SRC, now=0.0)
    gate.verify("", SRC, now=0.0)
    forged = "0123456789abcdef"
    assert gate.verify(forged, SRC, now=0.0).action == "drop"
    gate.rotate_key(now=1.0)
    assert gate.stats() == {
        "queries": 3,
        "answered": 1,
        "retried": 1,
        "dropped": 1,
        "truncated": 0,
        "missing_client": 1,
        "bad_server": 0,
        "rotations": 1,
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    gate = guard()
    client = gate.client_cookie(SRC)
    server = gate.issue_server_cookie(SRC)
    gate.set_source_policy(SRC, missing_budget=7)
    state = gate.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "generation", "active", "policies",
                             "windows", "stats"}

    state["policies"].clear()
    state["stats"]["answered"] = 999
    assert gate.policy_for(SRC).missing_budget == 7
    assert gate.stats()["answered"] == 0

    clone = guard()
    clone.restore(pristine)
    assert clone.policy_for(SRC).missing_budget == 7
    assert clone.verify(f"{client} {server}", SRC, now=0.0).action == "answer"


def test_restore_rejects_malformed_state_without_touching_live_data():
    gate = guard()
    server = gate.issue_server_cookie(SRC)
    good = gate.snapshot()
    bad_states = [
        None,
        {},
        dict(good, version=2),
        dict(good, active="1,2"),
        dict(good, policies=[]),
        dict(good, stats={"queries": 0}),
    ]
    for bad in bad_states:
        with pytest.raises(dcg.DnsCookieError) as exc:
            gate.restore(bad)
        assert exc.value.code == "DNS_COOKIE_SNAPSHOT_INVALID"

    assert tuple(gate.active_generations()) == (1,)
    assert gate.issue_server_cookie(SRC) == server
    assert gate.stats()["queries"] == 0
