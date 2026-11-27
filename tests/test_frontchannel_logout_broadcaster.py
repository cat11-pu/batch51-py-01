import copy
import hashlib
import threading

import pytest

import frontchannel_logout_broadcaster as fb

NOW = "2026-11-27T10:00:00+00:00"
DEADLINE = "2026-11-27T10:00:02+00:00"


def builder(**kwargs):
    return fb.FrontchannelLogoutBroadcaster(**kwargs)


def seeded(**kwargs):
    instance = builder(**kwargs)
    instance.register_participant(session_id="s1", participant_id="p-b",
                                  url="https://rp-b.example/logout?tenant=t1",
                                  now=NOW)
    instance.register_participant(session_id="s1", participant_id="p-a",
                                  url="https://rp-a.example/logout", now=NOW)
    return instance


def token_for(signer_key, session_id, participant_id):
    payload = f"{signer_key}|{session_id}|{participant_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def test_register_participant_validates_and_lists_sorted():
    instance = seeded()
    assert instance.participants_for("s1") == ("p-a", "p-b")
    assert instance.participants_for("s-other") == ()

    with pytest.raises(fb.FrontchannelError) as exc:
        instance.register_participant(session_id="s1", participant_id="p-c",
                                      url="ftp://rp-c.example/logout", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_REQUEST_INVALID"

    with pytest.raises(fb.FrontchannelError) as exc:
        instance.register_participant(session_id="s1", participant_id="",
                                      url="https://rp-c.example/logout", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_REQUEST_INVALID"


def test_broadcast_unknown_session_and_empty_signer():
    instance = seeded()
    with pytest.raises(fb.FrontchannelError) as exc:
        instance.broadcast(session_id="s-missing", signer_key="k-1", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_SESSION_UNKNOWN"

    with pytest.raises(fb.FrontchannelError) as exc:
        instance.broadcast(session_id="s1", signer_key="", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_REQUEST_INVALID"
    assert instance.stats()["broadcasts"] == 0


def test_broadcast_builds_ordered_signed_entries():
    instance = seeded()
    out = instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    assert out.session_id == "s1"
    assert [entry.participant_id for entry in out.entries] == ["p-a", "p-b"]
    token_a = token_for("k-1", "s1", "p-a")
    assert out.entries[0].token == token_a
    assert out.entries[0].url == (
        "https://rp-a.example/logout?session=s1&sig=" + token_a)
    assert out.started_at == NOW
    assert instance.stats()["broadcasts"] == 1
    assert instance.stats()["entries"] == 2


def test_broadcast_uses_ampersand_for_existing_query():
    instance = seeded()
    out = instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    entry = [row for row in out.entries if row.participant_id == "p-b"][0]
    token_b = token_for("k-1", "s1", "p-b")
    assert entry.url == (
        "https://rp-b.example/logout?tenant=t1&session=s1&sig=" + token_b)
    assert entry.url.count("?") == 1


def test_repeated_broadcast_returns_same_entries():
    instance = seeded()
    first = instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    second = instance.broadcast(session_id="s1", signer_key="k-1",
                                now="2026-11-27T10:00:01+00:00")
    assert second.entries == first.entries
    assert second.started_at == NOW
    assert instance.stats()["broadcasts"] == 1
    assert instance.stats()["entries"] == 2


def test_collect_requires_broadcast_and_known_participant():
    instance = seeded()
    with pytest.raises(fb.FrontchannelError) as exc:
        instance.collect(session_id="s1", participant_id="p-a", token="x", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_NOT_BROADCAST"

    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    with pytest.raises(fb.FrontchannelError) as exc:
        instance.collect(session_id="s1", participant_id="p-z", token="x", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_PARTICIPANT_UNKNOWN"

    with pytest.raises(fb.FrontchannelError) as exc:
        instance.collect(session_id="s1", participant_id="p-a",
                         token="not-the-token", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_BAD_TOKEN"
    assert instance.stats()["confirmed"] == 0


def test_collect_records_confirmed_and_failed():
    instance = seeded()
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    token_a = token_for("k-1", "s1", "p-a")
    token_b = token_for("k-1", "s1", "p-b")
    assert instance.collect(session_id="s1", participant_id="p-a",
                            token=token_a, now=NOW) == "confirmed"
    assert instance.pending_for("s1") == ("p-b",)
    assert instance.collect(session_id="s1", participant_id="p-b",
                            token=token_b, ok=False, now=NOW) == "failed"
    assert instance.pending_for("s1") == ()
    assert instance.stats()["confirmed"] == 1
    assert instance.stats()["failed"] == 1


def test_duplicate_acknowledgement_is_refused():
    instance = seeded()
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    token_a = token_for("k-1", "s1", "p-a")
    instance.collect(session_id="s1", participant_id="p-a", token=token_a, now=NOW)
    with pytest.raises(fb.FrontchannelError) as exc:
        instance.collect(session_id="s1", participant_id="p-a",
                         token=token_a, now=NOW)
    assert exc.value.code == "FRONTCHANNEL_DUPLICATE_ACK"
    assert instance.stats()["confirmed"] == 1


def test_fallback_before_deadline_is_empty():
    instance = seeded(timeout_ms=2000)
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    assert instance.fallback(session_id="s1",
                             now="2026-11-27T10:00:01+00:00") == ()
    assert instance.attempts_for(session_id="s1", participant_id="p-a") == 0
    assert instance.stats()["fallbacks"] == 0


def test_fallback_at_deadline_retries_only_pending():
    instance = seeded(timeout_ms=2000)
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    instance.collect(session_id="s1", participant_id="p-a",
                     token=token_for("k-1", "s1", "p-a"), now=NOW)

    retried = instance.fallback(session_id="s1", now=DEADLINE)
    assert retried == ("p-b",)
    assert instance.attempts_for(session_id="s1", participant_id="p-b") == 1
    assert instance.attempts_for(session_id="s1", participant_id="p-a") == 0
    assert instance.pending_for("s1") == ("p-b",)
    assert instance.stats()["fallbacks"] == 1


def test_fallback_exhausts_after_max_attempts():
    instance = seeded(timeout_ms=2000, max_attempts=2)
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)

    first = instance.fallback(session_id="s1", now=DEADLINE)
    assert first == ("p-a", "p-b")
    second = instance.fallback(session_id="s1", now=DEADLINE)
    assert second == ("p-a", "p-b")
    assert instance.pending_for("s1") == ()
    assert instance.fallback(session_id="s1", now=DEADLINE) == ()
    assert instance.attempts_for(session_id="s1", participant_id="p-a") == 2
    assert instance.stats()["fallbacks"] == 2
    assert instance.stats()["attempts"] == 4


def test_concurrent_acknowledgement_allows_single_confirm():
    instance = seeded()
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    token_a = token_for("k-1", "s1", "p-a")
    confirmed = []
    duplicates = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            outcome = instance.collect(session_id="s1", participant_id="p-a",
                                       token=token_a, now=NOW)
            confirmed.append(outcome)
        except fb.FrontchannelError as exc:
            duplicates.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert confirmed == ["confirmed"]
    assert duplicates.count("FRONTCHANNEL_DUPLICATE_ACK") == 9
    assert instance.stats()["confirmed"] == 1


def test_close_session_drops_bindings_and_broadcast():
    instance = seeded()
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    assert instance.close_session("s1") == 2
    assert instance.participants_for("s1") == ()
    assert instance.pending_for("s1") == ()
    with pytest.raises(fb.FrontchannelError) as exc:
        instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    assert exc.value.code == "FRONTCHANNEL_SESSION_UNKNOWN"
    assert instance.close_session("s1") == 0
    assert instance.stats()["closed"] == 1


def test_snapshot_restore_keeps_pending_and_idempotency():
    instance = seeded()
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    instance.collect(session_id="s1", participant_id="p-a",
                     token=token_for("k-1", "s1", "p-a"), now=NOW)
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "sessions", "stats"}
    state["stats"]["entries"] = 99
    assert instance.stats()["entries"] == 2

    clone = builder()
    clone.restore(pristine)
    assert clone.pending_for("s1") == ("p-b",)
    cached = clone.broadcast(session_id="s1", signer_key="k-1",
                             now="2026-11-27T10:05:00+00:00")
    assert cached.started_at == NOW
    assert [entry.participant_id for entry in cached.entries] == ["p-a", "p-b"]
    assert clone.stats()["broadcasts"] == 1
    assert clone.collect(session_id="s1", participant_id="p-b",
                         token=token_for("k-1", "s1", "p-b"), now=NOW) == "confirmed"


def test_restore_rejects_malformed_state_without_mutating_live_data():
    instance = seeded()
    instance.broadcast(session_id="s1", signer_key="k-1", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "sessions": {}, "stats": {}},
        {"version": 1, "sessions": [], "stats": {}},
        {"version": 1, "sessions": {}, "stats": {"broadcasts": 1}},
        {"version": 1, "sessions": {"s1": []}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(fb.FrontchannelError) as exc:
            instance.restore(bad)
        assert exc.value.code == "FRONTCHANNEL_SNAPSHOT_INVALID"

    assert instance.stats()["entries"] == 2
    assert instance.pending_for("s1") == ("p-a", "p-b")
