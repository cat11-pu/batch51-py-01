import hashlib
import json
import threading

import pytest

import activitypub_inbox_guard as fed

SECRET = "inbox-hub-secret"
NOW = 1000
ACTOR_ID = "https://a.example/users/alice"
ACTOR_INBOX = "https://a.example/inbox"
DELIVERY_INBOX = "https://b.example/inbox"


def guard(**kwargs):
    return fed.ActivityPubInboxGuard(**kwargs)


def body_for(activity_id, actor_id=ACTOR_ID):
    payload = {
        "id": activity_id,
        "type": "Create",
        "actor": actor_id,
        "object": f"{activity_id}/note",
    }
    return json.dumps(payload, sort_keys=True)


def digest_for(body):
    return "sha256=" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def signature_for(secret, target, host, date, digest):
    raw = "|".join([secret, target, host, str(date), digest])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def make_request(key, body, *, actor_id=None, target="/inbox", host="b.example",
                 date=NOW, digest=None, signature=None, key_id=None,
                 headers=("request-target", "host", "date", "digest"),
                 inbox=DELIVERY_INBOX):
    actual_digest = digest if digest is not None else digest_for(body)
    actual_signature = signature if signature is not None else signature_for(
        key.secret, target, host, date, actual_digest)
    return fed.SignedRequest(
        actor_id=actor_id or key.actor_id,
        method="POST",
        target=target,
        host=host,
        date=date,
        digest=actual_digest,
        key_id=key_id or key.key_id,
        signature=actual_signature,
        body=body,
        inbox=inbox,
        headers=tuple(headers),
    )


def setup_actor(g, *, now=NOW, actor_id=ACTOR_ID, inbox=ACTOR_INBOX, secret=SECRET):
    g.register_actor(actor_id, inbox, secret=secret, now=now)
    return g.fetch_actor_key(actor_id, now=now)


def test_register_actor_validates_input():
    g = guard()
    bad_calls = [
        ("", ACTOR_INBOX, "secret"),
        (ACTOR_ID, "", "secret"),
        (ACTOR_ID, ACTOR_INBOX, "   "),
    ]
    for actor_id, inbox, secret in bad_calls:
        with pytest.raises(fed.FederationError) as exc:
            g.register_actor(actor_id, inbox, secret=secret)
        assert exc.value.code == "FED_INVALID_REQUEST"
    assert g.actor_state(ACTOR_ID) == "unknown"
    assert g.stats()["delivered"] == 0


def test_duplicate_actor_registration_rejected():
    g = guard()
    setup_actor(g)
    with pytest.raises(fed.FederationError) as exc:
        g.register_actor(ACTOR_ID, ACTOR_INBOX, secret=SECRET)
    assert exc.value.code == "FED_ACTOR_EXISTS"
    assert g.actor_state(ACTOR_ID) == "active"


def test_verify_rejects_incomplete_or_stale_envelope():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/1")

    partial = make_request(key, body,
                           headers=("request-target", "host", "date"))
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(partial, now=NOW)
    assert exc.value.code == "FED_SIGNATURE_HEADERS"
    assert exc.value.detail["missing"] == ["digest"]

    stale = make_request(key, body, date=NOW - 400)
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(stale, now=NOW)
    assert exc.value.code == "FED_DATE_SKEW"

    tampered = make_request(key, body, digest=digest_for("other body"))
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(tampered, now=NOW)
    assert exc.value.code == "FED_DIGEST_MISMATCH"


def test_verify_rejects_unknown_actor_and_foreign_key():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/2")

    stranger = make_request(key, body, actor_id="https://evil.example/users/mallory")
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(stranger, now=NOW)
    assert exc.value.code == "FED_ACTOR_UNKNOWN"

    foreign = make_request(key, body, key_id="https://a.example#rotated")
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(foreign, now=NOW)
    assert exc.value.code == "FED_KEY_MISMATCH"


def test_verify_rejects_bad_signature():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/3")
    request = make_request(key, body, signature="0" * 64)
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(request, now=NOW)
    assert exc.value.code == "FED_SIGNATURE_INVALID"
    assert g.stats()["delivered"] == 0


def test_verify_accepts_well_formed_request():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/4")
    request = make_request(key, body)
    verified = g.verify_signature(request, now=NOW)
    assert verified.actor_id == ACTOR_ID
    assert verified.key_id == key.key_id
    assert verified.digest == digest_for(body)
    assert verified.verified_at == NOW


def test_ingest_same_activity_is_idempotent():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/5")
    request = make_request(key, body)

    first = g.ingest_activity(request, now=NOW)
    assert first.status == "delivered"
    assert first.activity_id == "https://a.example/activities/5"
    assert g.dedupe("https://a.example/activities/5") is True
    assert g.delivery_status("https://a.example/activities/5") == "delivered"

    second = g.ingest_activity(request, now=NOW)
    assert second.status == "duplicate"
    assert g.inbox_depth(DELIVERY_INBOX) == 1
    assert g.stats()["delivered"] == 1
    assert g.stats()["duplicates"] == 1


def test_ingest_blocked_actor_rejected():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/6")
    blocked = g.block_actor(ACTOR_ID)
    assert blocked.state == "blocked"
    assert g.actor_state(ACTOR_ID) == "blocked"
    with pytest.raises(fed.FederationError) as exc:
        g.ingest_activity(make_request(key, body), now=NOW)
    assert exc.value.code == "FED_ACTOR_BLOCKED"
    assert g.stats()["delivered"] == 0
    assert g.inbox_depth(DELIVERY_INBOX) == 0


def test_dedupe_window_evicts_oldest():
    g = guard(max_dedupe=2)
    key = setup_actor(g)
    ids = [f"https://a.example/activities/w{index}" for index in range(3)]
    for activity_id in ids:
        g.ingest_activity(make_request(key, body_for(activity_id)),
                          now=NOW)
    assert g.dedupe(ids[0]) is False
    assert g.dedupe(ids[1]) is True
    assert g.dedupe(ids[2]) is True
    assert g.stats()["delivered"] == 3


def test_forward_depth_limit_rejects():
    g = guard(max_forward_depth=3)
    key = setup_actor(g)
    activity_id = "https://a.example/activities/f1"
    g.ingest_activity(make_request(key, body_for(activity_id)), now=NOW)
    with pytest.raises(fed.FederationError) as exc:
        g.forward(activity_id, target_inbox="https://c.example/inbox", depth=4,
                  now=NOW)
    assert exc.value.code == "FED_FORWARD_DEPTH"
    assert g.stats()["forwarded"] == 0
    with pytest.raises(fed.FederationError) as exc:
        g.forward("https://a.example/activities/missing",
                  target_inbox="https://c.example/inbox", depth=1, now=NOW)
    assert exc.value.code == "FED_ACTIVITY_UNKNOWN"


def test_inbox_capacity_limit():
    g = guard(max_inbox_items=2)
    key = setup_actor(g)
    for index in range(2):
        activity_id = f"https://a.example/activities/c{index}"
        g.ingest_activity(make_request(key, body_for(activity_id)), now=NOW)
    assert g.inbox_depth(DELIVERY_INBOX) == 2
    overflow_id = "https://a.example/activities/c2"
    with pytest.raises(fed.FederationError) as exc:
        g.ingest_activity(make_request(key, body_for(overflow_id)), now=NOW)
    assert exc.value.code == "FED_INBOX_FULL"
    assert g.inbox_depth(DELIVERY_INBOX) == 2
    assert g.delivery_status(overflow_id) == "unknown"


def test_key_rotation_grace_then_expiry():
    g = guard()
    old = setup_actor(g, now=1000)
    new = g.rotate_key(ACTOR_ID, "rotated-secret", now=1100, grace=100)
    assert new.key_id != old.key_id
    body = body_for("https://a.example/activities/k1")

    within_grace = make_request(old, body, date=1150)
    assert g.verify_signature(within_grace, now=1150).key_id == old.key_id

    fresh = make_request(new, body, date=1250)
    assert g.verify_signature(fresh, now=1250).key_id == new.key_id

    after_grace = make_request(old, body, date=1250)
    with pytest.raises(fed.FederationError) as exc:
        g.verify_signature(after_grace, now=1250)
    assert exc.value.code == "FED_KEY_EXPIRED"


def test_snapshot_restore_preserves_dedupe_and_keys():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/s1")
    request = make_request(key, body)
    g.ingest_activity(request, now=NOW)
    state = g.snapshot()

    clone = guard()
    clone.restore(state)
    assert clone.dedupe("https://a.example/activities/s1") is True
    assert clone.ingest_activity(request, now=NOW).status == "duplicate"
    assert clone.fetch_actor_key(ACTOR_ID, now=NOW).key_id == key.key_id

    with pytest.raises(fed.FederationError) as exc:
        clone.restore({})
    assert exc.value.code == "FED_SNAPSHOT_INVALID"
    assert clone.inbox_depth(DELIVERY_INBOX) == 1


def test_concurrent_ingest_same_activity_delivers_once():
    g = guard()
    key = setup_actor(g)
    body = body_for("https://a.example/activities/race")
    request = make_request(key, body)
    statuses = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            statuses.append(g.ingest_activity(request, now=NOW).status)
        except Exception as exc:  # pragma: no cover - reported through statuses
            statuses.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses.count("delivered") == 1
    assert statuses.count("duplicate") == 7
    assert g.inbox_depth(DELIVERY_INBOX) == 1
    assert g.delivery_status("https://a.example/activities/race") == "delivered"


def test_block_and_unblock_actor_state():
    g = guard()
    key = setup_actor(g)
    assert g.actor_state(ACTOR_ID) == "active"
    g.block_actor(ACTOR_ID)
    assert g.actor_state(ACTOR_ID) == "blocked"
    g.unblock_actor(ACTOR_ID)
    assert g.actor_state(ACTOR_ID) == "active"
    body = body_for("https://a.example/activities/u1")
    assert g.ingest_activity(make_request(key, body), now=NOW).status == "delivered"
