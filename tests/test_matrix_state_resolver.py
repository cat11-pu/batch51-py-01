import copy

import pytest

import matrix_state_resolver as mr

ROOM = "!ops:hs"
ADMIN = "@admin:hs"
ALICE = "@alice:hs"
BOB = "@bob:hs"

POWER_CONTENT = {
    "users": {ADMIN: 100, ALICE: 10},
    "users_default": 0,
    "events": {},
    "events_default": 0,
    "state_default": 50,
    "kick": 50,
    "ban": 50,
    "invite": 0,
}

CREATE = {
    "event_id": "$create", "type": "m.room.create", "sender": ADMIN,
    "room_id": ROOM, "depth": 1, "prev_events": [], "auth_events": [],
    "state_key": "", "content": {"creator": ADMIN},
}
JOIN_ADMIN = {
    "event_id": "$join-admin", "type": "m.room.member", "sender": ADMIN,
    "room_id": ROOM, "depth": 2, "prev_events": ["$create"],
    "auth_events": ["$create"], "state_key": ADMIN,
    "content": {"membership": "join"},
}
JOIN_ALICE = {
    "event_id": "$join-alice", "type": "m.room.member", "sender": ALICE,
    "room_id": ROOM, "depth": 3, "prev_events": ["$join-admin"],
    "auth_events": ["$create", "$join-admin"], "state_key": ALICE,
    "content": {"membership": "join"},
}
POWER = {
    "event_id": "$pl", "type": "m.room.power_levels", "sender": ADMIN,
    "room_id": ROOM, "depth": 4, "prev_events": ["$join-alice"],
    "auth_events": ["$create", "$join-admin"], "state_key": "",
    "content": POWER_CONTENT,
}


def resolver(**kwargs):
    return mr.MatrixStateResolver(ROOM, creator=ADMIN, **kwargs)


def event(event_id, event_type, sender=ADMIN, depth=5, prev=("$pl",),
          auth=("$create", "$join-admin", "$pl"), state_key="", content=None):
    return {
        "event_id": event_id,
        "type": event_type,
        "sender": sender,
        "room_id": ROOM,
        "depth": depth,
        "prev_events": list(prev),
        "auth_events": list(auth),
        "state_key": state_key,
        "content": dict(content or {}),
    }


def base(**kwargs):
    r = resolver(**kwargs)
    for item in (CREATE, JOIN_ADMIN, JOIN_ALICE, POWER):
        assert r.ingest_event(item).status == "accepted"
    return r


def error_code(callable_obj, *args, **kwargs):
    with pytest.raises(mr.FederationError) as exc:
        callable_obj(*args, **kwargs)
    return exc.value.code


def test_create_event_becomes_current_state():
    r = resolver()
    result = r.ingest_event(CREATE)
    assert result == mr.IngestResult("$create", "accepted", False, 1)
    assert r.resolve_state() == (mr.StateEntry("m.room.create", "", "$create", ADMIN),)
    assert r.dag_heads() == ("$create",)
    assert r.stats()["accepted"] == 1


def test_missing_predecessor_waits_then_applies():
    r = resolver()
    r.ingest_event(CREATE)
    r.ingest_event(JOIN_ADMIN)
    orphan = event("$orphan", "m.room.topic", depth=4, prev=("$missing",),
                   auth=("$create",), content={"topic": "second"})
    result = r.ingest_event(orphan)
    assert result.status == "pending"
    assert r.pending_events() == ("$orphan",)

    missing = event("$missing", "m.room.topic", depth=2, prev=("$join-admin",),
                    auth=("$create",), content={"topic": "first"})
    assert r.ingest_event(missing).status == "accepted"
    assert r.pending_events() == ()
    assert r.event_depth("$orphan") == 4
    winners = [entry for entry in r.resolve_state() if entry.type == "m.room.topic"]
    assert [entry.event_id for entry in winners] == ["$orphan"]


def test_missing_auth_event_also_parks_the_event():
    r = base()
    parked = event("$parked", "m.room.topic", depth=5,
                   auth=("$create", "$join-admin", "$nope"),
                   content={"topic": "x"})
    assert r.ingest_event(parked).status == "pending"
    assert r.pending_events() == ("$parked",)
    assert r.stats()["pending"] == 1


def test_replayed_event_is_reported_as_duplicate():
    r = base()
    result = r.ingest_event(CREATE)
    assert result == mr.IngestResult("$create", "duplicate", False, 1)
    assert len(r.resolve_state()) == 4
    assert r.stats()["duplicates"] == 1


def test_resolved_state_is_ordered_by_type_and_state_key():
    r = base()
    r.ingest_event(event("$topic", "m.room.topic", content={"topic": "ops"}))
    keys = [(entry.type, entry.state_key) for entry in r.resolve_state()]
    assert keys == [
        ("m.room.create", ""),
        ("m.room.member", ADMIN),
        ("m.room.member", ALICE),
        ("m.room.power_levels", ""),
        ("m.room.topic", ""),
    ]


def test_conflicts_resolve_by_depth_then_event_id():
    r = base()
    r.ingest_event(event("$early", "m.room.topic", depth=3, content={"topic": "early"}))
    r.ingest_event(event("$late", "m.room.topic", depth=5, content={"topic": "late"}))
    topic = [entry for entry in r.resolve_state() if entry.type == "m.room.topic"][0]
    assert topic.event_id == "$late"

    r.ingest_event(event("$t-a", "m.room.topic", depth=6, content={"topic": "a"}))
    r.ingest_event(event("$t-b", "m.room.topic", depth=6, content={"topic": "b"}))
    topic = [entry for entry in r.resolve_state() if entry.type == "m.room.topic"][0]
    assert topic.event_id == "$t-b"


def test_late_event_with_lower_depth_cannot_override_state():
    r = base()
    r.ingest_event(event("$modern", "m.room.topic", depth=8, content={"topic": "modern"}))
    result = r.ingest_event(event("$ancient", "m.room.topic", depth=2,
                                  prev=("$join-admin",), content={"topic": "ancient"}))
    assert result.status == "accepted"
    topic = [entry for entry in r.resolve_state() if entry.type == "m.room.topic"][0]
    assert topic.event_id == "$modern"


def test_authorize_checks_sender_power_level():
    r = base()
    allowed = r.authorize(event("$admin-topic", "m.room.topic", content={"topic": "ok"}))
    assert (allowed.allowed, allowed.reason) == (True, "allowed")
    assert (allowed.required_power, allowed.sender_power) == (50, 100)

    denied = r.authorize(event("$alice-topic", "m.room.topic", sender=ALICE,
                               depth=6, auth=("$create", "$join-alice", "$pl"),
                               content={"topic": "nope"}))
    assert denied.allowed is False
    assert denied.reason == "insufficient_power"
    assert (denied.required_power, denied.sender_power) == (50, 10)

    result = r.ingest_event(event("$alice-topic", "m.room.topic", sender=ALICE,
                                  depth=6, auth=("$create", "$join-alice", "$pl"),
                                  content={"topic": "nope"}))
    assert result.status == "rejected"
    assert r.stats()["rejected"] == 1


def test_authorize_rejects_non_member():
    r = base()
    result = r.authorize(event("$bob-topic", "m.room.topic", sender=BOB, depth=7,
                               auth=("$create",), content={"topic": "nope"}))
    assert result.allowed is False
    assert result.reason == "not_joined"
    assert r.ingest_event(event("$bob-topic", "m.room.topic", sender=BOB, depth=7,
                                auth=("$create",), content={"topic": "nope"})).status == "rejected"


def test_invite_only_room_requires_invite_before_join():
    r = base()
    rules = event("$jr", "m.room.join_rules", depth=5, content={"join_rule": "invite"})
    assert r.ingest_event(rules).status == "accepted"

    denied = r.authorize(event("$bob-join", "m.room.member", sender=BOB, depth=6,
                               prev=("$jr",), auth=("$create", "$join-admin", "$jr"),
                               state_key=BOB, content={"membership": "join"}))
    assert denied.allowed is False
    assert denied.reason == "membership_denied"

    invite = event("$invite-bob", "m.room.member", depth=6, prev=("$jr",),
                   auth=("$create", "$join-admin", "$jr"),
                   state_key=BOB, content={"membership": "invite"})
    assert r.ingest_event(invite).status == "accepted"

    join = event("$bob-join-2", "m.room.member", sender=BOB, depth=7,
                 prev=("$invite-bob",), auth=("$create", "$join-admin", "$invite-bob"),
                 state_key=BOB, content={"membership": "join"})
    assert r.ingest_event(join).status == "accepted"
    members = [entry for entry in r.resolve_state() if entry.state_key == BOB]
    assert [entry.event_id for entry in members] == ["$bob-join-2"]


def test_soft_failed_event_leaves_dag_but_not_state():
    r = base()
    r.ingest_event(event("$t-old", "m.room.topic", depth=5, content={"topic": "old"}))
    r.ingest_event(event("$t-new", "m.room.topic", depth=6, content={"topic": "new"}))
    assert r.soft_fail("$t-new", "manual review") is True
    topic = [entry for entry in r.resolve_state() if entry.type == "m.room.topic"][0]
    assert topic.event_id == "$t-old"
    assert r.event_depth("$t-new") == 6
    assert r.stats()["soft_failed"] == 1


def test_soft_fail_unknown_and_repeated():
    r = base()
    r.ingest_event(event("$t-one", "m.room.topic", depth=5, content={"topic": "one"}))
    assert error_code(r.soft_fail, "$ghost", "x") == "FEDERATION_UNKNOWN_EVENT"
    assert r.soft_fail("$t-one", "first") is True
    assert r.soft_fail("$t-one", "second") is False
    assert r.stats()["soft_failed"] == 1


def test_backfill_inserts_history_without_touching_state():
    r = base()
    r.ingest_event(event("$t-cur", "m.room.topic", depth=9, content={"topic": "cur"}))
    old_one = event("$old-1", "m.room.topic", depth=1, prev=(), auth=(),
                    content={"topic": "o1"})
    old_two = event("$old-2", "m.room.topic", depth=2, prev=("$old-1",), auth=(),
                    content={"topic": "o2"})
    assert r.backfill([old_one, old_two]) == 2
    assert r.event_depth("$old-1") == 1
    topic = [entry for entry in r.resolve_state() if entry.type == "m.room.topic"][0]
    assert topic.event_id == "$t-cur"
    assert r.backfill([old_one, old_two]) == 0
    assert r.stats()["backfilled"] == 2
    assert error_code(r.backfill, "not-a-list") == "FEDERATION_INVALID_EVENT"


def test_upgrade_resets_state_to_tombstone():
    r = base()
    assert r.upgrade_room("10") == "10"
    assert r.room_version() == "10"
    entries = r.resolve_state()
    assert [entry.type for entry in entries] == ["m.room.tombstone"]
    assert entries[0].event_id.startswith("$tombstone")
    assert r.stats()["upgraded"] == 1
    assert error_code(r.upgrade_room, "10") == "FEDERATION_INVALID_UPGRADE"
    assert error_code(r.upgrade_room, "99") == "FEDERATION_INVALID_UPGRADE"


def test_snapshot_is_detached_and_restore_roundtrips():
    r = base()
    r.ingest_event(event("$t-snap", "m.room.topic", depth=5, content={"topic": "s"}))
    parked = event("$parked", "m.room.topic", depth=6, prev=("$missing",),
                   auth=("$create", "$join-admin", "$pl"), content={"topic": "p"})
    assert r.ingest_event(parked).status == "pending"

    state = r.snapshot()
    pristine = copy.deepcopy(state)
    state["version"] = "11"
    assert r.room_version() == "9"
    assert r.event_depth("$pl") == 4

    clone = resolver()
    clone.restore(pristine)
    assert clone.room_version() == "9"
    assert clone.pending_events() == ("$parked",)
    assert clone.event_depth("$pl") == 4
    topic = [entry for entry in clone.resolve_state() if entry.type == "m.room.topic"][0]
    assert topic.event_id == "$t-snap"

    assert error_code(clone.restore, {"version": 7}) == "FEDERATION_SNAPSHOT_INVALID"
    assert clone.event_depth("$pl") == 4
