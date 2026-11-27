import copy
import threading

import pytest

import party_merge_guard as pm

NOW = 1_000.0


def guard(**kwargs):
    return pm.PartyMergeGuard(**kwargs)


def pair(g, *, band_a=(1, 60), band_b=(1, 60)):
    a = g.create_party("lead-a", max_size=4, level_min=band_a[0],
                       level_max=band_a[1])
    b = g.create_party("lead-b", max_size=4, level_min=band_b[0],
                       level_max=band_b[1])
    g.add_member(a.party_id, "m-a1", level=10)
    g.add_member(b.party_id, "m-b1", level=10)
    return a.party_id, b.party_id


def confirmed_request(g, now=NOW):
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=now)
    g.confirm(request.request_id, "lead-a", now=now)
    return g.confirm(request.request_id, "lead-b", now=now)


def test_create_party_records_leader_and_membership():
    g = guard()
    party = g.create_party("lead-a", max_size=4, level_min=1, level_max=60)
    assert party.leader == "lead-a"
    assert party.members == ("lead-a",)
    assert (party.max_size, party.level_min, party.level_max) == (4, 1, 60)
    assert g.party_of("lead-a") == party.party_id
    assert g.members_of(party.party_id) == ("lead-a",)
    assert g.party_of("ghost") is None
    g.add_member(party.party_id, "m-2", level=10)
    with pytest.raises(pm.MergeError) as exc:
        g.create_party("m-2")
    assert exc.value.code == "PLAYER_IN_PARTY"


def test_add_member_validates_capacity_membership_and_level():
    g = guard()
    party = g.create_party("lead-a", max_size=3, level_min=1, level_max=60)
    g.add_member(party.party_id, "m-2", level=10)
    with pytest.raises(pm.MergeError) as exc:
        g.add_member(party.party_id, "m-2", level=10)
    assert exc.value.code == "PLAYER_IN_PARTY"
    with pytest.raises(pm.MergeError) as exc:
        g.add_member(party.party_id, "m-3", level=99)
    assert exc.value.code == "PARTY_LEVEL_OUT_OF_RANGE"
    g.add_member(party.party_id, "m-4", level=20)
    with pytest.raises(pm.MergeError) as exc:
        g.add_member(party.party_id, "m-5", level=20)
    assert exc.value.code == "PARTY_FULL"
    with pytest.raises(pm.MergeError) as exc:
        g.add_member("p-404", "m-6")
    assert exc.value.code == "PARTY_UNKNOWN"


def test_invites_are_reused_and_listed_per_player():
    g = guard()
    party = g.create_party("lead-a")
    first = g.invite(party.party_id, "guest-1")
    assert g.invite(party.party_id, "guest-1") == first
    second = g.invite(party.party_id, "guest-2")
    assert g.pending_invites("guest-1") == (first,)
    assert g.pending_invites("guest-2") == (second,)
    assert g.pending_invites("guest-3") == ()
    assert g.stats()["invites"] == 2
    with pytest.raises(pm.MergeError) as exc:
        g.invite(party.party_id, "lead-a")
    assert exc.value.code == "PLAYER_IN_PARTY"


def test_propose_merge_records_request_and_requires_leader():
    g = guard()
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    assert (request.from_party, request.into_party) == (a, b)
    assert request.proposer == "lead-a"
    assert request.state == "proposed"
    assert request.confirmed_by == ()
    assert request.expires_at == NOW + 300.0
    with pytest.raises(pm.MergeError) as exc:
        g.propose_merge(a, b, "m-a1", now=NOW)
    assert exc.value.code == "MERGE_NOT_LEADER"


def test_propose_merge_refuses_unknown_self_and_band_mismatch():
    g = guard()
    a, b = pair(g)
    with pytest.raises(pm.MergeError) as exc:
        g.propose_merge(a, "p-404", "lead-a", now=NOW)
    assert exc.value.code == "MERGE_UNKNOWN_PARTY"
    with pytest.raises(pm.MergeError) as exc:
        g.propose_merge(a, a, "lead-a", now=NOW)
    assert exc.value.code == "MERGE_SAME_PARTY"

    low = g.create_party("lead-low", level_min=1, level_max=10)
    high = g.create_party("lead-high", level_min=20, level_max=30)
    with pytest.raises(pm.MergeError) as exc:
        g.propose_merge(low.party_id, high.party_id, "lead-low", now=NOW)
    assert exc.value.code == "MERGE_LEVEL_MISMATCH"


def test_both_leaders_must_confirm_and_non_leaders_are_refused():
    g = guard()
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    after_first = g.confirm(request.request_id, "lead-a", now=NOW)
    assert after_first.state == "proposed"
    assert after_first.confirmed_by == ("lead-a",)
    with pytest.raises(pm.MergeError) as exc:
        g.confirm(request.request_id, "m-b1", now=NOW)
    assert exc.value.code == "MERGE_NOT_LEADER"
    after_second = g.confirm(request.request_id, "lead-b", now=NOW)
    assert after_second.state == "confirmed"
    assert after_second.confirmed_by == ("lead-a", "lead-b")
    assert g.stats()["confirmed"] == 1


def test_repeated_confirmation_by_one_leader_is_idempotent():
    g = guard()
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    g.confirm(request.request_id, "lead-a", now=NOW)
    again = g.confirm(request.request_id, "lead-a", now=NOW)
    assert again.state == "proposed"
    assert again.confirmed_by == ("lead-a",)
    assert g.stats()["confirmed"] == 0


def test_apply_moves_every_source_member_into_the_target_party():
    g = guard()
    a, b = pair(g)
    request = confirmed_request(g)
    result = g.apply(request.request_id, now=NOW)
    assert result.applied is True
    assert result.state == "applied"
    assert result.reason == "MERGED"
    assert result.moved == ("lead-a", "m-a1")
    assert g.members_of(b) == ("lead-a", "lead-b", "m-a1", "m-b1")
    assert g.party_of("lead-a") == b
    assert g.party_of("m-a1") == b
    with pytest.raises(pm.MergeError) as exc:
        g.members_of(a)
    assert exc.value.code == "PARTY_UNKNOWN"


def test_apply_before_both_confirmations_is_refused():
    g = guard()
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    with pytest.raises(pm.MergeError) as exc:
        g.apply(request.request_id, now=NOW)
    assert exc.value.code == "MERGE_NOT_CONFIRMED"
    g.confirm(request.request_id, "lead-a", now=NOW)
    with pytest.raises(pm.MergeError) as exc:
        g.apply(request.request_id, now=NOW)
    assert exc.value.code == "MERGE_NOT_CONFIRMED"
    assert g.members_of(a) == ("lead-a", "m-a1")


def test_disband_after_confirmation_rolls_the_apply_back():
    g = guard()
    a, b = pair(g)
    request = confirmed_request(g)
    released = g.disband(b)
    assert released == ("lead-b", "m-b1")
    result = g.apply(request.request_id, now=NOW)
    assert result.applied is False
    assert result.state == "rolled_back"
    assert result.reason == "PARTY_DISSOLVED"
    assert result.moved == ()
    assert g.status(request.request_id).state == "rolled_back"
    assert g.members_of(a) == ("lead-a", "m-a1")


def test_parties_are_locked_while_a_merge_is_pending():
    g = guard()
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    for party_id in (a, b):
        with pytest.raises(pm.MergeError) as exc:
            g.add_member(party_id, "m-extra", level=10)
        assert exc.value.code == "PARTY_LOCKED"
    g.reject(request.request_id, "lead-b", reason="not now", now=NOW)
    assert g.status(request.request_id).state == "rejected"
    assert g.add_member(a, "m-extra", level=10).members == (
        "lead-a", "m-a1", "m-extra")


def test_reject_requires_a_leader_and_closes_the_request():
    g = guard()
    a, b = pair(g)
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    with pytest.raises(pm.MergeError) as exc:
        g.reject(request.request_id, "m-a1")
    assert exc.value.code == "MERGE_NOT_LEADER"
    closed = g.reject(request.request_id, "lead-a", now=NOW)
    assert closed.state == "rejected"
    with pytest.raises(pm.MergeError) as exc:
        g.confirm(request.request_id, "lead-b", now=NOW)
    assert exc.value.code == "MERGE_REQUEST_CLOSED"
    with pytest.raises(pm.MergeError) as exc:
        g.apply(request.request_id, now=NOW)
    assert exc.value.code == "MERGE_NOT_CONFIRMED"


def test_concurrent_apply_moves_members_exactly_once():
    g = guard()
    request = confirmed_request(g)
    target = request.into_party
    results = []
    errors = []
    barrier = threading.Barrier(5)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(g.apply(request.request_id, now=NOW))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sum(1 for row in results if row.moved) == 1
    assert all(row.state == "applied" for row in results)
    members = g.members_of(target)
    assert sorted(members) == ["lead-a", "lead-b", "m-a1", "m-b1"]
    assert len(set(members)) == 4


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    a, b = pair(g)
    g.invite(b, "guest-1")
    request = g.propose_merge(a, b, "lead-a", now=NOW)
    g.confirm(request.request_id, "lead-a", now=NOW)
    state = g.snapshot()
    assert set(state) == {"version", "parties", "players", "invites", "requests",
                          "counters", "stats"}
    pristine = copy.deepcopy(state)

    state["parties"].clear()
    state["stats"]["invites"] = 99
    assert g.members_of(a) == ("lead-a", "m-a1")
    assert g.stats()["invites"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.members_of(b) == ("lead-b", "m-b1")
    assert clone.party_of("m-a1") == a
    assert clone.status(request.request_id) == g.status(request.request_id)
    assert clone.pending_invites("guest-1") == g.pending_invites("guest-1")


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = guard()
    a, b = pair(g)
    bad_states = [
        None,
        {},
        {"version": 1, "parties": [], "players": {}, "invites": {},
         "requests": {}, "counters": {}},
        {"version": "1", "parties": [], "players": {}, "invites": {},
         "requests": {}, "counters": {}, "stats": {}},
        {"version": 1, "parties": {}, "players": {}, "invites": {},
         "requests": {}, "counters": {}, "stats": {}},
        {"version": 1, "parties": [], "players": [], "invites": {},
         "requests": {}, "counters": {}, "stats": {}},
        {"version": 1, "parties": [], "players": {}, "invites": [],
         "requests": {}, "counters": {}, "stats": {}},
        {"version": 1, "parties": [], "players": {}, "invites": {},
         "requests": {}, "counters": {}, "stats": {"invites": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(pm.MergeError) as exc:
            g.restore(bad)
        assert exc.value.code == "MERGE_SNAPSHOT_INVALID"
    assert g.members_of(a) == ("lead-a", "m-a1")
    assert g.party_of("lead-b") == b
