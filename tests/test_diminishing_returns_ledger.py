import copy

import pytest

import diminishing_returns_ledger as dr

SNAPSHOT_KEYS = {"version", "config", "buckets", "events", "parties", "counters"}


def ledger(**kwargs):
    return dr.DiminishingReturnsLedger(**kwargs)


def record(g, event_id="e-1", *, template="boss", player="p-1", at=0,
           instance=None, party=None):
    return g.record(event_id, template=template, player=player, at=at,
                    instance=instance, party=party)


def test_multiplier_is_full_before_any_event():
    g = ledger()
    assert g.multiplier("boss", "p-1", at=0) == 1.0
    assert g.multiplier("boss", "p-2", at=0) == 1.0
    assert g.stats()["events"] == 0


def test_first_record_starts_at_full_multiplier():
    g = ledger()
    result = record(g)
    assert (result.event_id, result.template, result.player) == ("e-1", "boss", "p-1")
    assert (result.count, result.multiplier) == (1, 1.0)
    assert result.duplicate is False


def test_multiplier_decays_by_step_and_stops_at_the_floor():
    g = ledger(floor=0.4, step=0.15)
    multipliers = []
    for index in range(6):
        multipliers.append(record(g, f"e-{index}", at=index).multiplier)
    assert multipliers == [1.0, 0.85, 0.7, 0.55, 0.4, 0.4]
    assert g.multiplier("boss", "p-1", at=5) == 0.4


def test_duplicate_event_id_does_not_count_again():
    g = ledger()
    first = record(g, "e-1", at=0)
    again = record(g, "e-1", at=5)
    assert again.duplicate is True
    assert (again.count, again.multiplier) == (first.count, first.multiplier)
    assert g.bucket_state("boss", "p-1", at=5).count == 1
    assert g.stats()["events"] == 1
    assert g.stats()["duplicates"] == 1


def test_record_validates_ids_and_timestamps():
    g = ledger()
    with pytest.raises(dr.DiminishingError) as exc:
        record(g, " ")
    assert exc.value.code == "DIM_INVALID_REQUEST"
    with pytest.raises(dr.DiminishingError) as exc:
        record(g, template=" ")
    assert exc.value.code == "DIM_INVALID_REQUEST"
    with pytest.raises(dr.DiminishingError) as exc:
        record(g, player=" ")
    assert exc.value.code == "DIM_INVALID_REQUEST"
    with pytest.raises(dr.DiminishingError) as exc:
        record(g, at=-1)
    assert exc.value.code == "DIM_INVALID_REQUEST"
    assert g.stats()["events"] == 0


def test_bucket_state_reports_count_and_cycle():
    g = ledger()
    record(g, "e-1", at=10)
    record(g, "e-2", at=20)
    state = g.bucket_state("boss", "p-1", at=20)
    assert (state.template, state.player) == ("boss", "p-1")
    assert (state.count, state.multiplier) == (2, 0.7)
    assert state.cycle == 0
    empty = g.bucket_state("boss", "p-9", at=20)
    assert (empty.count, empty.multiplier) == (0, 1.0)


def test_events_outside_the_window_stop_counting():
    g = ledger(window=600)
    record(g, "e-1", at=100)
    record(g, "e-2", at=200)
    record(g, "e-3", at=300)
    assert g.multiplier("boss", "p-1", at=300) == 0.55
    assert g.multiplier("boss", "p-1", at=700) == 0.7
    assert g.multiplier("boss", "p-1", at=1000) == 1.0


def test_party_members_share_the_strictest_bucket():
    g = ledger()
    assert g.share_with_party("p-1", "raid") == 1
    assert g.share_with_party("p-2", "raid") == 2
    for index in range(3):
        record(g, f"e-{index}", at=index)
    assert g.multiplier("boss", "p-2", at=2) == 0.55
    assert g.multiplier("boss", "p-1", at=2) == 0.55
    assert g.bucket_state("boss", "p-2", at=2).party == "raid"


def test_players_outside_a_party_keep_their_own_bucket():
    g = ledger()
    g.share_with_party("p-1", "raid")
    g.share_with_party("p-2", "raid")
    record(g, "e-1", at=0)
    record(g, "e-2", at=1)
    assert g.multiplier("boss", "p-3", at=1) == 1.0
    record(g, "e-3", player="p-3", at=2)
    assert g.multiplier("boss", "p-3", at=2) == 1.0
    assert g.multiplier("boss", "p-2", at=2) == 0.7


def test_share_with_party_reports_member_count():
    g = ledger()
    assert g.share_with_party("p-1", "raid") == 1
    assert g.share_with_party("p-2", "raid") == 2
    assert g.share_with_party("p-3", "raid") == 3
    assert g.party_of("p-2") == "raid"
    assert g.party_of("p-9") is None


def test_leave_party_clears_membership():
    g = ledger()
    g.share_with_party("p-1", "raid")
    assert g.leave_party("p-1") is True
    assert g.party_of("p-1") is None
    assert g.leave_party("p-9") is False


def test_bucket_cap_evicts_the_least_recently_used_target():
    g = ledger(max_buckets=2)
    record(g, "e-1", template="boss", at=0)
    record(g, "e-2", template="elite", at=1)
    record(g, "e-3", template="mob", at=2)
    assert g.stats()["buckets"] == 2
    assert g.stats()["evicted"] == 1
    assert g.multiplier("boss", "p-1", at=3) == 1.0


def test_prune_drops_events_that_are_out_of_window():
    g = ledger(window=600)
    record(g, "e-1", at=100)
    record(g, "e-2", at=200)
    assert g.prune(at=1000) == 2
    assert g.multiplier("boss", "p-1", at=1000) == 1.0
    assert g.prune(at=1000) == 0


def test_snapshot_is_detached_and_restore_roundtrips():
    g = ledger()
    g.share_with_party("p-1", "raid")
    record(g, "e-1", at=0)
    record(g, "e-2", at=1)
    state = g.snapshot()
    assert set(state) == SNAPSHOT_KEYS
    pristine = copy.deepcopy(state)
    state["buckets"].clear()
    state["parties"].clear()
    assert g.multiplier("boss", "p-1", at=1) == 0.85
    assert g.party_of("p-1") == "raid"

    clone = ledger()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.multiplier("boss", "p-1", at=1) == 0.85
    assert clone.party_of("p-1") == "raid"
    assert clone.bucket_state("boss", "p-1", at=1).party == "raid"
    repeat = record(clone, "e-1", at=1)
    assert repeat.duplicate is True


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = ledger()
    record(g, "e-1", at=0)
    record(g, "e-2", at=1)
    good = g.snapshot()
    bad_states = [
        None,
        {},
        {"version": 1},
        dict(good, version="1"),
        dict(good, buckets=[]),
        dict(good, events=[]),
        dict(good, parties=[]),
        dict(good, counters=[]),
        dict(good, config=[]),
    ]
    for bad in bad_states:
        with pytest.raises(dr.DiminishingError) as exc:
            g.restore(bad)
        assert exc.value.code == "DIM_SNAPSHOT_INVALID"
    assert g.multiplier("boss", "p-1", at=1) == 0.85
    assert g.stats()["events"] == 2
