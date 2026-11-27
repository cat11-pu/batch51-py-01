import copy
import threading

import pytest

import faction_reputation_ledger as fr

SNAPSHOT_KEYS = {"version", "config", "factions", "hostiles", "points", "daily",
                 "awards", "unlocks", "stats"}


def ledger(**kwargs):
    return fr.FactionReputationLedger(**kwargs)


def rep(**kwargs):
    g = ledger(**kwargs)
    g.register_faction("guild")
    g.register_faction("league", hostiles=("guild",))
    return g


def award(g, player="p-1", faction="guild", amount=100, *, source="quest",
          at=0, event_id=None):
    return g.award(player, faction, amount, source=source, at=at,
                   event_id=event_id or f"e-{player}-{source}-{at}-{amount}")


def test_level_thresholds_follow_the_registered_table():
    g = rep()
    assert g.level_of("p-1", "guild") == 0
    award(g, amount=499)
    assert (g.points_of("p-1", "guild"), g.level_of("p-1", "guild")) == (499, 0)
    award(g, amount=1, source="raid", at=1)
    assert (g.points_of("p-1", "guild"), g.level_of("p-1", "guild")) == (500, 1)


def test_award_reports_granted_multiplier_and_level():
    g = rep()
    result = award(g, amount=120)
    assert (result.player, result.faction, result.requested) == ("p-1", "guild", 120)
    assert (result.granted, result.multiplier) == (120, 1.0)
    assert (result.points, result.level) == (120, 0)
    assert result.duplicate is False
    assert result.capped is False


def test_repeated_source_decays_with_the_table():
    g = rep()
    granted = []
    multipliers = []
    for index in range(5):
        result = award(g, amount=100, source="quest", at=index)
        granted.append(result.granted)
        multipliers.append(result.multiplier)
    assert multipliers == [1.0, 0.75, 0.5, 0.25, 0.25]
    assert granted == [100, 75, 50, 25, 25]
    assert g.points_of("p-1", "guild") == 275


def test_different_sources_do_not_share_the_decay_counter():
    g = rep()
    first = award(g, amount=100, source="quest", at=0)
    second = award(g, amount=100, source="raid", at=1)
    assert (first.granted, first.multiplier) == (100, 1.0)
    assert (second.granted, second.multiplier) == (100, 1.0)


def test_daily_cap_truncates_and_then_blocks_further_gain():
    g = rep(daily_cap=250)
    award(g, amount=100, source="quest", at=0)
    award(g, amount=100, source="raid", at=1)
    third = award(g, amount=100, source="boss", at=2)
    assert (third.granted, third.capped) == (50, True)
    fourth = award(g, amount=100, source="event", at=3)
    assert (fourth.granted, fourth.capped) == (0, True)
    assert g.daily_used("p-1", at=3) == 250
    assert g.points_of("p-1", "guild") == 250


def test_duplicate_event_id_returns_the_first_result_without_awarding_again():
    g = rep()
    first = award(g, amount=100, source="quest", at=0, event_id="e-1")
    again = award(g, amount=100, source="quest", at=0, event_id="e-1")
    assert again.duplicate is True
    assert (again.granted, again.points, again.multiplier) == (
        first.granted, first.points, first.multiplier)
    assert g.points_of("p-1", "guild") == 100
    assert g.daily_used("p-1", at=0) == 100


def test_award_validates_amount_faction_source_and_event():
    g = rep()
    for bad_amount in (0, -5):
        with pytest.raises(fr.ReputationError) as exc:
            award(g, amount=bad_amount)
        assert exc.value.code == "REP_INVALID_AMOUNT"
    with pytest.raises(fr.ReputationError) as exc:
        award(g, faction="cult")
    assert exc.value.code == "REP_UNKNOWN_FACTION"
    with pytest.raises(fr.ReputationError) as exc:
        award(g, source="  ")
    assert exc.value.code == "REP_INVALID_REQUEST"
    with pytest.raises(fr.ReputationError) as exc:
        g.award("p-1", "guild", 100, source="quest", at=0, event_id=" ")
    assert exc.value.code == "REP_INVALID_REQUEST"
    with pytest.raises(fr.ReputationError) as exc:
        award(g, player="  ")
    assert exc.value.code == "REP_INVALID_REQUEST"
    assert g.points_of("p-1", "guild") == 0


def test_penalize_validates_amount_and_faction():
    g = rep()
    for bad_amount in (0, -1):
        with pytest.raises(fr.ReputationError) as exc:
            g.penalize("p-1", "guild", bad_amount, at=0)
        assert exc.value.code == "REP_INVALID_AMOUNT"
    with pytest.raises(fr.ReputationError) as exc:
        g.penalize("p-1", "cult", 10, at=0)
    assert exc.value.code == "REP_UNKNOWN_FACTION"


def test_penalize_reduces_points_inside_the_current_level():
    g = rep(daily_cap=5000)
    award(g, amount=1600, source="quest", at=0)
    assert g.level_of("p-1", "guild") == 2
    result = g.penalize("p-1", "guild", 50, at=1)
    assert (result.requested, result.applied) == (50, 50)
    assert (result.points, result.level) == (1550, 2)
    assert result.floored is False
    assert g.points_of("p-1", "guild") == 1550


def test_unlock_check_claims_each_level_once():
    g = rep(daily_cap=5000)
    award(g, amount=600, source="quest", at=0)
    assert g.unlock_check("p-1", "guild") == (1,)
    assert g.unlock_check("p-1", "guild") == ()
    award(g, amount=900, source="raid", at=1)
    assert g.points_of("p-1", "guild") == 1500
    assert g.unlock_check("p-1", "guild") == (2,)
    assert g.unlock_check("p-1", "guild") == ()


def test_daily_used_counts_only_the_granted_part():
    g = rep(daily_cap=5000)
    award(g, amount=100, source="quest", at=0)
    award(g, amount=100, source="quest", at=1)
    assert g.daily_used("p-1", at=1) == 175
    assert g.daily_used("p-2", at=1) == 0


def test_concurrent_awards_never_exceed_the_daily_cap():
    g = rep(daily_cap=500)
    granted = []
    barrier = threading.Barrier(20)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            result = g.award("p-1", "guild", 100, source=f"src-{index}",
                             at=0, event_id=f"e-{index}")
            granted.append(result.granted)
        except Exception as exc:  # pragma: no cover - reported through granted
            granted.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert all(isinstance(value, int) for value in granted)
    assert sum(granted) == 500
    assert g.points_of("p-1", "guild") == 500
    assert g.daily_used("p-1", at=0) == 500


def test_transfer_moves_points_and_checks_the_source_balance():
    g = rep(daily_cap=5000)
    award(g, amount=100, source="quest", at=0)
    with pytest.raises(fr.ReputationError) as exc:
        g.transfer("p-1", "guild", "league", 150, at=1)
    assert exc.value.code == "REP_INSUFFICIENT"
    with pytest.raises(fr.ReputationError) as exc:
        g.transfer("p-1", "guild", "league", 0, at=1)
    assert exc.value.code == "REP_INVALID_AMOUNT"
    result = g.transfer("p-1", "guild", "league", 60, at=2)
    assert (result.requested, result.moved, result.converted) == (60, 60, 60)
    assert (result.source_points, result.target_points) == (40, 60)
    assert g.points_of("p-1", "guild") == 40
    assert g.points_of("p-1", "league") == 60


def test_snapshot_is_detached_and_restore_roundtrips():
    g = rep(daily_cap=5000)
    award(g, amount=600, source="quest", at=0, event_id="e-1")
    award(g, amount=300, source="raid", at=1, event_id="e-2")
    g.unlock_check("p-1", "guild")
    state = g.snapshot()
    assert set(state) == SNAPSHOT_KEYS
    pristine = copy.deepcopy(state)
    state["points"].clear()
    state["daily"].clear()
    assert g.points_of("p-1", "guild") == 900
    assert g.daily_used("p-1", at=1) == 900

    clone = rep(daily_cap=5000)
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.points_of("p-1", "guild") == 900
    assert clone.level_of("p-1", "guild") == 1
    assert clone.unlock_check("p-1", "guild") == ()
    repeat = clone.award("p-1", "guild", 600, source="quest", at=0, event_id="e-1")
    assert repeat.duplicate is True


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = rep()
    award(g, amount=200, source="quest", at=0)
    good = g.snapshot()
    bad_states = [
        None,
        {},
        {"version": 1},
        dict(good, version=1.0),
        dict(good, factions={}),
        dict(good, hostiles=[]),
        dict(good, points=[]),
        dict(good, daily=[]),
        dict(good, awards=[]),
        dict(good, unlocks={}),
    ]
    for bad in bad_states:
        with pytest.raises(fr.ReputationError) as exc:
            g.restore(bad)
        assert exc.value.code == "REP_SNAPSHOT_INVALID"
    assert g.points_of("p-1", "guild") == 200
