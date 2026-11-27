import copy
import threading

import pytest

import ladder_soft_reset_planner as ld


def planner(**kwargs):
    kwargs.setdefault("baseline", 1500)
    kwargs.setdefault("keep_bps", 5000)
    kwargs.setdefault("placement_matches", 10)
    kwargs.setdefault("rating_floor", 800)
    kwargs.setdefault("rating_ceiling", 2000)
    kwargs.setdefault("placement_delta", 25)
    kwargs.setdefault("uncertainty_start", 100)
    kwargs.setdefault("uncertainty_step", 100)
    kwargs.setdefault("uncertainty_cap", 300)
    kwargs.setdefault("uncertainty_decay", 40)
    kwargs.setdefault("uncertainty_floor", 0)
    return ld.SoftResetPlanner(**kwargs)


def enroll(plan, player, rating, matches=12):
    return plan.register_player(player, rating, matches_last_season=matches)


def prepared(**kwargs):
    plan = planner(**kwargs)
    enroll(plan, "p1", 2000)
    batch = plan.plan_batch("s2", ["p1"])
    plan.apply(batch)
    return plan, batch


def test_plan_and_apply_compress_rating_toward_baseline():
    plan, batch = prepared()
    assert isinstance(batch, str)
    assert batch.startswith("s2#")
    assert plan.rating_of("p1") == 1750
    assert plan.state_of("p1").prev_rating == 2000
    assert plan.uncertainty_of("p1") == 200
    assert plan.stats()["applied"] == 1


def test_apply_marks_players_provisional_with_zero_progress():
    plan, _ = prepared()
    assert plan.provisional_of("p1") is True
    assert plan.progress("p1") == {"played": 0, "needed": 10, "remaining": 10}
    state = plan.state_of("p1")
    assert (state.player, state.season, state.rating) == ("p1", "s2", 1750)
    assert (state.played, state.needed) == (0, 10)


def test_apply_unknown_batch_is_rejected():
    plan = planner()
    enroll(plan, "p1", 2000)
    with pytest.raises(ld.LadderError) as exc:
        plan.apply("s2#7")
    assert exc.value.code == "LADDER_UNKNOWN_BATCH"
    assert plan.rating_of("p1") == 2000
    assert plan.provisional_of("p1") is False


def test_apply_rejects_unknown_player_without_touching_the_batch():
    plan = planner()
    enroll(plan, "p1", 2000)
    enroll(plan, "p2", 1700)
    batch = plan.plan_batch("s2", ["p1", "p2"])
    with pytest.raises(ld.LadderError) as exc:
        plan.apply(batch, players=["p1", "ghost"])
    assert exc.value.code == "LADDER_UNKNOWN_PLAYER"
    assert plan.rating_of("p1") == 2000
    assert plan.stats()["applied"] == 0
    result = plan.apply(batch)
    assert result["applied"] == 2
    assert (plan.rating_of("p1"), plan.rating_of("p2")) == (1750, 1600)


def test_compression_is_clamped_to_floor_and_ceiling():
    plan = planner(keep_bps=12000)
    enroll(plan, "high", 2000)
    enroll(plan, "low", 900)
    batch = plan.plan_batch("s2", ["high", "low"])
    plan.apply(batch)
    assert plan.rating_of("high") == 2000
    assert plan.rating_of("low") == 800


def test_plan_batch_rejects_empty_and_duplicate_players():
    plan = planner()
    enroll(plan, "p1", 2000)
    with pytest.raises(ld.LadderError) as exc:
        plan.plan_batch("s2", [])
    assert exc.value.code == "LADDER_INVALID_PLAYER"
    with pytest.raises(ld.LadderError) as exc:
        plan.plan_batch("s2", ["p1", "p1"])
    assert exc.value.code == "LADDER_INVALID_PLAYER"
    assert plan.stats()["batches"] == 0
    assert plan.plan_batch("s2", ["p1"]).startswith("s2#")


def test_season_must_move_forward():
    plan, _ = prepared()
    with pytest.raises(ld.LadderError) as exc:
        plan.plan_batch("s1", ["p1"])
    assert exc.value.code == "LADDER_SEASON_ORDER"
    assert plan.stats()["batches"] == 1


def test_register_player_validates_identity_and_rating_bounds():
    plan = planner()
    enroll(plan, "p1", 2000)
    with pytest.raises(ld.LadderError) as exc:
        enroll(plan, "p1", 1500)
    assert exc.value.code == "LADDER_PLAYER_EXISTS"
    for bad_rating in (799, 2001):
        with pytest.raises(ld.LadderError) as exc:
            enroll(plan, f"p-{bad_rating}", bad_rating)
        assert exc.value.code == "LADDER_RATING_OUT_OF_RANGE"
    with pytest.raises(ld.LadderError) as exc:
        enroll(plan, "   ", 1500)
    assert exc.value.code == "LADDER_INVALID_PLAYER"
    assert plan.stats()["players"] == 1


def test_completed_win_moves_rating_and_shrinks_uncertainty():
    plan, _ = prepared()
    rating = plan.record_placement("p1", won=True)
    assert rating == 1775
    assert plan.rating_of("p1") == 1775
    assert plan.uncertainty_of("p1") == 160
    assert plan.progress("p1")["played"] == 1
    assert plan.record_placement("p1", won=False) == 1750
    assert plan.stats()["placements"] == 2


def test_placement_completion_clears_provisional_state():
    plan = planner(placement_matches=3)
    enroll(plan, "p1", 2000)
    batch = plan.plan_batch("s2", ["p1"])
    plan.apply(batch)
    assert plan.provisional_of("p1") is True
    for _ in range(3):
        plan.record_placement("p1", won=True)
    assert plan.provisional_of("p1") is False
    assert plan.rating_of("p1") == 1825
    assert plan.progress("p1") == {"played": 3, "needed": 3, "remaining": 0}


def test_placement_after_completion_is_rejected():
    plan = planner(placement_matches=2)
    enroll(plan, "p1", 2000)
    batch = plan.plan_batch("s2", ["p1"])
    plan.apply(batch)
    plan.record_placement("p1", won=True)
    plan.record_placement("p1", won=True)
    with pytest.raises(ld.LadderError) as exc:
        plan.record_placement("p1", won=True)
    assert exc.value.code == "LADDER_NOT_PROVISIONAL"
    with pytest.raises(ld.LadderError) as exc:
        plan.record_placement("nobody", won=True)
    assert exc.value.code == "LADDER_UNKNOWN_PLAYER"


def test_progress_reports_remaining_placement_matches():
    plan, _ = prepared()
    for _ in range(3):
        plan.record_placement("p1", won=True)
    assert plan.progress("p1") == {"played": 3, "needed": 10, "remaining": 7}
    assert plan.state_of("p1").provisional is True


def test_snapshot_is_detached_and_restore_roundtrips():
    plan = planner()
    enroll(plan, "p1", 2000)
    enroll(plan, "p2", 1700)
    batch = plan.plan_batch("s2", ["p1", "p2"])
    plan.apply(batch)
    plan.record_placement("p1", won=True)
    state = plan.snapshot()
    assert set(state) == {"version", "season", "batches", "players",
                          "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["players"].clear()
    state["stats"]["applied"] = 99
    assert plan.rating_of("p1") == 1775
    clone = planner()
    clone.restore(pristine)
    assert clone.rating_of("p1") == 1775
    assert clone.rating_of("p2") == 1600
    assert clone.progress("p1")["played"] == 1
    assert clone.stats() == plan.stats()


def test_restore_rejects_malformed_state():
    plan, _ = prepared()
    bad_states = [
        None,
        {},
        {"version": 1, "season": "s2", "batches": [], "players": [],
         "counters": {}, "stats": {}},
        {"version": 1, "season": "s2", "batches": {}, "players": {},
         "counters": [], "stats": {}},
        {"version": 1, "season": "s2", "batches": {}, "players": {},
         "counters": {}, "stats": []},
        {"version": 1, "season": "s2", "batches": {}, "players": {},
         "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ld.LadderError) as exc:
            plan.restore(bad)
        assert exc.value.code == "LADDER_SNAPSHOT_INVALID"
    assert plan.rating_of("p1") == 1750
    assert plan.provisional_of("p1") is True


def test_concurrent_placements_are_counted_exactly_once_each():
    plan = planner(placement_matches=100, rating_ceiling=5000)
    enroll(plan, "p1", 2000)
    batch = plan.plan_batch("s2", ["p1"])
    plan.apply(batch)
    failures = []
    barrier = threading.Barrier(20)

    def worker():
        try:
            barrier.wait(timeout=5)
            plan.record_placement("p1", won=True)
        except Exception as exc:  # pragma: no cover - surfaced through failures
            failures.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert plan.progress("p1")["played"] == 20
    assert plan.rating_of("p1") == 2250
    assert plan.uncertainty_of("p1") == 0
    assert plan.stats()["placements"] == 20
