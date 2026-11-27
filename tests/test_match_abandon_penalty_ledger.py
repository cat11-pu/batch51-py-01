import copy
import threading

import pytest

import match_abandon_penalty_ledger as penalty

NOW = 1_800_000_000


def ledger(**kwargs):
    return penalty.AbandonPenaltyLedger(**kwargs)


def test_mark_leave_records_once_and_is_idempotent():
    board = ledger()
    record = board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    assert record.match_id == "m-1"
    assert record.player_id == "p-1"
    assert record.kind == "voluntary"
    assert record.left_at == NOW
    assert record.reconnected_at is None
    assert record.exempt_reason is None
    again = board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    assert again == record
    assert board.records_for("m-1") == (record,)
    assert board.stats() == {"leaves": 1, "reconnects": 0, "settlements": 0,
                             "duplicate_settlements": 0, "waived_matches": 0,
                             "decayed_points": 0}


def test_mark_leave_rejects_invalid_arguments():
    board = ledger()
    for bad_kind in ["afk", "", None]:
        with pytest.raises(penalty.PenaltyError) as exc:
            board.mark_leave("m-1", "p-1", bad_kind, at=NOW)
        assert exc.value.code == "ABANDON_INVALID_REQUEST"
    for match_id, player_id in [("", "p-1"), ("m-1", ""), ("m-1", None)]:
        with pytest.raises(penalty.PenaltyError) as exc:
            board.mark_leave(match_id, player_id, penalty.KIND_VOLUNTARY, at=NOW)
        assert exc.value.code == "ABANDON_INVALID_REQUEST"
    with pytest.raises(penalty.PenaltyError) as exc:
        board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at="soon")
    assert exc.value.code == "ABANDON_INVALID_REQUEST"
    assert board.stats()["leaves"] == 0


def test_settle_applies_voluntary_points():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    out = board.settle_match("m-1", at=NOW + 10)
    assert out.match_id == "m-1"
    assert out.settled_at == NOW + 10
    assert out.awards == (("p-1", 3),)
    assert out.duplicate is False
    assert board.penalty_of("p-1", at=NOW + 10) == 3
    assert board.stats()["settlements"] == 1


def test_settle_applies_disconnect_points():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_DISCONNECT, at=NOW)
    out = board.settle_match("m-1", at=NOW + 5)
    assert out.awards == (("p-1", 1),)
    assert board.penalty_of("p-1") == 1
    assert board.tier_of("p-1") == penalty.TIER_CLEAN


def test_settle_is_idempotent_per_match():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    first = board.settle_match("m-1", at=NOW + 10)
    second = board.settle_match("m-1", at=NOW + 999)
    assert second.duplicate is True
    assert second.settled_at == first.settled_at
    assert second.awards == first.awards
    assert board.penalty_of("p-1", at=NOW + 999) == 3
    assert board.stats()["settlements"] == 1
    assert board.stats()["duplicate_settlements"] == 1


def test_settle_accumulates_across_matches():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    board.mark_leave("m-2", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    board.settle_match("m-1", at=NOW)
    assert board.penalty_of("p-1") == 3
    board.settle_match("m-2", at=NOW + 10)
    assert board.penalty_of("p-1") == 6


def test_points_are_capped_at_limit():
    board = ledger(max_points=4)
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    board.mark_leave("m-2", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    board.settle_match("m-1", at=NOW)
    out = board.settle_match("m-2", at=NOW + 10)
    assert out.awards == (("p-1", 1),)
    assert board.penalty_of("p-1") == 4
    assert board.tier_of("p-1") == penalty.TIER_RESTRICTED


def test_tier_and_queue_ladder():
    clean = ledger()
    assert clean.tier_of("ghost") == penalty.TIER_CLEAN
    assert clean.penalty_of("ghost") == 0
    assert clean.queue_block_until("ghost") is None

    watch = ledger()
    watch.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    settled = watch.settle_match("m-1", at=NOW + 10)
    assert watch.penalty_of("p-1") == 3
    assert watch.tier_of("p-1") == penalty.TIER_WATCH
    assert watch.queue_block_until("p-1", at=settled.settled_at) == settled.settled_at + 300
    assert watch.queue_block_until("p-1", at=settled.settled_at + 300) is None

    restricted = ledger()
    restricted.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    restricted.mark_leave("m-2", "p-1", penalty.KIND_DISCONNECT, at=NOW)
    restricted.settle_match("m-1", at=NOW)
    out = restricted.settle_match("m-2", at=NOW + 10)
    assert restricted.penalty_of("p-1") == 4
    assert restricted.tier_of("p-1") == penalty.TIER_RESTRICTED
    assert restricted.queue_block_until("p-1", at=out.settled_at) == out.settled_at + 900

    suspended = ledger()
    suspended.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    suspended.mark_leave("m-2", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    suspended.settle_match("m-1", at=NOW)
    out = suspended.settle_match("m-2", at=NOW + 10)
    assert suspended.penalty_of("p-1") == 6
    assert suspended.tier_of("p-1") == penalty.TIER_SUSPENDED
    assert suspended.queue_block_until("p-1", at=out.settled_at) == out.settled_at + 1800


def test_reconnect_within_grace_clears_cooldown():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    assert board.queue_block_until("p-1", at=NOW) == NOW + 300
    out = board.mark_reconnect("m-1", "p-1", at=NOW + 30)
    assert out.accepted is True
    assert out.within_grace is True
    assert out.cooldown_cleared is True
    assert out.grace_remaining == 60
    assert board.queue_block_until("p-1", at=NOW + 30) is None
    assert board.records_for("m-1")[0].reconnected_at == NOW + 30
    assert board.stats()["reconnects"] == 1


def test_reconnect_after_grace_is_refused():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    out = board.mark_reconnect("m-1", "p-1", at=NOW + 91)
    assert out.accepted is False
    assert out.within_grace is False
    assert out.cooldown_cleared is False
    assert out.grace_remaining == 0
    assert board.queue_block_until("p-1", at=NOW + 91) == NOW + 300
    assert board.records_for("m-1")[0].reconnected_at is None


def test_reconnect_without_leave_is_refused():
    board = ledger()
    with pytest.raises(penalty.PenaltyError) as exc:
        board.mark_reconnect("m-1", "p-1", at=NOW)
    assert exc.value.code == "ABANDON_UNKNOWN_LEAVE"
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    with pytest.raises(penalty.PenaltyError) as exc:
        board.mark_reconnect("m-1", "p-2", at=NOW)
    assert exc.value.code == "ABANDON_UNKNOWN_LEAVE"


def test_settle_unknown_match_is_refused():
    board = ledger()
    with pytest.raises(penalty.PenaltyError) as exc:
        board.settle_match("m-9", at=NOW)
    assert exc.value.code == "ABANDON_UNKNOWN_MATCH"
    board.mark_leave("m-1", "p-1", penalty.KIND_DISCONNECT, at=NOW)
    with pytest.raises(penalty.PenaltyError) as exc:
        board.settle_match("m-2", at=NOW)
    assert exc.value.code == "ABANDON_UNKNOWN_MATCH"


def test_snapshot_is_detached_and_restore_roundtrips():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    board.mark_leave("m-1", "p-2", penalty.KIND_DISCONNECT, at=NOW)
    board.settle_match("m-1", at=NOW + 10)
    state = board.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "config", "records", "points",
                             "cooldowns", "settlements", "stats"}
    assert pristine["config"] == {"grace_window": 90, "provisional_cooldown": 300,
                                 "max_points": 12, "daily_decay": 1}
    state["points"]["p-1"] = 99
    state["records"][0]["kind"] = "disconnect"
    state["stats"]["leaves"] = 99
    assert board.penalty_of("p-1") == 3
    assert board.records_for("m-1")[0].kind == "voluntary"
    assert board.stats()["leaves"] == 2
    clone = ledger()
    clone.restore(pristine)
    assert clone.penalty_of("p-1") == 3
    assert clone.penalty_of("p-2") == 1
    assert clone.records_for("m-1") == board.records_for("m-1")
    assert clone.stats() == board.stats()
    assert clone.tier_of("p-1") == penalty.TIER_WATCH


def test_restore_rejects_malformed_state():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    board.settle_match("m-1", at=NOW + 10)
    good = board.snapshot()
    bad_states = [
        None,
        [],
        {},
        {"version": 2, "config": good["config"], "records": good["records"],
         "points": good["points"], "cooldowns": good["cooldowns"],
         "settlements": good["settlements"], "stats": good["stats"]},
        {"version": 1, "config": {"grace_window": 90}, "records": [],
         "points": {}, "cooldowns": {}, "settlements": {}, "stats": {}},
        {"version": 1, "config": good["config"], "records": {},
         "points": good["points"], "cooldowns": good["cooldowns"],
         "settlements": good["settlements"], "stats": good["stats"]},
        {"version": 1, "config": good["config"], "records": good["records"],
         "points": good["points"], "cooldowns": good["cooldowns"],
         "settlements": good["settlements"], "stats": {"leaves": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(penalty.PenaltyError) as exc:
            board.restore(bad)
        assert exc.value.code == "ABANDON_SNAPSHOT_INVALID"
    assert board.penalty_of("p-1") == 3
    assert board.stats() == good["stats"]


def test_concurrent_settle_same_match_applies_once():
    board = ledger()
    board.mark_leave("m-1", "p-1", penalty.KIND_VOLUNTARY, at=NOW)
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(board.settle_match("m-1", at=NOW + 10))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert sum(1 for row in results if row.duplicate is False) == 1
    assert sum(1 for row in results if row.duplicate is True) == 7
    assert board.penalty_of("p-1") == 3
    assert board.stats()["settlements"] == 1
    assert board.stats()["duplicate_settlements"] == 7
