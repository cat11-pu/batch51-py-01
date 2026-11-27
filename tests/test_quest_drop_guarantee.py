import copy
import threading

import pytest

import quest_drop_guarantee as drops

NOW = 1_800_000_000


def board(**kwargs):
    return drops.QuestDropGuarantee(**kwargs)


def seed_kills(engine, count, player="p-1", quest="q-1"):
    for index in range(1, count + 1):
        engine.register_kill(player, quest, kill_id=f"k-{index}",
                             monster_id="mob-alpha", at=NOW)


def test_register_kill_starts_quest_progress():
    engine = board()
    receipt = engine.register_kill("p-1", "q-1", kill_id="k-1",
                                   monster_id="mob-alpha", at=NOW)
    assert receipt.player_id == "p-1"
    assert receipt.quest_id == "q-1"
    assert receipt.kill_id == "k-1"
    assert receipt.accepted is True
    assert receipt.duplicate is False
    assert receipt.kills == 1
    progress = engine.progress("p-1", "q-1")
    assert progress.registered is True
    assert progress.counter == 0
    assert progress.threshold == 3
    assert progress.remaining == 3
    assert progress.item_count == 0
    assert progress.kills == 1
    assert engine.stats() == {"kills": 1, "duplicate_kills": 0, "drops": 0,
                              "forced_drops": 0, "resets": 0}


def test_duplicate_kill_id_is_not_counted_twice():
    engine = board()
    seed_kills(engine, 1)
    again = engine.register_kill("p-1", "q-1", kill_id="k-1",
                                 monster_id="mob-alpha", at=NOW + 1)
    assert again.accepted is False
    assert again.duplicate is True
    assert again.kills == 1
    assert engine.progress("p-1", "q-1").kills == 1
    assert engine.kill_ids("p-1", "q-1") == ("k-1",)
    assert engine.stats()["kills"] == 1
    assert engine.stats()["duplicate_kills"] == 1


def test_roll_without_drop_increments_counter():
    engine = board()
    seed_kills(engine, 1)
    out = engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    assert out.dropped is False
    assert out.forced is False
    assert out.counter_after == 1
    assert out.threshold == 3
    assert out.item_count == 0
    assert engine.progress("p-1", "q-1").counter == 1
    assert engine.stats()["drops"] == 0


def test_roll_with_drop_resets_counter():
    engine = board()
    seed_kills(engine, 2)
    engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    out = engine.roll_drop("p-1", "q-1", kill_id="k-2", base_drop=True)
    assert out.dropped is True
    assert out.forced is False
    assert out.counter_after == 0
    assert out.item_count == 1
    assert engine.progress("p-1", "q-1").remaining == 3
    assert engine.stats()["drops"] == 1
    assert engine.stats()["forced_drops"] == 0


def test_guarantee_reports_not_forced_before_threshold():
    engine = board()
    seed_kills(engine, 2)
    first = engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    second = engine.roll_drop("p-1", "q-1", kill_id="k-2", base_drop=False)
    assert first.dropped is False
    assert first.forced is False
    assert first.counter_after == 1
    assert second.dropped is False
    assert second.forced is False
    assert second.counter_after == 2
    assert engine.progress("p-1", "q-1").remaining == 1


def test_guarantee_forces_drop_at_threshold():
    engine = board()
    seed_kills(engine, 3)
    engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    engine.roll_drop("p-1", "q-1", kill_id="k-2", base_drop=False)
    third = engine.roll_drop("p-1", "q-1", kill_id="k-3", base_drop=False)
    assert third.dropped is True
    assert third.forced is True
    assert third.counter_after == 0
    assert third.item_count == 1
    assert third.threshold == 3
    assert engine.progress("p-1", "q-1").counter == 0
    assert engine.progress("p-1", "q-1").remaining == 3
    assert engine.stats()["drops"] == 1
    assert engine.stats()["forced_drops"] == 1


def test_threshold_is_configurable_per_quest():
    engine = board()
    assert engine.configure_threshold("q-1", 2) == 2
    seed_kills(engine, 2)
    engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    forced = engine.roll_drop("p-1", "q-1", kill_id="k-2", base_drop=False)
    assert forced.forced is True
    assert forced.threshold == 2
    assert forced.item_count == 1
    with pytest.raises(drops.QuestError) as exc:
        engine.configure_threshold("q-2", 0)
    assert exc.value.code == "DROP_INVALID_REQUEST"
    assert engine.progress("p-1", "q-2").threshold == 3


def test_quests_are_isolated():
    engine = board()
    engine.register_kill("p-1", "q-1", kill_id="k-1",
                         monster_id="mob-alpha", at=NOW)
    engine.register_kill("p-1", "q-2", kill_id="k-2",
                         monster_id="mob-beta", at=NOW)
    engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    assert engine.progress("p-1", "q-1").counter == 1
    assert engine.progress("p-1", "q-1").kills == 1
    assert engine.progress("p-1", "q-2").counter == 0
    assert engine.progress("p-1", "q-2").kills == 1
    assert engine.progress("p-1", "q-2").item_count == 0


def test_roll_for_unregistered_kill_raises():
    engine = board()
    seed_kills(engine, 1)
    with pytest.raises(drops.QuestError) as exc:
        engine.roll_drop("p-1", "q-1", kill_id="k-9", base_drop=False)
    assert exc.value.code == "DROP_UNKNOWN_KILL"
    with pytest.raises(drops.QuestError) as exc:
        engine.roll_drop("p-2", "q-1", kill_id="k-1", base_drop=False)
    assert exc.value.code == "DROP_UNKNOWN_KILL"
    assert engine.progress("p-1", "q-1").counter == 0


def test_invalid_arguments_are_refused():
    engine = board()
    for bad_player in ["", None, 7]:
        with pytest.raises(drops.QuestError) as exc:
            engine.register_kill(bad_player, "q-1", kill_id="k-1",
                                 monster_id="mob-alpha", at=NOW)
        assert exc.value.code == "DROP_INVALID_REQUEST"
    with pytest.raises(drops.QuestError) as exc:
        engine.register_kill("p-1", "q-1", kill_id="", monster_id="mob-alpha", at=NOW)
    assert exc.value.code == "DROP_INVALID_REQUEST"
    seed_kills(engine, 1)
    with pytest.raises(drops.QuestError) as exc:
        engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop="yes")
    assert exc.value.code == "DROP_INVALID_REQUEST"
    with pytest.raises(drops.QuestError) as exc:
        drops.QuestDropGuarantee(threshold=0)
    assert exc.value.code == "DROP_INVALID_REQUEST"
    assert engine.stats()["kills"] == 1


def test_progress_for_unknown_quest_is_unregistered():
    engine = board()
    progress = engine.progress("p-9", "q-9")
    assert progress.registered is False
    assert progress.counter == 0
    assert progress.threshold == 3
    assert progress.remaining == 3
    assert progress.item_count == 0
    assert progress.kills == 0
    assert engine.kill_ids("p-9", "q-9") == ()
    assert engine.stats() == {"kills": 0, "duplicate_kills": 0, "drops": 0,
                              "forced_drops": 0, "resets": 0}


def test_snapshot_is_detached_and_restore_roundtrips():
    engine = board()
    seed_kills(engine, 2)
    engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    state = engine.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "config", "quests", "stats"}
    assert pristine["config"] == {"threshold": 3}
    state["quests"]["p-1"]["q-1"]["counter"] = 99
    state["stats"]["kills"] = 99
    assert engine.progress("p-1", "q-1").counter == 1
    assert engine.stats()["kills"] == 2
    clone = board()
    clone.restore(pristine)
    assert clone.progress("p-1", "q-1").counter == 1
    assert clone.progress("p-1", "q-1").kills == 2
    assert clone.kill_ids("p-1", "q-1") == ("k-1", "k-2")
    assert clone.stats() == engine.stats()
    out = clone.roll_drop("p-1", "q-1", kill_id="k-2", base_drop=False)
    assert out.counter_after == 2
    assert out.threshold == 3


def test_restore_rejects_malformed_state():
    engine = board()
    seed_kills(engine, 1)
    engine.roll_drop("p-1", "q-1", kill_id="k-1", base_drop=False)
    good = engine.snapshot()
    bad_states = [
        None,
        [],
        {},
        {"version": 2, "config": good["config"], "quests": good["quests"],
         "stats": good["stats"]},
        {"version": 1, "config": {}, "quests": good["quests"],
         "stats": good["stats"]},
        {"version": 1, "config": good["config"], "quests": [],
         "stats": good["stats"]},
        {"version": 1, "config": good["config"], "quests": good["quests"],
         "stats": {"kills": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(drops.QuestError) as exc:
            engine.restore(bad)
        assert exc.value.code == "DROP_SNAPSHOT_INVALID"
    assert engine.progress("p-1", "q-1").counter == 1
    assert engine.stats() == good["stats"]


def test_concurrent_rolls_follow_guarantee():
    engine = board(threshold=3)
    seed_kills(engine, 8)
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            results.append(engine.roll_drop("p-1", "q-1", kill_id=f"k-{index + 1}",
                                            base_drop=False))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert sum(1 for row in results if row.forced) == 2
    assert sum(1 for row in results if row.dropped) == 2
    progress = engine.progress("p-1", "q-1")
    assert progress.counter == 2
    assert progress.item_count == 2
    assert engine.stats()["forced_drops"] == 2
    assert engine.stats()["drops"] == 2


def test_kill_ids_are_kept_per_quest():
    engine = board()
    engine.register_kill("p-1", "q-1", kill_id="k-3",
                         monster_id="mob-alpha", at=NOW)
    engine.register_kill("p-1", "q-1", kill_id="k-1",
                         monster_id="mob-alpha", at=NOW)
    engine.register_kill("p-1", "q-1", kill_id="k-1",
                         monster_id="mob-alpha", at=NOW)
    engine.register_kill("p-1", "q-2", kill_id="k-2",
                         monster_id="mob-beta", at=NOW)
    assert engine.kill_ids("p-1", "q-1") == ("k-1", "k-3")
    assert engine.kill_ids("p-1", "q-2") == ("k-2",)
    assert engine.stats()["kills"] == 3
    assert engine.stats()["duplicate_kills"] == 1
