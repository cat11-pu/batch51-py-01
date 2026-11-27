import copy
import threading

import pytest

import dynamic_difficulty_director as dd


def director(**kwargs):
    return dd.DifficultyDirector(**kwargs)


def test_initial_tier_and_coefficients():
    d = director()
    assert d.tier_of() == 0
    assert d.coefficients_of() == (10000, 10000)
    assert d.coefficients_of(1) == (11500, 11000)
    assert d.coefficients_of(3) == (15000, 13500)
    for bad in (-1, 4):
        with pytest.raises(dd.DirectorError) as exc:
            d.coefficients_of(bad)
        assert exc.value.code == "DIRECTOR_INVALID_TIER"


def test_observe_accumulates_window_metrics():
    d = director()
    d.observe(deaths=1, wipes=1, kills=4, kill_ms=4000, healing=30, at_ms=0)
    snapshot = d.observe(deaths=2, wipes=0, kills=6, kill_ms=2000,
                         healing=25, at_ms=100)
    window = d.metrics()
    assert (window["deaths"], window["wipes"], window["kills"]) == (3, 1, 10)
    assert window["kill_ms_avg"] == 600
    assert window["healing"] == 55
    assert snapshot["deaths"] == 3
    assert snapshot["kills"] == 10


def test_observe_rejects_negative_metrics():
    d = director()
    bad_calls = [
        dict(deaths=-1),
        dict(wipes=-2),
        dict(kills=-1),
        dict(kill_ms=-5),
        dict(healing=-1),
        dict(members=0),
    ]
    for kwargs in bad_calls:
        with pytest.raises(dd.DirectorError) as exc:
            d.observe(**kwargs)
        assert exc.value.code == "DIRECTOR_INVALID_METRIC"
    window = d.metrics()
    assert (window["deaths"], window["kills"], window["healing"]) == (0, 0, 0)
    assert d.stats()["observations"] == 0


def test_stress_must_clear_the_up_threshold():
    calm = director()
    calm.observe(deaths=3, kills=3)
    steady = calm.evaluate_adjust(at_ms=0)
    assert (steady.changed, steady.reason, steady.to_tier) == (False, "NO_CHANGE", 0)
    assert steady.stress_bps == 10000

    hot = director()
    hot.observe(deaths=4, kills=3)
    moved = hot.evaluate_adjust(at_ms=0)
    assert (moved.changed, moved.reason, moved.to_tier) == (True, "ADJUST_UP", 1)


def test_adjustment_records_stress_window_and_history():
    d = director()
    d.observe(deaths=4, kills=3, healing=10, at_ms=0)
    adjustment = d.evaluate_adjust(at_ms=500)
    assert (adjustment.from_tier, adjustment.to_tier) == (0, 1)
    assert adjustment.stress_bps == 13333
    assert adjustment.at_ms == 500
    assert adjustment.window["deaths"] == 4
    rows = d.history_of()
    assert len(rows) == 1
    assert (rows[0].to_tier, rows[0].stress_bps) == (1, 13333)
    assert d.reason_of(1) == "ADJUST_UP"
    assert d.reason_of(0) == "INITIAL"


def test_min_interval_blocks_adjustment_but_keeps_the_window():
    d = director()
    d.observe(deaths=4, kills=3)
    first = d.evaluate_adjust(at_ms=1000)
    assert first.changed is True
    d.observe(deaths=9, kills=4)
    blocked = d.evaluate_adjust(at_ms=2000)
    assert (blocked.changed, blocked.reason, blocked.to_tier) == (False, "COOLDOWN", 1)
    assert d.metrics()["deaths"] == 9
    allowed = d.evaluate_adjust(at_ms=31000)
    assert (allowed.changed, allowed.reason, allowed.to_tier) == (True, "ADJUST_UP", 2)


def test_downgrade_follows_an_easy_window():
    d = director(min_interval_ms=0)
    d.observe(deaths=4, kills=3)
    d.evaluate_adjust(at_ms=0)
    d.observe(deaths=5, kills=3)
    assert d.evaluate_adjust(at_ms=0).to_tier == 2
    d.observe(kills=10, deaths=0)
    easy = d.evaluate_adjust(at_ms=0)
    assert (easy.changed, easy.reason, easy.to_tier) == (True, "ADJUST_DOWN", 1)


def test_freeze_blocks_adjustment_and_stays_out_of_history():
    d = director()
    assert d.freeze("boss", at_ms=0) is True
    assert d.is_frozen() is True
    d.observe(deaths=9, kills=3)
    frozen = d.evaluate_adjust(at_ms=100000)
    assert (frozen.changed, frozen.reason, frozen.to_tier) == (False, "FROZEN", 0)
    assert d.history_of() == []


def test_freeze_and_unfreeze_report_state_changes():
    d = director()
    assert d.freeze("boss") is True
    assert d.freeze("boss") is False
    assert d.unfreeze() is True
    assert d.unfreeze() is False
    assert d.is_frozen() is False


def test_window_is_cleared_after_evaluation():
    d = director(min_interval_ms=0)
    d.observe(deaths=4, kills=3)
    d.evaluate_adjust(at_ms=0)
    window = d.metrics()
    assert (window["deaths"], window["kills"], window["kill_ms_avg"]) == (0, 0, 0)
    d.observe(deaths=5, kills=10)
    steady = d.evaluate_adjust(at_ms=0)
    assert (steady.changed, steady.reason) == (False, "NO_CHANGE")
    assert d.metrics()["deaths"] == 0


def test_history_keeps_only_the_newest_changes():
    d = director(min_interval_ms=0, max_history=3)
    for _ in range(5):
        d.observe(deaths=4, kills=3)
        d.evaluate_adjust(at_ms=0)
        d.observe(kills=10, deaths=0)
        d.evaluate_adjust(at_ms=0)
    rows = d.history_of()
    assert [row.seq for row in rows] == [8, 9, 10]
    assert [row.to_tier for row in rows] == [0, 1, 0]
    assert d.stats()["adjustments"] == 10


def test_snapshot_is_detached_and_restore_roundtrips():
    d = director()
    d.observe(deaths=4, kills=3)
    d.evaluate_adjust(at_ms=1000)
    d.freeze("boss", at_ms=2000)
    state = d.snapshot()
    assert set(state) == {"version", "tier", "window", "history",
                          "reasons", "frozen", "stats"}
    pristine = copy.deepcopy(state)
    state["history"].clear()
    state["stats"]["adjustments"] = 99
    assert d.tier_of() == 1
    clone = director()
    clone.restore(pristine)
    assert clone.tier_of() == 1
    assert clone.is_frozen() is True
    assert len(clone.history_of()) == 1
    assert clone.coefficients_of() == (11500, 11000)
    assert clone.stats() == d.stats()


def test_restore_rejects_malformed_state():
    d = director()
    d.observe(deaths=4, kills=3)
    d.evaluate_adjust(at_ms=0)
    bad_states = [
        None,
        {},
        {"version": 1, "tier": 1, "window": [], "history": [], "reasons": {},
         "frozen": None, "stats": {}},
        {"version": 1, "tier": 1, "window": {}, "history": {}, "reasons": {},
         "frozen": None, "stats": {}},
        {"version": 1, "tier": 1, "window": {}, "history": [], "reasons": [],
         "frozen": None, "stats": {}},
        {"version": 1, "tier": 1, "window": {}, "history": [], "reasons": {},
         "frozen": None},
    ]
    for bad in bad_states:
        with pytest.raises(dd.DirectorError) as exc:
            d.restore(bad)
        assert exc.value.code == "DIRECTOR_SNAPSHOT_INVALID"
    assert d.tier_of() == 1
    assert len(d.history_of()) == 1


def test_concurrent_observations_are_counted_exactly():
    d = director()
    failures = []
    barrier = threading.Barrier(16)

    def worker():
        try:
            barrier.wait(timeout=5)
            for _ in range(5):
                d.observe(deaths=1, kills=1, at_ms=0)
        except Exception as exc:  # pragma: no cover - surfaced through failures
            failures.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    window = d.metrics()
    assert (window["deaths"], window["kills"]) == (80, 80)
    assert d.stats()["observations"] == 80


def test_stats_track_observations_evaluations_and_freezes():
    d = director()
    d.observe(deaths=4, kills=3)
    d.observe(deaths=1, kills=1)
    d.evaluate_adjust(at_ms=0)
    d.freeze("boss")
    assert d.stats() == {"observations": 2, "evaluations": 1,
                         "adjustments": 1, "freezes": 1}
