import copy
import threading

import pytest

import gacha_pity_guard as gp


def guard(**kwargs):
    return gp.GachaPityGuard(**kwargs)


def test_register_pool_defaults_and_view():
    g = guard()
    view = g.register_pool("std")
    assert isinstance(view, gp.PoolView)
    assert (view.pool_id, view.group) == ("std", "std")
    assert (view.base_rate_bps, view.hard_pity, view.soft_pity,
            view.step_bps) == (60, 90, 75, 600)
    assert view.counter == 0
    assert (view.total_pulls, view.golds, view.pity_triggers) == (0, 0, 0)
    assert g.pool_view("std") == view
    assert g.current_counter("std") == 0
    assert g.rate_bps("std") == 60
    assert g.stats() == {"pools": 1, "draws": 0, "golds": 0,
                         "pity_triggers": 0, "switches": 0, "carried": 0}


def test_register_pool_rejects_invalid_and_duplicate():
    g = guard()
    bad = [
        dict(pool_id=""),
        dict(pool_id="   "),
        dict(pool_id="p1", group="  "),
        dict(pool_id="p2", base_rate_bps=-1),
        dict(pool_id="p3", base_rate_bps=10001),
        dict(pool_id="p4", hard_pity=0),
        dict(pool_id="p5", hard_pity=10, soft_pity=10),
        dict(pool_id="p6", soft_pity=-1),
        dict(pool_id="p7", step_bps=-1),
    ]
    for kwargs in bad:
        with pytest.raises(gp.GachaError) as exc:
            g.register_pool(**kwargs)
        assert exc.value.code == "GACHA_POOL_INVALID"
    assert g.stats()["pools"] == 0

    g.register_pool("std", hard_pity=20, soft_pity=15)
    with pytest.raises(gp.GachaError) as exc:
        g.register_pool("std")
    assert exc.value.code == "GACHA_POOL_EXISTS"
    assert g.pool_view("std").hard_pity == 20


def test_pool_capacity_cap_blocks_new_registration():
    g = guard(max_pools=2)
    g.register_pool("a")
    g.register_pool("b")
    with pytest.raises(gp.GachaError) as exc:
        g.register_pool("c")
    assert exc.value.code == "GACHA_CAPACITY"
    assert g.stats()["pools"] == 2
    assert g.pool_view("a").group == "a"
    with pytest.raises(gp.GachaError) as exc:
        g.pool_view("c")
    assert exc.value.code == "GACHA_UNKNOWN_POOL"


def test_single_miss_advances_water_and_audit():
    g = guard()
    g.register_pool("std")
    out = g.draw("std", roll=9999)
    assert isinstance(out, gp.DrawOutcome)
    assert out.index == 0
    assert out.roll == 9999
    assert out.rate_bps == 60
    assert (out.natural, out.pity, out.gold) == (False, False, False)
    assert out.counter_after == 1
    assert g.current_counter("std") == 1
    assert g.pity_left("std") == 89
    view = g.pool_view("std")
    assert (view.total_pulls, view.golds, view.pity_triggers) == (1, 0, 0)

    entries = g.audit("std")
    assert len(entries) == 1
    entry = entries[0]
    assert entry.seq == 1
    assert entry.kind == "draw"
    assert (entry.counter_before, entry.counter_after) == (0, 1)
    assert entry.roll == 9999
    assert entry.gold is False
    assert entry.pity is False
    assert g.stats()["draws"] == 1

    second = g.draw("std", roll=9999)
    assert second.index == 1
    assert second.counter_after == 2


def test_natural_gold_clears_water():
    g = guard()
    g.register_pool("std")
    for _ in range(5):
        assert g.draw("std", roll=9999).gold is False
    assert g.current_counter("std") == 5

    out = g.draw("std", roll=0)
    assert out.natural is True
    assert out.pity is False
    assert out.gold is True
    assert out.counter_after == 0
    assert g.current_counter("std") == 0

    view = g.pool_view("std")
    assert (view.total_pulls, view.golds, view.pity_triggers) == (6, 1, 0)
    assert g.stats()["golds"] == 1
    assert g.stats()["pity_triggers"] == 0


def test_hard_pity_forces_gold_on_threshold_pull():
    g = guard()
    g.register_pool("std", hard_pity=10, soft_pity=9)
    for _ in range(9):
        assert g.draw("std", roll=9999).gold is False

    out = g.draw("std", roll=9999)
    assert out.natural is False
    assert out.pity is True
    assert out.gold is True
    assert g.stats()["pity_triggers"] == 1
    assert g.stats()["golds"] == 1
    view = g.pool_view("std")
    assert (view.golds, view.pity_triggers) == (1, 1)


def test_soft_pity_rate_ramp_and_cap():
    g = guard()
    g.register_pool("ramp", base_rate_bps=60, hard_pity=90,
                    soft_pity=75, step_bps=600)
    for _ in range(74):
        assert g.draw("ramp", roll=9999).gold is False
    assert g.current_counter("ramp") == 74
    assert g.rate_bps("ramp") == 60

    assert g.draw("ramp", roll=9999).gold is False
    assert g.current_counter("ramp") == 75
    assert g.rate_bps("ramp") == 660

    assert g.draw("ramp", roll=9999).gold is False
    assert g.rate_bps("ramp") == 1260

    cap = guard()
    cap.register_pool("fast", base_rate_bps=60, hard_pity=90,
                      soft_pity=1, step_bps=2500)
    for _ in range(4):
        assert cap.draw("fast", roll=9999).gold is False
    assert cap.current_counter("fast") == 4
    assert cap.rate_bps("fast") == 10000


def test_pity_left_tracks_remaining_pulls():
    g = guard()
    g.register_pool("std", hard_pity=20, soft_pity=15)
    assert g.pity_left("std") == 20
    for _ in range(3):
        g.draw("std", roll=9999)
    assert g.current_counter("std") == 3
    assert g.pity_left("std") == 17
    g.draw("std", roll=9999)
    assert g.pity_left("std") == 16


def test_invalid_roll_and_unknown_pool_leave_state_untouched():
    g = guard()
    g.register_pool("std")
    for roll in (-1, 10000, "5", 3.5):
        with pytest.raises(gp.GachaError) as exc:
            g.draw("std", roll=roll)
        assert exc.value.code == "GACHA_INVALID_ROLL"

    with pytest.raises(gp.GachaError) as exc:
        g.draw("ghost", roll=1)
    assert exc.value.code == "GACHA_UNKNOWN_POOL"

    assert g.current_counter("std") == 0
    assert g.pool_view("std").total_pulls == 0
    assert g.audit("std") == []
    assert g.stats()["draws"] == 0


def test_ten_pull_requires_exactly_ten_rolls_atomically():
    g = guard()
    g.register_pool("std")
    for rolls in ([9999] * 9, [9999] * 11):
        with pytest.raises(gp.GachaError) as exc:
            g.draw_ten("std", rolls=rolls)
        assert exc.value.code == "GACHA_BATCH_SIZE"

    with pytest.raises(gp.GachaError) as exc:
        g.draw_ten("std", rolls=[9999] * 9 + [10000])
    assert exc.value.code == "GACHA_INVALID_ROLL"

    with pytest.raises(gp.GachaError) as exc:
        g.draw_ten("ghost", rolls=[0] * 10)
    assert exc.value.code == "GACHA_UNKNOWN_POOL"

    assert g.current_counter("std") == 0
    assert g.pool_view("std").total_pulls == 0
    assert g.audit("std") == []
    assert g.stats()["draws"] == 0


def test_ten_pull_report_aggregates_outcomes():
    g = guard()
    g.register_pool("std")
    rolls = [0] + [9999] * 9
    report = g.draw_ten("std", rolls=rolls)

    assert isinstance(report, gp.TenPullReport)
    assert report.pool_id == "std"
    assert len(report.outcomes) == 10
    assert [row.index for row in report.outcomes] == list(range(10))
    assert [row.roll for row in report.outcomes] == rolls
    assert report.outcomes[0].natural is True
    assert report.outcomes[0].gold is True
    assert report.outcomes[0].counter_after == 0
    assert all(row.gold is False for row in report.outcomes[1:])
    assert report.golds == 1
    assert report.pity_triggers == 0
    assert report.counter_after == 9

    assert g.current_counter("std") == 9
    assert g.stats()["draws"] == 10
    assert len(g.audit("std")) == 10


def test_switch_pool_carries_water_within_group():
    g = guard()
    g.register_pool("std", group="anniversary")
    g.register_pool("limited", group="anniversary")
    for _ in range(4):
        g.draw("std", roll=9999)
    assert g.current_counter("std") == 4

    carried = g.switch_pool("std", "limited")
    assert carried == 4
    assert g.current_counter("std") == 0
    assert g.current_counter("limited") == 4
    assert g.pity_left("limited") == 86

    entry = g.audit("limited")[-1]
    assert entry.kind == "carry"
    assert (entry.counter_before, entry.counter_after) == (0, 4)
    assert entry.roll is None
    assert g.stats()["switches"] == 1
    assert g.stats()["carried"] == 4


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    g.register_pool("std", hard_pity=20, soft_pity=15)
    g.draw("std", roll=9999)
    state = g.snapshot()
    assert isinstance(state, dict)
    assert set(state) == {"version", "pools", "audit", "counters", "stats"}
    pristine = copy.deepcopy(state)

    state["pools"].clear()
    state["audit"].clear()
    state["stats"]["draws"] = 999

    assert g.current_counter("std") == 1
    assert len(g.audit()) == 1
    assert g.stats()["draws"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.current_counter("std") == 1
    assert clone.pool_view("std").hard_pity == 20
    assert clone.stats() == g.stats()
    assert len(clone.audit("std")) == 1
    assert clone.draw("std", roll=9999).index == 1


def test_restore_rejects_malformed_snapshot():
    g = guard()
    g.register_pool("std")
    g.draw("std", roll=9999)
    good = g.snapshot()
    bad_states = [
        None,
        {},
        {"version": 2, "pools": {}, "audit": [], "counters": {}, "stats": {}},
        {**good, "pools": []},
        {**good, "audit": {}},
        {**good, "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(gp.GachaError) as exc:
            g.restore(bad)
        assert exc.value.code == "GACHA_SNAPSHOT_INVALID"

    assert g.current_counter("std") == 1
    assert len(g.audit("std")) == 1
    assert g.stats()["draws"] == 1


def test_concurrent_draws_keep_every_count():
    g = guard()
    g.register_pool("std")
    errors = []
    barrier = threading.Barrier(16)

    def worker():
        try:
            barrier.wait(timeout=5)
            g.draw("std", roll=9999)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.current_counter("std") == 16
    assert g.pool_view("std").total_pulls == 16
    assert g.stats()["draws"] == 16
    registry = g.audit("std")
    assert len(registry) == 16
    assert [entry.seq for entry in registry] == list(range(1, 17))
