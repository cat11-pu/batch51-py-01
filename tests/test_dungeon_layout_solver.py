import copy
import threading

import pytest

import dungeon_layout_solver as solver


def make_layout(**overrides):
    base = {
        "seed": 1,
        "attempt": 1,
        "rooms": ("entrance", "hall", "vault"),
        "entrance": "entrance",
        "boss": "vault",
        "corridors": (("entrance", "hall"),),
        "doors": (("d1", "hall", "vault"),),
        "keys": (("d1", "hall"),),
        "monsters": (),
        "chests": (),
        "monster_budget": 10,
        "chest_budget": 4,
    }
    base.update(overrides)
    return solver.Layout(**base)


def test_generate_is_deterministic_for_same_seed():
    first = solver.LayoutSolver()
    second = solver.LayoutSolver()
    left = first.generate(11)
    right = second.generate(11)
    assert left == right
    assert left.seed == 11
    assert left.attempt == 1
    assert first.describe(left) == second.describe(right)
    assert first.describe(first.generate(11)) == second.describe(right)


def test_different_seeds_produce_different_layouts():
    engine = solver.LayoutSolver()
    left = engine.generate(11)
    right = engine.generate(12)
    assert left != right
    assert engine.describe(left)["fingerprint"] != engine.describe(right)["fingerprint"]
    assert engine.describe(left)["seed"] == 11
    assert engine.describe(right)["seed"] == 12


def test_generate_respects_monster_and_chest_budgets():
    engine = solver.LayoutSolver()
    layout = engine.generate(5, monster_budget=6, chest_budget=3)
    assert layout.monster_budget == 6
    assert layout.chest_budget == 3
    assert sum(count for _, count in layout.monsters) <= 6
    assert sum(count for _, count in layout.chests) <= 3
    report = engine.validate(layout)
    assert report.monster_total == sum(count for _, count in layout.monsters)
    assert report.chest_total == sum(count for _, count in layout.chests)
    assert report.ok is True


def test_generated_layout_validates_clean():
    engine = solver.LayoutSolver()
    layout = engine.generate(3)
    report = engine.validate(layout)
    assert report.ok is True
    assert report.reason == "DUNGEON_OK"
    assert report.unreachable == ()
    assert report.reachable == tuple(sorted(layout.rooms))
    assert report.reachable == layout.rooms


def test_validate_accepts_key_placed_before_its_door():
    engine = solver.LayoutSolver()
    layout = make_layout()
    report = engine.validate(layout)
    assert report.ok is True
    assert report.reason == "DUNGEON_OK"
    assert report.reachable == ("entrance", "hall", "vault")
    assert report.unreachable == ()
    assert engine.path_to(layout, "vault") == ("entrance", "hall", "vault")
    assert engine.path_to(layout, "hall") == ("entrance", "hall")
    assert engine.path_to(layout, "tomb") is None


def test_validate_reports_unreachable_rooms():
    engine = solver.LayoutSolver()
    layout = make_layout(doors=(), keys=())
    report = engine.validate(layout)
    assert report.ok is False
    assert report.reason == "DUNGEON_UNREACHABLE_ROOMS"
    assert report.reachable == ("entrance", "hall")
    assert report.unreachable == ("vault",)
    assert engine.path_to(layout, "vault") is None


def test_validate_flags_budget_overflow():
    engine = solver.LayoutSolver()
    layout = make_layout(monsters=(("hall", 4), ("entrance", 2)), monster_budget=5)
    report = engine.validate(layout)
    assert report.ok is False
    assert report.reason == "DUNGEON_BUDGET_EXCEEDED"
    assert report.monster_total == 6
    assert report.unreachable == ()

    chests = make_layout(chests=(("vault", 3), ("hall", 2)), chest_budget=4)
    report = engine.validate(chests)
    assert report.ok is False
    assert report.reason == "DUNGEON_BUDGET_EXCEEDED"
    assert report.chest_total == 5


def test_validate_rejects_malformed_layout():
    engine = solver.LayoutSolver()
    broken = [
        make_layout(rooms=("entrance", "hall", "hall")),
        make_layout(corridors=(("entrance", "ghost"),)),
        make_layout(doors=(("d1", "hall", "ghost"),)),
        make_layout(keys=(("d9", "hall"),)),
        make_layout(boss="tomb"),
        make_layout(entrance="porch"),
        make_layout(rooms=()),
        make_layout(corridors=(("hall", "hall"),)),
    ]
    for layout in broken:
        report = engine.validate(layout)
        assert report.ok is False
        assert report.reason == "DUNGEON_LAYOUT_MALFORMED"
        assert report.reachable == ()
        assert report.unreachable == ()


def test_describe_is_order_independent():
    engine = solver.LayoutSolver()
    left = make_layout(corridors=(("entrance", "hall"),),
                       monsters=(("hall", 2), ("entrance", 1)),
                       chests=(("vault", 1),))
    right = make_layout(corridors=(("hall", "entrance"),),
                        monsters=(("entrance", 1), ("hall", 2)),
                        chests=(("vault", 1),))
    left_view = engine.describe(left)
    right_view = engine.describe(right)
    assert left_view == right_view
    assert left_view["fingerprint"] == right_view["fingerprint"]
    assert len(left_view["fingerprint"]) == 32
    assert left_view["rooms"] == ("entrance", "hall", "vault")
    assert left_view["corridors"] == (("entrance", "hall"),)
    assert left_view["monster_total"] == 3
    assert left_view["chest_total"] == 1
    assert set(left_view) == {"seed", "attempt", "entrance", "boss", "rooms",
                              "corridors", "doors", "keys", "monsters", "chests",
                              "monster_total", "chest_total", "monster_budget",
                              "chest_budget", "fingerprint"}


def test_regenerate_first_attempt_matches_generate():
    engine = solver.LayoutSolver()
    out = engine.regenerate(9, max_attempts=4)
    assert out.ok is True
    assert out.attempts == 1
    assert out.reason == "DUNGEON_OK"
    assert out.layout is not None
    assert engine.describe(out.layout) == engine.describe(engine.generate(9))
    assert engine.stats()["regenerations"] == 1


def test_invalid_arguments_are_refused():
    engine = solver.LayoutSolver()
    for bad_seed in ["7", None, 1.5, True, [3]]:
        with pytest.raises(solver.DungeonError) as exc:
            engine.generate(bad_seed)
        assert exc.value.code == "DUNGEON_INVALID_REQUEST"
    with pytest.raises(solver.DungeonError) as exc:
        engine.validate(None)
    assert exc.value.code == "DUNGEON_INVALID_REQUEST"
    with pytest.raises(solver.DungeonError) as exc:
        engine.generate(1, monster_budget=-1)
    assert exc.value.code == "DUNGEON_INVALID_REQUEST"
    with pytest.raises(solver.DungeonError) as exc:
        engine.regenerate(1, max_attempts=0)
    assert exc.value.code == "DUNGEON_INVALID_REQUEST"
    assert engine.stats()["generations"] == 0


def test_snapshot_is_detached_and_restore_roundtrips():
    engine = solver.LayoutSolver()
    layout = engine.generate(17)
    state = engine.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "config", "current", "counters"}
    assert pristine["config"] == {"monster_budget": 12, "chest_budget": 4,
                                  "max_attempts": 4}
    state["current"]["monster_budget"] = 99
    state["counters"]["generations"] = 99
    assert engine.current() == layout
    assert engine.stats() == {"generations": 1, "regenerations": 0, "validations": 0}
    clone = solver.LayoutSolver()
    clone.restore(pristine)
    assert clone.current() == layout
    assert clone.describe(clone.current()) == engine.describe(layout)
    assert clone.validate(clone.current()).ok is True
    assert clone.stats()["generations"] == 1


def test_restore_rejects_malformed_state():
    engine = solver.LayoutSolver()
    layout = engine.generate(17)
    good = engine.snapshot()
    bad_states = [
        None,
        [],
        {},
        {"version": 2, "config": good["config"], "current": good["current"],
         "counters": good["counters"]},
        {"version": 1, "config": {"monster_budget": 12}, "current": None,
         "counters": good["counters"]},
        {"version": 1, "config": good["config"], "current": {},
         "counters": good["counters"]},
        {"version": 1, "config": good["config"], "current": good["current"],
         "counters": {"generations": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(solver.DungeonError) as exc:
            engine.restore(bad)
        assert exc.value.code == "DUNGEON_SNAPSHOT_INVALID"
    assert engine.current() == layout
    assert engine.stats()["generations"] == 1


def test_concurrent_generate_same_seed_is_stable():
    engine = solver.LayoutSolver()
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(engine.describe(engine.generate(21))["fingerprint"])
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert len(set(results)) == 1
    assert engine.stats()["generations"] == 8


def test_validate_flags_locked_door_without_key():
    engine = solver.LayoutSolver()
    layout = make_layout(keys=())
    report = engine.validate(layout)
    assert report.ok is False
    assert report.reason == "DUNGEON_UNREACHABLE_ROOMS"
    assert report.reachable == ("entrance", "hall")
    assert report.unreachable == ("vault",)
