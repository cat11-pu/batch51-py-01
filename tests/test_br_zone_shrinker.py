import pytest

import br_zone_shrinker as bz

PHASES = [
    {"phase": 0, "hold_ms": 10_000, "shrink_ms": 0,
     "center": (0.0, 0.0), "radius": 500.0},
    {"phase": 1, "hold_ms": 20_000, "shrink_ms": 10_000,
     "center": (100.0, 0.0), "radius": 300.0},
    {"phase": 2, "hold_ms": 20_000, "shrink_ms": 10_000,
     "center": (150.0, 50.0), "radius": 100.0},
]


def phases_copy():
    return [dict(item) for item in PHASES]


def shrinker(**kwargs):
    obj = bz.BrZoneShrinker(**kwargs)
    obj.configure_phases(phases_copy())
    return obj


def test_configure_rejects_phase_index_gaps():
    obj = bz.BrZoneShrinker()
    broken = phases_copy()
    broken[2]["phase"] = 3
    with pytest.raises(bz.ZoneError) as exc:
        obj.configure_phases(broken)
    assert exc.value.code == "ZS_INVALID_PHASE"


def test_configure_rejects_radius_not_strictly_decreasing():
    obj = bz.BrZoneShrinker()
    broken = phases_copy()
    broken[2]["radius"] = 300.0
    with pytest.raises(bz.ZoneError) as exc:
        obj.configure_phases(broken)
    assert exc.value.code == "ZS_INVALID_PHASE"


def test_configure_rejects_center_outside_previous_circle():
    obj = bz.BrZoneShrinker()
    broken = phases_copy()
    broken[2]["center"] = (900.0, 0.0)
    broken[2]["radius"] = 250.0
    with pytest.raises(bz.ZoneError) as exc:
        obj.configure_phases(broken)
    assert exc.value.code == "ZS_CENTER_OUTSIDE"


def test_configure_rejects_negative_hold_ms():
    obj = bz.BrZoneShrinker()
    broken = phases_copy()
    broken[1]["hold_ms"] = -1
    with pytest.raises(bz.ZoneError) as exc:
        obj.configure_phases(broken)
    assert exc.value.code == "ZS_INVALID_PHASE"


def test_configure_is_single_shot_and_caps_phase_count():
    too_many = [dict(PHASES[0])]
    for index in range(1, bz.MAX_PHASES + 1):
        too_many.append({"phase": index, "hold_ms": 1_000, "shrink_ms": 1_000,
                         "center": (0.0, 0.0), "radius": 500.0 - index})
    with pytest.raises(bz.ZoneError) as exc:
        bz.BrZoneShrinker().configure_phases(too_many)
    assert exc.value.code == "ZS_TOO_MANY_PHASES"

    obj = shrinker()
    with pytest.raises(bz.ZoneError) as exc:
        obj.configure_phases(phases_copy())
    assert exc.value.code == "ZS_PHASES_LOCKED"


def test_advance_returns_every_crossed_phase_in_order():
    obj = shrinker()
    assert obj.advance(45_000) == (1, 2)
    assert obj.stats()["clock_ms"] == 45_000
    assert obj.current_zone().phase == 2
    assert obj.advance(5_000) == ()


def test_advance_rejects_negative_elapsed():
    obj = shrinker()
    with pytest.raises(bz.ZoneError) as exc:
        obj.advance(-1)
    assert exc.value.code == "ZS_CLOCK_REWIND"
    assert obj.stats()["clock_ms"] == 0


def test_advance_zero_keeps_the_clock_and_the_initial_circle():
    obj = shrinker()
    assert obj.advance(0) == ()
    assert obj.advance(0) == ()
    assert obj.stats()["clock_ms"] == 0
    zone = obj.current_zone()
    assert (zone.phase, zone.center_x, zone.center_y, zone.radius) == (0, 0.0, 0.0, 500.0)


def test_current_zone_is_exact_during_hold_windows():
    obj = shrinker()
    obj.advance(5_000)
    first = obj.current_zone()
    assert (first.phase, first.center_x, first.center_y, first.radius) == (0, 0.0, 0.0, 500.0)
    obj.advance(25_000)
    second = obj.current_zone()
    assert (second.phase, second.center_x, second.center_y,
            second.radius) == (1, 100.0, 0.0, 300.0)


def test_current_zone_interpolates_during_shrink():
    obj = shrinker()
    obj.advance(15_000)
    mid = obj.current_zone()
    assert mid.phase == 1
    assert mid.radius == pytest.approx(400.0)
    assert (mid.center_x, mid.center_y) == (pytest.approx(50.0), pytest.approx(0.0))
    obj.advance(30_000)
    last = obj.current_zone()
    assert last.phase == 2
    assert last.radius == pytest.approx(200.0)
    assert (last.center_x, last.center_y) == (pytest.approx(125.0), pytest.approx(25.0))


def test_next_zone_follows_the_timeline():
    obj = shrinker()
    upcoming = obj.next_zone()
    assert (upcoming.phase, upcoming.center_x, upcoming.center_y,
            upcoming.radius) == (1, 100.0, 0.0, 300.0)
    obj.advance(15_000)
    upcoming = obj.next_zone()
    assert (upcoming.phase, upcoming.center_x, upcoming.center_y,
            upcoming.radius) == (2, 150.0, 50.0, 100.0)
    obj.advance(30_000)
    assert obj.next_zone() is None


def test_damage_tick_hits_only_players_outside():
    obj = shrinker()
    obj.player_entered("p-in", x=0.0, y=0.0, at_ms=0)
    obj.player_entered("p-out", x=900.0, y=900.0, at_ms=0)
    obj.advance(1_000)
    assert obj.damage_tick() == {"p-out": 1}
    assert obj.health_of("p-out") == 99
    assert obj.health_of("p-in") == 100
    assert obj.players_outside() == ("p-out",)

    obj.move_player("p-in", x=2_000.0, y=2_000.0)
    obj.advance(1_000)
    assert obj.damage_tick() == {"p-in": 1, "p-out": 1}
    assert obj.players_outside() == ("p-in", "p-out")


def test_damage_tick_settles_each_tick_exactly_once():
    obj = shrinker()
    obj.player_entered("p1", x=900.0, y=0.0, at_ms=0)
    obj.advance(1_000)
    assert obj.damage_tick() == {"p1": 1}
    assert obj.damage_tick() == {}
    assert obj.health_of("p1") == 99
    obj.advance(2_000)
    assert obj.damage_tick() == {"p1": 2}
    assert obj.health_of("p1") == 97


def test_zero_health_players_leave_the_outside_roster():
    obj = shrinker()
    obj.player_entered("p1", x=900.0, y=0.0, at_ms=0)
    obj.advance(100_000)
    assert obj.damage_tick() == {"p1": 100}
    assert obj.health_of("p1") == 0
    assert obj.players_outside() == ()
    assert obj.damage_tick() == {}


def test_snapshot_restore_roundtrip_and_malformed_rejection():
    obj = shrinker()
    obj.player_entered("p1", x=900.0, y=0.0, at_ms=0)
    obj.advance(5_000)
    obj.damage_tick()
    state = obj.snapshot()
    assert state["clock_ms"] == 5_000

    clone = bz.BrZoneShrinker()
    clone.restore(state)
    assert clone.stats()["clock_ms"] == 5_000
    assert clone.health_of("p1") == 95
    assert clone.damage_tick() == {}
    assert clone.current_zone().radius == pytest.approx(500.0)

    with pytest.raises(bz.ZoneError) as exc:
        clone.restore({"clock_ms": 1})
    assert exc.value.code == "ZS_SNAPSHOT_INVALID"
    assert clone.stats()["clock_ms"] == 5_000
    assert clone.health_of("p1") == 95
