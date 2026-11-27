import copy

import pytest

import troop_march_scheduler as tm

SNAPSHOT_KEYS = {"version", "config", "marches", "seq", "counters"}


def sched(**kwargs):
    return tm.TroopMarchScheduler(**kwargs)


def march(g, troop_id="t-1", player="p-1", *, origin=(0, 0), target=(2, 2),
          speed=1, troops=100, at=0):
    return g.dispatch(troop_id, player, origin=origin, target=target,
                      speed=speed, troops=troops, at=at)


def test_eta_uses_chebyshev_distance_and_speed():
    g = sched()
    record = march(g, target=(3, 4), speed=2, at=1000)
    assert (record.seq, record.state) == (1, "marching")
    assert record.arrive_at == 3000
    assert g.eta("t-1") == 3000


def test_eta_rounds_partial_seconds_up():
    g = sched()
    record = march(g, origin=(5, 5), target=(6, 6), speed=3, at=0)
    assert record.arrive_at == 334
    assert g.eta("t-1") == 334


def test_dispatch_validates_coordinates_speed_and_troops():
    g = sched()
    bad_cases = [
        (dict(origin=(-1, 0)), "MARCH_INVALID_COORD"),
        (dict(target=(0, "2")), "MARCH_INVALID_COORD"),
        (dict(speed=0), "MARCH_INVALID_SPEED"),
        (dict(speed=11), "MARCH_INVALID_SPEED"),
        (dict(troops=0), "MARCH_INVALID_TROOPS"),
        (dict(origin=(2, 2)), "MARCH_INVALID_TARGET"),
        (dict(player="  "), "MARCH_INVALID_REQUEST"),
    ]
    for kwargs, code in bad_cases:
        with pytest.raises(tm.MarchError) as exc:
            march(g, **kwargs)
        assert exc.value.code == code
    with pytest.raises(tm.MarchError) as exc:
        march(g, troop_id=" ")
    assert exc.value.code == "MARCH_INVALID_REQUEST"
    assert g.stats()["dispatched"] == 0


def test_dispatch_refuses_an_active_troop_until_it_settles():
    g = sched()
    march(g, at=0)
    with pytest.raises(tm.MarchError) as exc:
        march(g, at=10)
    assert exc.value.code == "MARCH_ALREADY_MARCHING"
    g.resolve_arrival("t-1", at=2000)
    again = march(g, target=(1, 1), at=2000)
    assert again.seq == 2
    assert again.arrive_at == 3000


def test_dispatch_enforces_the_per_player_march_limit():
    g = sched(max_marches_per_player=2)
    march(g, "t-1", target=(1, 1), at=0)
    march(g, "t-2", target=(2, 2), at=1)
    with pytest.raises(tm.MarchError) as exc:
        march(g, "t-3", target=(3, 3), at=2)
    assert exc.value.code == "MARCH_LIMIT_EXCEEDED"
    march(g, "t-9", player="p-2", target=(3, 3), at=2)
    assert g.active_marches("p-1") == ("t-1", "t-2")


def test_arrive_queue_orders_by_arrival_time():
    g = sched()
    march(g, "t-1", target=(2, 2), at=0)
    march(g, "t-2", target=(2, 2), at=1000)
    assert g.arrive_queue((2, 2), at=5000) == ("t-1", "t-2")
    assert g.arrive_queue((9, 9), at=5000) == ()


def test_arrive_queue_hides_troops_that_have_not_arrived_yet():
    g = sched()
    march(g, "t-1", target=(2, 2), at=0)
    march(g, "t-2", target=(2, 2), at=1000)
    assert g.arrive_queue((2, 2), at=1999) == ()
    assert g.arrive_queue((2, 2), at=2000) == ("t-1",)
    assert g.arrive_queue((2, 2), at=2999) == ("t-1",)


def test_arrive_queue_drops_settled_troops():
    g = sched()
    march(g, "t-1", target=(2, 2), at=0)
    march(g, "t-2", target=(2, 2), at=1000)
    g.resolve_arrival("t-1", at=2000)
    assert g.arrive_queue((2, 2), at=5000) == ("t-2",)


def test_resolve_arrival_requires_an_arrived_known_troop():
    g = sched()
    march(g, at=0)
    with pytest.raises(tm.MarchError) as exc:
        g.resolve_arrival("t-1", at=1999)
    assert exc.value.code == "MARCH_NOT_ARRIVED"
    with pytest.raises(tm.MarchError) as exc:
        g.resolve_arrival("t-404", at=5000)
    assert exc.value.code == "MARCH_UNKNOWN_TROOP"


def test_resolve_arrival_reports_order_and_next_troop_once():
    g = sched()
    march(g, "t-1", target=(2, 2), at=0)
    march(g, "t-2", target=(2, 2), at=1000)
    first = g.resolve_arrival("t-1", at=2000)
    assert (first.order, first.state, first.next_troop) == (1, "resolved", "t-2")
    assert g.march_of("t-1").state == "resolved"
    with pytest.raises(tm.MarchError) as exc:
        g.resolve_arrival("t-1", at=2000)
    assert exc.value.code == "MARCH_ALREADY_RESOLVED"
    second = g.resolve_arrival("t-2", at=3000)
    assert (second.order, second.next_troop) == (2, None)


def test_recall_rejects_unknown_and_already_arrived_troops():
    g = sched()
    march(g, at=0)
    with pytest.raises(tm.MarchError) as exc:
        g.recall("t-404", at=10)
    assert exc.value.code == "MARCH_UNKNOWN_TROOP"
    g.resolve_arrival("t-1", at=2000)
    with pytest.raises(tm.MarchError) as exc:
        g.recall("t-1", at=2001)
    assert exc.value.code == "MARCH_ALREADY_ARRIVED"


def test_march_of_and_active_marches_expose_departure_order():
    g = sched()
    march(g, "t-2", target=(1, 1), at=0)
    march(g, "t-1", target=(2, 2), at=1)
    assert g.active_marches("p-1") == ("t-2", "t-1")
    assert g.active_marches("p-2") == ()
    record = g.march_of("t-1")
    assert (record.troop_id, record.player) == ("t-1", "p-1")
    assert (record.origin, record.target) == ((0, 0), (2, 2))
    assert (record.speed, record.troops, record.departed_at) == (1, 100, 1)
    assert g.march_of("t-404") is None


def test_arrival_order_is_computed_per_tile():
    g = sched()
    march(g, "t-1", target=(2, 2), at=0)
    march(g, "t-2", origin=(4, 4), target=(5, 5), at=0)
    march(g, "t-3", target=(2, 2), at=1000)
    other = g.resolve_arrival("t-2", at=1000)
    assert (other.order, other.tile, other.next_troop) == (1, (5, 5), None)
    first = g.resolve_arrival("t-1", at=2000)
    assert (first.order, first.next_troop) == (1, "t-3")
    last = g.resolve_arrival("t-3", at=3000)
    assert (last.order, last.next_troop) == (2, None)


def test_snapshot_is_detached_and_restore_resumes_the_queue():
    g = sched()
    march(g, "t-1", target=(2, 2), at=0)
    march(g, "t-2", target=(2, 2), at=100)
    state = g.snapshot()
    assert set(state) == SNAPSHOT_KEYS
    pristine = copy.deepcopy(state)
    state["marches"].clear()
    assert g.eta("t-1") == 2000
    assert g.arrive_queue((2, 2), at=5000) == ("t-1", "t-2")

    clone = sched()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.eta("t-1") == 2000
    assert clone.eta("t-2") == 2100
    assert clone.arrive_queue((2, 2), at=5000) == ("t-1", "t-2")
    assert clone.active_marches("p-1") == ("t-1", "t-2")
    first = clone.resolve_arrival("t-1", at=2000)
    assert (first.order, first.next_troop) == (1, "t-2")


def test_restore_rejects_malformed_state_and_keeps_live_marches():
    g = sched()
    march(g, at=0)
    good = g.snapshot()
    bad_states = [
        None,
        {},
        {"version": 1},
        dict(good, version="1"),
        dict(good, marches={}),
        dict(good, seq="2"),
        dict(good, counters=[]),
        dict(good, config=[]),
    ]
    for bad in bad_states:
        with pytest.raises(tm.MarchError) as exc:
            g.restore(bad)
        assert exc.value.code == "MARCH_SNAPSHOT_INVALID"
    assert g.eta("t-1") == 2000
    assert g.active_marches("p-1") == ("t-1",)
