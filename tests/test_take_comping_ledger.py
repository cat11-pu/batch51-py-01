import copy

import pytest

import take_comping_ledger as tc


def ledger(**kwargs):
    return tc.TakeCompingLedger(**kwargs)


def takes(led, *names, length=500):
    for name in names:
        led.add_take(name, length_samples=length)


def shape(result):
    return [(seg.take_id, seg.start_sample, seg.end_sample) for seg in result.segments]


def test_add_take_validates_and_returns_info():
    led = ledger()
    info = led.add_take("  take-a ", length_samples=480, gain_db=-3.5)
    assert (info.take_id, info.length_samples, info.gain_db, info.muted) == (
        "take-a", 480, -3.5, False)
    assert led.stats()["takes"] == 1

    with pytest.raises(tc.TakeError) as exc:
        led.add_take("take-a", length_samples=10)
    assert exc.value.code == "TAKE_EXISTS"

    for take_id, length, gain in (("", 100, 0.0), ("   ", 100, 0.0),
                                  ("take-b", 0, 0.0), ("take-b", -3, 0.0),
                                  ("take-b", 100, -61.0), ("take-b", 100, 25.0)):
        with pytest.raises(tc.TakeError) as exc:
            led.add_take(take_id, length_samples=length, gain_db=gain)
        assert exc.value.code == "TAKE_INVALID"
    assert led.stats()["takes"] == 1


def test_add_take_capacity_is_hard():
    led = ledger(max_takes=2)
    takes(led, "a", "b")
    with pytest.raises(tc.TakeError) as exc:
        led.add_take("c", length_samples=100)
    assert exc.value.code == "TAKE_CAPACITY"
    assert led.stats()["takes"] == 2


def test_place_region_validates_bounds():
    led = ledger()
    led.add_take("a", length_samples=100)
    cases = [
        ("ghost", 0, 10, 0, 0, "TAKE_UNKNOWN"),
        ("a", -1, 10, 0, 0, "TAKE_REGION_INVALID"),
        ("a", 0, 101, 0, 0, "TAKE_REGION_INVALID"),
        ("a", 10, 10, 0, 0, "TAKE_REGION_INVALID"),
        ("a", 20, 10, 0, 0, "TAKE_REGION_INVALID"),
        ("a", 0, 10, -1, 0, "TAKE_REGION_INVALID"),
        ("a", 0, 10, 0, 1001, "TAKE_REGION_INVALID"),
    ]
    for take_id, start, end, at, priority, code in cases:
        with pytest.raises(tc.TakeError) as exc:
            led.place_region(take_id, start=start, end=end, at=at,
                             priority=priority)
        assert exc.value.code == code
    assert led.stats()["regions"] == 0
    assert led.stats()["placed"] == 0


def test_region_ids_are_monotonic_and_capped():
    led = ledger(max_regions=2)
    led.add_take("a", length_samples=100)
    first = led.place_region("a", start=0, end=10, at=0)
    second = led.place_region("a", start=0, end=10, at=20)
    assert (first.region_id, second.region_id) == (1, 2)
    assert (first.take_id, first.start, first.end, first.at, first.priority) == (
        "a", 0, 10, 0, 0)

    with pytest.raises(tc.TakeError) as exc:
        led.place_region("a", start=0, end=10, at=40)
    assert exc.value.code == "TAKE_CAPACITY"

    led.remove_region(second.region_id)
    third = led.place_region("a", start=0, end=10, at=40)
    assert third.region_id == 3
    assert led.stats()["regions"] == 2
    assert led.stats()["placed"] == 3


def test_bounce_single_region_is_sample_exact():
    led = ledger()
    led.add_take("take-a", length_samples=1000)
    led.place_region("take-a", start=100, end=300, at=50)

    result = led.bounce(start=0, end=400)
    assert shape(result) == [("take-a", 50, 250)]
    assert result.total_samples == 400
    assert result.silent_samples == 200
    assert led.resolve_overlaps(start=0, end=400) == result.segments
    assert led.stats()["bounces"] == 1


def test_gap_between_regions_counts_as_silent():
    led = ledger()
    takes(led, "a", "b", length=1000)
    led.place_region("a", start=0, end=100, at=0)
    led.place_region("b", start=0, end=100, at=300)

    result = led.bounce(start=0, end=500)
    assert shape(result) == [("a", 0, 100), ("b", 300, 400)]
    assert result.total_samples == 500
    assert result.silent_samples == 300


def test_priority_wins_inside_overlap():
    led = ledger()
    takes(led, "a", "b")
    led.place_region("a", start=0, end=200, at=0, priority=1)
    led.place_region("b", start=0, end=200, at=100, priority=5)

    result = led.bounce(start=0, end=300)
    assert shape(result) == [("a", 0, 100), ("b", 100, 300)]
    assert result.silent_samples == 0
    assert result.total_samples == 300


def test_equal_priority_prefers_later_region():
    led = ledger()
    takes(led, "a", "b")
    first = led.place_region("a", start=0, end=200, at=0, priority=0)
    second = led.place_region("b", start=0, end=200, at=100, priority=0)
    assert second.region_id > first.region_id

    assert shape(led.bounce(start=0, end=300)) == [("a", 0, 100), ("b", 100, 300)]


def test_empty_timeline_is_all_silent_and_validated():
    led = ledger()
    result = led.bounce(start=10, end=60)
    assert result.segments == ()
    assert result.total_samples == 50
    assert result.silent_samples == 50

    for start, end in ((60, 60), (70, 60), (-1, 10)):
        with pytest.raises(tc.TakeError) as exc:
            led.bounce(start=start, end=end)
        assert exc.value.code == "TAKE_INVALID"


def test_muted_take_drops_out_of_bounce():
    led = ledger()
    led.add_take("a", length_samples=500)
    led.place_region("a", start=0, end=100, at=0)

    led.set_muted("a", True)
    result = led.bounce(start=0, end=100)
    assert result.segments == ()
    assert result.silent_samples == 100
    assert led.stats()["audible_regions"] == 0

    led.set_muted("a", False)
    result = led.bounce(start=0, end=100)
    assert shape(result) == [("a", 0, 100)]
    assert result.silent_samples == 0
    assert led.stats()["audible_regions"] == 1

    with pytest.raises(tc.TakeError) as exc:
        led.set_muted("ghost", True)
    assert exc.value.code == "TAKE_UNKNOWN"


def test_remove_region_falls_back_and_rejects_unknown():
    led = ledger()
    takes(led, "a", "b")
    led.place_region("a", start=0, end=200, at=0, priority=1)
    top = led.place_region("b", start=0, end=200, at=100, priority=5)
    assert shape(led.bounce(start=0, end=300)) == [("a", 0, 100), ("b", 100, 300)]

    removed = led.remove_region(top.region_id)
    assert removed.region_id == top.region_id
    result = led.bounce(start=0, end=300)
    assert shape(result) == [("a", 0, 200)]
    assert result.silent_samples == 100
    assert led.stats()["regions"] == 1

    with pytest.raises(tc.TakeError) as exc:
        led.remove_region(999)
    assert exc.value.code == "TAKE_UNKNOWN"


def test_undo_reverts_last_placement():
    led = ledger()
    led.add_take("a", length_samples=500)
    led.place_region("a", start=0, end=100, at=0)
    assert led.stats()["regions"] == 1

    assert led.undo() == 1
    assert led.stats()["regions"] == 0
    assert led.stats()["undone"] == 1
    assert led.bounce(start=0, end=100).silent_samples == 100


def test_undo_restores_removed_region_and_empty_stack():
    led = ledger()
    with pytest.raises(tc.TakeError) as exc:
        led.undo()
    assert exc.value.code == "TAKE_NOTHING_TO_UNDO"

    led.add_take("a", length_samples=500)
    region = led.place_region("a", start=0, end=100, at=0)
    led.remove_region(region.region_id)
    assert led.stats()["regions"] == 0

    assert led.undo() == 1
    assert led.stats()["regions"] == 1
    assert shape(led.bounce(start=0, end=100)) == [("a", 0, 100)]
    assert led.stats()["undone"] == 1


def test_snapshot_restore_keeps_undo_stack():
    led = ledger()
    led.add_take("a", length_samples=500)
    led.place_region("a", start=0, end=100, at=0)
    led.place_region("a", start=0, end=100, at=200)

    state = led.snapshot()
    pristine = copy.deepcopy(state)
    state["regions"].clear()
    state["stats"]["regions"] = 99
    assert led.stats()["regions"] == 2

    clone = ledger()
    clone.restore(pristine)
    assert clone.stats() == led.stats()
    assert shape(clone.bounce(start=0, end=300)) == [("a", 0, 100), ("a", 200, 300)]

    assert clone.undo() == 1
    assert clone.stats()["regions"] == 1

    bad_states = [
        None,
        {},
        {"version": 2, "next_region": 1, "takes": [], "regions": [],
         "undo": [], "stats": {}},
        {"version": 1, "next_region": 1, "takes": "nope", "regions": [],
         "undo": [], "stats": {}},
        {"version": 1, "next_region": 1, "takes": [], "regions": "nope",
         "undo": [], "stats": {}},
        {"version": 1, "next_region": 1, "takes": [], "regions": [],
         "undo": "nope", "stats": {}},
        {"version": 1, "next_region": 1, "takes": [{"take_id": "a"}],
         "regions": [], "undo": [], "stats": {}},
        {"version": 1, "next_region": 1, "takes": [], "regions": [],
         "undo": [], "stats": {"placed": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(tc.TakeError) as exc:
            clone.restore(bad)
        assert exc.value.code == "TAKE_SNAPSHOT_INVALID"

    assert clone.stats()["regions"] == 1


def test_stats_track_each_operation():
    led = ledger()
    led.add_take("a", length_samples=500)
    led.add_take("b", length_samples=500, muted=True)
    first = led.place_region("a", start=0, end=100, at=0)
    second = led.place_region("b", start=0, end=100, at=0)
    led.bounce(start=0, end=100)
    led.remove_region(second.region_id)
    led.undo()
    led.set_priority(first.region_id, 3)

    assert led.stats() == {"takes": 2, "regions": 2, "audible_regions": 1,
                           "placed": 2, "removed": 1, "bounces": 1,
                           "undone": 1}
