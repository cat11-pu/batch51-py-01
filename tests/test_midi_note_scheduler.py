import copy

import pytest

import midi_note_scheduler as ms


def scheduler(**kwargs):
    return ms.MidiNoteScheduler(**kwargs)


def note_on(sched, channel=0, pitch=60, velocity=100, at=0, device="kbd-a"):
    return sched.note_on(channel=channel, pitch=pitch, velocity=velocity,
                         at_ms=at, device=device)


def note_off(sched, channel=0, pitch=60, at=10, device="kbd-a"):
    return sched.note_off(channel=channel, pitch=pitch, at_ms=at, device=device)


def test_note_on_assigns_increasing_ids():
    sched = scheduler()
    first = note_on(sched)
    second = note_on(sched, channel=1)

    assert (first.note_id, second.note_id) == (1, 2)
    assert (first.channel, first.pitch, first.velocity) == (0, 60, 100)
    assert (first.at_ms, first.device, first.state) == (0, "kbd-a", "down")
    assert [row.note_id for row in sched.active_notes()] == [1, 2]
    assert [row.note_id for row in sched.active_notes(channel=1)] == [2]
    assert sched.stats()["note_on"] == 2
    assert sched.stats()["pending"] == 2


def test_note_on_rejects_invalid_values():
    sched = scheduler()
    cases = [
        dict(channel=16),
        dict(channel=-1),
        dict(pitch=128),
        dict(pitch=-1),
        dict(velocity=0),
        dict(velocity=128),
        dict(at=-1),
        dict(device=""),
        dict(device="   "),
    ]
    for patch in cases:
        kwargs = dict(channel=0, pitch=60, velocity=100, at=0, device="kbd-a")
        kwargs.update(patch)
        with pytest.raises(ms.MidiError) as exc:
            sched.note_on(channel=kwargs["channel"], pitch=kwargs["pitch"],
                          velocity=kwargs["velocity"], at_ms=kwargs["at"],
                          device=kwargs["device"])
        assert exc.value.code == "MIDI_INVALID"
    assert sched.stats()["note_on"] == 0
    assert sched.active_notes() == ()


def test_note_on_stack_limit_per_pitch():
    sched = scheduler(max_stack=2)
    note_on(sched, velocity=10, at=0)
    note_on(sched, velocity=20, at=1)
    with pytest.raises(ms.MidiError) as exc:
        note_on(sched, velocity=30, at=2)
    assert exc.value.code == "MIDI_STACK_LIMIT"
    assert len(sched.active_notes()) == 2

    note_on(sched, pitch=72, velocity=40, at=3)
    assert len(sched.active_notes()) == 3


def test_note_off_releases_note():
    sched = scheduler()
    pressed = note_on(sched)
    released = note_off(sched, at=50)
    assert released.note_id == pressed.note_id
    assert released.state == "released"
    assert sched.active_notes() == ()
    assert sched.stats()["note_off"] == 1
    assert sched.stats()["sustained"] == 0


def test_note_off_unknown_note_is_rejected():
    sched = scheduler()
    with pytest.raises(ms.MidiError) as exc:
        note_off(sched)
    assert exc.value.code == "MIDI_NOT_ACTIVE"

    note_on(sched, pitch=60)
    with pytest.raises(ms.MidiError) as exc:
        note_off(sched, pitch=61)
    assert exc.value.code == "MIDI_NOT_ACTIVE"
    assert sched.stats()["note_off"] == 0
    assert len(sched.active_notes()) == 1


def test_note_off_validates_pitch_and_device():
    sched = scheduler()
    note_on(sched)
    with pytest.raises(ms.MidiError) as exc:
        note_off(sched, device="   ")
    assert exc.value.code == "MIDI_INVALID"

    with pytest.raises(ms.MidiError) as exc:
        note_off(sched, pitch=200)
    assert exc.value.code == "MIDI_INVALID"

    with pytest.raises(ms.MidiError) as exc:
        note_off(sched, device="kbd-b")
    assert exc.value.code == "MIDI_NOT_ACTIVE"


def test_pedal_down_turns_release_into_sustain():
    sched = scheduler()
    note_on(sched)
    assert sched.pedal(channel=0, down=True, at_ms=10) is True
    sustained = note_off(sched, at=20)
    assert sustained.state == "sustained"
    assert sched.stats()["sustained"] == 1
    rows = sched.active_notes()
    assert len(rows) == 1
    assert rows[0].state == "sustained"
    assert sched.pedal_down(channel=0) is True


def test_pedal_up_releases_sustained_notes():
    sched = scheduler()
    note_on(sched)
    sched.pedal(channel=0, down=True, at_ms=10)
    note_off(sched, at=20)
    assert sched.pedal(channel=0, down=False, at_ms=30) is True
    assert sched.active_notes() == ()
    assert sched.stats()["pedal_down"] == 1
    assert sched.stats()["pedal_up"] == 1


def test_pedal_rejects_repeat_state_and_bad_input():
    sched = scheduler()
    with pytest.raises(ms.MidiError) as exc:
        sched.pedal(channel=0, down=False, at_ms=0)
    assert exc.value.code == "MIDI_PEDAL_STATE"

    sched.pedal(channel=0, down=True, at_ms=1)
    with pytest.raises(ms.MidiError) as exc:
        sched.pedal(channel=0, down=True, at_ms=2)
    assert exc.value.code == "MIDI_PEDAL_STATE"

    with pytest.raises(ms.MidiError) as exc:
        sched.pedal(channel=0, down="yes", at_ms=3)
    assert exc.value.code == "MIDI_INVALID"

    with pytest.raises(ms.MidiError) as exc:
        sched.pedal(channel=16, down=False, at_ms=4)
    assert exc.value.code == "MIDI_INVALID"

    assert sched.stats()["pedal_down"] == 1
    assert sched.pedal_down(channel=0) is True
    assert sched.pedal_down(channel=1) is False


def test_all_notes_off_is_channel_scoped():
    sched = scheduler()
    first = note_on(sched, channel=0)
    second = note_on(sched, channel=1)
    assert sched.all_notes_off(at_ms=10, channel=0) == 1
    assert [row.note_id for row in sched.active_notes()] == [second.note_id]

    third = note_on(sched, channel=0, pitch=62, at=11)
    assert sched.all_notes_off(at_ms=20) == 2
    assert sched.active_notes() == ()
    assert sched.stats()["last_reason"] == "all_notes_off"

    note_on(sched, at=21)
    assert sched.all_notes_off(at_ms=22, reason="panic") == 1
    assert sched.stats()["last_reason"] == "panic"


def test_tick_cleans_stuck_notes():
    sched = scheduler(stuck_timeout_ms=1000)
    pressed = note_on(sched, at=0)
    assert sched.tick(now_ms=999) == ()
    released = sched.tick(now_ms=1000)
    assert len(released) == 1
    assert released[0].note_id == pressed.note_id
    assert released[0].state == "stuck"
    assert sched.active_notes() == ()
    assert sched.stats()["stuck_cleaned"] == 1


def test_tick_leaves_fresh_notes_alone():
    sched = scheduler(stuck_timeout_ms=1000)
    note_on(sched, at=500)
    assert sched.tick(now_ms=1000) == ()
    assert len(sched.active_notes()) == 1
    assert sched.stats()["stuck_cleaned"] == 0
    assert sched.tick(now_ms=1500)[0].state == "stuck"


def test_device_disconnect_reports_released_count():
    sched = scheduler()
    note_on(sched, pitch=60, device="kbd-a")
    note_on(sched, pitch=64, device="kbd-b")
    assert sched.device_disconnect(device="ghost", at_ms=10) == 0
    assert sched.device_disconnect(device="kbd-a", at_ms=20) == 1
    assert sched.stats()["disconnect_released"] == 1


def test_schedule_is_stable_by_arrival():
    sched = scheduler()
    events = [{"at_ms": 200}, {"at_ms": 100}, {"at_ms": 100}, {"at_ms": 50}]
    ordered = sched.schedule(events=events)
    assert [row["index"] for row in ordered] == [3, 1, 2, 0]
    assert [row["at_ms"] for row in ordered] == [50, 100, 100, 200]
    assert [row["serial"] for row in ordered] == [3, 1, 2, 0]
    assert events == [{"at_ms": 200}, {"at_ms": 100}, {"at_ms": 100}, {"at_ms": 50}]
    assert sched.stats()["scheduled"] == 4

    second = sched.schedule(events=[{"at_ms": 10}, {"at_ms": 10}])
    assert [row["serial"] for row in second] == [4, 5]
    assert sched.stats()["scheduled"] == 6

    for bad in ([], [{"at_ms": -1}], [{"at": 5}], "nope"):
        with pytest.raises(ms.MidiError) as exc:
            sched.schedule(events=bad)
        assert exc.value.code == "MIDI_INVALID"


def test_snapshot_restore_roundtrip_and_malformed_state():
    sched = scheduler()
    first = note_on(sched, channel=0, pitch=60, at=0, device="kbd-a")
    second = note_on(sched, channel=1, pitch=64, at=5, device="kbd-b")
    sched.pedal(channel=0, down=True, at_ms=10)
    note_off(sched, channel=0, pitch=60, at=20, device="kbd-a")

    state = sched.snapshot()
    pristine = copy.deepcopy(state)
    state["notes"].clear()
    state["stats"]["note_on"] = 99
    assert sched.stats()["note_on"] == 2
    assert len(sched.active_notes()) == 2

    clone = scheduler()
    clone.restore(pristine)
    assert clone.stats() == sched.stats()
    assert [(row.note_id, row.state) for row in clone.active_notes()] == [
        (first.note_id, "sustained"), (second.note_id, "down")]
    assert clone.pedal_down(channel=0) is True
    assert clone.note_on(channel=2, pitch=70, velocity=50, at_ms=30,
                         device="kbd-c").note_id == 3

    bad_states = [
        None,
        {},
        {"version": 2, "notes": [], "pedals": {}, "next_id": 1, "stats": {}},
        {"version": 1, "notes": "nope", "pedals": {}, "next_id": 1, "stats": {}},
        {"version": 1, "notes": [], "pedals": [], "next_id": 1, "stats": {}},
        {"version": 1, "notes": [{"note_id": 1}], "pedals": {}, "next_id": 1,
         "stats": {}},
        {"version": 1, "notes": [], "pedals": {}, "next_id": 1,
         "stats": {"note_on": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(ms.MidiError) as exc:
            clone.restore(bad)
        assert exc.value.code == "MIDI_SNAPSHOT_INVALID"

    assert clone.stats()["note_on"] == 3
    assert len(clone.active_notes()) == 3
