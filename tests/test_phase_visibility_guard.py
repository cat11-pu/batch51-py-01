import copy
import threading

import pytest

import phase_visibility_guard as pv


def guard(**kwargs):
    return pv.PhaseVisibilityGuard(**kwargs)


def phase(g, phase_id, *, group="g-gate", quest="q-1", priority=0):
    return g.register_phase(phase_id, quest_id=quest, group=group,
                            priority=priority)


def test_register_phase_returns_spec_and_refuses_bad_names():
    g = guard()
    spec = phase(g, "ph-open", group="g-gate", quest="q-1", priority=3)
    assert (spec.phase_id, spec.quest_id, spec.group, spec.priority) == (
        "ph-open", "q-1", "g-gate", 3)
    with pytest.raises(pv.PhaseError) as exc:
        phase(g, "ph-open")
    assert exc.value.code == "PHASE_ALREADY_DEFINED"
    for bad in (
        dict(phase_id="", quest="q-1", group="g"),
        dict(phase_id="ph-x", quest=" ", group="g"),
        dict(phase_id="ph-x", quest="q-1", group=""),
    ):
        with pytest.raises(pv.PhaseError) as exc:
            g.register_phase(bad["phase_id"], quest_id=bad["quest"],
                             group=bad["group"])
        assert exc.value.code == "PHASE_INVALID_NAME"


def test_phase_and_object_capacity_limits_are_enforced():
    g = guard(max_phases=1)
    phase(g, "ph-1")
    with pytest.raises(pv.PhaseError) as exc:
        phase(g, "ph-2")
    assert exc.value.code == "PHASE_CAPACITY_EXCEEDED"

    small = guard(max_objects=1)
    phase(small, "ph-1")
    small.register_object("obj-a", None)
    with pytest.raises(pv.PhaseError) as exc:
        small.register_object("obj-b", None)
    assert exc.value.code == "PHASE_OBJECT_CAPACITY_EXCEEDED"

    other = guard()
    phase(other, "ph-1")
    other.register_object("obj-a", "ph-1")
    with pytest.raises(pv.PhaseError) as exc:
        other.register_object("obj-a", "ph-1")
    assert exc.value.code == "PHASE_OBJECT_EXISTS"
    with pytest.raises(pv.PhaseError) as exc:
        other.register_object("obj-b", "ph-ghost")
    assert exc.value.code == "PHASE_UNKNOWN"


def test_enter_phase_makes_its_objects_visible():
    g = guard()
    phase(g, "ph-open")
    g.register_object("obj-a", "ph-open")
    g.register_object("obj-global", None)

    assert g.visible_to("p-1", "obj-a") is False
    assert g.visible_to("p-1", "obj-global") is True
    moved = g.enter_phase("p-1", "ph-open")
    assert (moved.applied, moved.reason) == (True, "PHASE_ENTERED")
    assert moved.active == ("ph-open",)
    assert moved.added == ("ph-open",)
    assert moved.removed == ()
    assert g.visible_to("p-1", "obj-a") is True
    assert g.visible_to("p-2", "obj-a") is False


def test_enter_same_phase_twice_is_idempotent():
    g = guard()
    phase(g, "ph-open")
    g.enter_phase("p-1", "ph-open")
    again = g.enter_phase("p-1", "ph-open")
    assert (again.applied, again.reason) == (False, "PHASE_ALREADY_ACTIVE")
    assert again.added == ()
    assert again.removed == ()
    assert again.active == ("ph-open",)


def test_entering_the_same_group_replaces_the_old_phase():
    g = guard()
    phase(g, "ph-before", group="g-gate", priority=1)
    phase(g, "ph-after", group="g-gate", priority=2)
    g.register_object("obj-before", "ph-before")
    g.register_object("obj-after", "ph-after")
    g.enter_phase("p-1", "ph-before")

    moved = g.enter_phase("p-1", "ph-after")
    assert moved.applied is True
    assert moved.reason == "PHASE_SWITCHED"
    assert moved.added == ("ph-after",)
    assert moved.removed == ("ph-before",)
    assert moved.active == ("ph-after",)
    assert g.visible_to("p-1", "obj-before") is False
    assert g.visible_to("p-1", "obj-after") is True


def test_leave_phase_hides_objects_and_is_not_repeatable():
    g = guard()
    phase(g, "ph-open")
    g.register_object("obj-a", "ph-open")
    g.enter_phase("p-1", "ph-open")
    left = g.leave_phase("p-1", "ph-open")
    assert (left.applied, left.reason) == (True, "PHASE_LEFT")
    assert left.removed == ("ph-open",)
    assert left.active == ()
    assert g.visible_to("p-1", "obj-a") is False
    second = g.leave_phase("p-1", "ph-open")
    assert (second.applied, second.reason) == (False, "PHASE_NOT_ACTIVE")


def test_switch_phase_reports_the_replacement_pair():
    g = guard()
    phase(g, "ph-a", group="g-quest")
    phase(g, "ph-b", group="g-quest")
    g.enter_phase("p-1", "ph-a")
    moved = g.switch_phase("p-1", "ph-b")
    assert moved.applied is True
    assert moved.reason == "PHASE_SWITCHED"
    assert moved.added == ("ph-b",)
    assert moved.removed == ("ph-a",)
    assert moved.active == ("ph-b",)


def test_switch_phase_leaves_other_groups_alone():
    g = guard()
    phase(g, "ph-a", group="g-quest")
    phase(g, "ph-b", group="g-world")
    phase(g, "ph-c", group="g-world")
    g.enter_phase("p-1", "ph-a")
    g.enter_phase("p-1", "ph-b")
    moved = g.switch_phase("p-1", "ph-c")
    assert moved.added == ("ph-c",)
    assert moved.removed == ("ph-b",)
    assert moved.active == ("ph-a", "ph-c")


def test_unknown_players_see_only_global_objects():
    g = guard()
    phase(g, "ph-open")
    g.register_object("obj-a", "ph-open")
    g.register_object("obj-global", None)
    assert g.visible_to("nobody", "obj-a") is False
    assert g.visible_to("nobody", "obj-global") is True
    assert g.active_phases("nobody") == ()
    with pytest.raises(pv.PhaseError) as exc:
        g.enter_phase("p-1", "ph-ghost")
    assert exc.value.code == "PHASE_UNKNOWN"


def test_active_phases_are_sorted_lexicographically():
    g = guard()
    phase(g, "z-phase", group="g-one")
    phase(g, "a-phase", group="g-two")
    g.enter_phase("p-1", "z-phase")
    g.enter_phase("p-1", "a-phase")
    assert g.active_phases("p-1") == ("a-phase", "z-phase")


def test_sync_party_phase_pushes_leader_phase_to_matching_members():
    g = guard()
    phase(g, "ph-open", group="g-quest", quest="q-1")
    g.register_object("obj-a", "ph-open")
    g.enter_phase("leader", "ph-open")
    for player in ("leader", "m-1", "m-2"):
        g.set_map(player, "map-1")
        g.set_progress(player, "q-1", 2)
    synced = g.sync_party_phase("leader", ["m-2", "m-1"])
    assert synced.accepted == ("m-1", "m-2")
    assert synced.rejected == ()
    assert synced.reason == "PARTY_SYNCED"
    assert g.active_phases("m-1") == ("ph-open",)
    assert g.visible_to("m-2", "obj-a") is True


def test_sync_party_phase_refuses_bad_requests_and_exposes_stats():
    g = guard()
    phase(g, "ph-open")
    with pytest.raises(pv.PhaseError) as exc:
        g.sync_party_phase("", ["m-1"])
    assert exc.value.code == "PHASE_INVALID_REQUEST"
    with pytest.raises(pv.PhaseError) as exc:
        g.sync_party_phase("leader", "m-1")
    assert exc.value.code == "PHASE_INVALID_REQUEST"
    g.enter_phase("p-1", "ph-open")
    g.visible_to("p-1", "obj-global")
    g.set_map("p-1", "map-1")
    assert set(g.stats()) == {"phases", "objects", "players", "entries",
                              "switches", "lookups"}
    assert g.stats()["phases"] == 1
    assert g.stats()["players"] >= 1


def test_concurrent_switches_keep_one_phase_per_group():
    g = guard()
    names = [f"ph-{index}" for index in range(4)]
    for name in names:
        phase(g, name, group="g-quest", priority=1)
        g.register_object(f"obj-{index}", name)
    errors = []
    barrier = threading.Barrier(len(names))

    def worker(name):
        try:
            barrier.wait(timeout=5)
            g.switch_phase("p-1", name)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    active = g.active_phases("p-1")
    assert len(active) == 1
    assert active[0] in names
    visible = sum(1 for index in range(4) if g.visible_to("p-1", f"obj-{index}"))
    assert visible == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    phase(g, "ph-open")
    g.register_object("obj-a", "ph-open")
    g.enter_phase("p-1", "ph-open")
    g.set_map("p-1", "map-1")
    g.set_progress("p-1", "q-1", 4)
    state = g.snapshot()
    assert set(state) == {"version", "phases", "objects", "players", "counters",
                          "stats"}
    pristine = copy.deepcopy(state)

    state["players"].clear()
    state["stats"]["entries"] = 99
    assert g.active_phases("p-1") == ("ph-open",)
    assert g.visible_to("p-1", "obj-a") is True

    clone = guard()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.active_phases("p-1") == ("ph-open",)
    assert clone.visible_to("p-1", "obj-a") is True
    assert clone.active_phases("ghost") == ()


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = guard()
    phase(g, "ph-open")
    g.register_object("obj-a", "ph-open")
    g.enter_phase("p-1", "ph-open")
    bad_states = [
        None,
        {},
        {"version": 1, "phases": [], "objects": [], "players": [],
         "counters": {}},
        {"version": "1", "phases": [], "objects": [], "players": [],
         "counters": {}, "stats": {}},
        {"version": 1, "phases": {}, "objects": [], "players": [],
         "counters": {}, "stats": {}},
        {"version": 1, "phases": [], "objects": {}, "players": [],
         "counters": {}, "stats": {}},
        {"version": 1, "phases": [], "objects": [], "players": [],
         "counters": [], "stats": {}},
        {"version": 1, "phases": [], "objects": [], "players": [],
         "counters": {}, "stats": {"entries": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(pv.PhaseError) as exc:
            g.restore(bad)
        assert exc.value.code == "PHASE_SNAPSHOT_INVALID"
    assert g.active_phases("p-1") == ("ph-open",)
    assert g.visible_to("p-1", "obj-a") is True
