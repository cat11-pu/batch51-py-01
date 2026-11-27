import threading

import pytest

import nameplate_overlay_compositor as nc

SCREEN = {"width": 800, "height": 600}


def compositor(**kwargs):
    params = dict(SCREEN)
    params.update(kwargs)
    return nc.NameplateCompositor(**params)


def test_submit_validates_and_registers_plate():
    comp = compositor()
    state = comp.submit("npc-1", position=(0, 0, -10), priority=3, text="Guard")
    assert state.entity == "npc-1"
    assert state.position == (0.0, 0.0, -10.0)
    assert state.priority == 3
    assert state.text == "Guard"
    assert state.frame == 0
    assert comp.plate_of("npc-1") == state

    with pytest.raises(nc.NameplateError) as exc:
        comp.submit("", position=(0, 0, -10))
    assert exc.value.code == "NAMEPLATE_INVALID_ARGUMENT"
    for position in ((1, 2), (1, 2, "x")):
        with pytest.raises(nc.NameplateError) as exc:
            comp.submit("npc-2", position=position)
        assert exc.value.code == "NAMEPLATE_INVALID_ARGUMENT"
    with pytest.raises(nc.NameplateError) as exc:
        comp.submit("npc-3", position=(0, 0, -10), priority=1.5)
    assert exc.value.code == "NAMEPLATE_INVALID_ARGUMENT"


def test_project_maps_world_to_screen():
    comp = compositor()
    assert comp.project(0.0, 0.0, -10.0) == pytest.approx((400.0, 300.0, 10.0))
    assert comp.project(10.0, 0.0, -10.0) == pytest.approx((700.0, 300.0, 10.0))
    assert comp.project(0.0, 7.5, -10.0) == pytest.approx((400.0, 75.0, 10.0))
    assert comp.project(0.0, 0.0, 10.0) is None
    assert comp.project(0.0, 0.0, 0.0) is None


def test_custom_camera_moves_the_projection():
    comp = compositor()
    camera = comp.set_camera(eye=(5.0, 0.0, 0.0), fov_y_deg=90.0)
    assert camera == {"eye": (5.0, 0.0, 0.0), "fov_y_deg": 90.0}
    assert comp.project(5.0, 0.0, -10.0) == pytest.approx((400.0, 300.0, 10.0))
    assert comp.project(0.0, 0.0, -10.0) == pytest.approx((250.0, 300.0, 10.0))


def test_compose_culls_offscreen_plates():
    comp = compositor()
    comp.submit("offscreen", position=(100, 0, -10))
    comp.submit("visible", position=(0, 0, -10))
    plates = comp.compose()
    assert [plate.entity for plate in plates] == ["visible"]
    assert comp.stats()["culled"] == 1


def test_occluded_plate_keeps_outline_alpha():
    comp = compositor()
    comp.set_depth_probe(lambda x, y: 5.0 if x < 550 else 100.0)
    comp.submit("behind-wall", position=(0, 0, -10), priority=2)
    comp.submit("in-front", position=(10, 0, -10), priority=1)
    plates = {plate.entity: plate for plate in comp.compose()}
    assert len(plates) == 2
    assert plates["behind-wall"].alpha == pytest.approx(0.25)
    assert plates["in-front"].alpha == pytest.approx(1.0)
    assert plates["behind-wall"].x == pytest.approx(400.0)


def test_higher_priority_keeps_position_on_overlap():
    comp = compositor()
    comp.submit("boss", position=(0, 0, -10), priority=5)
    comp.submit("mob", position=(0, 0, -10), priority=1)
    plates = comp.compose()
    assert [plate.entity for plate in plates] == ["boss", "mob"]
    assert (plates[0].x, plates[0].y) == pytest.approx((400.0, 300.0))
    assert (plates[1].x, plates[1].y) == pytest.approx((400.0, 328.0))


def test_layout_is_stable_within_a_frame():
    comp = compositor()
    comp.submit("boss", position=(0, 0, -10), priority=5)
    comp.submit("mob", position=(0, 0, -10), priority=1)
    first = comp.resolve_overlap()
    second = comp.resolve_overlap()
    assert first == second
    assert comp.compose() == comp.compose()


def test_compose_orders_by_priority_then_entity():
    comp = compositor()
    comp.submit("m-low", position=(10, 0, -10), priority=1)
    comp.submit("b-two", position=(5, 0, -10), priority=3)
    comp.submit("z-boss", position=(0, 0, -10), priority=5)
    comp.submit("a-one", position=(-5, 0, -10), priority=3)
    plates = comp.compose()
    assert [plate.entity for plate in plates] == ["z-boss", "a-one", "b-two",
                                                  "m-low"]
    assert [plate.x for plate in plates] == pytest.approx([400.0, 250.0, 550.0,
                                                           700.0])


def test_budget_drops_lowest_priority_plates():
    comp = compositor()
    positions = [-10, -5, 0, 5, 10]
    for index, x in enumerate(positions, start=1):
        comp.submit(f"e{index}", position=(x, 0, -10), priority=index)
    comp.set_budget(2)
    plates = comp.compose()
    assert [plate.entity for plate in plates] == ["e5", "e4"]
    assert comp.stats()["dropped"] == 3
    with pytest.raises(nc.NameplateError) as exc:
        comp.set_budget(0)
    assert exc.value.code == "NAMEPLATE_INVALID_ARGUMENT"


def test_budget_shrink_keeps_retained_positions():
    positions = [-10, -5, 0, 5, 10]
    full = compositor()
    small = compositor()
    for index, x in enumerate(positions, start=1):
        full.submit(f"e{index}", position=(x, 0, -10), priority=index)
        small.submit(f"e{index}", position=(x, 0, -10), priority=index)
    small.set_budget(2)
    kept = {plate.entity: (plate.x, plate.y) for plate in small.compose()}
    everything = {plate.entity: (plate.x, plate.y) for plate in full.compose()}
    assert set(kept) == {"e5", "e4"}
    for entity, coords in kept.items():
        assert coords == pytest.approx(everything[entity])


def test_begin_frame_updates_existing_plate_in_place():
    comp = compositor()
    comp.submit("npc-1", position=(0, 0, -10), priority=2, text="Guard")
    assert comp.begin_frame(1) == 1
    comp.submit("npc-1", position=(5, 0, -10), priority=2, text="Guard")
    assert comp.plate_of("npc-1").position == (5.0, 0.0, -10.0)
    assert comp.plate_of("npc-1").frame == 1
    plates = comp.compose()
    assert len(plates) == 1
    assert plates[0].x == pytest.approx(550.0)


def test_snapshot_restore_roundtrip_and_malformed():
    comp = compositor()
    comp.submit("boss", position=(0, 0, -10), priority=5)
    comp.submit("mob", position=(0, 0, -10), priority=1)
    comp.compose()
    state = comp.snapshot()
    assert set(state) == {"version", "frame", "plates", "layout", "counters"}

    state["plates"].clear()
    state["layout"].clear()
    assert comp.plate_of("boss").priority == 5
    assert len(comp.compose()) == 2

    pristine = comp.snapshot()
    clone = compositor()
    clone.restore(pristine)
    assert clone.compose() == comp.compose()
    assert clone.plate_of("mob").priority == 1

    for bad in (None, {},
                {"version": 2, "frame": 0, "plates": {}, "layout": [],
                 "counters": {}},
                {"version": 1, "frame": 0, "plates": {}}):
        with pytest.raises(nc.NameplateError) as exc:
            clone.restore(bad)
        assert exc.value.code == "NAMEPLATE_SNAPSHOT_INVALID"
    assert len(clone.compose()) == 2


def test_stats_track_submits_and_culls():
    comp = compositor()
    comp.begin_frame(1)
    comp.submit("boss", position=(0, 0, -10), priority=5)
    comp.submit("mob", position=(0, 0, -10), priority=1)
    comp.submit("offscreen", position=(100, 0, -10), priority=4)
    comp.compose()
    stats = comp.stats()
    assert stats["submits"] == 3
    assert stats["frames"] == 1
    assert stats["culled"] == 1
    assert stats["dropped"] == 0
    assert stats["rejected"] == 0


def test_invalid_camera_and_probe_are_rejected():
    comp = compositor()
    for kwargs in ({"fov_y_deg": 0.0}, {"fov_y_deg": 180.0},
                   {"eye": (0.0, 0.0)}):
        with pytest.raises(nc.NameplateError) as exc:
            comp.set_camera(**kwargs)
        assert exc.value.code == "NAMEPLATE_INVALID_ARGUMENT"
    with pytest.raises(nc.NameplateError) as exc:
        comp.set_depth_probe("not-a-probe")
    assert exc.value.code == "NAMEPLATE_INVALID_ARGUMENT"


def test_concurrent_submits_are_all_composited():
    comp = compositor(max_plates=32)
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            comp.submit(f"unit-{index}", position=(-7 + index * 2, 0, -10),
                        priority=index)
        except Exception as exc:  # pragma: no cover - surfaced through assertions
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    plates = comp.compose()
    assert len(plates) == 8
    assert sorted(plate.entity for plate in plates) == [
        f"unit-{index}" for index in range(8)]
    assert comp.stats()["submits"] == 8
