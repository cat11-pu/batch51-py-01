import copy
import math
from concurrent.futures import ThreadPoolExecutor

import pytest

import occluder_fan_builder as ofb


def builder(**kwargs):
    return ofb.OccluderFanBuilder(**kwargs)


def polar(radius, deg):
    rad = math.radians(deg)
    return radius * math.cos(rad), radius * math.sin(rad)


def wedge(b, seg_id, radius, start_deg, end_deg):
    x1, y1 = polar(radius, start_deg)
    x2, y2 = polar(radius, end_deg)
    return b.add_segment(seg_id, x1, y1, x2, y2)


def scanned(b, light_id="lamp", x=0.0, y=0.0, radius=50.0):
    b.add_light(light_id, x, y, radius)
    return b.build_fan(light_id)


def test_add_segment_rejects_degenerate_and_duplicate():
    b = builder()
    for coords in ((1.0, 1.0, 1.0, 1.0), (2.0, 3.0, 2.0, 3.0000000001)):
        with pytest.raises(ofb.FanError) as exc:
            b.add_segment("bad", *coords)
        assert exc.value.code == "FAN_DEGENERATE_SEGMENT"
    with pytest.raises(ofb.FanError) as exc:
        b.add_segment("nan", 0.0, 0.0, float("nan"), 1.0)
    assert exc.value.code == "FAN_INVALID_SEGMENT"

    seg = b.add_segment("wall", 4.0, 1.0, 4.0, 3.0)
    assert (seg.seg_id, seg.x1, seg.y1, seg.y2) == ("wall", 4.0, 1.0, 3.0)
    with pytest.raises(ofb.FanError) as exc:
        b.add_segment("wall", 5.0, 1.0, 5.0, 3.0)
    assert exc.value.code == "FAN_DUPLICATE_SEGMENT"
    assert b.stats()["segments"] == 1


def test_add_light_validates_radius_and_cone():
    b = builder()
    for args in ((0.0, 0.0, 0.0), (0.0, 0.0, -2.0),
                 (float("nan"), 0.0, 10.0)):
        with pytest.raises(ofb.FanError) as exc:
            b.add_light("bad", *args)
        assert exc.value.code == "FAN_INVALID_LIGHT"
    with pytest.raises(ofb.FanError) as exc:
        b.add_light("half-cone", 0.0, 0.0, 10.0, facing_deg=90.0)
    assert exc.value.code == "FAN_INVALID_LIGHT"
    with pytest.raises(ofb.FanError) as exc:
        b.add_light("open-cone", 0.0, 0.0, 10.0, facing_deg=90.0,
                    cone_deg=360.0)
    assert exc.value.code == "FAN_INVALID_LIGHT"

    light = b.add_light("lamp", 3.0, 4.0, 12.0)
    assert (light.light_id, light.x, light.y, light.radius) == \
        ("lamp", 3.0, 4.0, 12.0)
    cone = b.add_light("torch", 0.0, 0.0, 10.0, facing_deg=90.0,
                       cone_deg=45.0)
    assert cone.cone_deg == 45.0
    assert b.stats()["lights"] == 2


def test_build_fan_unknown_light_and_empty_scene():
    b = builder()
    with pytest.raises(ofb.FanError) as exc:
        b.build_fan("missing")
    assert exc.value.code == "FAN_UNKNOWN_LIGHT"

    b.add_light("lamp", 0.0, 0.0, 20.0)
    fan = b.build_fan("lamp")
    assert fan.sectors == ()
    assert fan.vertices == 0
    assert fan.dropped == 0
    assert b.coverage("lamp") == 0.0
    assert b.stats()["builds"] == 1


def test_single_segment_sector_angles():
    b = builder()
    wedge(b, "wall", 10.0, 30.0, 45.0)
    fan = scanned(b)

    assert len(fan.sectors) == 1
    sector = fan.sectors[0]
    assert sector.start_deg == pytest.approx(30.0)
    assert sector.end_deg == pytest.approx(45.0)
    assert sector.span_deg == pytest.approx(15.0)
    assert sector.seg_ids == ("wall",)
    assert fan.vertices == 2
    assert b.coverage("lamp") == pytest.approx(15.0)


def test_touching_wedges_merge_into_one_sector():
    b = builder()
    wedge(b, "a", 10.0, 20.0, 30.0)
    wedge(b, "b", 10.0, 30.0, 50.0)
    fan = scanned(b)

    assert len(fan.sectors) == 1
    assert fan.sectors[0].start_deg == pytest.approx(20.0)
    assert fan.sectors[0].end_deg == pytest.approx(50.0)
    assert fan.sectors[0].span_deg == pytest.approx(30.0)
    assert fan.sectors[0].seg_ids == ("a", "b")
    assert b.stats()["merged"] == 1


def test_separated_wedges_stay_separate():
    b = builder()
    wedge(b, "a", 10.0, 20.0, 30.0)
    wedge(b, "b", 10.0, 40.0, 70.0)
    fan = scanned(b)

    assert [round(s.start_deg, 6) for s in fan.sectors] == [20.0, 40.0]
    assert [round(s.span_deg, 6) for s in fan.sectors] == [10.0, 30.0]
    assert b.coverage("lamp") == pytest.approx(40.0)
    assert b.stats()["merged"] == 0


def test_vertex_budget_keeps_widest_wedges():
    b = builder(vertex_budget=4)
    wedge(b, "small", 10.0, 5.0, 15.0)
    wedge(b, "mid", 10.0, 20.0, 50.0)
    wedge(b, "big", 10.0, 60.0, 120.0)
    fan = scanned(b)

    assert [s.seg_ids for s in fan.sectors] == [("mid",), ("big",)]
    assert fan.dropped == 1
    assert fan.vertices == 4
    assert b.coverage("lamp") == pytest.approx(90.0)
    assert b.stats()["dropped"] == 1

    assert b.set_vertex_budget(6) == 6
    fan = b.build_fan("lamp")
    assert fan.vertices == 6
    assert fan.dropped == 0
    assert b.coverage("lamp") == pytest.approx(100.0)
    assert len(b.sectors("lamp")) == 3


def test_set_vertex_budget_rejects_odd_and_zero():
    b = builder()
    for bad in (0, -2, 3, 9, "8", 2.5):
        with pytest.raises(ofb.FanError) as exc:
            b.set_vertex_budget(bad)
        assert exc.value.code == "FAN_INVALID_BUDGET"
    assert b.set_vertex_budget(2) == 2
    assert b.stats()["vertex_budget"] == 2


def test_fan_vertices_follow_segment_endpoints():
    b = builder()
    first_seg = wedge(b, "a", 10.0, 20.0, 30.0)
    second_seg = wedge(b, "b", 10.0, 40.0, 70.0)
    scanned(b)

    polygons = b.fan_vertices("lamp")
    assert len(polygons) == 2
    assert polygons[0][0] == pytest.approx((0.0, 0.0))
    assert polygons[0][1] == pytest.approx((first_seg.x1, first_seg.y1))
    assert polygons[0][2] == pytest.approx((first_seg.x2, first_seg.y2))
    assert polygons[1][0] == pytest.approx((0.0, 0.0))
    assert polygons[1][1] == pytest.approx((second_seg.x1, second_seg.y1))


def test_segments_beyond_light_radius_are_skipped():
    b = builder()
    wedge(b, "far", 40.0, 20.0, 30.0)
    b.add_light("lamp", 0.0, 0.0, 12.0)
    fan = b.build_fan("lamp")

    assert fan.sectors == ()
    assert fan.vertices == 0
    assert b.stats()["skipped_range"] == 1
    assert b.coverage("lamp") == 0.0


def test_remove_segment_updates_fan_and_unknown_removal():
    b = builder()
    wedge(b, "a", 10.0, 20.0, 30.0)
    scanned(b)
    assert len(b.sectors("lamp")) == 1

    removed = b.remove_segment("a")
    assert removed.seg_id == "a"
    with pytest.raises(ofb.FanError) as exc:
        b.remove_segment("a")
    assert exc.value.code == "FAN_UNKNOWN_SEGMENT"

    fan = b.build_fan("lamp")
    assert fan.sectors == ()
    assert b.coverage("lamp") == 0.0
    assert b.stats()["segments"] == 0


def test_addition_order_does_not_change_sectors():
    first = builder()
    wedge(first, "a", 10.0, 20.0, 30.0)
    wedge(first, "b", 10.0, 45.0, 60.0)
    wedge(first, "c", 10.0, 30.0, 45.0)

    second = builder()
    wedge(second, "c", 10.0, 30.0, 45.0)
    wedge(second, "a", 10.0, 20.0, 30.0)
    wedge(second, "b", 10.0, 45.0, 60.0)

    fan_first = scanned(first)
    fan_second = scanned(second)
    assert fan_first == fan_second
    assert fan_first.sectors[0].seg_ids == ("a", "c", "b")
    assert first.fan_vertices("lamp") == second.fan_vertices("lamp")


def test_parallel_build_constructs_once():
    b = builder()
    wedge(b, "s0", 10.0, 10.0, 25.0)
    wedge(b, "s1", 10.0, 40.0, 55.0)
    wedge(b, "s2", 10.0, 70.0, 100.0)
    b.add_light("lamp", 0.0, 0.0, 50.0)

    with ThreadPoolExecutor(max_workers=4) as pool:
        fans = list(pool.map(lambda _: b.build_fan("lamp"), range(8)))
    assert all(fan == fans[0] for fan in fans)
    assert fans[0].vertices == 6
    assert b.stats()["builds"] == 1


def test_snapshot_restore_roundtrip_and_malformed_state():
    b = builder(vertex_budget=8)
    wedge(b, "a", 10.0, 20.0, 30.0)
    scanned(b)

    state = b.snapshot()
    assert set(state) == {"version", "merge_epsilon_deg", "vertex_budget",
                          "lights", "segments", "fans", "stats"}
    pristine = copy.deepcopy(state)
    state["stats"]["builds"] = 99
    state["segments"].clear()
    assert b.stats()["builds"] == 1
    assert b.stats()["segments"] == 1

    clone = builder()
    clone.restore(pristine)
    assert clone.stats()["segments"] == 1
    assert clone.stats()["vertex_budget"] == 8
    assert clone.sectors("lamp")[0].span_deg == pytest.approx(10.0)
    assert clone.coverage("lamp") == pytest.approx(10.0)
    assert clone.fan_vertices("lamp")[0][0] == pytest.approx((0.0, 0.0))

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(ofb.FanError) as exc:
            b.restore(broken)
        assert exc.value.code == "FAN_SNAPSHOT_INVALID"
    assert b.stats()["builds"] == 1


def test_mutation_invalidates_built_fan():
    b = builder()
    wedge(b, "a", 10.0, 20.0, 30.0)
    scanned(b)
    wedge(b, "b", 10.0, 40.0, 70.0)

    for call in (lambda: b.fan_vertices("lamp"),
                 lambda: b.sectors("lamp"),
                 lambda: b.coverage("lamp")):
        with pytest.raises(ofb.FanError) as exc:
            call()
        assert exc.value.code == "FAN_NOT_BUILT"

    fan = b.build_fan("lamp")
    assert len(fan.sectors) == 2
    assert fan.vertices == 4
    assert b.stats()["invalidations"] == 1
    assert b.stats()["builds"] == 2
