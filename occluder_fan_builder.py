"""Build 2D shadow fan sectors for point and cone lights from occluder segments."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass


class FanError(ValueError):
    """Raised when a light, an occluder segment or a fan request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Light:
    light_id: str
    x: float
    y: float
    radius: float
    facing_deg: float | None = None
    cone_deg: float | None = None


@dataclass(frozen=True)
class Segment:
    seg_id: str
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True)
class Sector:
    start_deg: float
    end_deg: float
    span_deg: float
    seg_ids: tuple


@dataclass(frozen=True)
class Fan:
    light_id: str
    sectors: tuple
    vertices: int
    dropped: int
    culled: int


@dataclass(frozen=True)
class _Candidate:
    seg_id: str
    start_deg: float
    end_deg: float
    span_deg: float
    start_xy: tuple
    end_xy: tuple


@dataclass(frozen=True)
class _SectorDraft:
    start_deg: float
    end_deg: float
    span_deg: float
    seg_ids: tuple
    start_xy: tuple
    end_xy: tuple


@dataclass(frozen=True)
class _FanState:
    fan: Fan
    polygons: tuple


_ANGLE_TOL = 1e-12


def _finite_float(value) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite number")
    return number


def _valid_budget(value) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and value >= 2 and value % 2 == 0)


def _angle_of(light: Light, x: float, y: float) -> float:
    return math.degrees(math.atan2(y - light.y, x - light.x)) % 360.0


def _shadow_arc(first: float, second: float) -> tuple[float, float, float]:
    if first <= second:
        direct = second - first
        if direct <= 180.0:
            return first, second, direct
        return second, first + 360.0, 360.0 - direct
    direct = first - second
    if direct <= 180.0:
        return second, first, direct
    return first, second + 360.0, 360.0 - direct


def _arc_touches(first: _Candidate, second: _Candidate,
                 epsilon: float) -> bool:
    relative = (second.start_deg - first.start_deg) % 360.0
    return (relative <= first.span_deg + epsilon
            or relative + second.span_deg >= 360.0 - epsilon)


def _arc_contains(outer: _Candidate, inner: _Candidate) -> bool:
    relative = (inner.start_deg - outer.start_deg) % 360.0
    return (relative <= outer.span_deg + _ANGLE_TOL
            and relative + inner.span_deg <= outer.span_deg + _ANGLE_TOL)


def _angle_in_cone(angle: float, light: Light) -> bool:
    assert light.facing_deg is not None
    assert light.cone_deg is not None
    cone_start = (light.facing_deg - light.cone_deg / 2.0) % 360.0
    return (angle - cone_start) % 360.0 <= light.cone_deg + _ANGLE_TOL


def _close(first: float, second: float) -> bool:
    return abs(first - second) <= _ANGLE_TOL


class OccluderFanBuilder:
    """Collect occluder segments and derive closed shadow sectors per light."""

    _SNAPSHOT_KEYS = {
        "version", "merge_epsilon_deg", "vertex_budget", "lights",
        "segments", "fans", "stats",
    }
    _STAT_KEYS = {
        "lights", "segments", "builds", "merged", "culled", "dropped",
        "skipped_range", "invalidations", "vertex_budget",
    }

    def __init__(self, *, merge_epsilon_deg: float = 1e-6,
                 vertex_budget: int = 64, max_segments: int = 256) -> None:
        try:
            merge_epsilon = _finite_float(merge_epsilon_deg)
        except (TypeError, ValueError, OverflowError) as exc:
            raise FanError("FAN_INVALID_CONFIG", detail=str(exc)) from exc
        if merge_epsilon < 0.0:
            raise FanError("FAN_INVALID_CONFIG",
                           detail="merge_epsilon_deg must be non-negative")
        if not _valid_budget(vertex_budget):
            raise FanError("FAN_INVALID_BUDGET", detail=vertex_budget)
        if (not isinstance(max_segments, int)
                or isinstance(max_segments, bool) or max_segments < 1):
            raise FanError("FAN_INVALID_CONFIG", detail=max_segments)

        self._lock = threading.RLock()
        self._merge_epsilon = merge_epsilon
        self._vertex_budget = vertex_budget
        self._max_segments = max_segments
        self._lights: dict[str, Light] = {}
        self._segments: dict[str, Segment] = {}
        self._fans: dict[str, _FanState] = {}
        self._revision = 0
        self._stats = {
            "lights": 0,
            "segments": 0,
            "builds": 0,
            "merged": 0,
            "culled": 0,
            "dropped": 0,
            "skipped_range": 0,
            "invalidations": 0,
            "vertex_budget": vertex_budget,
        }

    def add_light(self, light_id: str, x: float, y: float, radius: float, *,
                  facing_deg: float | None = None,
                  cone_deg: float | None = None) -> Light:
        with self._lock:
            try:
                light_x = _finite_float(x)
                light_y = _finite_float(y)
                light_radius = _finite_float(radius)
                if light_radius <= 0.0:
                    raise ValueError("radius must be positive")
                if (facing_deg is None) != (cone_deg is None):
                    raise ValueError("facing_deg and cone_deg must be paired")
                facing = None
                cone = None
                if facing_deg is not None:
                    facing = _finite_float(facing_deg)
                    cone = _finite_float(cone_deg)
                    if not 0.0 < cone < 360.0:
                        raise ValueError("cone_deg must be between 0 and 360")
            except (TypeError, ValueError, OverflowError) as exc:
                raise FanError("FAN_INVALID_LIGHT",
                               detail={"light_id": light_id,
                                       "reason": str(exc)}) from exc

            light = Light(light_id, light_x, light_y, light_radius,
                          facing, cone)
            previous = self._lights.get(light_id)
            if previous == light:
                return previous

            self._lights[light_id] = light
            if previous is not None:
                self._invalidate_one_locked(light_id)
            self._stats["lights"] = len(self._lights)
            self._revision += 1
            return light

    def add_segment(self, seg_id: str, x1: float, y1: float,
                    x2: float, y2: float) -> Segment:
        with self._lock:
            try:
                first_x = _finite_float(x1)
                first_y = _finite_float(y1)
                second_x = _finite_float(x2)
                second_y = _finite_float(y2)
            except (TypeError, ValueError, OverflowError) as exc:
                raise FanError("FAN_INVALID_SEGMENT",
                               detail={"seg_id": seg_id,
                                       "reason": str(exc)}) from exc

            length = math.hypot(second_x - first_x, second_y - first_y)
            if length < 1e-6:
                raise FanError("FAN_DEGENERATE_SEGMENT",
                               detail={"seg_id": seg_id, "length": length})
            if seg_id in self._segments:
                raise FanError("FAN_DUPLICATE_SEGMENT",
                               detail={"seg_id": seg_id})
            if len(self._segments) >= self._max_segments:
                raise FanError("FAN_SEGMENT_LIMIT",
                               detail={"max_segments": self._max_segments})

            segment = Segment(seg_id, first_x, first_y, second_x, second_y)
            self._invalidate_all_locked()
            self._segments[seg_id] = segment
            self._stats["segments"] = len(self._segments)
            self._revision += 1
            return segment

    def remove_segment(self, seg_id: str) -> Segment:
        with self._lock:
            if seg_id not in self._segments:
                raise FanError("FAN_UNKNOWN_SEGMENT",
                               detail={"seg_id": seg_id})
            self._invalidate_all_locked()
            segment = self._segments.pop(seg_id)
            self._stats["segments"] = len(self._segments)
            self._revision += 1
            return segment

    def set_vertex_budget(self, budget: int) -> int:
        with self._lock:
            if not _valid_budget(budget):
                raise FanError("FAN_INVALID_BUDGET", detail=budget)
            if budget != self._vertex_budget:
                self._invalidate_all_locked()
                self._vertex_budget = budget
                self._stats["vertex_budget"] = budget
                self._revision += 1
            return self._vertex_budget

    def build_fan(self, light_id: str) -> Fan:
        with self._lock:
            light = self._lights.get(light_id)
            if light is None:
                raise FanError("FAN_UNKNOWN_LIGHT",
                               detail={"light_id": light_id})
            cached = self._fans.get(light_id)
            if cached is not None:
                return cached.fan

            fan, polygons = self._compute_fan(light)
            self._fans[light_id] = _FanState(fan, polygons)
            self._stats["builds"] += 1
            self._revision += 1
            return fan

    def fan_vertices(self, light_id: str) -> tuple:
        with self._lock:
            state = self._built_fan_locked(light_id)
            return state.polygons

    def sectors(self, light_id: str) -> tuple:
        with self._lock:
            return self._built_fan_locked(light_id).fan.sectors

    def coverage(self, light_id: str) -> float:
        with self._lock:
            fan = self._built_fan_locked(light_id).fan
            return float(sum(sector.span_deg for sector in fan.sectors))

    def invalidate(self, light_id: str | None = None) -> int:
        with self._lock:
            if light_id is None:
                return self._invalidate_all_locked()
            if light_id not in self._lights:
                raise FanError("FAN_UNKNOWN_LIGHT",
                               detail={"light_id": light_id})
            return self._invalidate_one_locked(light_id)

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            lights = {
                light_id: {
                    "light_id": light.light_id,
                    "x": light.x,
                    "y": light.y,
                    "radius": light.radius,
                    "facing_deg": light.facing_deg,
                    "cone_deg": light.cone_deg,
                }
                for light_id, light in self._lights.items()
            }
            segments = {
                seg_id: {
                    "seg_id": segment.seg_id,
                    "x1": segment.x1,
                    "y1": segment.y1,
                    "x2": segment.x2,
                    "y2": segment.y2,
                }
                for seg_id, segment in self._segments.items()
            }
            fans = {}
            for light_id, state in self._fans.items():
                fan = state.fan
                fans[light_id] = {
                    "light_id": fan.light_id,
                    "sectors": [
                        {
                            "start_deg": sector.start_deg,
                            "end_deg": sector.end_deg,
                            "span_deg": sector.span_deg,
                            "seg_ids": list(sector.seg_ids),
                        }
                        for sector in fan.sectors
                    ],
                    "vertices": fan.vertices,
                    "dropped": fan.dropped,
                    "culled": fan.culled,
                    "polygons": [
                        [[point[0], point[1]] for point in polygon]
                        for polygon in state.polygons
                    ],
                }

            return copy.deepcopy({
                "version": 1,
                "merge_epsilon_deg": self._merge_epsilon,
                "vertex_budget": self._vertex_budget,
                "lights": lights,
                "segments": segments,
                "fans": fans,
                "stats": self._stats,
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except Exception as exc:
                if isinstance(exc, FanError) and exc.code == "FAN_SNAPSHOT_INVALID":
                    raise
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=str(exc)) from exc

            (merge_epsilon, vertex_budget, lights, segments,
             fans, stats) = restored
            self._merge_epsilon = merge_epsilon
            self._vertex_budget = vertex_budget
            self._lights = lights
            self._segments = segments
            self._fans = fans
            self._stats = stats
            self._revision += 1

    def _built_fan_locked(self, light_id: str) -> _FanState:
        if light_id not in self._lights:
            raise FanError("FAN_UNKNOWN_LIGHT",
                           detail={"light_id": light_id})
        state = self._fans.get(light_id)
        if state is None:
            raise FanError("FAN_NOT_BUILT",
                           detail={"light_id": light_id})
        return state

    def _invalidate_one_locked(self, light_id: str) -> int:
        if self._fans.pop(light_id, None) is not None:
            self._stats["invalidations"] += 1
            self._revision += 1
            return 1
        return 0

    def _invalidate_all_locked(self) -> int:
        count = len(self._fans)
        if count:
            self._fans.clear()
            self._stats["invalidations"] += count
            self._revision += 1
        return count

    def _compute_fan(self, light: Light) -> tuple[Fan, tuple]:
        candidates: list[_Candidate] = []
        skipped_range = 0

        for seg_id in sorted(self._segments):
            segment = self._segments[seg_id]
            first_distance = math.hypot(segment.x1 - light.x,
                                        segment.y1 - light.y)
            second_distance = math.hypot(segment.x2 - light.x,
                                         segment.y2 - light.y)
            if first_distance > light.radius and second_distance > light.radius:
                skipped_range += 1
                continue

            first_angle = _angle_of(light, segment.x1, segment.y1)
            second_angle = _angle_of(light, segment.x2, segment.y2)
            if light.cone_deg is not None:
                if (not _angle_in_cone(first_angle, light)
                        and not _angle_in_cone(second_angle, light)):
                    continue

            start, end, span = _shadow_arc(first_angle, second_angle)
            if span <= _ANGLE_TOL:
                continue
            candidates.append(_Candidate(
                seg_id=segment.seg_id,
                start_deg=start,
                end_deg=end,
                span_deg=span,
                start_xy=(segment.x1, segment.y1),
                end_xy=(segment.x2, segment.y2),
            ))

        candidates.sort(
            key=lambda item: (-item.span_deg, item.start_deg, item.seg_id)
        )
        kept: list[_Candidate] = []
        culled = 0
        for candidate in candidates:
            if any(_arc_contains(other, candidate) for other in kept):
                culled += 1
            else:
                kept.append(candidate)

        parent = list(range(len(kept)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(first: int, second: int) -> None:
            first_root = find(first)
            second_root = find(second)
            if first_root != second_root:
                if first_root < second_root:
                    parent[second_root] = first_root
                else:
                    parent[first_root] = second_root

        for first in range(len(kept)):
            for second in range(first):
                if _arc_touches(kept[first], kept[second],
                                self._merge_epsilon):
                    union(first, second)

        components: dict[int, list[_Candidate]] = {}
        for index, candidate in enumerate(kept):
            components.setdefault(find(index), []).append(candidate)

        merged = sum(len(component) - 1
                     for component in components.values())
        drafts: list[_SectorDraft] = []
        for component in components.values():
            drafts.extend(self._component_drafts(component, light))

        drafts.sort(
            key=lambda item: (-item.span_deg, item.start_deg,
                              item.end_deg, item.seg_ids)
        )
        kept_count = self._vertex_budget // 2
        selected = drafts[:kept_count]
        dropped = len(drafts) - len(selected)
        selected.sort(
            key=lambda item: (item.start_deg, item.end_deg, item.seg_ids)
        )

        sectors = tuple(
            Sector(item.start_deg, item.end_deg, item.span_deg,
                   item.seg_ids)
            for item in selected
        )
        polygons = tuple(
            ((light.x, light.y), item.start_xy, item.end_xy)
            for item in selected
        )
        fan = Fan(light.light_id, sectors, len(sectors) * 2,
                  dropped, culled)

        self._stats["merged"] += merged
        self._stats["culled"] += culled
        self._stats["dropped"] += dropped
        self._stats["skipped_range"] += skipped_range
        return fan, polygons

    def _component_drafts(self, component: list[_Candidate],
                          light: Light) -> list[_SectorDraft]:
        by_id = {candidate.seg_id: candidate for candidate in component}
        seg_ids = tuple(sorted(
            by_id,
            key=lambda seg_id: (by_id[seg_id].start_deg, seg_id),
        ))

        pieces: list[tuple[float, float]] = []
        for candidate in component:
            end = candidate.start_deg + candidate.span_deg
            if end <= 360.0:
                pieces.append((candidate.start_deg, end))
            else:
                pieces.append((candidate.start_deg, 360.0))
                pieces.append((0.0, end - 360.0))
        pieces.sort()

        ranges: list[list[float]] = []
        for start, end in pieces:
            if not ranges or start > ranges[-1][1] + self._merge_epsilon:
                ranges.append([start, end])
            else:
                ranges[-1][1] = max(ranges[-1][1], end)

        drafts: list[_SectorDraft] = []

        def append_range(start: float, end: float) -> None:
            start = max(0.0, min(360.0, start))
            end = max(0.0, min(360.0, end))
            span = end - start
            if span <= _ANGLE_TOL:
                return
            if span >= 360.0 - _ANGLE_TOL:
                append_range(0.0, 180.0)
                append_range(180.0, 360.0)
                return
            drafts.append(_SectorDraft(
                start_deg=start,
                end_deg=end,
                span_deg=span,
                seg_ids=seg_ids,
                start_xy=self._start_point(start, component, light),
                end_xy=self._end_point(end, component, light),
            ))

        if len(ranges) == 1:
            start, end = ranges[0]
            if (start <= self._merge_epsilon
                    and end >= 360.0 - self._merge_epsilon):
                append_range(0.0, 180.0)
                append_range(180.0, 360.0)
            else:
                append_range(start, end)
        else:
            first = ranges[0]
            last = ranges[-1]
            if (first[0] <= self._merge_epsilon
                    and last[1] >= 360.0 - self._merge_epsilon):
                append_range(0.0, first[1])
                for middle in ranges[1:-1]:
                    append_range(*middle)
                append_range(last[0], 360.0)
            else:
                for start, end in ranges:
                    append_range(start, end)
        return drafts

    @staticmethod
    def _start_point(angle: float, component: list[_Candidate],
                     light: Light) -> tuple[float, float]:
        for candidate in component:
            if _close(candidate.start_deg, angle):
                return candidate.start_xy
        return OccluderFanBuilder._ray_point(light, angle)

    @staticmethod
    def _end_point(angle: float, component: list[_Candidate],
                   light: Light) -> tuple[float, float]:
        for candidate in component:
            candidate_end = candidate.start_deg + candidate.span_deg
            normalized_end = candidate_end % 360.0
            if _close(normalized_end, 0.0) and _close(angle, 360.0):
                return candidate.end_xy
            if _close(normalized_end, angle):
                return candidate.end_xy
        return OccluderFanBuilder._ray_point(light, angle)

    @staticmethod
    def _ray_point(light: Light, angle: float) -> tuple[float, float]:
        radians = math.radians(angle % 360.0)
        return (light.x + light.radius * math.cos(radians),
                light.y + light.radius * math.sin(radians))

    def _parse_snapshot(self, state: dict) -> tuple:
        if not isinstance(state, dict):
            raise FanError("FAN_SNAPSHOT_INVALID", detail="state is not a dict")
        if set(state) != self._SNAPSHOT_KEYS:
            raise FanError("FAN_SNAPSHOT_INVALID",
                           detail="snapshot keys do not match")
        if state["version"] != 1:
            raise FanError("FAN_SNAPSHOT_INVALID", detail="unsupported version")

        try:
            merge_epsilon = _finite_float(state["merge_epsilon_deg"])
            if merge_epsilon < 0.0:
                raise ValueError("negative merge epsilon")
        except (TypeError, ValueError, OverflowError) as exc:
            raise FanError("FAN_SNAPSHOT_INVALID", detail=str(exc)) from exc

        vertex_budget = state["vertex_budget"]
        if not _valid_budget(vertex_budget):
            raise FanError("FAN_SNAPSHOT_INVALID",
                           detail="invalid vertex budget")

        raw_lights = state["lights"]
        raw_segments = state["segments"]
        raw_fans = state["fans"]
        raw_stats = state["stats"]
        if not isinstance(raw_lights, dict):
            raise FanError("FAN_SNAPSHOT_INVALID", detail="lights is not a dict")
        if not isinstance(raw_segments, dict):
            raise FanError("FAN_SNAPSHOT_INVALID",
                           detail="segments is not a dict")
        if not isinstance(raw_fans, dict):
            raise FanError("FAN_SNAPSHOT_INVALID", detail="fans is not a dict")
        if not isinstance(raw_stats, dict):
            raise FanError("FAN_SNAPSHOT_INVALID", detail="stats is not a dict")
        if not self._STAT_KEYS <= set(raw_stats):
            raise FanError("FAN_SNAPSHOT_INVALID",
                           detail="stats keys do not match")

        lights: dict[str, Light] = {}
        for light_id, value in raw_lights.items():
            if not isinstance(value, dict):
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail="invalid light record")
            if value.get("light_id") != light_id:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail="light id mismatch")
            try:
                light_x = _finite_float(value["x"])
                light_y = _finite_float(value["y"])
                radius = _finite_float(value["radius"])
                if radius <= 0.0:
                    raise ValueError("radius must be positive")
                facing = value["facing_deg"]
                cone = value["cone_deg"]
                if (facing is None) != (cone is None):
                    raise ValueError("unpaired cone")
                if facing is not None:
                    facing = _finite_float(facing)
                    cone = _finite_float(cone)
                    if not 0.0 < cone < 360.0:
                        raise ValueError("invalid cone")
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=f"invalid light {light_id!r}") from exc
            lights[light_id] = Light(light_id, light_x, light_y, radius,
                                     facing, cone)

        segments: dict[str, Segment] = {}
        for seg_id, value in raw_segments.items():
            if not isinstance(value, dict):
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail="invalid segment record")
            if value.get("seg_id") != seg_id:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail="segment id mismatch")
            try:
                first_x = _finite_float(value["x1"])
                first_y = _finite_float(value["y1"])
                second_x = _finite_float(value["x2"])
                second_y = _finite_float(value["y2"])
                if math.hypot(second_x - first_x,
                              second_y - first_y) < 1e-6:
                    raise ValueError("degenerate segment")
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=f"invalid segment {seg_id!r}") from exc
            segments[seg_id] = Segment(seg_id, first_x, first_y,
                                       second_x, second_y)

        fans: dict[str, _FanState] = {}
        for light_id, value in raw_fans.items():
            if light_id not in lights or not isinstance(value, dict):
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail="invalid fan record")
            if value.get("light_id") != light_id:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail="fan light id mismatch")
            try:
                raw_sectors = value["sectors"]
                raw_polygons = value["polygons"]
                if not isinstance(raw_sectors, list) or not isinstance(
                        raw_polygons, list):
                    raise ValueError("sector or polygon list expected")
                if len(raw_sectors) != len(raw_polygons):
                    raise ValueError("sector and polygon count mismatch")

                sectors = []
                polygons = []
                for raw_sector, raw_polygon in zip(raw_sectors, raw_polygons):
                    if not isinstance(raw_sector, dict):
                        raise ValueError("sector is not a dict")
                    start = _finite_float(raw_sector["start_deg"])
                    end = _finite_float(raw_sector["end_deg"])
                    span = _finite_float(raw_sector["span_deg"])
                    seg_ids = raw_sector["seg_ids"]
                    if (not 0.0 <= start < 360.0
                            or not start < end <= 360.0
                            or not 0.0 < span < 360.0
                            or not math.isclose(span, end - start,
                                                rel_tol=0.0,
                                                abs_tol=_ANGLE_TOL)):
                        raise ValueError("invalid sector angles")
                    if not isinstance(seg_ids, (list, tuple)):
                        raise ValueError("seg_ids must be a sequence")
                    if any(not isinstance(seg_id, str)
                           or seg_id not in segments for seg_id in seg_ids):
                        raise ValueError("unknown segment in sector")

                    if not isinstance(raw_polygon, list) or len(raw_polygon) != 3:
                        raise ValueError("invalid polygon")
                    polygon = []
                    for point in raw_polygon:
                        if not isinstance(point, (list, tuple)) or len(point) != 2:
                            raise ValueError("invalid polygon point")
                        polygon.append((_finite_float(point[0]),
                                        _finite_float(point[1])))
                    sectors.append(Sector(start, end, span, tuple(seg_ids)))
                    polygons.append(tuple(polygon))

                fan_vertices = value["vertices"]
                dropped = value["dropped"]
                culled = value["culled"]
                if (not isinstance(fan_vertices, int)
                        or isinstance(fan_vertices, bool)
                        or fan_vertices != len(sectors) * 2):
                    raise ValueError("invalid vertex count")
                if (not isinstance(dropped, int) or isinstance(dropped, bool)
                        or dropped < 0
                        or not isinstance(culled, int)
                        or isinstance(culled, bool) or culled < 0):
                    raise ValueError("invalid fan counters")
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=f"invalid fan {light_id!r}") from exc

            fan = Fan(light_id, tuple(sectors), fan_vertices,
                      dropped, culled)
            fans[light_id] = _FanState(fan, tuple(polygons))

        stats = {}
        for key in self._STAT_KEYS:
            value = raw_stats[key]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=f"invalid stat {key!r}")
            if not math.isfinite(float(value)):
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=f"invalid stat {key!r}")
            stats[key] = value
        for key in self._STAT_KEYS - {"vertex_budget"}:
            if stats[key] < 0:
                raise FanError("FAN_SNAPSHOT_INVALID",
                               detail=f"negative stat {key!r}")
        if (not _valid_budget(stats["vertex_budget"])
                or stats["vertex_budget"] != vertex_budget):
            raise FanError("FAN_SNAPSHOT_INVALID",
                           detail="inconsistent vertex budget")
        if (stats["lights"] != len(lights)
                or stats["segments"] != len(segments)):
            raise FanError("FAN_SNAPSHOT_INVALID",
                           detail="inconsistent collection counts")

        return merge_epsilon, vertex_budget, lights, segments, fans, stats
