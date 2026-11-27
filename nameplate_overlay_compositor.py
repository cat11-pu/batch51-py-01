"""Nameplate overlay compositor: projection, depth occlusion, stable overlap avoidance."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1

_COUNTER_KEYS = ("submits", "frames", "culled", "dropped", "pushed", "rejected")


class NameplateError(ValueError):
    """Raised when a nameplate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PlateState:
    """Submitted nameplate of one entity."""

    entity: str
    position: tuple
    priority: int
    text: str | None
    frame: int


@dataclass(frozen=True)
class CompositedPlate:
    """One nameplate after culling, budgeting and overlap avoidance."""

    entity: str
    x: float
    y: float
    depth: float
    priority: int
    alpha: float
    text: str | None


class NameplateCompositor:
    """Project nameplates to screen, fade occluded ones and avoid overlaps stably."""

    def __init__(self, *, width: int = 1920, height: int = 1080,
                 max_plates: int = 32, plate_width: float = 120.0,
                 plate_height: float = 28.0, occlusion_alpha: float = 0.25,
                 occlusion_bias: float = 0.05,
                 offscreen_margin: float = 64.0) -> None:
        self._lock = threading.RLock()
        self._config = {
            "width": width,
            "height": height,
            "max_plates": max_plates,
            "plate_width": plate_width,
            "plate_height": plate_height,
            "occlusion_alpha": occlusion_alpha,
            "occlusion_bias": occlusion_bias,
            "offscreen_margin": offscreen_margin,
        }
        self._camera = {"eye": (0.0, 0.0, 0.0), "fov_y_deg": 90.0}
        self._probe = None
        self._frame = 0
        self._plates: dict = {}
        self._fading: dict = {}
        self._layout: tuple = ()
        self._dirty = True
        self._counters: dict = {key: 0 for key in _COUNTER_KEYS}

    def _reject(self, code: str, detail: object = None):
        self._counters["rejected"] += 1
        raise NameplateError(code, detail)

    @staticmethod
    def _floats3(value):
        if isinstance(value, (str, bytes)):
            return None
        try:
            items = tuple(value)
        except TypeError:
            return None
        if len(items) != 3:
            return None
        try:
            result = tuple(float(item) for item in items)
        except (TypeError, ValueError):
            return None
        if not all(math.isfinite(item) for item in result):
            return None
        return result

    def begin_frame(self, frame: int | None = None) -> int:
        with self._lock:
            if frame is None:
                self._frame += 1
            else:
                if isinstance(frame, bool) or not isinstance(frame, int):
                    self._reject("NAMEPLATE_INVALID_ARGUMENT",
                                 ("frame", frame))
                self._frame = frame
            self._counters["frames"] += 1
            self._dirty = True
            return self._frame

    def set_camera(self, *, eye=(0.0, 0.0, 0.0), fov_y_deg: float = 90.0) -> dict:
        with self._lock:
            eye3 = self._floats3(eye)
            if eye3 is None:
                self._reject("NAMEPLATE_INVALID_ARGUMENT", ("eye", eye))
            if (isinstance(fov_y_deg, bool)
                    or not isinstance(fov_y_deg, (int, float))):
                self._reject("NAMEPLATE_INVALID_ARGUMENT",
                             ("fov_y_deg", fov_y_deg))
            fov = float(fov_y_deg)
            if not math.isfinite(fov) or not 0.0 < fov < 180.0:
                self._reject("NAMEPLATE_INVALID_ARGUMENT",
                             ("fov_y_deg", fov_y_deg))
            self._camera = {"eye": eye3, "fov_y_deg": fov}
            self._dirty = True
            return dict(self._camera)

    def set_depth_probe(self, probe) -> None:
        with self._lock:
            if not callable(probe):
                self._reject("NAMEPLATE_INVALID_ARGUMENT", ("probe", probe))
            self._probe = probe
            self._dirty = True

    def submit(self, entity: str, *, position, priority: int = 0,
               text: str | None = None) -> PlateState:
        with self._lock:
            if not isinstance(entity, str) or not entity:
                self._reject("NAMEPLATE_INVALID_ARGUMENT", ("entity", entity))
            pos = self._floats3(position)
            if pos is None:
                self._reject("NAMEPLATE_INVALID_ARGUMENT",
                             ("position", position))
            if isinstance(priority, bool) or not isinstance(priority, int):
                self._reject("NAMEPLATE_INVALID_ARGUMENT",
                             ("priority", priority))
            if text is not None and not isinstance(text, str):
                self._reject("NAMEPLATE_INVALID_ARGUMENT", ("text", text))
            state = PlateState(entity=entity, position=pos, priority=priority,
                               text=text, frame=self._frame)
            self._plates[entity] = state
            self._fading.pop(entity, None)
            self._counters["submits"] += 1
            self._dirty = True
            return state

    def _project_point(self, x: float, y: float, z: float):
        eye_x, eye_y, eye_z = self._camera["eye"]
        dz = eye_z - z
        if dz <= 0.1:
            return None
        width = self._config["width"]
        height = self._config["height"]
        tan_half = math.tan(math.radians(self._camera["fov_y_deg"]) / 2.0)
        norm_x = (x - eye_x) / (dz * tan_half * (width / height))
        norm_y = (y - eye_y) / (dz * tan_half)
        screen_x = (norm_x + 1.0) * 0.5 * width
        screen_y = (1.0 - norm_y) * 0.5 * height
        return (screen_x, screen_y, dz)

    def project(self, x: float, y: float, z: float):
        with self._lock:
            try:
                point = (float(x), float(y), float(z))
            except (TypeError, ValueError):
                self._reject("NAMEPLATE_INVALID_ARGUMENT", ("point", (x, y, z)))
            if not all(math.isfinite(v) for v in point):
                self._reject("NAMEPLATE_INVALID_ARGUMENT", ("point", (x, y, z)))
            return self._project_point(*point)

    def _compute_layout(self) -> None:
        cfg = self._config
        margin = cfg["offscreen_margin"]
        max_x = cfg["width"] + margin
        max_y = cfg["height"] + margin
        candidates = []
        culled = 0
        for state in self._plates.values():
            projected = self._project_point(*state.position)
            if projected is None:
                culled += 1
                continue
            screen_x, screen_y, depth = projected
            if not (-margin <= screen_x <= max_x
                    and -margin <= screen_y <= max_y):
                culled += 1
                continue
            alpha = 1.0
            if self._probe is not None:
                scene_depth = self._probe(screen_x, screen_y)
                if (scene_depth is not None
                        and scene_depth < depth - cfg["occlusion_bias"]):
                    alpha = cfg["occlusion_alpha"]
            candidates.append((state, screen_x, screen_y, depth, alpha))
        self._counters["culled"] += culled

        candidates.sort(key=lambda item: (-item[0].priority, item[3],
                                          item[0].entity))
        budget = cfg["max_plates"]
        kept = candidates[:budget]
        self._counters["dropped"] += len(candidates) - len(kept)

        plate_w = cfg["plate_width"]
        plate_h = cfg["plate_height"]
        placed = []
        pushed = 0
        for state, screen_x, screen_y, depth, alpha in kept:
            y = screen_y
            while any(abs(screen_x - other_x) < plate_w
                      and abs(y - other_y) < plate_h
                      for _, other_x, other_y, _, _ in placed):
                y += plate_h
            if y != screen_y:
                pushed += 1
            placed.append((state, screen_x, y, depth, alpha))
        self._counters["pushed"] += pushed

        result = [
            CompositedPlate(entity=state.entity, x=screen_x, y=y, depth=depth,
                            priority=state.priority, alpha=alpha,
                            text=state.text)
            for state, screen_x, y, depth, alpha in placed
        ]
        result.sort(key=lambda plate: (-plate.priority, plate.entity))
        self._layout = tuple(result)
        self._dirty = False

    def _current_layout(self) -> tuple:
        if self._dirty:
            self._compute_layout()
        return self._layout

    def resolve_overlap(self) -> tuple:
        with self._lock:
            return self._current_layout()

    def compose(self) -> tuple:
        with self._lock:
            return self._current_layout()

    def set_budget(self, max_plates: int) -> int:
        with self._lock:
            if (isinstance(max_plates, bool) or not isinstance(max_plates, int)
                    or max_plates <= 0):
                self._reject("NAMEPLATE_INVALID_ARGUMENT",
                             ("max_plates", max_plates))
            self._config["max_plates"] = max_plates
            self._dirty = True
            return max_plates

    def destroy(self, entity: str) -> bool:
        with self._lock:
            state = self._plates.pop(entity, None)
            if state is None:
                return False
            self._fading[entity] = state
            self._dirty = True
            return True

    def plate_of(self, entity: str) -> PlateState:
        with self._lock:
            state = self._plates.get(entity)
            if state is None:
                self._reject("NAMEPLATE_UNKNOWN_ENTITY", ("entity", entity))
            return state

    def snapshot(self) -> dict:
        with self._lock:
            layout = self._current_layout()
            return {
                "version": SNAPSHOT_VERSION,
                "frame": self._frame,
                "plates": {
                    entity: {
                        "position": list(state.position),
                        "priority": state.priority,
                        "text": state.text,
                        "frame": state.frame,
                    }
                    for entity, state in self._plates.items()
                },
                "layout": [
                    {
                        "entity": plate.entity,
                        "x": plate.x,
                        "y": plate.y,
                        "depth": plate.depth,
                        "priority": plate.priority,
                        "alpha": plate.alpha,
                        "text": plate.text,
                    }
                    for plate in layout
                ],
                "counters": dict(self._counters),
            }

    def _parse_snapshot(self, state: dict):
        def invalid(detail):
            self._reject("NAMEPLATE_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != {
                "version", "frame", "plates", "layout", "counters"}:
            invalid("keys")
        version = state["version"]
        if (isinstance(version, bool) or not isinstance(version, int)
                or version != SNAPSHOT_VERSION):
            invalid("version")
        frame = state["frame"]
        if isinstance(frame, bool) or not isinstance(frame, int):
            invalid("frame")

        raw_plates = state["plates"]
        if not isinstance(raw_plates, dict):
            invalid("plates")
        plates = {}
        for entity, record in raw_plates.items():
            if not isinstance(entity, str) or not entity:
                invalid(("plates", entity))
            if not isinstance(record, dict) or set(record) != {
                    "position", "priority", "text", "frame"}:
                invalid(("plates", entity))
            position = self._floats3(record["position"])
            priority = record["priority"]
            text = record["text"]
            plate_frame = record["frame"]
            if position is None:
                invalid(("plates", entity, "position"))
            if isinstance(priority, bool) or not isinstance(priority, int):
                invalid(("plates", entity, "priority"))
            if text is not None and not isinstance(text, str):
                invalid(("plates", entity, "text"))
            if isinstance(plate_frame, bool) or not isinstance(plate_frame, int):
                invalid(("plates", entity, "frame"))
            plates[entity] = PlateState(entity=entity, position=position,
                                        priority=priority, text=text,
                                        frame=plate_frame)

        raw_layout = state["layout"]
        if not isinstance(raw_layout, (list, tuple)):
            invalid("layout")
        layout = []
        for entry in raw_layout:
            if not isinstance(entry, dict) or set(entry) != {
                    "entity", "x", "y", "depth", "priority", "alpha", "text"}:
                invalid("layout")
            entity = entry["entity"]
            if not isinstance(entity, str) or not entity:
                invalid("layout")
            try:
                x = float(entry["x"])
                y = float(entry["y"])
                depth = float(entry["depth"])
                alpha = float(entry["alpha"])
            except (TypeError, ValueError):
                invalid("layout")
            if not all(math.isfinite(v) for v in (x, y, depth, alpha)):
                invalid("layout")
            priority = entry["priority"]
            text = entry["text"]
            if isinstance(priority, bool) or not isinstance(priority, int):
                invalid("layout")
            if text is not None and not isinstance(text, str):
                invalid("layout")
            layout.append(CompositedPlate(entity=entity, x=x, y=y,
                                          depth=depth, priority=priority,
                                          alpha=alpha, text=text))

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict) \
                or set(raw_counters) != set(_COUNTER_KEYS):
            invalid("counters")
        counters = {}
        for key in _COUNTER_KEYS:
            value = raw_counters[key]
            if isinstance(value, bool) or not isinstance(value, int):
                invalid("counters")
            counters[key] = value

        return frame, plates, tuple(layout), counters

    def restore(self, state: dict) -> None:
        with self._lock:
            frame, plates, layout, counters = self._parse_snapshot(state)
            self._frame = frame
            self._plates = plates
            self._fading = {}
            self._layout = layout
            self._counters = counters
            self._dirty = False

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
