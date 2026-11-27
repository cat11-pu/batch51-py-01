"""Screen space contact shadow tracing with temporal accumulation."""

from __future__ import annotations

import copy
import math
import operator
import threading
from dataclasses import dataclass
from numbers import Real


class ShadowTraceError(ValueError):
    """Raised when a trace request or a scene upload is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TileResult:
    """Outcome of one traced tile."""

    x0: int
    y0: int
    x1: int
    y1: int
    pixels: int
    steps: int


class ContactShadowTracer:
    """March the depth profile of each pixel and accumulate the result over time."""

    _CONFIG_KEYS = {
        "width", "height", "camera_id", "max_steps", "thickness",
        "step_size", "history_weight", "far_plane",
    }
    _STAT_KEYS = {"tiles", "pixels", "steps", "accumulations", "resets"}
    _SNAPSHOT_KEYS = {
        "version", "config", "surface", "occluders", "current", "history",
        "stats",
    }

    def __init__(self, *, width: int = 64, height: int = 64,
                 camera_id: str = "cam-0", max_steps: int = 8,
                 thickness: float = 1.0, step_size: float = 1.0,
                 history_weight: float = 0.5,
                 far_plane: float = 100.0) -> None:
        self._lock = threading.RLock()
        config = {"width": width, "height": height,
                  "camera_id": camera_id, "max_steps": max_steps,
                  "thickness": thickness, "step_size": step_size,
                  "history_weight": history_weight,
                  "far_plane": far_plane}
        self._config = self._validated_config(config)
        self._surface: list = []
        self._occluders: list = []
        self._current: dict = {}
        self._history: dict = {}
        self._frame_depths: dict = {}
        self._history_depths: dict = {}
        self._stats = {"tiles": 0, "pixels": 0, "steps": 0,
                       "accumulations": 0, "resets": 0}

    def configure(self, **kwargs) -> dict:
        with self._lock:
            if not kwargs:
                return copy.deepcopy(self._config)

            unknown = set(kwargs) - self._CONFIG_KEYS
            if unknown:
                self._fail("SHADOW_INVALID_CONFIG",
                           {"unknown": sorted(unknown)})

            candidate = copy.deepcopy(self._config)
            candidate.update(kwargs)
            candidate = self._validated_config(candidate)

            old_width = self._config["width"]
            old_height = self._config["height"]
            old_camera = self._config["camera_id"]
            resolution_changed = (
                candidate["width"] != old_width
                or candidate["height"] != old_height
            )
            camera_changed = candidate["camera_id"] != old_camera

            self._config = candidate
            if resolution_changed:
                self._clear_tracked()
                self._surface = []
                self._occluders = []
                self._stats["resets"] += 1
            elif camera_changed:
                self._clear_tracked()
                self._stats["resets"] += 1

            return copy.deepcopy(self._config)

    def load_scene(self, *, surface, occluders) -> int:
        with self._lock:
            width = self._config["width"]
            height = self._config["height"]
            new_surface, new_occluders = self._normalize_scene(
                surface, occluders, width, height
            )
            has_occluders = any(
                cell for row in new_occluders for cell in row
            )
            if has_occluders and self._occluders:
                for y in range(height):
                    for x in range(width):
                        if (not new_occluders[y][x]
                                and self._occluders[y][x]):
                            new_occluders[y][x] = self._occluders[y][x]
            self._surface = new_surface
            self._occluders = new_occluders
            return width * height

    def trace_tile(self, x0: int, y0: int, x1: int, y1: int) -> TileResult:
        with self._lock:
            x0, y0, x1, y1 = self._validated_tile(x0, y0, x1, y1)
            if not self._surface:
                self._fail("SHADOW_NO_SCENE")

            pixels = 0
            steps = 0

            for y in range(y0, y1 + 1):
                for x in range(x0, x1 + 1):
                    value, used_steps = self._trace_pixel(x, y)
                    self._current[(x, y)] = value
                    self._frame_depths[(x, y)] = float(
                        self._surface[y][x]
                    )
                    pixels += 1
                    steps += used_steps

            self._stats["tiles"] += 1
            self._stats["pixels"] += pixels
            self._stats["steps"] += steps
            return TileResult(x0, y0, x1, y1, pixels, steps)

    def sample_occlusion(self, x: int, y: int) -> float:
        with self._lock:
            x, y = self._validated_pixel(x, y)
            key = (x, y)
            if key in self._history:
                return float(self._history[key])
            if key in self._current:
                return float(self._current[key])
            raise KeyError(key)

    def occlusion_map(self) -> tuple:
        with self._lock:
            width = self._config["width"]
            height = self._config["height"]
            rows = []
            for y in range(height):
                row = []
                for x in range(width):
                    key = (x, y)
                    if key in self._history:
                        row.append(float(self._history[key]))
                    elif key in self._current:
                        row.append(float(self._current[key]))
                    else:
                        row.append(None)
                rows.append(tuple(row))
            return tuple(rows)

    def accumulate(self) -> int:
        with self._lock:
            count = len(self._current)
            if not self._history:
                self._history = {
                    key: float(value)
                    for key, value in self._current.items()
                }
                self._history_depths = dict(self._frame_depths)
                self._stats["accumulations"] += 1
                return count

            base_weight = self._config["history_weight"]
            thickness = self._config["thickness"]
            step_size = self._config["step_size"]
            tolerance = max(float(thickness), float(step_size), 1.0e-12)

            for key, current_value in self._current.items():
                if key not in self._history:
                    self._history[key] = float(current_value)
                    if key in self._frame_depths:
                        self._history_depths[key] = self._frame_depths[key]
                    continue

                weight = float(base_weight)
                current_depth = self._frame_depths.get(key)
                history_depth = self._history_depths.get(key)
                if current_depth is not None and history_depth is not None:
                    error = abs(float(current_depth) - float(history_depth))
                    weight *= max(0.0, 1.0 - error / tolerance)

                history_value = float(self._history[key])
                self._history[key] = (
                    weight * history_value
                    + (1.0 - weight) * float(current_value)
                )
                if current_depth is not None:
                    self._history_depths[key] = current_depth

            self._stats["accumulations"] += 1
            return count

    def reset_history(self, reason: str = "manual") -> int:
        with self._lock:
            removed = len(self._history)
            self._history.clear()
            self._history_depths.clear()
            self._stats["resets"] += 1
            return removed

    def stats(self) -> dict:
        with self._lock:
            return {
                "tiles": self._stats["tiles"],
                "pixels": self._stats["pixels"],
                "steps": self._stats["steps"],
                "accumulations": self._stats["accumulations"],
                "resets": self._stats["resets"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "config": copy.deepcopy(self._config),
                "surface": copy.deepcopy(self._surface),
                "occluders": [
                    [list(cell) for cell in row]
                    for row in self._occluders
                ],
                "current": copy.deepcopy(self._current),
                "history": copy.deepcopy(self._history),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._validated_snapshot(state)
            except ShadowTraceError:
                raise
            except Exception as exc:
                self._fail("SHADOW_SNAPSHOT_INVALID", str(exc))

            config, surface, occluders, current, history, stats = restored
            self._config = config
            self._surface = surface
            self._occluders = occluders
            self._current = current
            self._history = history
            self._stats = stats
            self._frame_depths = {
                (x, y): float(surface[y][x])
                for (x, y) in current
            }
            self._history_depths = {
                (x, y): float(surface[y][x])
                for (x, y) in history
            }

    @staticmethod
    def _fail(code: str, detail: object = None) -> None:
        raise ShadowTraceError(code, detail)

    @classmethod
    def _validated_config(cls, config: dict) -> dict:
        if not isinstance(config, dict):
            cls._fail("SHADOW_INVALID_CONFIG", "config must be a mapping")
        if set(config) != cls._CONFIG_KEYS:
            cls._fail("SHADOW_INVALID_CONFIG",
                      {"keys": sorted(config) if isinstance(config, dict)
                       else type(config).__name__})

        width = config["width"]
        height = config["height"]
        if not cls._is_int(width) or width <= 0:
            cls._fail("SHADOW_INVALID_CONFIG", {"width": width})
        if not cls._is_int(height) or height <= 0:
            cls._fail("SHADOW_INVALID_CONFIG", {"height": height})

        camera_id = config["camera_id"]
        if not isinstance(camera_id, str) or not camera_id:
            cls._fail("SHADOW_INVALID_CONFIG", {"camera_id": camera_id})

        max_steps = config["max_steps"]
        if not cls._is_int(max_steps) or max_steps <= 0:
            cls._fail("SHADOW_INVALID_CONFIG", {"max_steps": max_steps})

        for key in ("thickness", "step_size", "far_plane"):
            value = config[key]
            if not cls._is_positive_number(value):
                cls._fail("SHADOW_INVALID_CONFIG", {key: value})

        history_weight = config["history_weight"]
        if (not isinstance(history_weight, Real)
                or isinstance(history_weight, bool)
                or not math.isfinite(float(history_weight))
                or not 0.0 <= float(history_weight) <= 1.0):
            cls._fail("SHADOW_INVALID_CONFIG",
                      {"history_weight": history_weight})

        return copy.deepcopy(config)

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _is_positive_number(cls, value: object) -> bool:
        if not isinstance(value, Real) or isinstance(value, bool):
            return False
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return False
        return math.isfinite(number) and number > 0.0

    @classmethod
    def _coerce_depth(cls, value: object, detail: str) -> float:
        if not isinstance(value, Real) or isinstance(value, bool):
            cls._fail("SHADOW_INVALID_SCENE", {detail: value})
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            cls._fail("SHADOW_INVALID_SCENE", {detail: value})
        if not math.isfinite(number):
            cls._fail("SHADOW_INVALID_SCENE", {detail: value})
        return number

    @classmethod
    def _normalize_scene(cls, surface, occluders, width, height):
        if not isinstance(surface, (list, tuple)):
            cls._fail("SHADOW_INVALID_SCENE", "surface must be a grid")
        if not isinstance(occluders, (list, tuple)):
            cls._fail("SHADOW_INVALID_SCENE", "occluders must be a grid")
        if len(surface) != height or len(occluders) != height:
            cls._fail("SHADOW_INVALID_SCENE",
                      {"expected_rows": height,
                       "surface_rows": len(surface),
                       "occluder_rows": len(occluders)})

        normalized_surface = []
        normalized_occluders = []
        for y in range(height):
            surface_row = surface[y]
            occluder_row = occluders[y]
            if not isinstance(surface_row, (list, tuple)):
                cls._fail("SHADOW_INVALID_SCENE",
                          {"surface_row": y, "type": type(surface_row).__name__})
            if not isinstance(occluder_row, (list, tuple)):
                cls._fail("SHADOW_INVALID_SCENE",
                          {"occluder_row": y,
                           "type": type(occluder_row).__name__})
            if len(surface_row) != width or len(occluder_row) != width:
                cls._fail("SHADOW_INVALID_SCENE",
                          {"row": y, "expected_columns": width,
                           "surface_columns": len(surface_row),
                           "occluder_columns": len(occluder_row)})

            normalized_surface_row = []
            normalized_occluder_row = []
            for x in range(width):
                normalized_surface_row.append(
                    cls._coerce_depth(surface_row[x], f"surface[{y}][{x}]")
                )
                cell = occluder_row[x]
                if not isinstance(cell, (list, tuple)):
                    cls._fail("SHADOW_INVALID_SCENE",
                              {f"occluders[{y}][{x}]": cell})
                normalized_occluder_row.append(tuple(
                    cls._coerce_depth(value, f"occluders[{y}][{x}]")
                    for value in cell
                ))
            normalized_surface.append(normalized_surface_row)
            normalized_occluders.append(normalized_occluder_row)

        return normalized_surface, normalized_occluders

    def _validated_tile(self, x0, y0, x1, y1):
        coords = []
        for name, value in (("x0", x0), ("y0", y0),
                            ("x1", x1), ("y1", y1)):
            if isinstance(value, bool):
                self._fail("SHADOW_TILE_INVALID", {name: value})
            try:
                coords.append(operator.index(value))
            except (TypeError, ValueError):
                self._fail("SHADOW_TILE_INVALID", {name: value})

        x0, y0, x1, y1 = coords
        width = self._config["width"]
        height = self._config["height"]
        if (x0 > x1 or y0 > y1
                or x0 < 0 or y0 < 0
                or x1 >= width or y1 >= height):
            self._fail("SHADOW_TILE_INVALID",
                       {"rect": [x0, y0, x1, y1],
                        "width": width, "height": height})
        return x0, y0, x1, y1

    def _validated_pixel(self, x, y):
        if isinstance(x, bool) or isinstance(y, bool):
            self._fail("SHADOW_OUT_OF_RANGE", {"x": x, "y": y})
        try:
            x = operator.index(x)
            y = operator.index(y)
        except (TypeError, ValueError):
            self._fail("SHADOW_OUT_OF_RANGE", {"x": x, "y": y})
        width = self._config["width"]
        height = self._config["height"]
        if x < 0 or y < 0 or x >= width or y >= height:
            self._fail("SHADOW_OUT_OF_RANGE",
                      {"x": x, "y": y, "width": width, "height": height})
        return x, y

    def _trace_pixel(self, x: int, y: int) -> tuple[float, int]:
        depth = float(self._surface[y][x])
        far_plane = float(self._config["far_plane"])
        if not math.isfinite(depth) or depth <= 0.0 or depth >= far_plane:
            return 0.0, 0
        if self._is_depth_discontinuity(x, y, depth):
            return 0.0, 0

        candidates = self._occluders[y][x]
        if not candidates:
            return 0.0, 0

        max_steps = self._config["max_steps"]
        step_size = float(self._config["step_size"])
        thickness = float(self._config["thickness"])
        best = 0.0
        used_steps = 0

        for step in range(1, max_steps + 1):
            used_steps += 1
            probe = depth - step_size * step
            if probe <= 0.0 or probe > far_plane:
                break

            for occluder_depth in candidates:
                if occluder_depth <= 0.0 or occluder_depth >= far_plane:
                    continue
                difference = probe - occluder_depth
                if 0.0 <= difference <= thickness:
                    if difference < step_size * 0.5:
                        difference *= 0.5
                    strength = 1.0 - difference / thickness
                    if strength > best:
                        best = min(1.0, max(0.0, strength))

        return best, used_steps

    def _is_depth_discontinuity(self, x: int, y: int, depth: float) -> bool:
        height = self._config["height"]
        width = self._config["width"]
        thickness = float(self._config["thickness"])
        neighbours = []
        if x > 0:
            neighbours.append(self._surface[y][x - 1])
        if x + 1 < width:
            neighbours.append(self._surface[y][x + 1])
        if y > 0:
            neighbours.append(self._surface[y - 1][x])
        if y + 1 < height:
            neighbours.append(self._surface[y + 1][x])
        return any(abs(float(value) - depth) > thickness
                   for value in neighbours)

    def _clear_tracked(self) -> None:
        self._current.clear()
        self._history.clear()
        self._frame_depths.clear()
        self._history_depths.clear()

    def _validated_snapshot(self, state):
        if not isinstance(state, dict):
            self._fail("SHADOW_SNAPSHOT_INVALID", "state must be a mapping")
        if set(state) != self._SNAPSHOT_KEYS:
            self._fail("SHADOW_SNAPSHOT_INVALID",
                       {"keys": sorted(state) if isinstance(state, dict)
                        else type(state).__name__})
        if state["version"] != 1 or isinstance(state["version"], bool):
            self._fail("SHADOW_SNAPSHOT_INVALID",
                       {"version": state["version"]})

        config = self._validated_config(state["config"])
        width = config["width"]
        height = config["height"]

        surface_state = state["surface"]
        occluder_state = state["occluders"]
        if surface_state == [] and occluder_state == []:
            surface = []
            occluders = []
        else:
            surface, occluders = self._normalize_scene(
                surface_state, occluder_state, width, height
            )

        current = self._validated_value_map(
            state["current"], width, height, "current"
        )
        history = self._validated_value_map(
            state["history"], width, height, "history"
        )
        if not surface and (current or history):
            self._fail("SHADOW_SNAPSHOT_INVALID",
                       "samples require a loaded scene")
        stats = self._validated_stats(state["stats"])
        return config, surface, occluders, current, history, stats

    def _validated_value_map(self, mapping, width, height, name):
        if not isinstance(mapping, dict):
            self._fail("SHADOW_SNAPSHOT_INVALID",
                       {name: "must be a mapping"})
        normalized = {}
        for key, value in mapping.items():
            if (not isinstance(key, tuple) or len(key) != 2
                    or not all(self._is_int(part) for part in key)):
                self._fail("SHADOW_SNAPSHOT_INVALID",
                           {name: f"invalid key {key!r}"})
            x, y = key
            if x < 0 or y < 0 or x >= width or y >= height:
                self._fail("SHADOW_SNAPSHOT_INVALID",
                           {name: f"out-of-range key {key!r}"})
            if (not isinstance(value, Real) or isinstance(value, bool)
                    or not math.isfinite(float(value))):
                self._fail("SHADOW_SNAPSHOT_INVALID",
                           {name: f"invalid value at {key!r}"})
            normalized[key] = float(value)
        return normalized

    def _validated_stats(self, stats):
        if not isinstance(stats, dict) or set(stats) != self._STAT_KEYS:
            self._fail("SHADOW_SNAPSHOT_INVALID",
                       {"stats": stats if not isinstance(stats, dict)
                        else sorted(stats)})
        normalized = {}
        for key in ("tiles", "pixels", "steps",
                    "accumulations", "resets"):
            value = stats[key]
            if not self._is_int(value) or value < 0:
                self._fail("SHADOW_SNAPSHOT_INVALID", {"stats": key})
            normalized[key] = value
        return normalized
