"""Volumetric cloudscape: weather maps, density integration, temporal blending."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1
EXTINCTION_COEFF = 0.01


class CloudError(ValueError):
    """Raised when a weather or integration request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class WeatherMap:
    version: int
    coverage: float
    base_height: float
    top_height: float
    transition_ms: int = 0


@dataclass(frozen=True)
class CloudFrame:
    frame: int
    weather_version: int
    density: float
    transmittance: float
    steps: int
    history_weight: float
    history_valid: bool


class Cloudscape:
    """Map weather maps onto a marched cloud volume with temporal history."""

    def __init__(self, *, max_steps: int = 64, min_steps: int = 8,
                 terrain_height: float = 0.0, history_decay: float = 0.9,
                 reprojection_threshold: float = 0.35) -> None:
        self.max_steps = max_steps
        self.min_steps = min_steps
        self.terrain_height = terrain_height
        self.history_decay = history_decay
        self.reprojection_threshold = reprojection_threshold
        self._lock = threading.RLock()
        self._weather = None
        self._prev_weather = None
        self._now_ms = 0
        self._transition_start_ms = 0
        self._camera_weight = 1.0
        self._frames = {}
        self._history = None
        self._last_frame = None
        self._stats = {
            "weather_sets": 0,
            "integrates": 0,
            "resolves": 0,
            "invalidations": 0,
            "frames_dropped": 0,
            "camera_updates": 0,
        }

    def _effective_profile(self):
        """Return (coverage, base, top, transition_progress) at current time."""
        weather = self._weather
        if weather is None:
            return None
        prev = self._prev_weather
        span = weather.transition_ms
        if prev is None or span <= 0:
            return (weather.coverage, weather.base_height, weather.top_height, 1.0)
        elapsed = self._now_ms - self._transition_start_ms
        if elapsed >= span:
            return (weather.coverage, weather.base_height, weather.top_height, 1.0)
        t = elapsed / span
        coverage = prev.coverage + (weather.coverage - prev.coverage) * t
        base = prev.base_height + (weather.base_height - prev.base_height) * t
        top = prev.top_height + (weather.top_height - prev.top_height) * t
        return (coverage, base, top, t)

    def _drop_history(self):
        dropped = len(self._frames)
        self._frames.clear()
        self._history = None
        self._last_frame = None
        self._stats["frames_dropped"] += dropped
        return dropped

    def set_weather(self, weather, *, now_ms=0):
        with self._lock:
            if not (0.0 <= weather.coverage <= 1.0):
                raise CloudError("CLOUD_WEATHER_INVALID",
                                 {"coverage": weather.coverage})
            if not weather.base_height < weather.top_height:
                raise CloudError("CLOUD_WEATHER_INVALID",
                                 {"base_height": weather.base_height,
                                  "top_height": weather.top_height})
            if self._weather is not None and weather.version <= self._weather.version:
                raise CloudError("CLOUD_WEATHER_STALE",
                                 {"version": weather.version,
                                  "current": self._weather.version})
            self._drop_history()
            self._prev_weather = self._weather
            self._weather = weather
            self._transition_start_ms = now_ms
            self._now_ms = now_ms
            self._stats["weather_sets"] += 1
            return weather.version

    def current_weather(self):
        with self._lock:
            return self._weather

    def sample_density(self, x, y, z):
        with self._lock:
            profile = self._effective_profile()
            if profile is None:
                return 0.0
            coverage, base, top, _ = profile
            base = max(base, self.terrain_height)
            if base <= z <= top:
                return coverage
            return 0.0

    def integrate(self, frame, *, ray_origin, ray_dir, step_budget=None):
        with self._lock:
            if step_budget is None:
                steps = self.max_steps
            else:
                steps = min(step_budget, self.max_steps)
                steps = max(steps, self.min_steps)
            steps = max(0, min(steps, self.max_steps))

            density = 0.0
            transmittance = 1.0
            profile = self._effective_profile()
            if profile is not None and steps > 0:
                coverage, base, top, _ = profile
                ox, oy, oz = ray_origin
                dx, dy, dz = ray_dir
                norm = math.sqrt(dx * dx + dy * dy + dz * dz)
                if norm > 0.0 and coverage > 0.0 and top > base:
                    dx, dy, dz = dx / norm, dy / norm, dz / norm
                    full_path = self._slab_path(oz, dz, base, top)
                    visible_path = self._slab_path(
                        oz, dz, max(base, self.terrain_height), top)
                    budget_scale = steps / self.max_steps if self.max_steps else 0.0
                    density = coverage * visible_path * budget_scale
                    optical_depth = (EXTINCTION_COEFF * coverage
                                     * full_path * budget_scale)
                    transmittance = math.exp(-optical_depth)

            version = self._weather.version if self._weather is not None else 0
            record = CloudFrame(frame=frame, weather_version=version,
                                density=density, transmittance=transmittance,
                                steps=steps, history_weight=0.0,
                                history_valid=False)
            self._frames[frame] = record
            self._last_frame = frame
            self._stats["integrates"] += 1
            return record

    @staticmethod
    def _slab_path(oz, dz, bottom, top):
        """Length of the ray segment inside the horizontal slab [bottom, top]."""
        if top <= bottom:
            return 0.0
        if abs(dz) < 1e-12:
            return 0.0
        t1 = (bottom - oz) / dz
        t2 = (top - oz) / dz
        t_enter, t_exit = min(t1, t2), max(t1, t2)
        t_start = max(t_enter, 0.0)
        if t_exit <= t_start:
            return 0.0
        return t_exit - t_start

    def resolve(self):
        with self._lock:
            self._stats["resolves"] += 1
            if self._last_frame is None or self._last_frame not in self._frames:
                raise CloudError("CLOUD_NO_FRAME",
                                 "no integrated frame to resolve")
            current = self._frames[self._last_frame]
            history = self._history
            if history is None or history.weather_version != current.weather_version:
                resolved = CloudFrame(
                    frame=current.frame,
                    weather_version=current.weather_version,
                    density=current.density,
                    transmittance=current.transmittance,
                    steps=current.steps,
                    history_weight=0.0,
                    history_valid=False)
            else:
                profile = self._effective_profile()
                progress = profile[3] if profile is not None else 1.0
                weight = self.history_decay * self._camera_weight * progress
                weight = min(1.0, max(0.0, weight))
                resolved = CloudFrame(
                    frame=current.frame,
                    weather_version=current.weather_version,
                    density=(weight * history.density
                             + (1.0 - weight) * current.density),
                    transmittance=(weight * history.transmittance
                                   + (1.0 - weight) * current.transmittance),
                    steps=current.steps,
                    history_weight=weight,
                    history_valid=True)
            self._frames[current.frame] = resolved
            self._history = resolved
            return resolved

    def invalidate_history(self, reason=""):
        with self._lock:
            dropped = self._drop_history()
            self._stats["invalidations"] += 1
            return dropped

    def set_camera(self, *, reprojection_error):
        with self._lock:
            self._stats["camera_updates"] += 1
            threshold = self.reprojection_threshold
            if threshold > 0.0:
                weight = 1.0 - reprojection_error / threshold
                teleported = reprojection_error >= threshold
            else:
                weight = 1.0 if reprojection_error <= 0.0 else 0.0
                teleported = reprojection_error > 0.0
            weight = min(1.0, max(0.0, weight))
            self._camera_weight = weight
            if teleported:
                self._drop_history()
            return weight

    def frame_state(self, frame):
        with self._lock:
            return self._frames.get(frame)

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "max_steps": self.max_steps,
                    "min_steps": self.min_steps,
                    "terrain_height": self.terrain_height,
                    "history_decay": self.history_decay,
                    "reprojection_threshold": self.reprojection_threshold,
                },
                "weather": self._weather_to_dict(self._weather),
                "prev_weather": self._weather_to_dict(self._prev_weather),
                "now_ms": self._now_ms,
                "transition_start_ms": self._transition_start_ms,
                "camera_weight": self._camera_weight,
                "frames": [self._frame_to_dict(f) for f in self._frames.values()],
                "history": (self._frame_to_dict(self._history)
                            if self._history is not None else None),
                "last_frame": self._last_frame,
                "stats": dict(self._stats),
            }

    @staticmethod
    def _weather_to_dict(weather):
        if weather is None:
            return None
        return {"version": weather.version, "coverage": weather.coverage,
                "base_height": weather.base_height,
                "top_height": weather.top_height,
                "transition_ms": weather.transition_ms}

    @staticmethod
    def _frame_to_dict(frame):
        return {"frame": frame.frame, "weather_version": frame.weather_version,
                "density": frame.density, "transmittance": frame.transmittance,
                "steps": frame.steps, "history_weight": frame.history_weight,
                "history_valid": frame.history_valid}

    @staticmethod
    def _invalid(detail):
        return CloudError("CLOUD_SNAPSHOT_INVALID", detail)

    @classmethod
    def _weather_from_dict(cls, data):
        if data is None:
            return None
        if not isinstance(data, dict):
            raise cls._invalid("weather entry is not a mapping")
        try:
            return WeatherMap(version=int(data["version"]),
                              coverage=float(data["coverage"]),
                              base_height=float(data["base_height"]),
                              top_height=float(data["top_height"]),
                              transition_ms=int(data.get("transition_ms", 0)))
        except (KeyError, TypeError, ValueError) as exc:
            raise cls._invalid("malformed weather entry") from exc

    @classmethod
    def _frame_from_dict(cls, data):
        if not isinstance(data, dict):
            raise cls._invalid("frame entry is not a mapping")
        try:
            return CloudFrame(frame=int(data["frame"]),
                              weather_version=int(data["weather_version"]),
                              density=float(data["density"]),
                              transmittance=float(data["transmittance"]),
                              steps=int(data["steps"]),
                              history_weight=float(data["history_weight"]),
                              history_valid=bool(data["history_valid"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise cls._invalid("malformed frame entry") from exc

    def restore(self, state):
        with self._lock:
            if not isinstance(state, dict):
                raise self._invalid("snapshot is not a mapping")
            if state.get("version") != SNAPSHOT_VERSION:
                raise self._invalid("unknown snapshot version")
            required = ("config", "weather", "prev_weather", "now_ms",
                        "transition_start_ms", "camera_weight", "frames",
                        "history", "last_frame", "stats")
            if any(key not in state for key in required):
                raise self._invalid("snapshot is missing fields")
            config = state["config"]
            if not isinstance(config, dict) or any(
                    key not in config for key in
                    ("max_steps", "min_steps", "terrain_height",
                     "history_decay", "reprojection_threshold")):
                raise self._invalid("malformed config")
            stats = state["stats"]
            if not isinstance(stats, dict) or any(
                    key not in stats for key in
                    ("weather_sets", "integrates", "resolves", "invalidations",
                     "frames_dropped", "camera_updates")):
                raise self._invalid("malformed stats")
            frames_data = state["frames"]
            if not isinstance(frames_data, (list, tuple)):
                raise self._invalid("frames is not a list")

            weather = self._weather_from_dict(state["weather"])
            prev_weather = self._weather_from_dict(state["prev_weather"])
            frames = {}
            for entry in frames_data:
                record = self._frame_from_dict(entry)
                frames[record.frame] = record
            history = (None if state["history"] is None
                       else self._frame_from_dict(state["history"]))
            try:
                now_ms = int(state["now_ms"])
                transition_start_ms = int(state["transition_start_ms"])
                camera_weight = float(state["camera_weight"])
                last_frame = (None if state["last_frame"] is None
                              else int(state["last_frame"]))
                new_stats = {key: int(stats[key]) for key in stats}
                new_config = {key: float(config[key]) for key in config}
            except (TypeError, ValueError) as exc:
                raise self._invalid("malformed scalar fields") from exc

            self.max_steps = int(new_config["max_steps"])
            self.min_steps = int(new_config["min_steps"])
            self.terrain_height = new_config["terrain_height"]
            self.history_decay = new_config["history_decay"]
            self.reprojection_threshold = new_config["reprojection_threshold"]
            self._weather = weather
            self._prev_weather = prev_weather
            self._now_ms = now_ms
            self._transition_start_ms = transition_start_ms
            self._camera_weight = camera_weight
            self._frames = frames
            self._history = history
            self._last_frame = last_frame
            self._stats = new_stats

    def stats(self):
        with self._lock:
            return dict(self._stats)
