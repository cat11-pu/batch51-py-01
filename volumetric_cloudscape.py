"""Volumetric cloudscape: weather maps, density integration, temporal blending."""

from __future__ import annotations

import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1


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

    def set_weather(self, weather, *, now_ms=0):
        raise NotImplementedError

    def current_weather(self):
        raise NotImplementedError

    def sample_density(self, x, y, z):
        raise NotImplementedError

    def integrate(self, frame, *, ray_origin, ray_dir, step_budget=None):
        raise NotImplementedError

    def resolve(self):
        raise NotImplementedError

    def invalidate_history(self, reason=""):
        raise NotImplementedError

    def set_camera(self, *, reprojection_error):
        raise NotImplementedError

    def frame_state(self, frame):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
