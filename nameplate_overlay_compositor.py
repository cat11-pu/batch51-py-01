"""Nameplate overlay compositor: projection, depth occlusion, stable overlap avoidance."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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
        self._layout: tuple = ()
        self._counters: dict = {
            "submits": 0,
            "frames": 0,
            "culled": 0,
            "dropped": 0,
            "pushed": 0,
            "rejected": 0,
        }

    def begin_frame(self, frame: int | None = None) -> int:
        raise NotImplementedError

    def set_camera(self, *, eye=(0.0, 0.0, 0.0), fov_y_deg: float = 90.0) -> dict:
        raise NotImplementedError

    def set_depth_probe(self, probe) -> None:
        raise NotImplementedError

    def submit(self, entity: str, *, position, priority: int = 0,
               text: str | None = None) -> PlateState:
        raise NotImplementedError

    def project(self, x: float, y: float, z: float):
        raise NotImplementedError

    def resolve_overlap(self) -> tuple:
        raise NotImplementedError

    def compose(self) -> tuple:
        raise NotImplementedError

    def set_budget(self, max_plates: int) -> int:
        raise NotImplementedError

    def destroy(self, entity: str) -> bool:
        raise NotImplementedError

    def plate_of(self, entity: str) -> PlateState:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
