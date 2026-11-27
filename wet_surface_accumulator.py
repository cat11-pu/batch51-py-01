"""Wet surface accumulator: precipitation exposure, evaporation, puddle material blend."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class WetSurfaceError(ValueError):
    """Raised when a surface update is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SurfaceState:
    """Published state of one surface patch."""

    surface_id: str
    wetness: float
    sheltered: bool
    exposure: float
    frame: int


@dataclass(frozen=True)
class MaterialState:
    """Wet material parameters derived from the published wetness."""

    surface_id: str
    roughness: float
    albedo_scale: float
    blended: bool


@dataclass(frozen=True)
class PuddleMask:
    """Puddle coverage of one surface patch."""

    surface_id: str
    depth: float
    blended: bool
    threshold: float


class WetSurfaceAccumulator:
    """Accumulate rain or snow per surface patch and blend a wet material on top."""

    def __init__(self, *, max_surfaces: int = 4096,
                 puddle_threshold: float = 0.6,
                 base_roughness: float = 0.85,
                 wet_roughness: float = 0.25,
                 min_albedo: float = 0.72) -> None:
        self._lock = threading.RLock()
        self._config = {
            "max_surfaces": max_surfaces,
            "puddle_threshold": puddle_threshold,
            "base_roughness": base_roughness,
            "wet_roughness": wet_roughness,
            "min_albedo": min_albedo,
        }
        self._surfaces: dict = {}
        self._working: dict = {}
        self._published: dict = {}
        self._precipitation = {"kind": "none", "intensity": 0.0}
        self._frame = 0
        self._counters: dict = {
            "surfaces": 0,
            "accumulates": 0,
            "evaporates": 0,
            "publishes": 0,
            "puddle_events": 0,
            "rejected": 0,
        }

    def register_surface(self, surface_id: str, *, sheltered: bool = False,
                         exposure: float = 1.0) -> SurfaceState:
        raise NotImplementedError

    def set_precipitation(self, kind: str, *, intensity: float = 1.0) -> dict:
        raise NotImplementedError

    def accumulate(self, surface_id: str, seconds: float) -> float:
        raise NotImplementedError

    def evaporate(self, surface_id: str, seconds: float) -> float:
        raise NotImplementedError

    def publish(self, *, frame: int | None = None) -> int:
        raise NotImplementedError

    def wetness_of(self, surface_id: str) -> float:
        raise NotImplementedError

    def surface_of(self, surface_id: str) -> SurfaceState:
        raise NotImplementedError

    def material_of(self, surface_id: str) -> MaterialState:
        raise NotImplementedError

    def puddle_mask(self, surface_id: str) -> PuddleMask:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
