"""Build 2D shadow fan sectors for point and cone lights from occluder segments."""

from __future__ import annotations

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


class OccluderFanBuilder:
    """Collect occluder segments and derive closed shadow sectors per light."""

    def __init__(self, *, merge_epsilon_deg: float = 1e-6,
                 vertex_budget: int = 64, max_segments: int = 256) -> None:
        self._lock = threading.RLock()
        self._merge_epsilon = float(merge_epsilon_deg)
        self._vertex_budget = vertex_budget
        self._max_segments = max_segments
        self._lights: dict = {}
        self._segments: dict = {}
        self._fans: dict = {}
        self._revision = 0
        self._stats = {"lights": 0, "segments": 0, "builds": 0, "merged": 0,
                       "culled": 0, "dropped": 0, "skipped_range": 0,
                       "invalidations": 0, "vertex_budget": vertex_budget}

    def add_light(self, light_id: str, x: float, y: float, radius: float, *,
                  facing_deg: float | None = None,
                  cone_deg: float | None = None) -> Light:
        raise NotImplementedError

    def add_segment(self, seg_id: str, x1: float, y1: float,
                    x2: float, y2: float) -> Segment:
        raise NotImplementedError

    def remove_segment(self, seg_id: str) -> Segment:
        raise NotImplementedError

    def set_vertex_budget(self, budget: int) -> int:
        raise NotImplementedError

    def build_fan(self, light_id: str) -> Fan:
        raise NotImplementedError

    def fan_vertices(self, light_id: str) -> tuple:
        raise NotImplementedError

    def sectors(self, light_id: str) -> tuple:
        raise NotImplementedError

    def coverage(self, light_id: str) -> float:
        raise NotImplementedError

    def invalidate(self, light_id: str | None = None) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
