"""Deterministic procedural scatter placement over streamed chunks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ScatterError(ValueError):
    """Raised when a layer, a chunk request or a terrain upload is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ScatterPoint:
    x: float
    y: float
    z: float
    yaw_deg: float
    layer: str
    cell_x: int
    cell_y: int


@dataclass(frozen=True)
class ChunkResult:
    cx: int
    cy: int
    points: tuple
    clipped: int
    filtered: int


class ProceduralScatterPlanner:
    """Place vegetation and props per chunk from density layers and a seed."""

    def __init__(self, *, chunk_size: int = 32, cache_limit: int = 16,
                 chunk_point_cap: int = 512, max_layers: int = 16,
                 max_chunk_coord: int = 1_000_000) -> None:
        self._lock = threading.RLock()
        self._chunk_size = chunk_size
        self._cache_limit = cache_limit
        self._chunk_point_cap = chunk_point_cap
        self._max_layers = max_layers
        self._max_chunk_coord = max_chunk_coord
        self._seed = 0
        self._layers: dict = {}
        self._height = None
        self._slope = None
        self._chunks: dict = {}
        self._cache_order: list = []
        self._stats = {"seed": 0, "layers": 0, "cached": 0, "placed": 0,
                       "points": 0, "filtered": 0, "clipped": 0,
                       "evicted": 0, "rejected": 0}

    def set_seed(self, seed: int) -> int:
        raise NotImplementedError

    def add_layer(self, name: str, *, density: float, seed_offset: int = 0,
                  min_height: float | None = None,
                  max_height: float | None = None,
                  max_slope: float | None = None,
                  water_level: float | None = None,
                  exclusion: tuple | None = None) -> dict:
        raise NotImplementedError

    def remove_layer(self, name: str) -> dict:
        raise NotImplementedError

    def set_terrain(self, height, slope=None) -> int:
        raise NotImplementedError

    def place_chunk(self, cx: int, cy: int) -> ChunkResult:
        raise NotImplementedError

    def points_in_chunk(self, cx: int, cy: int) -> tuple:
        raise NotImplementedError

    def evict_chunk(self, cx: int, cy: int) -> bool:
        raise NotImplementedError

    def cached_chunks(self) -> tuple:
        raise NotImplementedError

    def chunk_of(self, x: float, y: float) -> tuple:
        raise NotImplementedError

    def set_cache_limit(self, limit: int) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
