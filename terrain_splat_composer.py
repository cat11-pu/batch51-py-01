"""Compose terrain splat weights into a fixed number of sampled layers."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SplatError(ValueError):
    """Raised when a layer table, a weight or a tile request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class WeightedLayer:
    layer: str
    index: int
    weight: float


@dataclass(frozen=True)
class TileResult:
    x0: int
    y0: int
    x1: int
    y1: int
    pixels: int
    clipped: int
    merged: int
    residency_version: int
    slots: tuple


class TerrainSplatComposer:
    """Blend multi layer terrain weights into sampled layer indices."""

    def __init__(self, *, max_layers: int = 8, max_layers_per_pixel: int = 4,
                 max_slots: int = 8, max_stored_pixels: int = 4096,
                 grid_limit: int = 1024,
                 merge_distance: float = 64.0) -> None:
        self._lock = threading.RLock()
        self._max_layers = max_layers
        self._max_layers_per_pixel = max_layers_per_pixel
        self._max_slots = max_slots
        self._max_stored_pixels = max_stored_pixels
        self._grid_limit = grid_limit
        self._merge_distance = merge_distance
        self._layers: tuple = ()
        self._weights: dict = {}
        self._tiles: dict = {}
        self._composed: dict = {}
        self._residency: dict = {}
        self._residency_version = 0
        self._mutation = 0
        self._stats = {"layers": 0, "pixels": 0, "tiles": 0,
                       "composed_pixels": 0, "clipped_pixels": 0,
                       "merged_pixels": 0, "rejections": 0,
                       "residency_version": 0, "version": 0}

    def set_layers(self, names) -> tuple:
        raise NotImplementedError

    def write_weight(self, x: int, y: int, layer: str, weight: float) -> float:
        raise NotImplementedError

    def clear_pixel(self, x: int, y: int) -> bool:
        raise NotImplementedError

    def compose_tile(self, x0: int, y0: int, x1: int, y1: int, *,
                     distance: float | None = None) -> TileResult:
        raise NotImplementedError

    def sample_layers(self, x: int, y: int) -> tuple:
        raise NotImplementedError

    def set_residency(self, names) -> dict:
        raise NotImplementedError

    def residency_map(self) -> dict:
        raise NotImplementedError

    def set_distance_merge(self, threshold: float) -> float:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
