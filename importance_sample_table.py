"""Luminance driven importance sampling tables with alias lookups."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class TableError(ValueError):
    """Raised when a luminance grid, a region or a sample is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BuildReport:
    rows: int
    cols: int
    total: float
    version: int


@dataclass(frozen=True)
class AliasEntry:
    prob: float
    alias: int


class ImportanceSampleTable:
    """Two level sampling table built from an environment luminance grid."""

    def __init__(self, *, max_dimension: int = 256,
                 min_luminance: float = 1e-12) -> None:
        self._lock = threading.RLock()
        self._max_dimension = max_dimension
        self._min_luminance = min_luminance
        self._luminance: list = []
        self._row_sums: list = []
        self._total = 0.0
        self._alias: list = []
        self._version = 0
        self._stats = {"builds": 0, "rebuilds": 0, "updates": 0,
                       "row_rebuilds": 0, "samples": 0, "rejections": 0,
                       "version": 0, "rows": 0, "cols": 0}

    def build(self, luminance) -> BuildReport:
        raise NotImplementedError

    def sample(self, u: float, v: float) -> tuple:
        raise NotImplementedError

    def pdf(self, x: int, y: int) -> float:
        raise NotImplementedError

    def update_region(self, x0: int, y0: int, x1: int, y1: int,
                      values) -> int:
        raise NotImplementedError

    def rebuild(self) -> int:
        raise NotImplementedError

    def row_distribution(self) -> tuple:
        raise NotImplementedError

    def alias_table(self, row: int) -> tuple:
        raise NotImplementedError

    def version(self) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
