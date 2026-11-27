"""Take comping ledger: region placement, overlap priority, crossfade and undo stack."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class TakeError(ValueError):
    """Raised when a comping operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TakeInfo:
    """One recorded take lane."""

    take_id: str
    length_samples: int
    gain_db: float
    muted: bool


@dataclass(frozen=True)
class RegionInfo:
    """One region placed on the timeline."""

    region_id: int
    take_id: str
    start: int
    end: int
    at: int
    priority: int


@dataclass(frozen=True)
class Segment:
    """One resolved piece of the bounced track."""

    take_id: str
    start_sample: int
    end_sample: int
    gain_db: float
    fade_in: int
    fade_out: int


@dataclass(frozen=True)
class BounceResult:
    """Result of bouncing one span of the timeline."""

    segments: tuple
    total_samples: int
    silent_samples: int


class TakeCompingLedger:
    """Keep take lanes, placed regions and the undo stack for one comp."""

    def __init__(self, *, max_takes: int = 8, max_regions: int = 32,
                 crossfade_samples: int = 64) -> None:
        self.max_takes = max_takes
        self.max_regions = max_regions
        self.crossfade_samples = crossfade_samples
        self._lock = threading.RLock()
        self._takes: dict = {}
        self._regions: dict = {}
        self._next_region = 1
        self._undo: list = []
        self._counters = {
            "placed": 0,
            "removed": 0,
            "bounces": 0,
            "undone": 0,
        }

    def add_take(self, take_id: str, *, length_samples: int,
                 gain_db: float = 0.0, muted: bool = False) -> TakeInfo:
        raise NotImplementedError

    def place_region(self, take_id: str, *, start: int, end: int,
                     at: int, priority: int = 0) -> RegionInfo:
        raise NotImplementedError

    def place_batch(self, *, placements) -> tuple:
        raise NotImplementedError

    def set_priority(self, region_id: int, priority: int) -> RegionInfo:
        raise NotImplementedError

    def set_muted(self, take_id: str, muted: bool) -> TakeInfo:
        raise NotImplementedError

    def remove_region(self, region_id: int) -> RegionInfo:
        raise NotImplementedError

    def resolve_overlaps(self, *, start: int, end: int) -> tuple:
        raise NotImplementedError

    def bounce(self, *, start: int, end: int) -> BounceResult:
        raise NotImplementedError

    def undo(self) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
