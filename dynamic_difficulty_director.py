"""Dynamic difficulty director: metric windows, tier hysteresis, in-fight freeze."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class DirectorError(ValueError):
    """Raised when a difficulty decision cannot be taken."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Adjustment:
    seq: int
    from_tier: int
    to_tier: int
    changed: bool
    reason: str
    stress_bps: int
    at_ms: int
    window: dict


class DifficultyDirector:
    """Raise or lower encounter difficulty from failure metrics with hysteresis."""

    DEFAULT_SCALING = ((10000, 10000), (11500, 11000),
                       (13000, 12000), (15000, 13500))

    def __init__(self, *, scaling=None, up_threshold_bps: int = 12000,
                 down_threshold_bps: int = 4000, hysteresis_bps: int = 1500,
                 min_interval_ms: int = 30000, max_tier: int = 3,
                 max_history: int = 8) -> None:
        self.scaling = tuple(scaling) if scaling else self.DEFAULT_SCALING
        self.up_threshold_bps = up_threshold_bps
        self.down_threshold_bps = down_threshold_bps
        self.hysteresis_bps = hysteresis_bps
        self.min_interval_ms = min_interval_ms
        self.max_tier = max_tier
        self.max_history = max_history
        self._lock = threading.RLock()

    def observe(self, *, deaths: int = 0, wipes: int = 0, kills: int = 0,
                kill_ms: int = 0, healing: int = 0, members: int = 4,
                at_ms: int = 0) -> dict:
        """Add one encounter observation to the statistic window."""
        raise NotImplementedError

    def metrics(self) -> dict:
        """Current window: deaths, wipes, kills, kill_ms_avg, healing, members."""
        raise NotImplementedError

    def tier_of(self) -> int:
        """Current difficulty tier."""
        raise NotImplementedError

    def coefficients_of(self, tier: int | None = None) -> tuple[int, int]:
        """Monster hp and damage coefficients of a tier."""
        raise NotImplementedError

    def evaluate_adjust(self, at_ms: int = 0) -> Adjustment:
        """Judge the window and move the tier when the hysteresis gate allows it."""
        raise NotImplementedError

    def freeze(self, reason: str, *, at_ms: int = 0) -> bool:
        """Freeze adjustments for boss fights or scripted events."""
        raise NotImplementedError

    def unfreeze(self, *, at_ms: int = 0) -> bool:
        """Release the freeze so the next evaluation can move the tier again."""
        raise NotImplementedError

    def is_frozen(self) -> bool:
        """Whether adjustments are currently frozen."""
        raise NotImplementedError

    def reason_of(self, tier: int | None = None) -> str:
        """Reason recorded for the current tier or for the given tier."""
        raise NotImplementedError

    def history_of(self, limit: int | None = None) -> list[Adjustment]:
        """Actual tier changes in ascending sequence order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of tier, window, history, reasons, freeze flag and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return observations, evaluations, adjustments and freezes."""
        raise NotImplementedError
