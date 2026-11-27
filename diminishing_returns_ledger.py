"""重复行为递减台账：收益桶衰减、周期重置与队伍共享系数。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

DEFAULT_FLOOR = 0.25
DEFAULT_STEP = 0.15
DEFAULT_WINDOW = 600
DEFAULT_CYCLE = 86400


class DiminishingError(ValueError):
    """Raised when a diminishing-returns operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BucketState:
    template: str
    player: str
    count: int
    multiplier: float
    window_start: int
    cycle: int
    party: str | None


@dataclass(frozen=True)
class RecordResult:
    event_id: str
    template: str
    player: str
    count: int
    multiplier: float
    duplicate: bool


class DiminishingReturnsLedger:
    """Decay the yield of repeated kills and gathers per target template and party."""

    def __init__(self, *, floor: float = DEFAULT_FLOOR, step: float = DEFAULT_STEP,
                 window: int = DEFAULT_WINDOW, cycle: int = DEFAULT_CYCLE,
                 max_buckets: int = 512, max_history: int = 64) -> None:
        self.floor = floor
        self.step = step
        self.window = window
        self.cycle = cycle
        self.max_buckets = max_buckets
        self.max_history = max_history
        self._lock = threading.RLock()

    def record(self, event_id: str, *, template: str, player: str, at: int,
               instance: str | None = None, party: str | None = None) -> RecordResult:
        """Record one kill or gather event and return the resulting multiplier."""
        raise NotImplementedError

    def multiplier(self, template: str, player: str, *, at: int) -> float:
        """Current decay multiplier for one target template and player."""
        raise NotImplementedError

    def bucket_state(self, template: str, player: str, *, at: int) -> BucketState:
        """Snapshot of one decay bucket at the given moment."""
        raise NotImplementedError

    def reset_cycle(self, *, at: int) -> int:
        """Clear every bucket whose cycle is older than the cycle of ``at``."""
        raise NotImplementedError

    def share_with_party(self, player: str, party: str) -> int:
        """Put one player into a party and return the resulting member count."""
        raise NotImplementedError

    def party_of(self, player: str) -> str | None:
        """Party currently joined by one player, or None."""
        raise NotImplementedError

    def leave_party(self, player: str) -> bool:
        """Remove one player from its party, keeping the personal bucket."""
        raise NotImplementedError

    def prune(self, *, at: int) -> int:
        """Drop events that have fallen out of the decay window."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep-copied ledger state for restart recovery."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the ledger state from a snapshot, rejecting malformed payloads."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters collected since the ledger was created."""
        raise NotImplementedError
