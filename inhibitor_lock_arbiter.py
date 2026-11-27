"""Inhibitor lock arbitration.

Sleep, shutdown and idle inhibitors are tracked as lock records with a mode
(block or delay), a set of ``what`` flags, a holder and a priority.  Delay
locks only extend a shutdown countdown; block locks veto it.  Holders that
stop sending heartbeats are reclaimed on ``expire``.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

WHAT_FLAGS = ("idle", "handle-lid-switch", "handle-power-key", "shutdown",
              "sleep")
MODES = ("block", "delay")
STAT_KEYS = ("acquired", "merged", "released", "expired", "blocked_queries",
             "cancelled", "deadline_updates", "restores")


class InhibitorError(ValueError):
    """Refusal raised while acquiring, releasing or restoring inhibitors."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Inhibitor:
    """One inhibitor lock."""

    lock_id: str
    holder: str
    mode: str
    what: tuple
    delay: int
    priority: int
    reason: str
    acquired_at: int


@dataclass(frozen=True)
class Arbitration:
    """The answer to one arbitration query."""

    status: str
    blockers: tuple
    delayers: tuple
    delay_total: int
    deadline: int | None


class InhibitorLockArbiter:
    """Arbitrate block and delay inhibitors for sleep, shutdown and idle."""

    def __init__(self, *, max_locks: int = 256,
                 max_locks_per_holder: int = 8,
                 delay_cap: int = 300,
                 holder_ttl: int = 30) -> None:
        self.max_locks = max_locks
        self.max_locks_per_holder = max_locks_per_holder
        self.delay_cap = delay_cap
        self.holder_ttl = holder_ttl
        self._lock = threading.RLock()
        self._locks = {}
        self._holders = {}
        self._countdown = None
        self._next_id = 1
        self._stats = {key: 0 for key in STAT_KEYS}

    def acquire(self, holder: str, what, *, mode: str = "block",
                delay: int = 0, priority: int = 0, reason: str = "",
                now: int = 0) -> Inhibitor:
        """Take an inhibitor lock for ``holder``."""
        raise NotImplementedError

    def release(self, lock_id: str) -> bool:
        """Release one lock and report whether it existed."""
        raise NotImplementedError

    def heartbeat(self, holder: str, *, now: int = 0) -> int:
        """Refresh the holder lease and return how many locks it owns."""
        raise NotImplementedError

    def mark_holder_gone(self, holder: str) -> int:
        """Mark a holder as gone without reclaiming its locks yet."""
        raise NotImplementedError

    def expire(self, *, now: int = 0) -> int:
        """Reclaim locks whose holder is gone or whose lease ran out."""
        raise NotImplementedError

    def query(self, what, *, now: int = 0) -> Arbitration:
        """Return the arbitration result for the requested ``what`` flags."""
        raise NotImplementedError

    def begin_shutdown(self, *, now: int = 0, grace: int = 60) -> dict:
        """Start a shutdown countdown and return its state."""
        raise NotImplementedError

    def countdown(self) -> dict:
        """Return the current shutdown countdown state."""
        raise NotImplementedError

    def lock_state(self, lock_id: str):
        """Return one lock record or None when it is unknown."""
        raise NotImplementedError

    def locks(self, *, holder: str | None = None) -> tuple:
        """Return lock records in acquisition order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of locks, holders and countdown."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
