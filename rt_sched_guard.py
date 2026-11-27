"""Real time scheduling admission control.

The guard keeps a tree of budget groups, admits real time reservations while
the group and every ancestor still have room, queues the overflow when asked
to, and demotes a process that tripped the watchdog back to the normal policy
with a cooldown.  Reservations are released exactly once.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

RT_POLICIES = ("fifo", "rr")
OTHER_POLICY = "other"
DEFAULT_PERIOD_US = 1_000_000


class RtSchedError(ValueError):
    """Refusal raised by the scheduling guard."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class GroupBudget:
    name: str
    limit_us: int
    used_us: int
    available_us: int
    over_us: int


@dataclass(frozen=True)
class Admission:
    pid: int
    group: str
    policy: str
    budget_us: int
    status: str
    sequence: int


@dataclass(frozen=True)
class Demotion:
    pid: int
    policy: str
    reason: str
    released_us: int
    cooldown_until_us: int


class RtSchedGuard:
    """Admit, queue, release and demote real time scheduling requests."""

    def __init__(self, *, period_us: int = DEFAULT_PERIOD_US,
                 watchdog_cooldown_us: int = 5_000_000) -> None:
        self.period_us = period_us
        self.watchdog_cooldown_us = watchdog_cooldown_us
        self._lock = threading.RLock()
        self._groups = {}
        self._reservations = {}
        self._queue = []
        self._cooldown = {}
        self._sequence = 0
        self._stats = {"groups": 0, "admitted": 0, "queued": 0, "rejected": 0,
                       "released": 0, "demotions": 0, "restores": 0}

    def create_group(self, name: str, *, parent: str | None = None,
                     budget_us: int) -> GroupBudget:
        """Create a budget group below ``parent`` and return its budget."""
        raise NotImplementedError

    def group_budget(self, name: str) -> GroupBudget:
        """Return the current budget view of ``name``."""
        raise NotImplementedError

    def set_group_budget(self, name: str, budget_us: int) -> GroupBudget:
        """Replace the limit of ``name`` and return the new budget view."""
        raise NotImplementedError

    def admit(self, pid: int, *, group: str, policy: str, budget_us: int,
              now_us: int, allow_queue: bool = False) -> Admission:
        """Admit a real time request, queue it, or refuse it."""
        raise NotImplementedError

    def release(self, pid: int, *, now_us: int) -> int:
        """Release the reservation of ``pid`` and return the freed budget."""
        raise NotImplementedError

    def reservation_of(self, pid: int) -> Admission | None:
        """Return the active admission of ``pid`` or ``None``."""
        raise NotImplementedError

    def admissions(self) -> tuple:
        """Return every active admission ordered by sequence."""
        raise NotImplementedError

    def queued(self) -> tuple:
        """Return the queued requests in arrival order."""
        raise NotImplementedError

    def pump(self, now_us: int) -> tuple:
        """Promote every queued request that now fits, keeping FIFO order."""
        raise NotImplementedError

    def watchdog(self, pid: int, *, now_us: int,
                 reason: str = "overrun") -> Demotion:
        """Demote ``pid`` to the normal policy and start its cooldown."""
        raise NotImplementedError

    def cooldown_until(self, pid: int) -> int:
        """Return the absolute cooldown deadline of ``pid`` (0 when none)."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the whole state."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
