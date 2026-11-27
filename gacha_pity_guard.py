"""Gacha pity accounting: soft/hard pity, pool-group carryover, draw audit."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GachaError(ValueError):
    """Raised when a gacha operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PoolView:
    pool_id: str
    group: str
    base_rate_bps: int
    hard_pity: int
    soft_pity: int
    step_bps: int
    counter: int
    total_pulls: int
    golds: int
    pity_triggers: int


@dataclass(frozen=True)
class DrawOutcome:
    pool_id: str
    index: int
    roll: int
    rate_bps: int
    natural: bool
    pity: bool
    gold: bool
    counter_after: int


@dataclass(frozen=True)
class TenPullReport:
    pool_id: str
    outcomes: tuple[DrawOutcome, ...]
    golds: int
    pity_triggers: int
    counter_after: int


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    pool_id: str
    group: str
    kind: str
    roll: int | None
    gold: bool
    pity: bool
    counter_before: int
    counter_after: int


class GachaPityGuard:
    """Keep per-pool pity water levels and adjudicate every pull."""

    def __init__(self, *, max_pools: int = 16, max_audit: int = 256) -> None:
        self.max_pools = max_pools
        self.max_audit = max_audit
        self._lock = threading.RLock()

    def register_pool(self, pool_id: str, *, group: str | None = None,
                      base_rate_bps: int = 60, hard_pity: int = 90,
                      soft_pity: int = 75, step_bps: int = 600) -> PoolView:
        """Register one banner and return its opening view."""
        raise NotImplementedError

    def pool_view(self, pool_id: str) -> PoolView:
        """Return the immutable view of one banner."""
        raise NotImplementedError

    def current_counter(self, pool_id: str) -> int:
        """Return the pity water level used by the next pull."""
        raise NotImplementedError

    def rate_bps(self, pool_id: str) -> int:
        """Effective gold rate of the next pull, in basis points."""
        raise NotImplementedError

    def pity_left(self, pool_id: str) -> int:
        """Pulls still needed before the hard pity line."""
        raise NotImplementedError

    def draw(self, pool_id: str, *, roll: int) -> DrawOutcome:
        """Adjudicate one single pull from an explicit roll value."""
        raise NotImplementedError

    def draw_ten(self, pool_id: str, *, rolls) -> TenPullReport:
        """Adjudicate one ten-pull batch atomically."""
        raise NotImplementedError

    def switch_pool(self, source_pool: str, target_pool: str) -> int:
        """Carry the pity water level inside one pool group."""
        raise NotImplementedError

    def audit(self, pool_id: str | None = None) -> list[AuditEntry]:
        """Return audit entries in sequence order, optionally scoped."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of pools, audit trail and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return counters exposed to the operations dashboard."""
        raise NotImplementedError
