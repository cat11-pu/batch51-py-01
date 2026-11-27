"""Abandon penalty ledger: leave kinds, grace reconnect and settlement ladder."""

from __future__ import annotations

import threading
from dataclasses import dataclass


KIND_VOLUNTARY = "voluntary"
KIND_DISCONNECT = "disconnect"
KIND_SERVER_FAULT = "server_fault"
KINDS = (KIND_VOLUNTARY, KIND_DISCONNECT, KIND_SERVER_FAULT)

POINTS_BY_KIND = {
    KIND_VOLUNTARY: 3,
    KIND_DISCONNECT: 1,
    KIND_SERVER_FAULT: 0,
}

TIER_CLEAN = "clean"
TIER_WATCH = "watch"
TIER_RESTRICTED = "restricted"
TIER_SUSPENDED = "suspended"

TIER_LADDER = (
    (6, TIER_SUSPENDED, 1800),
    (4, TIER_RESTRICTED, 900),
    (2, TIER_WATCH, 300),
    (0, TIER_CLEAN, 0),
)

DEFAULT_CONFIG = {
    "grace_window": 90,
    "provisional_cooldown": 300,
    "max_points": 12,
    "daily_decay": 1,
}

STAT_KEYS = (
    "leaves",
    "reconnects",
    "settlements",
    "duplicate_settlements",
    "waived_matches",
    "decayed_points",
)

SNAPSHOT_VERSION = 1


class PenaltyError(ValueError):
    """Refusal raised by the abandon penalty ledger."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LeaveRecord:
    match_id: str
    player_id: str
    kind: str
    left_at: int
    reconnected_at: int | None = None
    exempt_reason: str | None = None


@dataclass(frozen=True)
class ReconnectOutcome:
    accepted: bool
    within_grace: bool
    cooldown_cleared: bool
    grace_remaining: int


@dataclass(frozen=True)
class Settlement:
    match_id: str
    settled_at: int
    awards: tuple
    duplicate: bool


@dataclass(frozen=True)
class WaiveResult:
    match_id: str
    reason: str
    rolled_back: tuple
    already_waived: bool


@dataclass(frozen=True)
class PlayerStanding:
    player_id: str
    points: int
    tier: str
    queue_block_until: int | None


class AbandonPenaltyLedger:
    """Accumulate abandon points per player and map them onto queue cooldowns."""

    def __init__(
        self,
        *,
        grace_window: int = 90,
        provisional_cooldown: int = 300,
        max_points: int = 12,
        daily_decay: int = 1,
    ) -> None:
        self.grace_window = grace_window
        self.provisional_cooldown = provisional_cooldown
        self.max_points = max_points
        self.daily_decay = daily_decay
        self._lock = threading.RLock()

    def mark_leave(self, match_id: str, player_id: str, kind: str, *, at: int) -> LeaveRecord:
        raise NotImplementedError

    def mark_reconnect(self, match_id: str, player_id: str, *, at: int) -> ReconnectOutcome:
        raise NotImplementedError

    def settle_match(self, match_id: str, *, at: int) -> Settlement:
        raise NotImplementedError

    def waive_match(self, match_id: str, reason: str, *, at: int) -> WaiveResult:
        raise NotImplementedError

    def penalty_of(self, player_id: str, *, at: int | None = None) -> int:
        raise NotImplementedError

    def tier_of(self, player_id: str, *, at: int | None = None) -> str:
        raise NotImplementedError

    def queue_block_until(self, player_id: str, *, at: int | None = None) -> int | None:
        raise NotImplementedError

    def standing_of(self, player_id: str, *, at: int | None = None) -> PlayerStanding:
        raise NotImplementedError

    def records_for(self, match_id: str) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
