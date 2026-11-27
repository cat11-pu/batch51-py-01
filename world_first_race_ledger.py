"""Cross-realm world-first ledger: clock skew arbitration and invalidation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


DIFFICULTIES = ("normal", "heroic", "mythic")

STATUS_FIRST = "first"
STATUS_SUPERSEDED = "superseded"
STATUS_RECORDED = "recorded"
STATUS_INVALIDATED = "invalidated"

VERDICT_ACCEPTED = "accepted"
VERDICT_RECORDED = "recorded"
VERDICT_DUPLICATE = "duplicate"
VERDICT_INVALIDATED = "invalidated"

REASON_FIRST_CLAIM = "WORLD_FIRST_CLAIM"
REASON_DISPLACED = "WORLD_DISPLACED"
REASON_NOT_FASTER = "WORLD_NOT_FASTER"
REASON_DUPLICATE = "WORLD_DUPLICATE_EVIDENCE"

DEFAULT_CONFIG = {"skew_tolerance": 30}

STAT_KEYS = (
    "claims",
    "duplicates",
    "invalidations",
    "supersessions",
    "promotions",
)

SNAPSHOT_VERSION = 1


class RaceError(ValueError):
    """Refusal raised by the world-first ledger."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Claim:
    claim_id: int
    boss_id: str
    difficulty: str
    season: int
    server: str
    killed_at: int
    digest: str
    claim_seq: int
    status: str
    evidence_ok: bool


@dataclass(frozen=True)
class Adjudication:
    claim_id: int
    status: str
    first_claim_id: int | None
    changed: bool
    reason: str


class WorldFirstLedger:
    """Adjudicate cross-realm world-first claims per boss, difficulty and season."""

    def __init__(self, *, skew_tolerance: int = 30) -> None:
        self.skew_tolerance = skew_tolerance
        self._lock = threading.RLock()

    def claim(
        self,
        boss_id: str,
        difficulty: str,
        season: int,
        *,
        server: str,
        killed_at: int,
        digest: str,
        claim_seq: int,
    ) -> Adjudication:
        raise NotImplementedError

    def verify(self, claim_id: int, *, digest: str, ok: bool, reason: str = "") -> Adjudication:
        raise NotImplementedError

    def invalidate(self, claim_id: int, reason: str) -> Adjudication:
        raise NotImplementedError

    def first_of(self, boss_id: str, difficulty: str, season: int) -> Claim | None:
        raise NotImplementedError

    def history(self, boss_id: str, difficulty: str, season: int) -> tuple:
        raise NotImplementedError

    def claim_of(self, claim_id: int) -> Claim:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
