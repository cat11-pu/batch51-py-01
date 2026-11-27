"""阵营声望台账：递减收益、每日上限、阈值解锁与敌对惩罚下限。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

FACTION_LEVELS = (0, 500, 1500, 3000, 6000)
DECAY_TABLE = (1.0, 0.75, 0.5, 0.25)
DEFAULT_DAY = 86400


class ReputationError(ValueError):
    """Raised when a reputation operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AwardResult:
    player: str
    faction: str
    requested: int
    granted: int
    multiplier: float
    points: int
    level: int
    duplicate: bool
    capped: bool


@dataclass(frozen=True)
class PenalizeResult:
    player: str
    faction: str
    requested: int
    applied: int
    points: int
    level: int
    floored: bool


@dataclass(frozen=True)
class TransferResult:
    player: str
    source: str
    target: str
    requested: int
    moved: int
    converted: int
    source_points: int
    target_points: int


class FactionReputationLedger:
    """Track per-player reputation toward registered factions and its derived level."""

    def __init__(self, *, daily_cap: int = 1200,
                 levels: tuple[int, ...] = FACTION_LEVELS,
                 decay: tuple[float, ...] = DECAY_TABLE,
                 day: int = DEFAULT_DAY) -> None:
        self.daily_cap = daily_cap
        self.levels = tuple(levels)
        self.decay = tuple(decay)
        self.day = day
        self._lock = threading.RLock()

    def register_faction(self, faction: str, *, hostiles=()) -> None:
        """Register a faction and the factions it is hostile toward."""
        raise NotImplementedError

    def award(self, player: str, faction: str, amount: int, *, source: str,
              at: int, event_id: str) -> AwardResult:
        """Award reputation from one source, applying decay and the daily cap."""
        raise NotImplementedError

    def penalize(self, player: str, faction: str, amount: int, *, at: int) -> PenalizeResult:
        """Remove reputation without dropping under the current level floor."""
        raise NotImplementedError

    def points_of(self, player: str, faction: str) -> int:
        """Stored reputation points of one player toward one faction."""
        raise NotImplementedError

    def level_of(self, player: str, faction: str) -> int:
        """Level index derived from the stored points and the threshold table."""
        raise NotImplementedError

    def daily_used(self, player: str, *, at: int) -> int:
        """Reputation already granted to the player inside the server day of ``at``."""
        raise NotImplementedError

    def unlock_check(self, player: str, faction: str) -> tuple[int, ...]:
        """Levels unlocked since the previous check, claiming them for this call."""
        raise NotImplementedError

    def transfer(self, player: str, source: str, target: str, amount: int, *,
                 at: int) -> TransferResult:
        """Move reputation between factions, subject to the target level ceiling."""
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
