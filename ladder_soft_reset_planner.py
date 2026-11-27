"""Season soft reset: rating compression toward baseline, placement matches, idempotent batches."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class LadderError(ValueError):
    """Raised when a ladder reset or placement operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PlayerState:
    player: str
    season: str
    prev_rating: int
    rating: int
    uncertainty: int
    provisional: bool
    played: int
    needed: int
    matches_last_season: int


class SoftResetPlanner:
    """Plan and apply a season soft reset, then track placement progress."""

    def __init__(self, *, baseline: int = 1500, keep_bps: int = 5000,
                 placement_matches: int = 10, rating_floor: int = 800,
                 rating_ceiling: int = 2000, placement_delta: int = 25,
                 uncertainty_start: int = 100, uncertainty_step: int = 100,
                 uncertainty_cap: int = 300, uncertainty_decay: int = 40,
                 uncertainty_floor: int = 0) -> None:
        self.baseline = baseline
        self.keep_bps = keep_bps
        self.placement_matches = placement_matches
        self.rating_floor = rating_floor
        self.rating_ceiling = rating_ceiling
        self.placement_delta = placement_delta
        self.uncertainty_start = uncertainty_start
        self.uncertainty_step = uncertainty_step
        self.uncertainty_cap = uncertainty_cap
        self.uncertainty_decay = uncertainty_decay
        self.uncertainty_floor = uncertainty_floor
        self._lock = threading.RLock()

    def register_player(self, player: str, rating: int, *,
                        matches_last_season: int = 0) -> PlayerState:
        """Register a player with a rating inside the configured bounds."""
        raise NotImplementedError

    def plan_batch(self, season: str, players=None) -> str:
        """Build a reset batch for a new season and return its identifier."""
        raise NotImplementedError

    def apply(self, batch_id: str, *, players=None) -> dict:
        """Apply the compression of one batch and report how many players moved."""
        raise NotImplementedError

    def record_placement(self, player: str, *, won: bool,
                         completed: bool = True, now: str | None = None) -> int:
        """Record one placement match result and return the resulting rating."""
        raise NotImplementedError

    def rating_of(self, player: str) -> int:
        """Current rating of one player."""
        raise NotImplementedError

    def uncertainty_of(self, player: str) -> int:
        """Current rating uncertainty of one player."""
        raise NotImplementedError

    def provisional_of(self, player: str) -> bool:
        """Whether the player is still in placement."""
        raise NotImplementedError

    def progress(self, player: str) -> dict:
        """Return played, needed and remaining placement matches."""
        raise NotImplementedError

    def state_of(self, player: str) -> PlayerState:
        """Full ladder state of one player."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of season, batches, player states and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the counters exposed to the season dashboard."""
        raise NotImplementedError
