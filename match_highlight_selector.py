"""Match highlights: event dedup, window merging, per-player and per-match quotas."""

from __future__ import annotations

import threading
from dataclasses import dataclass


EVENT_KINDS = ("multi_kill", "low_hp_clash", "objective")


class HighlightError(ValueError):
    """Raised when a highlight selection operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MatchInfo:
    match_id: str
    end_at: float
    merge_gap: float


@dataclass(frozen=True)
class Clip:
    clip_id: str
    match_id: str
    start: float
    end: float
    priority: int
    players: tuple[str, ...]
    events: tuple[str, ...]
    streak: int


class HighlightSelector:
    """Turn a raw match event stream into ranked highlight clips."""

    def __init__(self, *, per_player_cap: int = 2, per_match_cap: int = 12,
                 streak_window: float = 5.0) -> None:
        self.per_player_cap = per_player_cap
        self.per_match_cap = per_match_cap
        self.streak_window = streak_window
        self._lock = threading.RLock()

    def open_match(self, match_id: str, *, end_at: float,
                   merge_gap: float = 2.5) -> MatchInfo:
        """Register one match and the timeline boundary of its event stream."""
        raise NotImplementedError

    def ingest(self, match_id: str, event_id: str, *, kind: str, player: str,
               at: float, priority: int = 0, duration: float = 1.0) -> bool:
        """Record one event, returning False when the event id was already seen."""
        raise NotImplementedError

    def merge_window(self, match_id: str, *, gap: float | None = None) -> tuple[Clip, ...]:
        """Merge adjacent events into clips and enforce the stored quotas."""
        raise NotImplementedError

    def select(self, match_id: str, *, limit: int = 5) -> tuple[Clip, ...]:
        """Return the highest priority clips of one match up to limit."""
        raise NotImplementedError

    def clips_of(self, match_id: str) -> tuple[Clip, ...]:
        """Stored clips of one match in start order."""
        raise NotImplementedError

    def export(self, match_id: str) -> dict:
        """Plain dictionary form of the clips for the highlight feed."""
        raise NotImplementedError

    def quota_of(self, player: str) -> int:
        """Number of stored clips that involve one player."""
        raise NotImplementedError

    def remove_event(self, match_id: str, event_id: str) -> bool:
        """Delete one event and force the clips of that match to be rebuilt."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of matches, events, clips and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters exposed to the highlight operations dashboard."""
        raise NotImplementedError
