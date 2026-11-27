"""Survival needs ledger: decay, offline catch-up, effect stack, dying state machine."""

from __future__ import annotations

import threading
from dataclasses import dataclass

NEED_NAMES = ("hunger", "thirst", "warmth")
NEED_CAP = 100
REVIVE_FLOOR = 25
DEFAULT_TICK_MS = 1000
DEFAULT_DECAY = {"hunger": 1, "thirst": 2, "warmth": 1}


class SurvivalError(ValueError):
    """Raised when a survival settlement request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Effect:
    """One timed modifier applied to a single need."""

    effect_id: str
    need: str
    multiplier: float
    priority: int
    expires_at_ms: int


class SurvivalNeedsLedger:
    """Track per-character survival needs and settle them from server time."""

    def __init__(self, *, decay=None, tick_ms: int = DEFAULT_TICK_MS,
                 cap: int = NEED_CAP) -> None:
        self.decay = dict(DEFAULT_DECAY if decay is None else decay)
        self.tick_ms = tick_ms
        self.cap = cap
        self._lock = threading.RLock()

    def register(self, character_id, *, needs=None, at_ms=0):
        """Create a character ledger and return its starting needs."""
        raise NotImplementedError

    def consume(self, character_id, need, amount):
        """Restore one need and return the value after clamping."""
        raise NotImplementedError

    def apply_effect(self, character_id, effect):
        """Attach a timed modifier and return the normalised effect."""
        raise NotImplementedError

    def tick(self, character_id, at_ms):
        """Settle natural decay up to the given server time."""
        raise NotImplementedError

    def offline_catchup(self, character_id, *, from_ms, to_ms):
        """Settle a missed window that the character spent offline."""
        raise NotImplementedError

    def state_of(self, character_id):
        """Return ``normal`` or ``dying`` for one character."""
        raise NotImplementedError

    def needs_of(self, character_id):
        """Return a detached mapping of the three need values."""
        raise NotImplementedError

    def effects_of(self, character_id):
        """Return the live effect stack ordered by need and effect id."""
        raise NotImplementedError

    def revive(self, character_id, *, at_ms):
        """Lift a dying character back to the revive floor."""
        raise NotImplementedError

    def snapshot(self):
        """Return a detached state dictionary for the whole ledger."""
        raise NotImplementedError

    def restore(self, state):
        """Replace the ledger with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self):
        """Return settlement counters for the ledger."""
        raise NotImplementedError
