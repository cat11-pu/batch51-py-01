"""Battle royale safe-zone shrinker: phase timeline, circle interpolation, damage settlement."""

from __future__ import annotations

import threading
from dataclasses import dataclass

DEFAULT_TICK_MS = 1000
DEFAULT_DAMAGE_PER_TICK = 1
DEFAULT_RESPAWN_PROTECT_MS = 5000
MAX_PHASES = 8
FULL_HEALTH = 100


class ZoneError(ValueError):
    """Raised when a zone timeline or a settlement request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Zone:
    """One circular safe zone at a point in the match timeline."""

    phase: int
    center_x: float
    center_y: float
    radius: float


@dataclass(frozen=True)
class ZonePhase:
    """One configured phase: a hold window followed by a shrink into this circle."""

    phase: int
    hold_ms: int
    shrink_ms: int
    center_x: float
    center_y: float
    radius: float


class BrZoneShrinker:
    """Advance the safe zone by match clock and settle out-of-zone damage."""

    def __init__(self, *, tick_ms: int = DEFAULT_TICK_MS,
                 damage_per_tick: int = DEFAULT_DAMAGE_PER_TICK,
                 respawn_protect_ms: int = DEFAULT_RESPAWN_PROTECT_MS) -> None:
        self.tick_ms = tick_ms
        self.damage_per_tick = damage_per_tick
        self.respawn_protect_ms = respawn_protect_ms
        self._lock = threading.RLock()

    def configure_phases(self, phases):
        """Install the phase table once and return the normalised phases."""
        raise NotImplementedError

    def advance(self, elapsed_ms):
        """Move the match clock forward and return the phase numbers crossed."""
        raise NotImplementedError

    def current_zone(self):
        """Return the circle that is in force for the current match clock."""
        raise NotImplementedError

    def next_zone(self):
        """Return the next configured circle, or None once the last shrink runs."""
        raise NotImplementedError

    def player_entered(self, player_id, *, x, y, at_ms=0):
        """Register a player on the battlefield at the given position."""
        raise NotImplementedError

    def player_respawn(self, player_id, *, x, y, at_ms):
        """Bring a player back after a revive or a late drop."""
        raise NotImplementedError

    def move_player(self, player_id, *, x, y):
        """Update a player position without touching health or timers."""
        raise NotImplementedError

    def damage_tick(self):
        """Settle every whole tick that elapsed since the previous settlement."""
        raise NotImplementedError

    def players_outside(self):
        """Return the living players currently outside the interpolated circle."""
        raise NotImplementedError

    def health_of(self, player_id):
        """Return the remaining health of one player."""
        raise NotImplementedError

    def snapshot(self):
        """Return a detached state dictionary for the running match."""
        raise NotImplementedError

    def restore(self, state):
        """Replace the running match with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self):
        """Return clock, phase and settlement counters."""
        raise NotImplementedError
