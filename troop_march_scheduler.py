"""部队行军调度：路径耗时、同格到达排队、加速与中途召回。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

MARCH_STATES = ("marching", "returning", "resolved")


class MarchError(ValueError):
    """Raised when a march operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class March:
    troop_id: str
    player: str
    origin: tuple[int, int]
    target: tuple[int, int]
    speed: int
    troops: int
    departed_at: int
    arrive_at: int
    seq: int
    state: str


@dataclass(frozen=True)
class ArrivalResult:
    troop_id: str
    tile: tuple[int, int]
    order: int
    state: str
    at: int
    next_troop: str | None


@dataclass(frozen=True)
class RecallResult:
    troop_id: str
    state: str
    progress: float
    return_arrive_at: int
    stamina_refund: int


class TroopMarchScheduler:
    """Plan marches on the world grid and settle same-tile arrivals in order."""

    def __init__(self, *, max_marches_per_player: int = 5,
                 tile_capacity: int = 3) -> None:
        self.max_marches_per_player = max_marches_per_player
        self.tile_capacity = tile_capacity
        self._lock = threading.RLock()

    def dispatch(self, troop_id: str, player: str, *, origin: tuple[int, int],
                 target: tuple[int, int], speed: int, troops: int, at: int) -> March:
        """Send one troop and compute its absolute arrival timestamp."""
        raise NotImplementedError

    def eta(self, troop_id: str) -> int:
        """Absolute arrival timestamp of one march."""
        raise NotImplementedError

    def arrive_queue(self, tile: tuple[int, int], *, at: int) -> tuple[str, ...]:
        """Troops that have reached one tile by ``at`` in settlement order."""
        raise NotImplementedError

    def speed_up(self, troop_id: str, seconds: int) -> int:
        """Spend speed-up items on one march and return the minutes charged."""
        raise NotImplementedError

    def recall(self, troop_id: str, *, at: int) -> RecallResult:
        """Turn one march around and refund part of the stamina."""
        raise NotImplementedError

    def resolve_arrival(self, troop_id: str, *, at: int) -> ArrivalResult:
        """Settle one arrived march against the tile arrival queue."""
        raise NotImplementedError

    def march_of(self, troop_id: str) -> March | None:
        """Stored march record, or None when the troop id is unknown."""
        raise NotImplementedError

    def active_marches(self, player: str) -> tuple[str, ...]:
        """Troops of one player that are still marching, in departure order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep-copied scheduler state for restart recovery."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the scheduler state from a snapshot, rejecting malformed payloads."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters collected since the scheduler was created."""
        raise NotImplementedError
