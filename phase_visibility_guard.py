"""Quest phase visibility: exclusive groups, atomic switches, party phase sync."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PhaseError(ValueError):
    """Raised when a phase visibility operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PhaseSpec:
    phase_id: str
    quest_id: str
    group: str
    priority: int


@dataclass(frozen=True)
class Transition:
    player: str
    applied: bool
    active: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class SyncResult:
    leader: str
    accepted: tuple[str, ...]
    rejected: tuple[str, ...]
    reason: str


class PhaseVisibilityGuard:
    """Track which quest phases a player holds and which world objects they see."""

    def __init__(self, *, max_phases: int = 256, max_objects: int = 4096,
                 cache_size: int = 256) -> None:
        self.max_phases = max_phases
        self.max_objects = max_objects
        self.cache_size = cache_size
        self._lock = threading.RLock()

    def register_phase(self, phase_id: str, *, quest_id: str, group: str,
                       priority: int = 0) -> PhaseSpec:
        """Define one quest phase and its exclusive group."""
        raise NotImplementedError

    def register_object(self, object_id: str, phase_id: str | None) -> None:
        """Bind one world object to a phase, or to every player when phase is None."""
        raise NotImplementedError

    def set_map(self, player: str, map_id: str) -> None:
        """Record the map a player currently stands on."""
        raise NotImplementedError

    def set_progress(self, player: str, quest_id: str, step: int) -> None:
        """Record one quest step of a player for party sync comparisons."""
        raise NotImplementedError

    def enter_phase(self, player: str, phase_id: str) -> Transition:
        """Add one phase, replacing a lower-priority phase of the same group."""
        raise NotImplementedError

    def leave_phase(self, player: str, phase_id: str) -> Transition:
        """Drop one active phase and hide its objects again."""
        raise NotImplementedError

    def switch_phase(self, player: str, phase_id: str) -> Transition:
        """Atomically replace every active phase of the target group."""
        raise NotImplementedError

    def visible_to(self, player: str, object_id: str) -> bool:
        """Whether one player may currently see one world object."""
        raise NotImplementedError

    def sync_party_phase(self, leader: str, members) -> SyncResult:
        """Push the leader phase set to party members on the same map and progress."""
        raise NotImplementedError

    def active_phases(self, player: str) -> tuple[str, ...]:
        """Active phases of one player in lexicographic order."""
        raise NotImplementedError

    def remove_object(self, object_id: str) -> bool:
        """Delete one world object and invalidate any cached visibility answer."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of phases, objects, player state and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters exposed to the world operations dashboard."""
        raise NotImplementedError
