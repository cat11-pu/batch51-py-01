"""Party merge handshake: two-leader confirmation, capacity checks, member migration."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class MergeError(ValueError):
    """Raised when a party merge operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PartyInfo:
    party_id: str
    leader: str
    members: tuple[str, ...]
    max_size: int
    level_min: int
    level_max: int


@dataclass(frozen=True)
class MergeRequest:
    request_id: str
    from_party: str
    into_party: str
    proposer: str
    state: str
    confirmed_by: tuple[str, ...]
    expires_at: float | None


@dataclass(frozen=True)
class MergeResult:
    request_id: str
    applied: bool
    state: str
    moved: tuple[str, ...]
    reason: str


class PartyMergeGuard:
    """Drive the handshake that folds one party into another without losing members."""

    def __init__(self, *, team_capacity: int = 16, request_ttl: float = 300.0,
                 clock=None) -> None:
        self.team_capacity = team_capacity
        self.request_ttl = request_ttl
        self._clock = clock
        self._lock = threading.RLock()

    def create_party(self, leader: str, *, max_size: int = 8, level_min: int = 1,
                     level_max: int = 999) -> PartyInfo:
        """Create a party led by one player and return its public shape."""
        raise NotImplementedError

    def add_member(self, party_id: str, player: str, *, level: int = 1,
                   in_instance: bool = False) -> PartyInfo:
        """Add one player to an unlocked party."""
        raise NotImplementedError

    def party_of(self, player: str) -> str | None:
        """Party id of one player, or None when unattached."""
        raise NotImplementedError

    def members_of(self, party_id: str) -> tuple[str, ...]:
        """Sorted member list of one party."""
        raise NotImplementedError

    def invite(self, party_id: str, player: str) -> str:
        """Create or reuse a pending join invitation and return its id."""
        raise NotImplementedError

    def pending_invites(self, player: str) -> tuple[str, ...]:
        """Active invitation ids of one player in ascending order."""
        raise NotImplementedError

    def propose_merge(self, from_party: str, into_party: str, proposer: str, *,
                      now: float | None = None) -> MergeRequest:
        """Open a merge request from one party into another."""
        raise NotImplementedError

    def confirm(self, request_id: str, leader: str, *,
                now: float | None = None) -> MergeRequest:
        """Record one leader confirmation and move to confirmed when both agree."""
        raise NotImplementedError

    def reject(self, request_id: str, leader: str, *, reason: str = "",
               now: float | None = None) -> MergeRequest:
        """Close one merge request without moving members."""
        raise NotImplementedError

    def apply(self, request_id: str, *, now: float | None = None) -> MergeResult:
        """Move the source party members into the target party exactly once."""
        raise NotImplementedError

    def status(self, request_id: str) -> MergeRequest:
        """Current public shape of one merge request."""
        raise NotImplementedError

    def disband(self, party_id: str) -> tuple[str, ...]:
        """Drop one party and release its members."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of parties, memberships, invites, requests and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters exposed to the party operations dashboard."""
        raise NotImplementedError
