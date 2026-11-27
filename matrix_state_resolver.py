"""Federated room state: event DAG ingest, deterministic state resolution, soft failure."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
SUPPORTED_VERSIONS = ("9", "10", "11")
DEFAULT_POWER = {
    "users_default": 0,
    "events": {},
    "events_default": 0,
    "state_default": 50,
    "kick": 50,
    "ban": 50,
    "invite": 0,
}


class FederationError(ValueError):
    """Raised when a federation state operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class StateEntry:
    type: str
    state_key: str
    event_id: str
    sender: str


@dataclass(frozen=True)
class IngestResult:
    event_id: str
    status: str
    soft_failed: bool
    depth: int


@dataclass(frozen=True)
class AuthResult:
    allowed: bool
    reason: str
    required_power: int
    sender_power: int


class MatrixStateResolver:
    """Keep one federated room's event DAG, current state and auth chain."""

    def __init__(self, room_id: str, *, room_version: str = "9",
                 max_pending: int = 256, max_depth: int = 1024,
                 creator: str = "@admin:hs") -> None:
        self.room_id = room_id
        self.creator = creator
        self.max_pending = max_pending
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._version = room_version
        self._events: dict[str, dict] = {}
        self._pending: dict[str, dict] = {}
        self._heads: set[str] = set()
        self._state: dict[tuple[str, str], str] = {}
        self._soft_failed: set[str] = set()
        self._rejected: set[str] = set()
        self._stats = {
            "accepted": 0,
            "pending": 0,
            "rejected": 0,
            "duplicates": 0,
            "soft_failed": 0,
            "backfilled": 0,
            "upgraded": 0,
        }

    def ingest_event(self, event: dict) -> IngestResult:
        raise NotImplementedError

    def resolve_state(self) -> tuple[StateEntry, ...]:
        raise NotImplementedError

    def authorize(self, event: dict) -> AuthResult:
        raise NotImplementedError

    def soft_fail(self, event_id: str, reason: str) -> bool:
        raise NotImplementedError

    def backfill(self, events) -> int:
        raise NotImplementedError

    def upgrade_room(self, new_version: str) -> str:
        raise NotImplementedError

    def room_version(self) -> str:
        raise NotImplementedError

    def event_depth(self, event_id: str) -> int:
        raise NotImplementedError

    def pending_events(self) -> tuple[str, ...]:
        raise NotImplementedError

    def dag_heads(self) -> tuple[str, ...]:
        raise NotImplementedError

    def power_levels(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
