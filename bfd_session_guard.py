"""BFD session state and detection timer governance."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
DOWN = "down"
INIT = "init"
UP = "up"


class BfdError(ValueError):
    """Raised when a session operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionView:
    session_id: str
    state: str
    local_discriminator: int
    remote_discriminator: int
    detection_time: int
    next_timeout_at: int | None
    auth_sequence: int


@dataclass(frozen=True)
class ReceiveResult:
    session_id: str
    accepted: bool
    reason: str
    state: str


class BfdSessionGuard:
    """Keep BFD sessions through down, init and up with detection timers."""

    def __init__(self, *, detection_multiplier: int = 3,
                 min_tx_interval: int = 50, auth_enabled: bool = True,
                 max_sessions: int = 64) -> None:
        self.detection_multiplier = detection_multiplier
        self.min_tx_interval = min_tx_interval
        self.auth_enabled = auth_enabled
        self.max_sessions = max_sessions
        self._lock = threading.RLock()
        self._sessions: dict[str, dict] = {}
        self._stats = {
            "created": 0,
            "transitioned": 0,
            "timeouts": 0,
            "auth_failures": 0,
            "duplicates": 0,
            "rejected": 0,
            "rebuilds": 0,
        }

    def create_session(self, session_id: str, local_discriminator: int,
                       remote_discriminator: int = 0,
                       now=None) -> SessionView:
        raise NotImplementedError

    def session_view(self, session_id: str) -> SessionView:
        raise NotImplementedError

    def receive(self, session_id: str, packet, now=None) -> ReceiveResult:
        raise NotImplementedError

    def advance(self, now) -> tuple[str, ...]:
        raise NotImplementedError

    def authenticate(self, session_id: str, packet) -> bool:
        raise NotImplementedError

    def set_auth_keys(self, session_id: str, key_id: int, secret: str) -> None:
        raise NotImplementedError

    def rebuild(self, session_id: str, remote_discriminator: int,
                now=None) -> SessionView:
        raise NotImplementedError

    def session_state(self, session_id: str) -> str:
        raise NotImplementedError

    def peer(self, session_id: str) -> int:
        raise NotImplementedError

    def timers(self, session_id: str) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError
