"""Front-channel logout broadcaster: per-session fan-out, acks and fallback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class FrontchannelError(ValueError):
    """Raised when a logout broadcast step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Participant:
    session_id: str
    participant_id: str
    url: str
    registered_at: str


@dataclass(frozen=True)
class LogoutEntry:
    participant_id: str
    url: str
    token: str
    status: str


@dataclass(frozen=True)
class Broadcast:
    session_id: str
    started_at: str
    entries: tuple[LogoutEntry, ...]


class FrontchannelLogoutBroadcaster:
    """Fan logout calls out to the participants bound to one session."""

    def __init__(self, *, timeout_ms: int = 800, max_attempts: int = 3,
                 clock=None) -> None:
        self.timeout_ms = timeout_ms
        self.max_attempts = max_attempts
        self._clock = clock
        self._lock = threading.RLock()

    def register_participant(self, *, session_id: str, participant_id: str,
                             url: str, now: str | None = None) -> Participant:
        raise NotImplementedError

    def participants_for(self, session_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def broadcast(self, *, session_id: str, signer_key: str,
                  now: str | None = None) -> Broadcast:
        raise NotImplementedError

    def collect(self, *, session_id: str, participant_id: str, token: str,
                ok: bool = True, now: str | None = None) -> str:
        raise NotImplementedError

    def fallback(self, *, session_id: str,
                 now: str | None = None) -> tuple[str, ...]:
        raise NotImplementedError

    def pending_for(self, session_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def attempts_for(self, *, session_id: str, participant_id: str) -> int:
        raise NotImplementedError

    def close_session(self, session_id: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
