"""Captive portal pre-authentication gate: allowlist, per-client budget, expiry settlement."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CaptiveError(ValueError):
    """Raised when a pre-authentication request cannot be served."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PreauthSession:
    mac: str
    addr: str
    state: str
    started_at: float
    expires_at: float
    bytes_used: int
    bytes_limit: int
    authenticated_at: float | None


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    host: str


class CaptivePortalGate:
    """Decide what a client may reach before it finishes portal authentication."""

    def __init__(self, *, session_ttl: float = 600.0, byte_budget: int = 1_000_000,
                 max_sessions: int = 128, portal_hosts=(), clock=None) -> None:
        self.session_ttl = session_ttl
        self.byte_budget = byte_budget
        self.max_sessions = max_sessions
        self.portal_hosts = tuple(portal_hosts)
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, PreauthSession] = {}
        self._allowlist: dict[str, dict] = {}
        self._stats = {
            "registered": 0,
            "authorized": 0,
            "allowed": 0,
            "denied": 0,
            "expired": 0,
            "bytes_consumed": 0,
        }

    def register_client(self, mac: str, addr: str, *, now: float | None = None) -> PreauthSession:
        raise NotImplementedError

    def complete_auth(self, mac: str, *, now: float | None = None) -> PreauthSession:
        raise NotImplementedError

    def authorize(self, mac: str, addr: str, host: str, *, now: float | None = None) -> AccessDecision:
        raise NotImplementedError

    def session_for(self, mac: str) -> PreauthSession | None:
        raise NotImplementedError

    def sessions(self) -> list[PreauthSession]:
        raise NotImplementedError

    def consume_bytes(self, mac: str, count: int, *, now: float | None = None) -> int:
        raise NotImplementedError

    def settle_expired(self, *, now: float | None = None) -> int:
        raise NotImplementedError

    def update_allowlist(self, host: str, *, addresses, ttl: float = 30.0,
                         now: float | None = None) -> tuple[str, ...]:
        raise NotImplementedError

    def allowlist_addresses(self, host: str, *, now: float | None = None) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
