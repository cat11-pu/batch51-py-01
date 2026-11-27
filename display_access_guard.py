"""Display session access control: per-session credentials, capability tiers, cascade revoke."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class DisplayError(ValueError):
    """Raised when a display access request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


CAPABILITIES = ("input", "screenshot")

DENY_CREDENTIAL_UNKNOWN = "CREDENTIAL_UNKNOWN"
DENY_CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
DENY_CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
DENY_CLIENT_MISMATCH = "CLIENT_MISMATCH"
DENY_SESSION_MISMATCH = "SESSION_MISMATCH"
DENY_SESSION_CLOSED = "SESSION_CLOSED"
DENY_CAPABILITY_MISSING = "CAPABILITY_MISSING"
DENY_MODE_TOO_WIDE = "CREDENTIAL_MODE_TOO_WIDE"


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    uid: int
    display: int
    seat: str
    opened_at: int
    closed: bool = False


@dataclass(frozen=True)
class Credential:
    token: str
    session_id: str
    uid: int
    display: int
    client_addr: str
    file_mode: int
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class Decision:
    status: str
    code: str
    session_id: str
    action: str
    uid: int


class DisplayAccessGuard:
    """Issue and validate per-session credentials for local graphical sessions."""

    def __init__(self, *, max_sessions: int = 64, credential_ttl: int = 300) -> None:
        self.max_sessions = max_sessions
        self.credential_ttl = credential_ttl
        self._lock = threading.RLock()

    def open_session(self, session_id: str, *, uid: int, display: int,
                     seat: str, now: int) -> SessionRecord:
        raise NotImplementedError

    def issue_credential(self, session_id: str, *, client_addr: str,
                         file_mode: int = 0o600, now: int) -> Credential:
        raise NotImplementedError

    def active_credential(self, session_id: str) -> Credential | None:
        raise NotImplementedError

    def credentials_for(self, session_id: str) -> tuple[Credential, ...]:
        raise NotImplementedError

    def authorize(self, token: str, *, client_addr: str, session_id: str,
                  action: str, now: int) -> Decision:
        raise NotImplementedError

    def grant_capability(self, session_id: str, capability: str, *,
                         now: int | None = None) -> tuple[str, ...]:
        raise NotImplementedError

    def revoke_capability(self, session_id: str, capability: str) -> bool:
        raise NotImplementedError

    def capabilities(self, session_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def revoke_credential(self, token: str, *, reason: str = "manual",
                          now: int | None = None) -> bool:
        raise NotImplementedError

    def close_session(self, session_id: str, *, now: int | None = None) -> int:
        raise NotImplementedError

    def sessions(self) -> tuple[SessionRecord, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
