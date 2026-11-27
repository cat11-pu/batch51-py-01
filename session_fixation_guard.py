"""Session fixation defence: identifier rotation, cookie scope checks, session caps."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SessionError(ValueError):
    """Raised when a session or cookie operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionRecord:
    sid: str
    user: str | None
    auth_level: int
    generation: int
    fingerprint: str | None
    created_at: str
    rotated_at: str


@dataclass(frozen=True)
class CookieSpec:
    name: str
    value: str
    secure: bool
    http_only: bool
    path: str
    domain: str | None
    same_site: str
    max_age: int | None


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    event: str
    subject: str
    code: str | None


class SessionFixationGuard:
    """Keep session identifiers rotating and cookie scopes inside policy."""

    def __init__(self, *, max_sessions_per_user: int = 5,
                 max_sessions_total: int = 1000, idle_timeout: int = 1800,
                 cookie_name: str = "__Host-SID") -> None:
        self._lock = threading.RLock()
        self._max_sessions_per_user = max_sessions_per_user
        self._max_sessions_total = max_sessions_total
        self._idle_timeout = idle_timeout
        self._cookie_name = cookie_name

    def create_session(self, *, user: str | None = None,
                       fingerprint: str | None = None, now: str | None = None) -> str:
        raise NotImplementedError

    def login(self, sid: str, *, user: str,
              fingerprint: str | None = None, now: str | None = None) -> str:
        raise NotImplementedError

    def elevate(self, sid: str, *, level: int,
                fingerprint: str | None = None, now: str | None = None) -> str:
        raise NotImplementedError

    def rotate(self, sid: str, *, fingerprint: str | None = None,
               now: str | None = None) -> str:
        raise NotImplementedError

    def logout(self, sid: str, *, now: str | None = None) -> bool:
        raise NotImplementedError

    def revoke_user(self, user: str, *, now: str | None = None) -> int:
        raise NotImplementedError

    def revoke_expired(self, now: str | None = None) -> int:
        raise NotImplementedError

    def session_record(self, sid: str, *, fingerprint: str | None = None,
                       now: str | None = None) -> SessionRecord:
        raise NotImplementedError

    def sessions_for(self, user: str) -> tuple[SessionRecord, ...]:
        raise NotImplementedError

    def sessions(self) -> tuple[SessionRecord, ...]:
        raise NotImplementedError

    def issue_cookie(self, sid: str, *, now: str | None = None) -> CookieSpec:
        raise NotImplementedError

    def validate_cookie(self, raw: str) -> CookieSpec:
        raise NotImplementedError

    def audit_log(self) -> tuple[AuditEntry, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
