"""Display session access control: per-session credentials, capability tiers, cascade revoke."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass, replace


class DisplayError(ValueError):
    """Raised when a display access request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


CAPABILITIES = ("input", "screenshot")

DISPLAY_SESSION_EXISTS = "DISPLAY_SESSION_EXISTS"
DISPLAY_SESSION_UNKNOWN = "DISPLAY_SESSION_UNKNOWN"
DISPLAY_CAPACITY_EXCEEDED = "DISPLAY_CAPACITY_EXCEEDED"
DISPLAY_CAPABILITY_UNKNOWN = "DISPLAY_CAPABILITY_UNKNOWN"
DISPLAY_CREDENTIAL_LIMIT_EXCEEDED = "DISPLAY_CREDENTIAL_LIMIT_EXCEEDED"
DISPLAY_SNAPSHOT_INVALID = "DISPLAY_SNAPSHOT_INVALID"

DENY_CREDENTIAL_UNKNOWN = "CREDENTIAL_UNKNOWN"
DENY_CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
DENY_CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
DENY_CLIENT_MISMATCH = "CLIENT_MISMATCH"
DENY_SESSION_MISMATCH = "SESSION_MISMATCH"
DENY_SESSION_CLOSED = "SESSION_CLOSED"
DENY_CAPABILITY_MISSING = "CAPABILITY_MISSING"
DENY_MODE_TOO_WIDE = "CREDENTIAL_MODE_TOO_WIDE"

SNAPSHOT_VERSION = 1
STATS_KEYS = (
    "sessions_opened",
    "credentials_issued",
    "credentials_rotated",
    "denied",
    "revoked",
    "sessions_closed",
)


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
    revoked: bool = False
    revoked_at: int | None = None
    revoked_reason: str | None = None


@dataclass(frozen=True)
class Decision:
    status: str
    code: str
    session_id: str
    action: str
    uid: int


class DisplayAccessGuard:
    """Issue and validate per-session credentials for local graphical sessions."""

    MAX_CREDENTIALS_PER_SESSION = 256

    def __init__(self, *, max_sessions: int = 64, credential_ttl: int = 300) -> None:
        if type(max_sessions) is not int or max_sessions < 0:
            raise ValueError("max_sessions must be a non-negative integer")
        if type(credential_ttl) is not int or credential_ttl < 0:
            raise ValueError("credential_ttl must be a non-negative integer")

        self.max_sessions = max_sessions
        self.credential_ttl = credential_ttl
        self.max_credentials_per_session = self.MAX_CREDENTIALS_PER_SESSION

        self._lock = threading.RLock()
        self._sessions: dict[str, SessionRecord] = {}
        self._credentials: dict[str, Credential] = {}
        self._active: dict[str, str] = {}
        self._capabilities: dict[str, set[str]] = {}
        self._counters = {key: 0 for key in STATS_KEYS}

    def open_session(self, session_id: str, *, uid: int, display: int,
                     seat: str, now: int) -> SessionRecord:
        with self._lock:
            if session_id in self._sessions:
                raise DisplayError(
                    DISPLAY_SESSION_EXISTS, {"session_id": session_id}
                )

            active_sessions = sum(
                not record.closed for record in self._sessions.values()
            )
            if active_sessions >= self.max_sessions:
                raise DisplayError(
                    DISPLAY_CAPACITY_EXCEEDED,
                    {"max_sessions": self.max_sessions},
                )

            record = SessionRecord(
                session_id=session_id,
                uid=uid,
                display=display,
                seat=seat,
                opened_at=now,
            )
            self._sessions[session_id] = record
            self._capabilities[session_id] = set()
            self._counters["sessions_opened"] += 1
            return record

    def issue_credential(self, session_id: str, *, client_addr: str,
                         file_mode: int = 0o600, now: int) -> Credential:
        with self._lock:
            session = self._require_session(session_id)
            if session.closed:
                raise DisplayError(
                    DENY_SESSION_CLOSED, {"session_id": session_id}
                )

            history = self._credentials_for_locked(session_id)
            if len(history) >= self.max_credentials_per_session:
                raise DisplayError(
                    DISPLAY_CREDENTIAL_LIMIT_EXCEEDED,
                    {
                        "session_id": session_id,
                        "limit": self.max_credentials_per_session,
                    },
                )

            old_token = self._active.get(session_id)
            if old_token is not None:
                old_credential = self._credentials[old_token]
                if not old_credential.revoked:
                    self._credentials[old_token] = replace(
                        old_credential,
                        revoked=True,
                        revoked_at=now,
                        revoked_reason="rotated",
                    )
                    self._counters["credentials_rotated"] += 1

            token = self._new_token_locked()
            credential = Credential(
                token=token,
                session_id=session_id,
                uid=session.uid,
                display=session.display,
                client_addr=client_addr,
                file_mode=file_mode,
                issued_at=now,
                expires_at=now + self.credential_ttl,
            )
            self._credentials[token] = credential
            self._active[session_id] = token
            self._counters["credentials_issued"] += 1
            return credential

    def active_credential(self, session_id: str) -> Credential | None:
        with self._lock:
            session = self._require_session(session_id)
            if session.closed:
                return None

            token = self._active.get(session_id)
            if token is None:
                return None
            credential = self._credentials.get(token)
            if credential is None or credential.revoked:
                return None
            return credential

    def credentials_for(self, session_id: str) -> tuple[Credential, ...]:
        with self._lock:
            self._require_session(session_id)
            return self._credentials_for_locked(session_id)

    def authorize(self, token: str, *, client_addr: str, session_id: str,
                  action: str, now: int) -> Decision:
        with self._lock:
            credential = (
                self._credentials.get(token) if isinstance(token, str) else None
            )
            if credential is None:
                return self._deny(
                    DENY_CREDENTIAL_UNKNOWN, session_id, action, 0
                )

            session = self._sessions.get(credential.session_id)
            if session is None or session.closed:
                return self._deny(
                    DENY_SESSION_CLOSED, session_id, action, credential.uid
                )
            if credential.revoked:
                return self._deny(
                    DENY_CREDENTIAL_REVOKED, session_id, action, credential.uid
                )
            if now >= credential.expires_at:
                return self._deny(
                    DENY_CREDENTIAL_EXPIRED, session_id, action, credential.uid
                )
            if session_id != credential.session_id:
                return self._deny(
                    DENY_SESSION_MISMATCH, session_id, action, credential.uid
                )
            if client_addr != credential.client_addr:
                return self._deny(
                    DENY_CLIENT_MISMATCH, session_id, action, credential.uid
                )
            if credential.file_mode & 0o077:
                return self._deny(
                    DENY_MODE_TOO_WIDE, session_id, action, credential.uid
                )
            if action not in self._capabilities.get(credential.session_id, set()):
                return self._deny(
                    DENY_CAPABILITY_MISSING, session_id, action, credential.uid
                )

            return Decision(
                status="allow",
                code="",
                session_id=session_id,
                action=action,
                uid=credential.uid,
            )

    def grant_capability(self, session_id: str, capability: str, *,
                         now: int | None = None) -> tuple[str, ...]:
        with self._lock:
            session = self._require_session(session_id)
            if session.closed:
                raise DisplayError(
                    DENY_SESSION_CLOSED, {"session_id": session_id}
                )
            if capability not in CAPABILITIES:
                raise DisplayError(
                    DISPLAY_CAPABILITY_UNKNOWN, {"capability": capability}
                )

            self._capabilities.setdefault(session_id, set()).add(capability)
            return tuple(sorted(self._capabilities[session_id]))

    def revoke_capability(self, session_id: str, capability: str) -> bool:
        with self._lock:
            session = self._require_session(session_id)
            if capability not in CAPABILITIES:
                raise DisplayError(
                    DISPLAY_CAPABILITY_UNKNOWN, {"capability": capability}
                )
            if session.closed:
                return False

            capabilities = self._capabilities.setdefault(session_id, set())
            if capability not in capabilities:
                return False
            capabilities.remove(capability)
            return True

    def capabilities(self, session_id: str) -> tuple[str, ...]:
        with self._lock:
            session = self._require_session(session_id)
            if session.closed:
                return ()
            return tuple(sorted(self._capabilities.get(session_id, set())))

    def revoke_credential(self, token: str, *, reason: str = "manual",
                          now: int | None = None) -> bool:
        with self._lock:
            credential = (
                self._credentials.get(token) if isinstance(token, str) else None
            )
            if credential is None or credential.revoked:
                return False

            self._credentials[token] = replace(
                credential,
                revoked=True,
                revoked_at=now,
                revoked_reason=reason,
            )
            if self._active.get(credential.session_id) == token:
                del self._active[credential.session_id]
            self._counters["revoked"] += 1
            return True

    def close_session(self, session_id: str, *, now: int | None = None) -> int:
        with self._lock:
            session = self._require_session(session_id)
            if session.closed:
                return 0

            revoked_count = 0
            for token, credential in tuple(self._credentials.items()):
                if credential.session_id != session_id or credential.revoked:
                    continue
                self._credentials[token] = replace(
                    credential,
                    revoked=True,
                    revoked_at=now,
                    revoked_reason="session_closed",
                )
                revoked_count += 1

            self._active.pop(session_id, None)
            self._capabilities[session_id] = set()
            self._sessions[session_id] = replace(session, closed=True)
            self._counters["revoked"] += revoked_count
            self._counters["sessions_closed"] += 1
            return revoked_count

    def sessions(self) -> tuple[SessionRecord, ...]:
        with self._lock:
            return tuple(
                record
                for record in self._sessions.values()
                if not record.closed
            )

    def snapshot(self) -> dict:
        with self._lock:
            sessions = {
                session_id: {
                    "session_id": record.session_id,
                    "uid": record.uid,
                    "display": record.display,
                    "seat": record.seat,
                    "opened_at": record.opened_at,
                    "closed": record.closed,
                }
                for session_id, record in self._sessions.items()
            }
            credentials = {
                token: {
                    "token": credential.token,
                    "session_id": credential.session_id,
                    "uid": credential.uid,
                    "display": credential.display,
                    "client_addr": credential.client_addr,
                    "file_mode": credential.file_mode,
                    "issued_at": credential.issued_at,
                    "expires_at": credential.expires_at,
                    "revoked": credential.revoked,
                    "revoked_at": credential.revoked_at,
                    "revoked_reason": credential.revoked_reason,
                }
                for token, credential in self._credentials.items()
            }
            capabilities = {
                session_id: tuple(sorted(self._capabilities.get(session_id, set())))
                for session_id in self._sessions
            }
            return {
                "version": SNAPSHOT_VERSION,
                "sessions": sessions,
                "credentials": credentials,
                "capabilities": capabilities,
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                new_state = self._parse_snapshot(state)
            except DisplayError:
                raise
            except Exception as exc:
                raise DisplayError(
                    DISPLAY_SNAPSHOT_INVALID, {"error": repr(exc)}
                ) from exc

            sessions, credentials, active, capabilities, counters = new_state
            self._sessions = sessions
            self._credentials = credentials
            self._active = active
            self._capabilities = capabilities
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def _require_session(self, session_id: str) -> SessionRecord:
        record = self._sessions.get(session_id)
        if record is None:
            raise DisplayError(
                DISPLAY_SESSION_UNKNOWN, {"session_id": session_id}
            )
        return record

    def _credentials_for_locked(self, session_id: str) -> tuple[Credential, ...]:
        return tuple(
            credential
            for credential in self._credentials.values()
            if credential.session_id == session_id
        )

    def _new_token_locked(self) -> str:
        while True:
            token = secrets.token_urlsafe(32)
            if token not in self._credentials:
                return token

    def _deny(self, code: str, session_id: str, action: str, uid: int) -> Decision:
        self._counters["denied"] += 1
        return Decision(
            status="deny",
            code=code,
            session_id=session_id,
            action=action,
            uid=uid,
        )

    def _parse_snapshot(
        self, state: object
    ) -> tuple[
        dict[str, SessionRecord],
        dict[str, Credential],
        dict[str, str],
        dict[str, set[str]],
        dict[str, int],
    ]:
        def invalid(detail: object) -> None:
            raise DisplayError(DISPLAY_SNAPSHOT_INVALID, detail)

        if not isinstance(state, dict):
            invalid({"field": "state", "expected": "dict"})
        if type(state.get("version")) is not int or state["version"] != SNAPSHOT_VERSION:
            invalid({"field": "version", "expected": SNAPSHOT_VERSION})

        required = ("sessions", "credentials", "capabilities", "counters")
        for field in required:
            if field not in state or not isinstance(state[field], dict):
                invalid({"field": field, "expected": "dict"})

        raw_sessions = state["sessions"]
        sessions: dict[str, SessionRecord] = {}
        for session_id, raw in raw_sessions.items():
            if not isinstance(session_id, str) or not isinstance(raw, dict):
                invalid({"field": "sessions", "session_id": session_id})
            if raw.get("session_id") != session_id:
                invalid(
                    {
                        "field": "sessions.session_id",
                        "session_id": session_id,
                    }
                )
            if (
                type(raw.get("uid")) is not int
                or type(raw.get("display")) is not int
                or type(raw.get("opened_at")) is not int
                or not isinstance(raw.get("seat"), str)
                or type(raw.get("closed")) is not bool
            ):
                invalid({"field": "sessions", "session_id": session_id})
            sessions[session_id] = SessionRecord(
                session_id=session_id,
                uid=raw["uid"],
                display=raw["display"],
                seat=raw["seat"],
                opened_at=raw["opened_at"],
                closed=raw["closed"],
            )

        active_sessions = sum(not record.closed for record in sessions.values())
        if active_sessions > self.max_sessions:
            invalid(
                {
                    "field": "sessions",
                    "active": active_sessions,
                    "max_sessions": self.max_sessions,
                }
            )

        raw_credentials = state["credentials"]
        credentials: dict[str, Credential] = {}
        per_session: dict[str, int] = {}
        unrevoked: dict[str, int] = {}
        for token, raw in raw_credentials.items():
            if not isinstance(token, str) or len(token) < 16 or not isinstance(raw, dict):
                invalid({"field": "credentials", "token": token})
            if raw.get("token") != token:
                invalid({"field": "credentials.token", "token": token})

            session_id = raw.get("session_id")
            session = sessions.get(session_id) if isinstance(session_id, str) else None
            if session is None:
                invalid({"field": "credentials.session_id", "token": token})
            if not isinstance(raw.get("client_addr"), str):
                invalid({"field": "credentials.client_addr", "token": token})
            if (
                type(raw.get("uid")) is not int
                or type(raw.get("display")) is not int
                or type(raw.get("file_mode")) is not int
                or type(raw.get("issued_at")) is not int
                or type(raw.get("expires_at")) is not int
                or type(raw.get("revoked")) is not bool
                or (
                    raw.get("revoked_at") is not None
                    and type(raw.get("revoked_at")) is not int
                )
                or (
                    raw.get("revoked_reason") is not None
                    and not isinstance(raw.get("revoked_reason"), str)
                )
            ):
                invalid({"field": "credentials", "token": token})
            if (
                raw["uid"] != session.uid
                or raw["display"] != session.display
                or raw["expires_at"] < raw["issued_at"]
            ):
                invalid({"field": "credentials", "token": token})
            if session.closed and not raw["revoked"]:
                invalid({"field": "credentials.revoked", "token": token})

            count = per_session.get(session_id, 0) + 1
            if count > self.max_credentials_per_session:
                invalid(
                    {
                        "field": "credentials",
                        "session_id": session_id,
                        "limit": self.max_credentials_per_session,
                    }
                )
            per_session[session_id] = count

            if not raw["revoked"]:
                current = unrevoked.get(session_id, 0) + 1
                if current > 1:
                    invalid(
                        {
                            "field": "credentials",
                            "session_id": session_id,
                            "reason": "multiple active credentials",
                        }
                    )
                unrevoked[session_id] = current

            credentials[token] = Credential(
                token=token,
                session_id=session_id,
                uid=raw["uid"],
                display=raw["display"],
                client_addr=raw["client_addr"],
                file_mode=raw["file_mode"],
                issued_at=raw["issued_at"],
                expires_at=raw["expires_at"],
                revoked=raw["revoked"],
                revoked_at=raw.get("revoked_at"),
                revoked_reason=raw.get("revoked_reason"),
            )

        active = {
            credential.session_id: credential.token
            for credential in credentials.values()
            if not credential.revoked
        }
        for session_id, record in sessions.items():
            if record.closed and session_id in active:
                invalid({"field": "credentials", "session_id": session_id})

        raw_capabilities = state["capabilities"]
        capabilities: dict[str, set[str]] = {
            session_id: set() for session_id in sessions
        }
        for session_id, raw_caps in raw_capabilities.items():
            if not isinstance(session_id, str) or session_id not in sessions:
                invalid({"field": "capabilities", "session_id": session_id})
            if not isinstance(raw_caps, (list, tuple)):
                invalid({"field": "capabilities", "session_id": session_id})
            if any(
                not isinstance(capability, str) or capability not in CAPABILITIES
                for capability in raw_caps
            ):
                invalid({"field": "capabilities", "session_id": session_id})
            if sessions[session_id].closed and raw_caps:
                invalid({"field": "capabilities", "session_id": session_id})
            capabilities[session_id].update(raw_caps)

        raw_counters = state["counters"]
        for key in STATS_KEYS:
            value = raw_counters.get(key)
            if type(value) is not int or value < 0:
                invalid({"field": "counters", "counter": key})
        counters = {key: raw_counters[key] for key in STATS_KEYS}

        return sessions, credentials, active, capabilities, counters
