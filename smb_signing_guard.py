"""SMB2 negotiate-time signing enforcement."""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
SERVER_DIALECTS = ("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1")


class SmbError(ValueError):
    """Raised when a negotiate or session operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Negotiation:
    client_id: str
    dialect: str
    dialects: tuple[str, ...]
    signing_required: bool
    encryption_required: bool
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    client_id: str
    dialect: str
    signing_required: bool
    encryption_required: bool
    state: str
    opened_at: int | None


class SmbSigningGuard:
    """Decide signing requirements during negotiate and verify message signatures."""

    def __init__(self, *, server_dialects=SERVER_DIALECTS,
                 require_signing: bool = True, allow_encryption: bool = True,
                 preauth_required: bool = True,
                 max_sessions: int = 32) -> None:
        self.server_dialects = tuple(server_dialects)
        self.require_signing = require_signing
        self.allow_encryption = allow_encryption
        self.preauth_required = preauth_required
        self.max_sessions = max_sessions
        self._lock = threading.RLock()
        self._negotiations: dict[str, Negotiation] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._keys: dict[str, str] = {}
        self._preauth: dict[str, str] = {}
        self._failures: list[tuple[str, str]] = []
        self._stats = {
            "negotiated": 0,
            "refused": 0,
            "sessions": 0,
            "signatures": 0,
            "signature_failures": 0,
            "preauth_updates": 0,
            "preauth_mismatches": 0,
        }

    def negotiate(self, client_id: str, dialects, capabilities=(),
                  now=None) -> Negotiation:
        raise NotImplementedError

    def negotiation_for(self, client_id: str) -> Negotiation | None:
        raise NotImplementedError

    def open_session(self, client_id: str, session_id: str,
                     now=None) -> SessionRecord:
        raise NotImplementedError

    def close_session(self, session_id: str, reason=None) -> bool:
        raise NotImplementedError

    def session_state(self, session_id: str) -> str:
        raise NotImplementedError

    def session_key(self, session_id: str) -> str:
        raise NotImplementedError

    def sign(self, session_id: str, message: str) -> str:
        raise NotImplementedError

    def verify(self, session_id: str, message: str, signature: str,
               now=None) -> bool:
        raise NotImplementedError

    def preauth_update(self, connection_id: str, message: str) -> str:
        raise NotImplementedError

    def preauth_hash(self, connection_id: str) -> str:
        raise NotImplementedError

    def verify_preauth(self, connection_id: str, expected: str) -> bool:
        raise NotImplementedError

    def failure_log(self, client_id: str | None = None) -> tuple:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError
