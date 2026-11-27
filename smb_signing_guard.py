"""SMB2 negotiate-time signing enforcement."""

from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass, replace

SNAPSHOT_VERSION = 1
SERVER_DIALECTS = ("2.0.2", "2.1", "3.0", "3.0.2", "3.1.1")
SNAPSHOT_KEYS = frozenset(
    {"version", "negotiations", "sessions", "keys", "preauth", "stats"}
)
STAT_KEYS = (
    "negotiated",
    "refused",
    "sessions",
    "signatures",
    "signature_failures",
    "preauth_updates",
    "preauth_mismatches",
)
SIGNING_POLICY_DRIFT = "SMB_SIGNING_POLICY_DRIFT"


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

    @staticmethod
    def _values(value) -> tuple:
        if isinstance(value, str):
            return (value,)
        try:
            return tuple(value)
        except TypeError:
            return ()

    @staticmethod
    def _dialect_key(dialect: object) -> tuple[int, ...]:
        if not isinstance(dialect, str):
            return ()
        parts = dialect.split(".")
        if not parts or any(not part.isdigit() for part in parts):
            return ()
        return tuple(int(part) for part in parts)

    @classmethod
    def _ordered_dialects(cls, dialects: set[str]) -> tuple[str, ...]:
        return tuple(
            sorted(
                dialects,
                key=lambda dialect: (
                    cls._dialect_key(dialect),
                    dialect,
                ),
            )
        )

    @staticmethod
    def _ordered_capabilities(capabilities) -> tuple[str, ...]:
        values = SmbSigningGuard._values(capabilities)
        return tuple(sorted({value for value in values if isinstance(value, str)}))

    @staticmethod
    def _has_capability(capabilities: tuple[str, ...], wanted: str) -> bool:
        return any(
            capability.casefold() == wanted.casefold()
            for capability in capabilities
        )

    @staticmethod
    def _message_bytes(message: object) -> bytes:
        if isinstance(message, bytes):
            return message
        if isinstance(message, (bytearray, memoryview)):
            return bytes(message)
        return str(message).encode("utf-8")

    @staticmethod
    def _signature_for(key: str, message: object) -> str:
        return hmac.new(
            bytes.fromhex(key),
            SmbSigningGuard._message_bytes(message),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _is_hex(value: object, length: int) -> bool:
        if not isinstance(value, str) or len(value) != length:
            return False
        return all(character in "0123456789abcdefABCDEF" for character in value)

    def _record_negotiation_refusal(self, client_id: str, code: str,
                                    detail=None) -> None:
        self._stats["refused"] += 1
        self._failures.append((client_id, code))
        raise SmbError(code, detail)

    def _record_policy_drift(self, client_id: str) -> None:
        marker = (client_id, SIGNING_POLICY_DRIFT)
        if marker not in self._failures:
            self._failures.append(marker)

    def _new_session_key(self) -> str:
        while True:
            key = secrets.token_hex(16)
            if key not in self._keys.values():
                return key

    def negotiate(self, client_id: str, dialects, capabilities=(),
                  now=None) -> Negotiation:
        with self._lock:
            if client_id in self._negotiations:
                self._record_negotiation_refusal(
                    client_id,
                    "SMB_NEGOTIATION_DUPLICATE",
                    {"client_id": client_id},
                )

            client_dialects = {
                dialect
                for dialect in self._values(dialects)
                if isinstance(dialect, str)
            }
            common_dialects = {
                dialect
                for dialect in set(self.server_dialects) & client_dialects
                if self._dialect_key(dialect) >= (2,)
            }
            if not common_dialects:
                self._record_negotiation_refusal(
                    client_id,
                    "SMB_DIALECT_UNSUPPORTED",
                    {"dialects": tuple(sorted(client_dialects))},
                )

            ordered_dialects = self._ordered_dialects(common_dialects)
            selected_dialect = ordered_dialects[-1]
            ordered_capabilities = self._ordered_capabilities(capabilities)
            has_signing = self._has_capability(ordered_capabilities, "signing")

            if self.require_signing and not has_signing:
                self._record_negotiation_refusal(
                    client_id,
                    "SMB_SIGNING_UNAVAILABLE",
                    {"capabilities": ordered_capabilities},
                )

            negotiation = Negotiation(
                client_id=client_id,
                dialect=selected_dialect,
                dialects=ordered_dialects,
                signing_required=self.require_signing,
                encryption_required=(
                    self.allow_encryption
                    and self._has_capability(
                        ordered_capabilities, "encryption"
                    )
                ),
                capabilities=ordered_capabilities,
            )
            self._negotiations[client_id] = negotiation
            self._stats["negotiated"] += 1
            return negotiation

    def negotiation_for(self, client_id: str) -> Negotiation | None:
        with self._lock:
            return self._negotiations.get(client_id)

    def open_session(self, client_id: str, session_id: str,
                     now=None) -> SessionRecord:
        with self._lock:
            negotiation = self._negotiations.get(client_id)
            if negotiation is None:
                raise SmbError(
                    "SMB_NOT_NEGOTIATED",
                    {"client_id": client_id},
                )
            if session_id in self._sessions:
                raise SmbError(
                    "SMB_SESSION_EXISTS",
                    {"session_id": session_id},
                )

            active_sessions = sum(
                record.state == "active"
                for record in self._sessions.values()
            )
            if active_sessions >= self.max_sessions:
                raise SmbError(
                    "SMB_SESSION_LIMIT",
                    {"max_sessions": self.max_sessions},
                )

            if negotiation.signing_required != self.require_signing:
                self._record_policy_drift(client_id)
            signing_required = self.require_signing
            if (
                signing_required
                and not self._has_capability(
                    negotiation.capabilities, "signing"
                )
            ):
                raise SmbError(
                    "SMB_SIGNING_UNAVAILABLE",
                    {"client_id": client_id},
                )

            encryption_required = (
                self.allow_encryption
                and self._has_capability(
                    negotiation.capabilities, "encryption"
                )
            )
            session = SessionRecord(
                session_id=session_id,
                client_id=client_id,
                dialect=negotiation.dialect,
                signing_required=signing_required,
                encryption_required=encryption_required,
                state="active",
                opened_at=now,
            )
            key = self._new_session_key()
            self._sessions[session_id] = session
            self._keys[session_id] = key
            self._stats["sessions"] += 1
            return session

    def close_session(self, session_id: str, reason=None) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.state != "active":
                return False
            self._sessions[session_id] = replace(
                session,
                state="closed",
            )
            return True

    def session_state(self, session_id: str) -> str:
        with self._lock:
            session = self._sessions.get(session_id)
            return "unknown" if session is None else session.state

    def session_key(self, session_id: str) -> str:
        with self._lock:
            if session_id not in self._sessions:
                raise SmbError(
                    "SMB_SESSION_UNKNOWN",
                    {"session_id": session_id},
                )
            key = self._keys.get(session_id)
            if key is None:
                raise SmbError(
                    "SMB_SESSION_UNKNOWN",
                    {"session_id": session_id},
                )
            return key

    def sign(self, session_id: str, message: str) -> str:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SmbError(
                    "SMB_SESSION_UNKNOWN",
                    {"session_id": session_id},
                )
            if session.state != "active":
                raise SmbError(
                    "SMB_SESSION_CLOSED",
                    {"session_id": session_id},
                )
            key = self._keys.get(session_id)
            if key is None:
                raise SmbError(
                    "SMB_SESSION_UNKNOWN",
                    {"session_id": session_id},
                )
            signature = self._signature_for(key, message)
            self._stats["signatures"] += 1
            return signature

    def verify(self, session_id: str, message: str, signature: str,
               now=None) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SmbError(
                    "SMB_SESSION_UNKNOWN",
                    {"session_id": session_id},
                )
            if session.state != "active":
                raise SmbError(
                    "SMB_SESSION_CLOSED",
                    {"session_id": session_id},
                )
            if session.signing_required != self.require_signing:
                self._record_policy_drift(session.client_id)

            key = self._keys.get(session_id)
            if key is None:
                raise SmbError(
                    "SMB_SESSION_UNKNOWN",
                    {"session_id": session_id},
                )

            expected = self._signature_for(key, message)
            valid = (
                self._is_hex(signature, 64)
                and hmac.compare_digest(signature.lower(), expected)
            )
            if not valid:
                self._stats["signature_failures"] += 1
                self._failures.append(
                    (session.client_id, "SMB_SIGNATURE_INVALID")
                )
                self._sessions[session_id] = replace(
                    session,
                    state="closed",
                )
                raise SmbError(
                    "SMB_SIGNATURE_INVALID",
                    {
                        "session_id": session_id,
                        "client_id": session.client_id,
                    },
                )
            return True

    def preauth_update(self, connection_id: str, message: str) -> str:
        with self._lock:
            previous = self._preauth.get(connection_id, "")
            digest = hashlib.sha256(
                previous.encode("ascii") + self._message_bytes(message)
            ).hexdigest()
            self._preauth[connection_id] = digest
            self._stats["preauth_updates"] += 1
            return digest

    def preauth_hash(self, connection_id: str) -> str:
        with self._lock:
            return self._preauth.get(connection_id, "")

    def verify_preauth(self, connection_id: str, expected: str) -> bool:
        with self._lock:
            actual = self._preauth.get(connection_id)
            matched = (
                actual is not None
                and self._is_hex(expected, 64)
                and hmac.compare_digest(expected.lower(), actual)
            )
            if not matched:
                self._stats["preauth_mismatches"] += 1
            return matched

    def failure_log(self, client_id: str | None = None) -> tuple:
        with self._lock:
            if client_id is None:
                return tuple(self._failures)
            return tuple(
                failure
                for failure in self._failures
                if failure[0] == client_id
            )

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "negotiations": copy.deepcopy(self._negotiations),
                "sessions": copy.deepcopy(self._sessions),
                "keys": copy.deepcopy(self._keys),
                "preauth": copy.deepcopy(self._preauth),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state) -> None:
        with self._lock:
            self._validate_snapshot(state)
            negotiations = copy.deepcopy(state["negotiations"])
            sessions = copy.deepcopy(state["sessions"])
            keys = copy.deepcopy(state["keys"])
            preauth = copy.deepcopy(state["preauth"])
            stats = copy.deepcopy(state["stats"])

            self._negotiations = negotiations
            self._sessions = sessions
            self._keys = keys
            self._preauth = preauth
            self._stats = stats

    @classmethod
    def _snapshot_invalid(cls, reason: str, detail=None) -> None:
        payload = {"reason": reason}
        if detail is not None:
            payload["detail"] = detail
        raise SmbError("SMB_SNAPSHOT_INVALID", payload)

    @classmethod
    def _validate_snapshot(cls, state) -> None:
        if not isinstance(state, dict):
            cls._snapshot_invalid("state_not_mapping")
        if set(state) != SNAPSHOT_KEYS:
            cls._snapshot_invalid(
                "keys_mismatch",
                sorted(set(state) ^ SNAPSHOT_KEYS),
            )
        if type(state["version"]) is not int or state["version"] != SNAPSHOT_VERSION:
            cls._snapshot_invalid("version")

        negotiations = state["negotiations"]
        if not isinstance(negotiations, dict):
            cls._snapshot_invalid("negotiations_type")
        for client_id, negotiation in negotiations.items():
            if (
                not isinstance(client_id, str)
                or not isinstance(negotiation, Negotiation)
                or negotiation.client_id != client_id
                or not isinstance(negotiation.dialect, str)
                or not isinstance(negotiation.dialects, tuple)
                or not all(
                    isinstance(dialect, str)
                    for dialect in negotiation.dialects
                )
                or type(negotiation.signing_required) is not bool
                or type(negotiation.encryption_required) is not bool
                or not isinstance(negotiation.capabilities, tuple)
                or not all(
                    isinstance(capability, str)
                    for capability in negotiation.capabilities
                )
            ):
                cls._snapshot_invalid(
                    "negotiation_entry", client_id
                )

        sessions = state["sessions"]
        if not isinstance(sessions, dict):
            cls._snapshot_invalid("sessions_type")
        for session_id, session in sessions.items():
            if (
                not isinstance(session_id, str)
                or not isinstance(session, SessionRecord)
                or session.session_id != session_id
                or not isinstance(session.client_id, str)
                or not isinstance(session.dialect, str)
                or type(session.signing_required) is not bool
                or type(session.encryption_required) is not bool
                or session.state not in {"active", "closed"}
                or (
                    session.opened_at is not None
                    and type(session.opened_at) is not int
                )
            ):
                cls._snapshot_invalid("session_entry", session_id)

        keys = state["keys"]
        if not isinstance(keys, dict):
            cls._snapshot_invalid("keys_type")
        for session_id, key in keys.items():
            if not isinstance(session_id, str) or not cls._is_hex(key, 32):
                cls._snapshot_invalid("key_entry", session_id)
            if session_id not in sessions:
                cls._snapshot_invalid("orphan_key", session_id)
        for session_id in sessions:
            if session_id not in keys:
                cls._snapshot_invalid("missing_key", session_id)

        preauth = state["preauth"]
        if not isinstance(preauth, dict):
            cls._snapshot_invalid("preauth_type")
        for connection_id, digest in preauth.items():
            if (
                not isinstance(connection_id, str)
                or not cls._is_hex(digest, 64)
            ):
                cls._snapshot_invalid("preauth_entry", connection_id)

        stats = state["stats"]
        if not isinstance(stats, dict) or set(stats) != set(STAT_KEYS):
            cls._snapshot_invalid("stats_structure")
        for name in STAT_KEYS:
            value = stats[name]
            if type(value) is not int or value < 0:
                cls._snapshot_invalid("stats_value", name)
