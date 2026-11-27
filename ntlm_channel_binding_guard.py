"""NTLM channel binding, target SPN, MIC and timestamp skew validation."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass

FLAG_UNICODE = 0x00000001
FLAG_SIGN = 0x00000010
FLAG_NTLM = 0x00000200
FLAG_ALWAYS_SIGN = 0x00008000
FLAG_EXTENDED_SESSION_SECURITY = 0x00080000
FLAG_TARGET_INFO = 0x00800000
FLAG_CBT_CAPABLE = 0x08000000
FLAG_VERSION = 0x02000000
FLAG_128 = 0x20000000
FLAG_KEY_EXCH = 0x40000000


class NtlmError(ValueError):
    """Refusal raised by the NTLM binding guard."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ServicePolicy:
    service: str
    spn: str
    require_cbt: bool
    strict_mic: bool


@dataclass(frozen=True)
class Challenge:
    connection_id: str
    service: str
    spn: str
    token: str
    require_cbt: bool
    strict_mic: bool
    attempts_left: int
    started_at: int


@dataclass(frozen=True)
class Type3Message:
    user: str
    domain: str
    target_name: str
    cbt: str | None
    mic: str | None
    timestamp: int
    nt_response: str


@dataclass(frozen=True)
class SessionResult:
    status: str
    code: str
    session_key: str | None
    mic_status: str


@dataclass(frozen=True)
class RefusalRecord:
    connection_id: str
    source: str
    code: str
    at: int


@dataclass(frozen=True)
class _SessionState:
    connection_id: str
    service: str
    spn: str
    token: str
    binding_material: str
    client_flags: int
    source: str
    require_cbt: bool
    strict_mic: bool
    started_at: int
    challenge_ttl: int
    max_skew_seconds: int
    attempts_left: int
    completed: bool
    session_key: str | None
    mic_status: str | None


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_SNAPSHOT_KEYS = {"version", "services", "sessions", "refusals", "stats"}
_SERVICE_FIELDS = {"service", "spn", "require_cbt", "strict_mic"}
_SESSION_FIELDS = {
    "connection_id",
    "service",
    "spn",
    "token",
    "binding_material",
    "client_flags",
    "source",
    "require_cbt",
    "strict_mic",
    "started_at",
    "challenge_ttl",
    "max_skew_seconds",
    "attempts_left",
    "completed",
    "session_key",
    "mic_status",
}
_REFUSAL_FIELDS = {"connection_id", "source", "code", "at"}
_STATS_FIELDS = {
    "begun",
    "authenticated",
    "refused",
    "attempts_exhausted",
    "mic_warnings",
}
_MIC_STATUSES = {"ok", "missing", "invalid"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in _HEX_DIGITS
                                        for character in value)


def _message_invalid(detail: object = None) -> NtlmError:
    return NtlmError("NTLM_MESSAGE_INVALID", detail)


def _snapshot_invalid(detail: object = None) -> NtlmError:
    return NtlmError("NTLM_SNAPSHOT_INVALID", detail)


class NtlmBindingGuard:
    """Validate inbound NTLM type 1 / type 3 messages before session setup."""

    def __init__(self, *, max_skew_seconds: int = 300, max_attempts: int = 3,
                 challenge_ttl: int = 120) -> None:
        if not _is_int(max_skew_seconds) or max_skew_seconds < 0:
            raise ValueError("max_skew_seconds must be a non-negative integer")
        if not _is_int(max_attempts) or max_attempts < 0:
            raise ValueError("max_attempts must be a non-negative integer")
        if not _is_int(challenge_ttl) or challenge_ttl < 0:
            raise ValueError("challenge_ttl must be a non-negative integer")
        self.max_skew_seconds = max_skew_seconds
        self.max_attempts = max_attempts
        self.challenge_ttl = challenge_ttl
        self._lock = threading.RLock()
        self._services: dict[str, ServicePolicy] = {}
        self._sessions: dict[str, _SessionState] = {}
        self._refusals: list[RefusalRecord] = []
        self._stats = {field: 0 for field in _STATS_FIELDS}

    def register_service(self, service: str, *, spn: str, require_cbt: bool = True,
                         strict_mic: bool = False) -> ServicePolicy:
        if not isinstance(service, str) or not service:
            raise _message_invalid("service must be a non-empty string")
        if not isinstance(spn, str) or not spn:
            raise _message_invalid("spn must be a non-empty string")
        if type(require_cbt) is not bool or type(strict_mic) is not bool:
            raise _message_invalid("service policy flags must be booleans")
        policy = ServicePolicy(
            service=service,
            spn=spn,
            require_cbt=require_cbt,
            strict_mic=strict_mic,
        )
        with self._lock:
            self._services[service] = policy
        return policy

    def service_policy(self, service: str) -> ServicePolicy:
        with self._lock:
            policy = self._services.get(service)
            if policy is None:
                raise NtlmError("NTLM_SERVICE_UNKNOWN", service)
            return policy

    def begin(self, connection_id: str, *, service: str, client_flags: int,
              binding_material: str, source: str, at: int) -> Challenge:
        if not isinstance(connection_id, str) or not connection_id:
            raise _message_invalid("connection_id must be a non-empty string")
        if not isinstance(service, str) or not service:
            raise _message_invalid("service must be a non-empty string")
        if not _is_int(client_flags) or client_flags < 0:
            raise _message_invalid("client_flags must be a non-negative integer")
        if not isinstance(binding_material, str):
            raise _message_invalid("binding_material must be a string")
        if not isinstance(source, str):
            raise _message_invalid("source must be a string")
        if not _is_int(at):
            raise _message_invalid("at must be an integer epoch second")

        with self._lock:
            policy = self._services.get(service)
            if policy is None:
                raise NtlmError("NTLM_SERVICE_UNKNOWN", service)
            if connection_id in self._sessions:
                raise NtlmError("NTLM_SESSION_EXISTS", connection_id)

            token_material = (
                f"challenge|{connection_id}|{service}|"
                f"{client_flags}|{binding_material}"
            )
            token = hashlib.sha256(token_material.encode()).hexdigest()[:32]
            session = _SessionState(
                connection_id=connection_id,
                service=service,
                spn=policy.spn,
                token=token,
                binding_material=binding_material,
                client_flags=client_flags,
                source=source,
                require_cbt=policy.require_cbt,
                strict_mic=policy.strict_mic,
                started_at=at,
                challenge_ttl=self.challenge_ttl,
                max_skew_seconds=self.max_skew_seconds,
                attempts_left=self.max_attempts,
                completed=False,
                session_key=None,
                mic_status=None,
            )
            self._sessions[connection_id] = session
            self._stats["begun"] += 1
            return Challenge(
                connection_id=connection_id,
                service=service,
                spn=policy.spn,
                token=token,
                require_cbt=policy.require_cbt,
                strict_mic=policy.strict_mic,
                attempts_left=self.max_attempts,
                started_at=at,
            )

    def complete(self, connection_id: str, *, fields: dict, at: int) -> SessionResult:
        if not _is_int(at):
            raise _message_invalid("at must be an integer epoch second")

        with self._lock:
            session = self._sessions.get(connection_id)
            if session is None:
                raise NtlmError("NTLM_SESSION_UNKNOWN", connection_id)
            if session.completed:
                return self._refuse(
                    session, "NTLM_SESSION_COMPLETED", at, consume_attempt=False
                )
            if session.attempts_left <= 0:
                self._stats["attempts_exhausted"] += 1
                return self._refuse(
                    session, "NTLM_ATTEMPTS_EXHAUSTED", at,
                    consume_attempt=False,
                )
            if at - session.started_at > session.challenge_ttl:
                return self._refuse(
                    session, "NTLM_CHALLENGE_EXPIRED", at,
                    consume_attempt=True,
                )

            try:
                message = self.parse_type3(fields)
            except NtlmError:
                self._refuse(
                    session, "NTLM_MESSAGE_INVALID", at,
                    consume_attempt=True,
                )
                raise

            mic_status = self._mic_status(message, session.token)

            if abs(message.timestamp - at) > session.max_skew_seconds:
                return self._refuse(
                    session, "NTLM_SKEW_EXCEEDED", at,
                    consume_attempt=True,
                    mic_status=mic_status,
                )

            if message.target_name.casefold() != session.spn.casefold():
                return self._refuse(
                    session, "NTLM_SPN_MISMATCH", at,
                    consume_attempt=True,
                    mic_status=mic_status,
                )

            cbt_status = self._channel_binding_status(
                message.cbt, session.binding_material
            )
            if cbt_status == "mismatch":
                return self._refuse(
                    session, "NTLM_CBT_MISMATCH", at,
                    consume_attempt=True,
                    mic_status=mic_status,
                )
            if cbt_status == "missing":
                client_supports_cbt = bool(
                    session.client_flags & FLAG_CBT_CAPABLE
                )
                if session.require_cbt or client_supports_cbt:
                    return self._refuse(
                        session, "NTLM_CBT_MISSING", at,
                        consume_attempt=True,
                        mic_status=mic_status,
                    )

            if mic_status == "invalid":
                return self._refuse(
                    session, "NTLM_MIC_INVALID", at,
                    consume_attempt=False,
                    mic_status=mic_status,
                )
            if mic_status == "missing":
                if session.strict_mic:
                    return self._refuse(
                        session, "NTLM_MIC_MISSING", at,
                        consume_attempt=True,
                        mic_status=mic_status,
                    )
                self._stats["mic_warnings"] += 1

            key_material = (
                f"session|{session.token}|{message.nt_response}"
            )
            session_key = hashlib.sha256(key_material.encode()).hexdigest()
            completed = _SessionState(
                connection_id=session.connection_id,
                service=session.service,
                spn=session.spn,
                token=session.token,
                binding_material=session.binding_material,
                client_flags=session.client_flags,
                source=session.source,
                require_cbt=session.require_cbt,
                strict_mic=session.strict_mic,
                started_at=session.started_at,
                challenge_ttl=session.challenge_ttl,
                max_skew_seconds=session.max_skew_seconds,
                attempts_left=session.attempts_left,
                completed=True,
                session_key=session_key,
                mic_status=mic_status,
            )
            self._sessions[connection_id] = completed
            self._stats["authenticated"] += 1
            return SessionResult(
                status="authenticated",
                code="NTLM_OK",
                session_key=session_key,
                mic_status=mic_status,
            )

    def parse_type3(self, fields: dict) -> Type3Message:
        if not isinstance(fields, dict):
            raise _message_invalid("type 3 fields must be an object")
        required = ("user", "domain", "target_name", "timestamp", "nt_response")
        if any(field not in fields for field in required):
            raise _message_invalid("type 3 message is missing required fields")

        user = fields["user"]
        domain = fields["domain"]
        target_name = fields["target_name"]
        timestamp = fields["timestamp"]
        nt_response = fields["nt_response"]
        cbt = fields.get("cbt")
        mic = fields.get("mic")

        if not isinstance(user, str) or not isinstance(domain, str):
            raise _message_invalid("user and domain must be strings")
        if not isinstance(target_name, str):
            raise _message_invalid("target_name must be a string")
        if not _is_int(timestamp):
            raise _message_invalid("timestamp must be an integer epoch second")
        if not isinstance(nt_response, str):
            raise _message_invalid("nt_response must be a hexadecimal string")
        if not _is_hex(nt_response, 32):
            raise _message_invalid(
                "nt_response must be 16 bytes of hexadecimal"
            )
        if cbt is not None and not isinstance(cbt, str):
            raise _message_invalid("cbt must be a string or None")
        if mic is not None and not isinstance(mic, str):
            raise _message_invalid("mic must be a string or None")

        return Type3Message(
            user=user,
            domain=domain,
            target_name=target_name,
            cbt=cbt,
            mic=mic,
            timestamp=timestamp,
            nt_response=nt_response,
        )

    def channel_binding_status(self, fields: dict, binding_material: str) -> str:
        if not isinstance(fields, dict):
            raise _message_invalid("type 3 fields must be an object")
        if not isinstance(binding_material, str):
            raise _message_invalid("binding_material must be a string")
        cbt = fields.get("cbt")
        if cbt is not None and not isinstance(cbt, str):
            raise _message_invalid("cbt must be a string or None")
        return self._channel_binding_status(cbt, binding_material)

    def verify_mic(self, fields: dict, *, challenge_token: str) -> str:
        if not isinstance(fields, dict):
            raise _message_invalid("type 3 fields must be an object")
        if not isinstance(challenge_token, str):
            raise _message_invalid("challenge_token must be a string")
        nt_response = fields.get("nt_response")
        if not isinstance(nt_response, str) or not _is_hex(nt_response, 32):
            raise _message_invalid(
                "nt_response must be 16 bytes of hexadecimal"
            )
        mic = fields.get("mic")
        if mic is not None and not isinstance(mic, str):
            raise _message_invalid("mic must be a string or None")
        return self._mic_status_for(nt_response, mic, challenge_token)

    def session_key(self, connection_id: str):
        with self._lock:
            session = self._sessions.get(connection_id)
            if session is None:
                raise NtlmError("NTLM_SESSION_UNKNOWN", connection_id)
            return session.session_key if session.completed else None

    def attempts_left(self, connection_id: str) -> int:
        with self._lock:
            session = self._sessions.get(connection_id)
            if session is None:
                raise NtlmError("NTLM_SESSION_UNKNOWN", connection_id)
            return session.attempts_left

    def refusals(self, *, source: str | None = None) -> list:
        with self._lock:
            if source is None:
                return list(self._refusals)
            return [record for record in self._refusals
                    if record.source == source]

    def close(self, connection_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(connection_id, None) is not None

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "services": {
                    service: {
                        "service": policy.service,
                        "spn": policy.spn,
                        "require_cbt": policy.require_cbt,
                        "strict_mic": policy.strict_mic,
                    }
                    for service, policy in self._services.items()
                },
                "sessions": {
                    connection_id: self._session_snapshot(session)
                    for connection_id, session in self._sessions.items()
                },
                "refusals": [
                    {
                        "connection_id": record.connection_id,
                        "source": record.source,
                        "code": record.code,
                        "at": record.at,
                    }
                    for record in self._refusals
                ],
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        services, sessions, refusals, stats = self._decode_snapshot(state)
        with self._lock:
            self._services = services
            self._sessions = sessions
            self._refusals = refusals
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _channel_binding_status(cbt: str | None,
                                binding_material: str) -> str:
        if cbt is None or cbt == "":
            return "missing"
        expected = hashlib.sha256(
            f"cbt|{binding_material}".encode()
        ).hexdigest()
        if cbt.lower() == expected:
            return "ok"
        return "mismatch"

    @staticmethod
    def _mic_status_for(nt_response: str, mic: str | None,
                        challenge_token: str) -> str:
        if mic is None or mic == "":
            return "missing"
        expected = hashlib.sha256(
            f"mic|{challenge_token}|{nt_response}".encode()
        ).hexdigest()
        if mic.lower() == expected:
            return "ok"
        return "invalid"

    def _mic_status(self, message: Type3Message,
                    challenge_token: str) -> str:
        return self._mic_status_for(
            message.nt_response, message.mic, challenge_token
        )

    def _refuse(self, session: _SessionState, code: str, at: int, *,
                consume_attempt: bool,
                mic_status: str | None = None) -> SessionResult:
        attempts_left = session.attempts_left
        if consume_attempt and attempts_left > 0:
            attempts_left -= 1
        self._sessions[session.connection_id] = _SessionState(
            connection_id=session.connection_id,
            service=session.service,
            spn=session.spn,
            token=session.token,
            binding_material=session.binding_material,
            client_flags=session.client_flags,
            source=session.source,
            require_cbt=session.require_cbt,
            strict_mic=session.strict_mic,
            started_at=session.started_at,
            challenge_ttl=session.challenge_ttl,
            max_skew_seconds=session.max_skew_seconds,
            attempts_left=attempts_left,
            completed=session.completed,
            session_key=session.session_key,
            mic_status=session.mic_status if mic_status is None else mic_status,
        )
        self._refusals.append(RefusalRecord(
            connection_id=session.connection_id,
            source=session.source,
            code=code,
            at=at,
        ))
        self._stats["refused"] += 1
        return SessionResult(
            status="refused",
            code=code,
            session_key=None,
            mic_status=mic_status or session.mic_status or "missing",
        )

    @staticmethod
    def _session_snapshot(session: _SessionState) -> dict:
        return {
            "connection_id": session.connection_id,
            "service": session.service,
            "spn": session.spn,
            "token": session.token,
            "binding_material": session.binding_material,
            "client_flags": session.client_flags,
            "source": session.source,
            "require_cbt": session.require_cbt,
            "strict_mic": session.strict_mic,
            "started_at": session.started_at,
            "challenge_ttl": session.challenge_ttl,
            "max_skew_seconds": session.max_skew_seconds,
            "attempts_left": session.attempts_left,
            "completed": session.completed,
            "session_key": session.session_key,
            "mic_status": session.mic_status,
        }

    @classmethod
    def _decode_snapshot(cls, state: object) -> tuple[
            dict[str, ServicePolicy],
            dict[str, _SessionState],
            list[RefusalRecord],
            dict[str, int]]:
        if not isinstance(state, dict):
            raise _snapshot_invalid("snapshot must be an object")
        if set(state) != _SNAPSHOT_KEYS:
            raise _snapshot_invalid("snapshot has an unexpected shape")
        if type(state["version"]) is not int or state["version"] != 1:
            raise _snapshot_invalid("unsupported snapshot version")

        raw_services = state["services"]
        raw_sessions = state["sessions"]
        raw_refusals = state["refusals"]
        raw_stats = state["stats"]
        if not isinstance(raw_services, dict):
            raise _snapshot_invalid("services must be an object")
        if not isinstance(raw_sessions, dict):
            raise _snapshot_invalid("sessions must be an object")
        if not isinstance(raw_refusals, list):
            raise _snapshot_invalid("refusals must be a list")
        if not isinstance(raw_stats, dict):
            raise _snapshot_invalid("stats must be an object")

        services: dict[str, ServicePolicy] = {}
        for service, raw in raw_services.items():
            if not isinstance(service, str) or not service:
                raise _snapshot_invalid("invalid service key")
            if not isinstance(raw, dict) or set(raw) != _SERVICE_FIELDS:
                raise _snapshot_invalid("invalid service policy")
            if raw["service"] != service:
                raise _snapshot_invalid("service policy key mismatch")
            if not isinstance(raw["spn"], str) or not raw["spn"]:
                raise _snapshot_invalid("invalid service SPN")
            if type(raw["require_cbt"]) is not bool:
                raise _snapshot_invalid("require_cbt must be a boolean")
            if type(raw["strict_mic"]) is not bool:
                raise _snapshot_invalid("strict_mic must be a boolean")
            services[service] = ServicePolicy(
                service=service,
                spn=raw["spn"],
                require_cbt=raw["require_cbt"],
                strict_mic=raw["strict_mic"],
            )

        sessions: dict[str, _SessionState] = {}
        for connection_id, raw in raw_sessions.items():
            if not isinstance(connection_id, str) or not connection_id:
                raise _snapshot_invalid("invalid connection key")
            if not isinstance(raw, dict) or set(raw) != _SESSION_FIELDS:
                raise _snapshot_invalid("invalid session state")
            if raw["connection_id"] != connection_id:
                raise _snapshot_invalid("session key mismatch")
            for field in ("service", "spn", "token", "binding_material",
                          "source"):
                if not isinstance(raw[field], str):
                    raise _snapshot_invalid(f"invalid session {field}")
            if not raw["service"] or not raw["spn"]:
                raise _snapshot_invalid("invalid session service or SPN")
            if raw["service"] not in services:
                raise _snapshot_invalid("session references unknown service")
            if not _is_hex(raw["token"], 32):
                raise _snapshot_invalid("invalid challenge token")
            if not _is_int(raw["client_flags"]) or raw["client_flags"] < 0:
                raise _snapshot_invalid("invalid client_flags")
            expected_token_material = (
                f"challenge|{connection_id}|{raw['service']}|"
                f"{raw['client_flags']}|{raw['binding_material']}"
            )
            expected_token = hashlib.sha256(
                expected_token_material.encode()
            ).hexdigest()[:32]
            if raw["token"] != expected_token:
                raise _snapshot_invalid("challenge token does not match state")
            if type(raw["require_cbt"]) is not bool:
                raise _snapshot_invalid("session require_cbt must be a boolean")
            if type(raw["strict_mic"]) is not bool:
                raise _snapshot_invalid("session strict_mic must be a boolean")
            for field in ("started_at", "challenge_ttl", "max_skew_seconds",
                          "attempts_left"):
                if not _is_int(raw[field]) or raw[field] < 0:
                    raise _snapshot_invalid(f"invalid session {field}")
            if type(raw["completed"]) is not bool:
                raise _snapshot_invalid("completed must be a boolean")
            mic_status = raw["mic_status"]
            if mic_status is not None and mic_status not in _MIC_STATUSES:
                raise _snapshot_invalid("invalid session mic_status")
            session_key = raw["session_key"]
            if raw["completed"]:
                if not isinstance(session_key, str) or not _is_hex(
                        session_key, 64):
                    raise _snapshot_invalid("completed session has no valid key")
            elif session_key is not None:
                raise _snapshot_invalid(
                    "incomplete session must not have a session key"
                )
            sessions[connection_id] = _SessionState(
                connection_id=connection_id,
                service=raw["service"],
                spn=raw["spn"],
                token=raw["token"],
                binding_material=raw["binding_material"],
                client_flags=raw["client_flags"],
                source=raw["source"],
                require_cbt=raw["require_cbt"],
                strict_mic=raw["strict_mic"],
                started_at=raw["started_at"],
                challenge_ttl=raw["challenge_ttl"],
                max_skew_seconds=raw["max_skew_seconds"],
                attempts_left=raw["attempts_left"],
                completed=raw["completed"],
                session_key=session_key,
                mic_status=mic_status,
            )

        refusals: list[RefusalRecord] = []
        for raw in raw_refusals:
            if not isinstance(raw, dict) or set(raw) != _REFUSAL_FIELDS:
                raise _snapshot_invalid("invalid refusal record")
            if not isinstance(raw["connection_id"], str):
                raise _snapshot_invalid("invalid refusal connection_id")
            if not isinstance(raw["source"], str):
                raise _snapshot_invalid("invalid refusal source")
            if not isinstance(raw["code"], str) or not raw["code"]:
                raise _snapshot_invalid("invalid refusal code")
            if not _is_int(raw["at"]):
                raise _snapshot_invalid("invalid refusal timestamp")
            refusals.append(RefusalRecord(
                connection_id=raw["connection_id"],
                source=raw["source"],
                code=raw["code"],
                at=raw["at"],
            ))

        if set(raw_stats) != _STATS_FIELDS:
            raise _snapshot_invalid("invalid stats shape")
        stats: dict[str, int] = {}
        for field in _STATS_FIELDS:
            value = raw_stats[field]
            if not _is_int(value) or value < 0:
                raise _snapshot_invalid(f"invalid stat {field}")
            stats[field] = value

        return services, sessions, refusals, stats
