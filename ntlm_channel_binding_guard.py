"""NTLM channel binding, target SPN, MIC and timestamp skew validation."""

from __future__ import annotations

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


class NtlmBindingGuard:
    """Validate inbound NTLM type 1 / type 3 messages before session setup."""

    def __init__(self, *, max_skew_seconds: int = 300, max_attempts: int = 3,
                 challenge_ttl: int = 120) -> None:
        self.max_skew_seconds = max_skew_seconds
        self.max_attempts = max_attempts
        self.challenge_ttl = challenge_ttl
        self._lock = threading.RLock()

    def register_service(self, service: str, *, spn: str, require_cbt: bool = True,
                         strict_mic: bool = False) -> ServicePolicy:
        raise NotImplementedError

    def service_policy(self, service: str) -> ServicePolicy:
        raise NotImplementedError

    def begin(self, connection_id: str, *, service: str, client_flags: int,
              binding_material: str, source: str, at: int) -> Challenge:
        raise NotImplementedError

    def complete(self, connection_id: str, *, fields: dict, at: int) -> SessionResult:
        raise NotImplementedError

    def parse_type3(self, fields: dict) -> Type3Message:
        raise NotImplementedError

    def channel_binding_status(self, fields: dict, binding_material: str) -> str:
        raise NotImplementedError

    def verify_mic(self, fields: dict, *, challenge_token: str) -> str:
        raise NotImplementedError

    def session_key(self, connection_id: str):
        raise NotImplementedError

    def attempts_left(self, connection_id: str) -> int:
        raise NotImplementedError

    def refusals(self, *, source: str | None = None) -> list:
        raise NotImplementedError

    def close(self, connection_id: str) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
