"""NTLM relay guard: challenge-to-target binding, EPA enforcement, replay detection."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class NtlmRelayError(ValueError):
    """Raised when the guard refuses a negotiation step."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TargetInfo:
    service_id: str
    channel_id: str
    epa_policy: str


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    account: str
    service_id: str
    channel_id: str
    nonce: str
    issued_at: str
    expires_at: str
    state: str


@dataclass(frozen=True)
class ResponseVerdict:
    challenge_id: str
    account: str
    service_id: str
    channel_id: str
    status: str


@dataclass(frozen=True)
class EpaVerdict:
    service_id: str
    policy: str
    status: str
    bound: bool


class NtlmRelayGuard:
    """Bind every challenge to one target service and one source channel."""

    def __init__(self, *, challenge_ttl: int = 120,
                 max_pending_per_account: int = 8, clock=None) -> None:
        self.challenge_ttl = challenge_ttl
        self.max_pending_per_account = max_pending_per_account
        self._clock = clock
        self._lock = threading.RLock()

    def register_target(self, *, service_id: str, channel_id: str,
                        epa_policy: str = "optional") -> None:
        raise NotImplementedError

    def target_info(self, service_id: str) -> TargetInfo:
        raise NotImplementedError

    def issue_challenge(self, *, account: str, service_id: str,
                        channel_id: str, nonce: str | None = None,
                        now: str | None = None) -> Challenge:
        raise NotImplementedError

    def bind_target(self, *, challenge_id: str, service_id: str,
                    channel_id: str, now: str | None = None) -> Challenge:
        raise NotImplementedError

    def verify_response(self, *, challenge_id: str, account: str,
                        channel_id: str, response_digest: str,
                        now: str | None = None) -> ResponseVerdict:
        raise NotImplementedError

    def check_epa(self, *, service_id: str,
                  client_digest: str | None = None) -> EpaVerdict:
        raise NotImplementedError

    def pending_for(self, account: str, *, now: str | None = None) -> list[Challenge]:
        raise NotImplementedError

    def expire_pending(self, *, now: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
