"""Signature counter watermark tracking and authenticator clone quarantine."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CloneDetectorError(ValueError):
    """Refusal raised by the authenticator clone detector."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CredentialView:
    account: str
    credential_id: str
    status: str
    counter_capable: bool
    watermark: int
    regressions: int


@dataclass(frozen=True)
class ObservationVerdict:
    status: str
    code: str
    watermark: int
    regressions: int
    quarantined: bool


@dataclass(frozen=True)
class ReviewRecord:
    credential_id: str
    reviewer: str
    at: int


class CloneDetector:
    """Track per credential signature counters and isolate cloned authenticators."""

    def __init__(self, *, quarantine_after: int = 2) -> None:
        self.quarantine_after = quarantine_after
        self._lock = threading.RLock()

    def register_credential(self, account: str, *, credential_id: str,
                            counter_capable: bool = True,
                            at: int = 0) -> CredentialView:
        raise NotImplementedError

    def observe(self, account: str, *, credential_id: str, counter: int,
                at: int) -> ObservationVerdict:
        raise NotImplementedError

    def credential_state(self, credential_id: str) -> CredentialView:
        raise NotImplementedError

    def list_credentials(self, account: str) -> tuple:
        raise NotImplementedError

    def quarantine(self, credential_id: str, *, reason: str, at: int = 0) -> bool:
        raise NotImplementedError

    def release_after_review(self, credential_id: str, *, reviewer: str,
                             at: int) -> CredentialView:
        raise NotImplementedError

    def revoke_credential(self, credential_id: str) -> bool:
        raise NotImplementedError

    def login_allowed(self, account: str, *, credential_id: str) -> bool:
        raise NotImplementedError

    def account_summary(self, account: str) -> dict:
        raise NotImplementedError

    def reviews(self, credential_id: str) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
