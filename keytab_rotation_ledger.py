"""Keytab rotation ledger: monotonic versions, replica confirmation, retention."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class KeytabError(ValueError):
    """Raised when a rotation step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReplicaState:
    replica_id: str
    status: str


@dataclass(frozen=True)
class KeyVersion:
    principal: str
    version: int
    state: str
    request_id: str | None
    replicas: tuple[ReplicaState, ...]
    created_at: str
    retained_at: str | None


class KeytabRotationLedger:
    """Track one key version at a time per principal and its replica rollout."""

    def __init__(self, *, retention: int = 3600, clock=None) -> None:
        self.retention = retention
        self._clock = clock
        self._lock = threading.RLock()

    def register_principal(self, *, principal: str, replicas) -> None:
        raise NotImplementedError

    def rotate(self, *, principal: str, request_id: str | None = None,
               now: str | None = None) -> KeyVersion:
        raise NotImplementedError

    def distribute(self, *, principal: str, version: int,
                   now: str | None = None) -> tuple[ReplicaState, ...]:
        raise NotImplementedError

    def confirm(self, *, principal: str, version: int, replica_id: str,
                ok: bool = True, now: str | None = None) -> KeyVersion:
        raise NotImplementedError

    def retire(self, *, principal: str, version: int | None = None,
               now: str | None = None) -> int:
        raise NotImplementedError

    def active_version(self, principal: str) -> int | None:
        raise NotImplementedError

    def issuable_versions(self, principal: str) -> tuple[int, ...]:
        raise NotImplementedError

    def verifiable_versions(self, principal: str) -> tuple[int, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
