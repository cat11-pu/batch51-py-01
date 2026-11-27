"""Process identity pinner: freeze a pid into an identity handle, re-check by triple."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ProcError(ValueError):
    """Raised when the pinner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProcHandle:
    handle_id: str
    owner: str
    pid: int
    start_time: int
    namespace: str
    pinned_at: int
    last_used: int
    state: str


@dataclass(frozen=True)
class ResolvedIdentity:
    handle_id: str
    pid: int
    start_time: int
    namespace: str
    state: str
    exe: str | None
    cwd: str | None
    available: bool


class ProcIdentityPinner:
    """Pin process observations into handles and judge them by identity triple."""

    def __init__(self, *, max_handles: int = 8, idle_timeout: int = 60,
                 clock=None) -> None:
        self.max_handles = max_handles
        self.idle_timeout = idle_timeout
        self._clock = clock
        self._lock = threading.RLock()

    def ingest_proc_table(self, entries) -> int:
        raise NotImplementedError

    def pin(self, pid: int, *, owner: str = "default", now=None) -> ProcHandle:
        raise NotImplementedError

    def resolve(self, handle_id: str, *, now=None) -> ResolvedIdentity:
        raise NotImplementedError

    def still_alive(self, handle_id: str, *, now=None) -> bool:
        raise NotImplementedError

    def invalid_reason(self, handle_id: str) -> str | None:
        raise NotImplementedError

    def release(self, handle_id: str, *, now=None) -> bool:
        raise NotImplementedError

    def release_owner(self, owner: str, *, now=None) -> int:
        raise NotImplementedError

    def handles_for(self, owner: str) -> list[str]:
        raise NotImplementedError

    def reap_idle(self, now=None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
