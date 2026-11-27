"""Scheduler affinity warden: tenant ceilings, online sets, reconcile with fallback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SchedError(ValueError):
    """Raised when the warden refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProcessAffinity:
    pid: int
    tenant: str
    desired: frozenset
    effective: frozenset
    epoch: int


class SchedAffinityWarden:
    """Keep tenant cpu ceilings, the online set and per-process affinity."""

    def __init__(self, *, cpus=(0, 1, 2, 3)) -> None:
        self.cpus = tuple(sorted(cpus))
        self._lock = threading.RLock()

    def set_allowed(self, tenant: str, cpus) -> tuple[int, ...]:
        raise NotImplementedError

    def allowed_for(self, tenant: str) -> tuple[int, ...]:
        raise NotImplementedError

    def set_online(self, cpus) -> tuple[int, ...]:
        raise NotImplementedError

    def register_process(self, pid: int, tenant: str, cpus) -> ProcessAffinity:
        raise NotImplementedError

    def unregister_process(self, pid: int) -> bool:
        raise NotImplementedError

    def apply(self, pid: int, cpus) -> ProcessAffinity:
        raise NotImplementedError

    def effective_set(self, pid: int) -> frozenset:
        raise NotImplementedError

    def reconcile(self) -> dict:
        raise NotImplementedError

    def history(self, pid: int) -> list[dict]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
