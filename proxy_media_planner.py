"""Proxy media planning: deduplicated generation queue, tier cache and relinking."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ProxyError(ValueError):
    """Raised when a proxy media operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TaskRecord:
    """One proxy generation task."""

    task_id: str
    asset_id: str
    checksum: str
    tier: str
    status: str
    attempts: int
    output_path: str | None
    stale: bool


class ProxyMediaPlanner:
    """Queue proxy renders per asset fingerprint and tier, then relink the timeline."""

    def __init__(self, *, tiers=("half", "quarter", "eighth"), max_tasks: int = 16,
                 max_workers: int = 2, max_attempts: int = 3) -> None:
        self.tiers = tiers
        self.max_tasks = max_tasks
        self.max_workers = max_workers
        self.max_attempts = max_attempts
        self._lock = threading.RLock()
        self._tasks: dict = {}
        self._order: list = []
        self._next_task = 1
        self._counters = {
            "enqueued": 0,
            "started": 0,
            "completed": 0,
            "failed": 0,
            "invalidated": 0,
            "retries": 0,
        }

    def enqueue(self, asset_id: str, *, checksum: str, tier: str,
                mtime: int | None = None) -> TaskRecord:
        raise NotImplementedError

    def start_next(self) -> str | None:
        raise NotImplementedError

    def complete(self, task_id: str, *, output_path: str) -> TaskRecord:
        raise NotImplementedError

    def fail(self, task_id: str) -> TaskRecord:
        raise NotImplementedError

    def progress(self, task_id: str) -> dict:
        raise NotImplementedError

    def resolve(self, asset_id: str, *, tier: str) -> TaskRecord:
        raise NotImplementedError

    def relink(self, asset_id: str, *, checksum: str, tier: str) -> str:
        raise NotImplementedError

    def invalidate(self, asset_id: str, *, checksum: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
