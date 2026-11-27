"""Userfaultfd budget guard: per-tenant instances, handler quotas, queue backpressure."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class UffdError(ValueError):
    """Raised when the guard refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TenantQuota:
    max_instances: int
    max_threads: int
    queue_capacity: int


@dataclass(frozen=True)
class InstanceView:
    instance_id: str
    tenant: str
    state: str
    ranges: tuple[tuple[int, int], ...]
    threads: tuple[str, ...]
    queued: int


class UserfaultfdBudgetGuard:
    """Track userfaultfd instances, their ranges, handlers and event queues."""

    def __init__(self, *, queue_capacity: int = 8, idle_timeout: int = 30,
                 clock=None) -> None:
        self.queue_capacity = queue_capacity
        self.idle_timeout = idle_timeout
        self._clock = clock
        self._lock = threading.RLock()

    def set_tenant_quota(self, tenant: str, *, max_instances: int,
                        max_threads: int, queue_capacity: int) -> TenantQuota:
        raise NotImplementedError

    def register(self, instance_id: str, tenant: str, *, threads: int = 0,
                 now=None) -> InstanceView:
        raise NotImplementedError

    def attach_range(self, instance_id: str, start: int,
                     length: int) -> tuple[int, int]:
        raise NotImplementedError

    def detach_range(self, instance_id: str, start: int,
                     length: int) -> tuple[tuple[int, int], ...]:
        raise NotImplementedError

    def spawn_handler(self, instance_id: str, thread_id: str) -> None:
        raise NotImplementedError

    def retire_handler(self, instance_id: str, thread_id: str,
                       *, crashed: bool = False) -> None:
        raise NotImplementedError

    def enqueue_event(self, instance_id: str, event, *,
                      policy: str = "drop") -> str:
        raise NotImplementedError

    def drain(self, instance_id: str, max_events=None) -> list:
        raise NotImplementedError

    def release(self, instance_id: str, *, force: bool = False,
                now=None) -> InstanceView:
        raise NotImplementedError

    def rebuild(self, instance_id: str, *, threads: int = 0,
                now=None) -> InstanceView:
        raise NotImplementedError

    def recover(self, now=None) -> dict:
        raise NotImplementedError

    def describe(self, instance_id: str) -> InstanceView:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
