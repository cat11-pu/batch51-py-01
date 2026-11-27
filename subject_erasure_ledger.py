"""Subject erasure ledger: per-shard deletion tasks, receipts and residual escalation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ErasureError(ValueError):
    """Raised when an erasure operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TaskView:
    subject_id: str
    generation: int
    shard: str
    state: str
    attempts: int
    dispatched_at: int | None
    confirmed_at: int | None


@dataclass(frozen=True)
class ErasureTicket:
    request_id: str
    subject_id: str
    generation: int
    state: str
    tasks: tuple[TaskView, ...]
    submitted_at: int
    closed_at: int | None


@dataclass(frozen=True)
class DispatchPlan:
    request_id: str
    created: tuple[str, ...]
    existing: tuple[str, ...]


class SubjectErasureLedger:
    """Track erasure requests across storage shards from submission to closure."""

    def __init__(self, *, shards=("blob", "index", "audit"),
                 max_attempts: int = 3) -> None:
        self.shards = tuple(shards)
        self.max_attempts = max_attempts
        self._lock = threading.RLock()

    def submit_request(self, subject_id: str, generation: int, *,
                       now: int) -> ErasureTicket:
        raise NotImplementedError

    def dispatch(self, subject_id: str, generation: int, *,
                 now: int) -> DispatchPlan:
        raise NotImplementedError

    def confirm(self, subject_id: str, shard: str, *, generation: int,
                now: int) -> ErasureTicket:
        raise NotImplementedError

    def audit_residual(self, subject_id: str, shard: str, *, generation: int,
                       residual_count: int, now: int) -> ErasureTicket:
        raise NotImplementedError

    def retry(self, subject_id: str, shard: str, *, generation: int,
              now: int) -> TaskView:
        raise NotImplementedError

    def resume(self, *, now: int) -> tuple:
        raise NotImplementedError

    def close(self, subject_id: str, generation: int, *, now: int) -> ErasureTicket:
        raise NotImplementedError

    def request(self, subject_id: str, generation: int) -> ErasureTicket:
        raise NotImplementedError

    def residuals(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
