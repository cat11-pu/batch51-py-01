"""Subject erasure ledger: per-shard deletion tasks, receipts and residual escalation."""

from __future__ import annotations

import json
import re
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


@dataclass
class _RequestRecord:
    request_id: str
    subject_id: str
    generation: int
    state: str
    submitted_at: int
    closed_at: int | None


@dataclass
class _TaskRecord:
    subject_id: str
    generation: int
    shard: str
    state: str
    attempts: int
    dispatched_at: int | None
    confirmed_at: int | None
    residual_count: int = 0
    audited_at: int | None = None


_REQUEST_STATES = frozenset({"new", "in_progress", "residual", "closed"})
_TASK_STATES = frozenset(
    {"pending", "dispatched", "confirmed", "residual_unclosable"}
)
_STAT_KEYS = (
    "submissions",
    "dispatches",
    "confirmations",
    "duplicate_confirmations",
    "retries",
    "reopened",
    "escalated",
    "closed",
)
_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "subject_id",
        "generation",
        "state",
        "submitted_at",
        "closed_at",
    }
)
_TASK_FIELDS = frozenset(
    {
        "subject_id",
        "generation",
        "shard",
        "state",
        "attempts",
        "dispatched_at",
        "confirmed_at",
        "residual_count",
        "audited_at",
    }
)
_REQUEST_ID_RE = re.compile(r"era-(\d+)\Z")
_SNAPSHOT_VERSION = 1


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _empty_stats() -> dict[str, int]:
    return {key: 0 for key in _STAT_KEYS}


class SubjectErasureLedger:
    """Track erasure requests across storage shards from submission to closure."""

    def __init__(self, *, shards=("blob", "index", "audit"),
                 max_attempts: int = 3) -> None:
        if isinstance(shards, str):
            raise ErasureError("ERASURE_INVALID_REQUEST", "shards must be a sequence")
        try:
            shard_tuple = tuple(shards)
        except TypeError as exc:
            raise ErasureError(
                "ERASURE_INVALID_REQUEST", "shards must be a sequence"
            ) from exc
        if not shard_tuple or any(
            not isinstance(shard, str) or not shard
            for shard in shard_tuple
        ):
            raise ErasureError(
                "ERASURE_INVALID_REQUEST", "shards must contain non-empty names"
            )
        if not _is_int(max_attempts) or max_attempts < 1:
            raise ErasureError(
                "ERASURE_INVALID_REQUEST", "max_attempts must be at least 1"
            )

        self.shards = shard_tuple
        self.max_attempts = max_attempts
        self._shards = tuple(sorted(set(shard_tuple)))
        self._lock = threading.RLock()
        self._requests: dict[tuple[str, int], _RequestRecord] = {}
        self._tasks: dict[tuple[str, str, int], _TaskRecord] = {}
        self._next_request = 1
        self._stats = _empty_stats()

    @staticmethod
    def _validate_request_key(subject_id: str, generation: int) -> None:
        if not isinstance(subject_id, str) or not subject_id.strip():
            raise ErasureError(
                "ERASURE_INVALID_REQUEST",
                {"subject_id": subject_id},
            )
        if not _is_int(generation) or generation < 1:
            raise ErasureError(
                "ERASURE_INVALID_REQUEST",
                {"generation": generation},
            )

    def _lookup_request(self, subject_id: str,
                        generation: int) -> _RequestRecord:
        self._validate_request_key(subject_id, generation)
        request = self._requests.get((subject_id, generation))
        if request is not None:
            return request
        if any(subject == subject_id for subject, _ in self._requests):
            raise ErasureError(
                "ERASURE_GENERATION_MISMATCH",
                {"subject_id": subject_id, "generation": generation},
            )
        raise ErasureError(
            "ERASURE_UNKNOWN_SUBJECT",
            {"subject_id": subject_id, "generation": generation},
        )

    def _require_shard(self, shard: str) -> None:
        if not isinstance(shard, str) or shard not in self._shards:
            raise ErasureError("ERASURE_UNKNOWN_SHARD", {"shard": shard})

    def _task_for(self, request: _RequestRecord, shard: str) -> _TaskRecord:
        task = self._tasks.get((request.subject_id, shard, request.generation))
        if task is None:  # pragma: no cover - protected by restore validation
            raise ErasureError(
                "ERASURE_SNAPSHOT_INVALID",
                {"subject_id": request.subject_id, "shard": shard},
            )
        return task

    def _request_tasks(self, request: _RequestRecord) -> list[_TaskRecord]:
        return [
            self._task_for(request, shard)
            for shard in self._shards
        ]

    @staticmethod
    def _task_view(task: _TaskRecord) -> TaskView:
        return TaskView(
            subject_id=task.subject_id,
            generation=task.generation,
            shard=task.shard,
            state=task.state,
            attempts=task.attempts,
            dispatched_at=task.dispatched_at,
            confirmed_at=task.confirmed_at,
        )

    def _request_view(self, request: _RequestRecord) -> ErasureTicket:
        return ErasureTicket(
            request_id=request.request_id,
            subject_id=request.subject_id,
            generation=request.generation,
            state=request.state,
            tasks=tuple(
                self._task_view(task)
                for task in self._request_tasks(request)
            ),
            submitted_at=request.submitted_at,
            closed_at=request.closed_at,
        )

    def _recompute_request_state(self, request: _RequestRecord) -> None:
        tasks = self._request_tasks(request)
        if any(task.state == "residual_unclosable" for task in tasks):
            request.state = "residual"
            request.closed_at = None
            return
        if request.state == "closed":
            if all(task.state == "confirmed" for task in tasks):
                return
            request.state = "in_progress"
            request.closed_at = None
            return
        if all(task.state == "confirmed" for task in tasks):
            request.state = "in_progress"
            return
        if request.state == "new":
            pristine = all(
                task.state == "pending"
                and task.attempts == 0
                and task.dispatched_at is None
                for task in tasks
            )
            if pristine:
                return
        request.state = "in_progress"

    def submit_request(self, subject_id: str, generation: int, *,
                       now: int) -> ErasureTicket:
        with self._lock:
            self._validate_request_key(subject_id, generation)
            key = (subject_id, generation)
            existing = self._requests.get(key)
            if existing is not None:
                return self._request_view(existing)

            request = _RequestRecord(
                request_id=f"era-{self._next_request:04d}",
                subject_id=subject_id,
                generation=generation,
                state="new",
                submitted_at=now,
                closed_at=None,
            )
            self._requests[key] = request
            for shard in self._shards:
                self._tasks[(subject_id, shard, generation)] = _TaskRecord(
                    subject_id=subject_id,
                    generation=generation,
                    shard=shard,
                    state="pending",
                    attempts=0,
                    dispatched_at=None,
                    confirmed_at=None,
                )
            self._next_request += 1
            self._stats["submissions"] += 1
            return self._request_view(request)

    def dispatch(self, subject_id: str, generation: int, *,
                 now: int) -> DispatchPlan:
        with self._lock:
            request = self._lookup_request(subject_id, generation)
            created: list[str] = []
            existing: list[str] = []
            for task in self._request_tasks(request):
                if task.state == "pending":
                    task.state = "dispatched"
                    task.dispatched_at = now
                    task.confirmed_at = None
                    created.append(task.shard)
                else:
                    existing.append(task.shard)
            self._stats["dispatches"] += 1
            self._recompute_request_state(request)
            return DispatchPlan(
                request_id=request.request_id,
                created=tuple(created),
                existing=tuple(existing),
            )

    def confirm(self, subject_id: str, shard: str, *, generation: int,
                now: int) -> ErasureTicket:
        with self._lock:
            request = self._lookup_request(subject_id, generation)
            self._require_shard(shard)
            task = self._task_for(request, shard)

            if task.state == "confirmed":
                self._stats["duplicate_confirmations"] += 1
                return self._request_view(request)
            if task.state == "pending":
                raise ErasureError(
                    "ERASURE_NOT_DISPATCHED",
                    {"subject_id": subject_id, "generation": generation,
                     "shard": shard},
                )
            if task.state == "residual_unclosable":
                raise ErasureError(
                    "ERASURE_RESIDUAL_UNCLOSABLE",
                    {"subject_id": subject_id, "generation": generation,
                     "shard": shard},
                )
            if task.state != "dispatched":  # pragma: no cover
                raise ErasureError(
                    "ERASURE_INVALID_REQUEST",
                    {"task_state": task.state},
                )

            task.state = "confirmed"
            task.confirmed_at = now
            self._stats["confirmations"] += 1
            self._recompute_request_state(request)
            return self._request_view(request)

    def audit_residual(self, subject_id: str, shard: str, *, generation: int,
                       residual_count: int, now: int) -> ErasureTicket:
        with self._lock:
            request = self._lookup_request(subject_id, generation)
            self._require_shard(shard)
            if not _is_int(residual_count) or residual_count < 0:
                raise ErasureError(
                    "ERASURE_INVALID_REQUEST",
                    {"residual_count": residual_count},
                )

            task = self._task_for(request, shard)
            task.residual_count = residual_count
            task.audited_at = now
            if residual_count > 0:
                if task.state in {"dispatched", "confirmed"}:
                    if task.state == "confirmed":
                        self._stats["reopened"] += 1
                    task.state = "pending"
                    task.dispatched_at = None
                    task.confirmed_at = None
            self._recompute_request_state(request)
            return self._request_view(request)

    def retry(self, subject_id: str, shard: str, *, generation: int,
              now: int) -> TaskView:
        with self._lock:
            request = self._lookup_request(subject_id, generation)
            self._require_shard(shard)
            task = self._task_for(request, shard)

            if task.state == "residual_unclosable":
                raise ErasureError(
                    "ERASURE_RESIDUAL_UNCLOSABLE",
                    {"subject_id": subject_id, "generation": generation,
                     "shard": shard},
                )
            if task.state != "dispatched":
                raise ErasureError(
                    "ERASURE_NOT_DISPATCHED",
                    {"subject_id": subject_id, "generation": generation,
                     "shard": shard, "task_state": task.state},
                )

            self._stats["retries"] += 1
            task.attempts += 1
            task.dispatched_at = now
            task.confirmed_at = None
            if task.attempts >= self.max_attempts:
                task.state = "residual_unclosable"
                self._stats["escalated"] += 1
            else:
                task.state = "dispatched"
            self._recompute_request_state(request)
            return self._task_view(task)

    def resume(self, *, now: int) -> tuple:
        with self._lock:
            active: dict[tuple[str, str], int] = {}
            for task in self._tasks.values():
                if task.state not in {"pending", "dispatched"}:
                    continue
                pair = (task.subject_id, task.shard)
                previous_generation = active.get(pair)
                if (previous_generation is None
                        or task.generation > previous_generation):
                    active[pair] = task.generation
            return tuple(sorted(active))

    def close(self, subject_id: str, generation: int, *,
              now: int) -> ErasureTicket:
        with self._lock:
            request = self._lookup_request(subject_id, generation)
            tasks = self._request_tasks(request)
            residual_shards = tuple(
                task.shard
                for task in tasks
                if task.state == "residual_unclosable"
            )
            if residual_shards:
                raise ErasureError(
                    "ERASURE_RESIDUAL_UNCLOSABLE",
                    {"subject_id": subject_id, "generation": generation,
                     "shards": residual_shards},
                )
            if request.state == "closed":
                return self._request_view(request)
            if not all(task.state == "confirmed" for task in tasks):
                raise ErasureError(
                    "ERASURE_NOT_COMPLETE",
                    {"subject_id": subject_id, "generation": generation},
                )

            request.state = "closed"
            request.closed_at = now
            self._stats["closed"] += 1
            return self._request_view(request)

    def request(self, subject_id: str, generation: int) -> ErasureTicket:
        with self._lock:
            return self._request_view(
                self._lookup_request(subject_id, generation)
            )

    def residuals(self) -> list:
        with self._lock:
            residual_tasks = sorted(
                (
                    task for task in self._tasks.values()
                    if task.state == "residual_unclosable"
                ),
                key=lambda task: (
                    task.subject_id,
                    task.generation,
                    task.shard,
                ),
            )
            return [self._task_view(task) for task in residual_tasks]

    @staticmethod
    def _task_snapshot_key(task: _TaskRecord) -> str:
        return json.dumps(
            [task.subject_id, task.shard, task.generation],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @staticmethod
    def _request_record(request: _RequestRecord) -> dict:
        return {
            "request_id": request.request_id,
            "subject_id": request.subject_id,
            "generation": request.generation,
            "state": request.state,
            "submitted_at": request.submitted_at,
            "closed_at": request.closed_at,
        }

    @staticmethod
    def _task_record(task: _TaskRecord) -> dict:
        return {
            "subject_id": task.subject_id,
            "generation": task.generation,
            "shard": task.shard,
            "state": task.state,
            "attempts": task.attempts,
            "dispatched_at": task.dispatched_at,
            "confirmed_at": task.confirmed_at,
            "residual_count": task.residual_count,
            "audited_at": task.audited_at,
        }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "next_request": self._next_request,
                "requests": {
                    request.request_id: self._request_record(request)
                    for request in self._requests.values()
                },
                "tasks": {
                    self._task_snapshot_key(task): self._task_record(task)
                    for task in self._tasks.values()
                },
                "stats": dict(self._stats),
            }

    @staticmethod
    def _snapshot_error(detail: object) -> ErasureError:
        return ErasureError("ERASURE_SNAPSHOT_INVALID", detail)

    def _build_restore_candidate(
        self, state: dict
    ) -> tuple[
        dict[tuple[str, int], _RequestRecord],
        dict[tuple[str, str, int], _TaskRecord],
        int,
        dict[str, int],
    ]:
        if not isinstance(state, dict):
            raise self._snapshot_error("snapshot must be a dict")
        if set(state) != {
            "version", "next_request", "requests", "tasks", "stats"
        }:
            raise self._snapshot_error("snapshot fields are invalid")
        if (not _is_int(state["version"])
                or state["version"] != _SNAPSHOT_VERSION):
            raise self._snapshot_error("unsupported snapshot version")
        next_request = state["next_request"]
        if not _is_int(next_request) or next_request < 1:
            raise self._snapshot_error("next_request is invalid")
        if not isinstance(state["requests"], dict):
            raise self._snapshot_error("requests must be a dict")
        if not isinstance(state["tasks"], dict):
            raise self._snapshot_error("tasks must be a dict")

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(_STAT_KEYS):
            raise self._snapshot_error("stats fields are invalid")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                raise self._snapshot_error(f"stats.{key} is invalid")
            stats[key] = value

        requests: dict[tuple[str, int], _RequestRecord] = {}
        request_ids: dict[str, int] = {}
        used_numbers: set[int] = set()
        for key, raw_request in state["requests"].items():
            if not isinstance(key, str) or not isinstance(raw_request, dict):
                raise self._snapshot_error("request record is invalid")
            if set(raw_request) != _REQUEST_FIELDS:
                raise self._snapshot_error("request fields are invalid")
            request_id = raw_request["request_id"]
            subject_id = raw_request["subject_id"]
            generation = raw_request["generation"]
            request_state = raw_request["state"]
            submitted_at = raw_request["submitted_at"]
            closed_at = raw_request["closed_at"]

            if not isinstance(request_id, str) or key != request_id:
                raise self._snapshot_error("request key is invalid")
            match = _REQUEST_ID_RE.fullmatch(request_id)
            if match is None:
                raise self._snapshot_error("request id is invalid")
            request_number = int(match.group(1))
            if request_number < 1 or request_number in used_numbers:
                raise self._snapshot_error("request id is duplicated")
            used_numbers.add(request_number)

            try:
                self._validate_request_key(subject_id, generation)
            except ErasureError as exc:
                raise self._snapshot_error(str(exc.detail)) from exc
            if request_state not in _REQUEST_STATES:
                raise self._snapshot_error("request state is invalid")
            if not _is_int(submitted_at):
                raise self._snapshot_error("submitted_at is invalid")
            if closed_at is not None and not _is_int(closed_at):
                raise self._snapshot_error("closed_at is invalid")
            if request_state == "closed" and closed_at is None:
                raise self._snapshot_error("closed request has no closed_at")
            if request_state != "closed" and closed_at is not None:
                raise self._snapshot_error("open request has closed_at")

            identity = (subject_id, generation)
            if identity in requests or request_id in request_ids:
                raise self._snapshot_error("request identity is duplicated")
            request_ids[request_id] = request_number
            requests[identity] = _RequestRecord(
                request_id=request_id,
                subject_id=subject_id,
                generation=generation,
                state=request_state,
                submitted_at=submitted_at,
                closed_at=closed_at,
            )

        if sorted(used_numbers) != list(range(1, next_request)):
            raise self._snapshot_error("request sequence is invalid")

        tasks: dict[tuple[str, str, int], _TaskRecord] = {}
        grouped: dict[tuple[str, int], list[_TaskRecord]] = {}
        for key, raw_task in state["tasks"].items():
            if not isinstance(key, str) or not isinstance(raw_task, dict):
                raise self._snapshot_error("task record is invalid")
            if set(raw_task) != _TASK_FIELDS:
                raise self._snapshot_error("task fields are invalid")

            subject_id = raw_task["subject_id"]
            generation = raw_task["generation"]
            shard = raw_task["shard"]
            task_state = raw_task["state"]
            attempts = raw_task["attempts"]
            dispatched_at = raw_task["dispatched_at"]
            confirmed_at = raw_task["confirmed_at"]
            residual_count = raw_task["residual_count"]
            audited_at = raw_task["audited_at"]

            try:
                self._validate_request_key(subject_id, generation)
            except ErasureError as exc:
                raise self._snapshot_error(str(exc.detail)) from exc
            self._require_shard_for_snapshot(shard)
            if task_state not in _TASK_STATES:
                raise self._snapshot_error("task state is invalid")
            if not _is_int(attempts) or attempts < 0:
                raise self._snapshot_error("attempts is invalid")
            if dispatched_at is not None and not _is_int(dispatched_at):
                raise self._snapshot_error("dispatched_at is invalid")
            if confirmed_at is not None and not _is_int(confirmed_at):
                raise self._snapshot_error("confirmed_at is invalid")
            if not _is_int(residual_count) or residual_count < 0:
                raise self._snapshot_error("residual_count is invalid")
            if audited_at is not None and not _is_int(audited_at):
                raise self._snapshot_error("audited_at is invalid")

            if task_state == "pending":
                if dispatched_at is not None or confirmed_at is not None:
                    raise self._snapshot_error("pending task has timestamps")
            elif task_state == "dispatched":
                if dispatched_at is None or confirmed_at is not None:
                    raise self._snapshot_error("dispatched task timestamps")
            elif task_state == "confirmed":
                if dispatched_at is None or confirmed_at is None:
                    raise self._snapshot_error("confirmed task timestamps")
            elif task_state == "residual_unclosable":
                if dispatched_at is None or confirmed_at is not None:
                    raise self._snapshot_error("residual task timestamps")
                if attempts < self.max_attempts:
                    raise self._snapshot_error("residual task attempts")
            elif attempts >= self.max_attempts:
                raise self._snapshot_error("task attempts exceed budget")

            identity = (subject_id, shard, generation)
            if identity in tasks:
                raise self._snapshot_error("task identity is duplicated")
            task = _TaskRecord(
                subject_id=subject_id,
                generation=generation,
                shard=shard,
                state=task_state,
                attempts=attempts,
                dispatched_at=dispatched_at,
                confirmed_at=confirmed_at,
                residual_count=residual_count,
                audited_at=audited_at,
            )
            if key != self._task_snapshot_key(task):
                raise self._snapshot_error("task key is invalid")
            tasks[identity] = task
            grouped.setdefault((subject_id, generation), []).append(task)

        if stats["submissions"] != len(requests):
            raise self._snapshot_error("submissions stat is inconsistent")
        residual_count = sum(
            task.state == "residual_unclosable" for task in tasks.values()
        )
        if stats["escalated"] != residual_count:
            raise self._snapshot_error("escalated stat is inconsistent")

        for identity, request in requests.items():
            request_tasks = grouped.get(identity, [])
            if len(request_tasks) != len(self._shards):
                raise self._snapshot_error("request task count is invalid")
            if {task.shard for task in request_tasks} != set(self._shards):
                raise self._snapshot_error("request shards are invalid")
            has_residual = any(
                task.state == "residual_unclosable"
                for task in request_tasks
            )
            all_confirmed = all(
                task.state == "confirmed"
                for task in request_tasks
            )
            if has_residual and request.state != "residual":
                raise self._snapshot_error("request residual state is invalid")
            if request.state == "residual" and not has_residual:
                raise self._snapshot_error("request residual state is invalid")
            if request.state == "closed" and not all_confirmed:
                raise self._snapshot_error("closed request is incomplete")
            if request.state == "new" and not all(
                task.state == "pending"
                and task.attempts == 0
                and task.dispatched_at is None
                for task in request_tasks
            ):
                raise self._snapshot_error("new request has active tasks")
            if all_confirmed and request.state not in {"in_progress", "closed"}:
                raise self._snapshot_error("request completion is invalid")

        for identity in grouped:
            if identity not in requests:
                raise self._snapshot_error("orphan task records")

        return requests, tasks, next_request, stats

    def _require_shard_for_snapshot(self, shard: object) -> None:
        if not isinstance(shard, str) or shard not in self._shards:
            raise self._snapshot_error("task shard is invalid")

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = self._build_restore_candidate(state)
            except ErasureError:
                raise
            except Exception as exc:
                raise self._snapshot_error(str(exc)) from exc
            requests, tasks, next_request, stats = candidate
            self._requests = requests
            self._tasks = tasks
            self._next_request = next_request
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
