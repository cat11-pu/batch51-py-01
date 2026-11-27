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

    _STATUSES = ("queued", "running", "done", "failed", "invalid")
    _SNAPSHOT_VERSION = 1

    def __init__(self, *, tiers=("half", "quarter", "eighth"), max_tasks: int = 16,
                 max_workers: int = 2, max_attempts: int = 3) -> None:
        if (not isinstance(tiers, (list, tuple)) or not tiers
                or any(not isinstance(t, str) or not t.strip() for t in tiers)
                or len({t.strip() for t in tiers}) != len(tiers)):
            raise ProxyError("PROXY_INVALID_CONFIG", {"tiers": tiers})
        for name, value in (("max_tasks", max_tasks), ("max_workers", max_workers),
                            ("max_attempts", max_attempts)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ProxyError("PROXY_INVALID_CONFIG", {name: value})
        self.tiers = tiers
        self.max_tasks = max_tasks
        self.max_workers = max_workers
        self.max_attempts = max_attempts
        self._lock = threading.RLock()
        self._tasks: dict = {}
        self._order: list = []
        self._next_task = 1
        self._complete_seq = 0
        self._counters = {
            "enqueued": 0,
            "started": 0,
            "completed": 0,
            "failed": 0,
            "invalidated": 0,
            "retries": 0,
        }

    @staticmethod
    def _clean(value) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ProxyError("PROXY_INVALID", {"value": value})
        return value.strip()

    def _record(self, task: dict) -> TaskRecord:
        return TaskRecord(
            task_id=task["task_id"],
            asset_id=task["asset_id"],
            checksum=task["checksum"],
            tier=task["tier"],
            status=task["status"],
            attempts=task["attempts"],
            output_path=task["output_path"],
            stale=task["stale"],
        )

    def _live_count(self) -> int:
        return sum(1 for t in self._tasks.values()
                   if t["status"] in ("queued", "running"))

    def _find_task(self, task_id: str) -> dict:
        task = self._tasks.get(task_id)
        if task is None:
            raise ProxyError("PROXY_UNKNOWN", {"task_id": task_id})
        return task

    def enqueue(self, asset_id: str, *, checksum: str, tier: str,
                mtime: int | None = None) -> TaskRecord:
        asset_id = self._clean(asset_id)
        checksum = self._clean(checksum)
        tier = self._clean(tier)
        if tier not in self.tiers:
            raise ProxyError("PROXY_INVALID", {"tier": tier})
        with self._lock:
            for task in self._tasks.values():
                if (task["asset_id"], task["tier"]) != (asset_id, tier):
                    continue
                if task["status"] not in ("queued", "running"):
                    continue
                if task["checksum"] == checksum:
                    return self._record(task)
                task["status"] = "invalid"
                task["stale"] = True
                self._counters["invalidated"] += 1
            if self._live_count() >= self.max_tasks:
                raise ProxyError("PROXY_CAPACITY", {"max_tasks": self.max_tasks})
            task_id = f"task-{self._next_task}"
            self._next_task += 1
            task = {
                "task_id": task_id,
                "asset_id": asset_id,
                "checksum": checksum,
                "tier": tier,
                "status": "queued",
                "attempts": 0,
                "output_path": None,
                "mtime": mtime,
                "stale": False,
                "completed_seq": 0,
            }
            self._tasks[task_id] = task
            self._order.append(task_id)
            self._counters["enqueued"] += 1
            return self._record(task)

    def start_next(self) -> str | None:
        with self._lock:
            running = sum(1 for t in self._tasks.values()
                          if t["status"] == "running")
            if running >= self.max_workers:
                return None
            for task_id in self._order:
                task = self._tasks[task_id]
                if task["status"] == "queued":
                    task["status"] = "running"
                    self._counters["started"] += 1
                    return task_id
            return None

    def complete(self, task_id: str, *, output_path: str) -> TaskRecord:
        with self._lock:
            task = self._find_task(task_id)
            if task["status"] != "running":
                raise ProxyError("PROXY_INVALID_STATE", {"status": task["status"]})
            output_path = self._clean(output_path)
            task["status"] = "done"
            task["output_path"] = output_path
            self._complete_seq += 1
            task["completed_seq"] = self._complete_seq
            self._counters["completed"] += 1
            return self._record(task)

    def fail(self, task_id: str) -> TaskRecord:
        with self._lock:
            task = self._find_task(task_id)
            if task["status"] != "running":
                raise ProxyError("PROXY_INVALID_STATE", {"status": task["status"]})
            task["attempts"] += 1
            if task["attempts"] < self.max_attempts:
                task["status"] = "queued"
                self._order.remove(task_id)
                self._order.append(task_id)
                self._counters["retries"] += 1
            else:
                task["status"] = "failed"
                self._counters["failed"] += 1
            return self._record(task)

    def progress(self, task_id: str) -> dict:
        with self._lock:
            task = self._find_task(task_id)
            return {
                "task_id": task["task_id"],
                "asset_id": task["asset_id"],
                "checksum": task["checksum"],
                "tier": task["tier"],
                "status": task["status"],
                "attempts": task["attempts"],
                "output_path": task["output_path"],
            }

    def resolve(self, asset_id: str, *, tier: str) -> TaskRecord:
        asset_id = asset_id.strip() if isinstance(asset_id, str) else asset_id
        tier = tier.strip() if isinstance(tier, str) else tier
        with self._lock:
            matches = [t for t in self._tasks.values()
                       if t["asset_id"] == asset_id and t["tier"] == tier]
            if not matches:
                raise ProxyError("PROXY_UNKNOWN",
                                 {"asset_id": asset_id, "tier": tier})
            done = [t for t in matches if t["status"] == "done"]
            if done:
                return self._record(max(done, key=lambda t: t["completed_seq"]))
            if any(t["status"] in ("queued", "running") for t in matches):
                raise ProxyError("PROXY_NOT_READY",
                                 {"asset_id": asset_id, "tier": tier})
            if any(t["status"] == "invalid" for t in matches):
                raise ProxyError("PROXY_INVALIDATED",
                                 {"asset_id": asset_id, "tier": tier})
            raise ProxyError("PROXY_NOT_READY",
                             {"asset_id": asset_id, "tier": tier})

    def relink(self, asset_id: str, *, checksum: str, tier: str) -> str:
        asset_id = asset_id.strip() if isinstance(asset_id, str) else asset_id
        checksum = checksum.strip() if isinstance(checksum, str) else checksum
        tier = tier.strip() if isinstance(tier, str) else tier
        with self._lock:
            if not any(t["asset_id"] == asset_id for t in self._tasks.values()):
                raise ProxyError("PROXY_UNKNOWN", {"asset_id": asset_id})
            matches = [t for t in self._tasks.values()
                       if t["asset_id"] == asset_id and t["checksum"] == checksum
                       and t["tier"] == tier]
            done = [t for t in matches if t["status"] == "done"]
            if done:
                return max(done, key=lambda t: t["completed_seq"])["output_path"]
            if any(t["status"] == "invalid" for t in matches):
                raise ProxyError("PROXY_INVALIDATED",
                                 {"asset_id": asset_id, "checksum": checksum,
                                  "tier": tier})
            raise ProxyError("PROXY_NOT_READY",
                             {"asset_id": asset_id, "checksum": checksum,
                              "tier": tier})

    def invalidate(self, asset_id: str, *, checksum: str | None = None) -> int:
        asset_id = asset_id.strip() if isinstance(asset_id, str) else asset_id
        if isinstance(checksum, str):
            checksum = checksum.strip()
        with self._lock:
            targets = [t for t in self._tasks.values()
                       if t["asset_id"] == asset_id and t["status"] != "invalid"
                       and (checksum is None or t["checksum"] == checksum)]
            for task in targets:
                task["status"] = "invalid"
                task["stale"] = True
            self._counters["invalidated"] += len(targets)
            return len(targets)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self._SNAPSHOT_VERSION,
                "next_task": self._next_task,
                "tasks": [{
                    "task_id": t["task_id"],
                    "asset_id": t["asset_id"],
                    "checksum": t["checksum"],
                    "tier": t["tier"],
                    "status": t["status"],
                    "attempts": t["attempts"],
                    "output_path": t["output_path"],
                    "mtime": t["mtime"],
                } for t in (self._tasks[tid] for tid in self._order)],
                "stats": dict(self._counters),
            }

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _validate_snapshot(self, state) -> None:
        bad = ProxyError("PROXY_SNAPSHOT_INVALID", None)
        if not isinstance(state, dict):
            raise bad
        if not {"version", "next_task", "tasks", "stats"} <= set(state):
            raise bad
        if state["version"] != self._SNAPSHOT_VERSION:
            raise bad
        if not self._is_int(state["next_task"]) or state["next_task"] < 1:
            raise bad
        if not isinstance(state["tasks"], list):
            raise bad
        required = {"task_id", "asset_id", "checksum", "tier", "status",
                    "attempts", "output_path", "mtime"}
        seen_ids = set()
        for entry in state["tasks"]:
            if not isinstance(entry, dict) or not required <= set(entry):
                raise bad
            if not all(isinstance(entry[k], str)
                       for k in ("task_id", "asset_id", "checksum", "tier")):
                raise bad
            if entry["task_id"] in seen_ids:
                raise bad
            seen_ids.add(entry["task_id"])
            if entry["status"] not in self._STATUSES:
                raise bad
            if not self._is_int(entry["attempts"]) or entry["attempts"] < 0:
                raise bad
            if (entry["output_path"] is not None
                    and not isinstance(entry["output_path"], str)):
                raise bad
            if entry["mtime"] is not None and not (
                    self._is_int(entry["mtime"])
                    or isinstance(entry["mtime"], float)):
                raise bad
        stats = state["stats"]
        if not isinstance(stats, dict):
            raise bad
        if not set(self._counters) <= set(stats):
            raise bad
        if not all(self._is_int(stats[k]) and stats[k] >= 0
                   for k in self._counters):
            raise bad

    def restore(self, state: dict) -> None:
        with self._lock:
            self._validate_snapshot(state)
            tasks = {}
            order = []
            seq = 0
            for entry in state["tasks"]:
                if entry["status"] == "done":
                    seq += 1
                tasks[entry["task_id"]] = {
                    "task_id": entry["task_id"],
                    "asset_id": entry["asset_id"],
                    "checksum": entry["checksum"],
                    "tier": entry["tier"],
                    "status": entry["status"],
                    "attempts": entry["attempts"],
                    "output_path": entry["output_path"],
                    "mtime": entry["mtime"],
                    "stale": entry["status"] == "invalid",
                    "completed_seq": seq if entry["status"] == "done" else 0,
                }
                order.append(entry["task_id"])
            self._tasks = tasks
            self._order = order
            self._next_task = state["next_task"]
            self._complete_seq = seq
            self._counters = {k: state["stats"][k] for k in self._counters}

    def stats(self) -> dict:
        with self._lock:
            result = dict(self._counters)
            result["live"] = self._live_count()
            return result
