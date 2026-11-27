"""Process identity pinner: freeze a pid into an identity handle, re-check by triple."""

from __future__ import annotations

import copy
import time
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
        self._processes: dict[int, dict] = {}
        self._handles: dict[str, _Handle] = {}
        self._dead: dict[str, _Handle] = {}
        self._owner_handles: dict[str, list[str]] = {}
        self._next_seq = 1
        self._stats = {
            "pins": 0,
            "releases": 0,
            "evictions": 0,
            "stale": 0,
            "reaped": 0,
            "pids_ingested": 0,
        }

    # ------------------------------------------------------------------ utils
    def _now(self, now) -> int:
        if now is not None:
            return now
        if self._clock is not None:
            return self._clock()
        return time.monotonic()

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _validate_row(cls, row) -> dict:
        if not isinstance(row, dict):
            raise ProcError("PROC_TABLE_INVALID", "entry_not_mapping")
        for field in ("pid", "start_time", "namespace", "state", "exe", "cwd"):
            if field not in row:
                raise ProcError("PROC_TABLE_INVALID", "missing_field:" + field)
        if not cls._is_int(row["pid"]):
            raise ProcError("PROC_TABLE_INVALID", "bad_type:pid")
        if not cls._is_int(row["start_time"]):
            raise ProcError("PROC_TABLE_INVALID", "bad_type:start_time")
        for field in ("namespace", "state", "exe", "cwd"):
            if not isinstance(row[field], str):
                raise ProcError("PROC_TABLE_INVALID", "bad_type:" + field)
        return {
            "pid": row["pid"],
            "start_time": row["start_time"],
            "namespace": row["namespace"],
            "state": row["state"],
            "exe": row["exe"],
            "cwd": row["cwd"],
        }

    def _public_handle(self, record: "_Handle") -> ProcHandle:
        return ProcHandle(
            handle_id=record.handle_id,
            owner=record.owner,
            pid=record.pid,
            start_time=record.start_time,
            namespace=record.namespace,
            pinned_at=record.pinned_at,
            last_used=record.last_used,
            state=record.state,
        )

    def _find_record(self, handle_id: str) -> "_Handle | None":
        record = self._handles.get(handle_id)
        if record is not None:
            return record
        return self._dead.get(handle_id)

    def _retire(self, record: "_Handle", reason: str) -> None:
        """Move a live handle into the dead archive with a sticky reason."""
        self._handles.pop(record.handle_id, None)
        record.reason = reason
        self._dead[record.handle_id] = record
        owner_ids = self._owner_handles.get(record.owner)
        if owner_ids is not None:
            owner_ids.remove(record.handle_id)
            if not owner_ids:
                del self._owner_handles[record.owner]

    def _classify(self, record: "_Handle") -> str | None:
        """Return the invalid reason for a live handle, or None while valid."""
        proc = self._processes.get(record.pid)
        if proc is None:
            return "process_gone"
        if (proc["start_time"] != record.start_time
                or proc["namespace"] != record.namespace):
            return "pid_reused"
        return None

    def _evict_oldest(self, reason: str) -> None:
        victim_id = min(
            self._handles,
            key=lambda hid: (self._handles[hid].last_used,
                             int(hid.split("-", 1)[1])),
        )
        victim = self._handles[victim_id]
        self._retire(victim, reason)
        self._stats["evictions"] += 1

    # ------------------------------------------------------------- public API
    def ingest_proc_table(self, entries) -> int:
        if not isinstance(entries, (list, tuple)):
            raise ProcError("PROC_TABLE_INVALID", "entries_not_sequence")
        validated = [self._validate_row(row) for row in entries]
        replacement: dict[int, dict] = {}
        for row in validated:
            replacement[row["pid"]] = row
        with self._lock:
            self._processes = replacement
            self._stats["pids_ingested"] += len(validated)
            return len(validated)

    def pin(self, pid: int, *, owner: str = "default", now=None) -> ProcHandle:
        with self._lock:
            proc = self._processes.get(pid)
            if proc is None:
                raise ProcError("PROC_UNKNOWN_PID", pid)
            moment = self._now(now)
            while len(self._handles) >= self.max_handles:
                self._evict_oldest("evicted")
            handle_id = "h-%d" % self._next_seq
            self._next_seq += 1
            state = "zombie" if proc["state"] == "zombie" else "live"
            record = _Handle(
                handle_id=handle_id,
                owner=owner,
                pid=pid,
                start_time=proc["start_time"],
                namespace=proc["namespace"],
                pinned_at=moment,
                last_used=moment,
                state=state,
                reason=None,
            )
            self._handles[handle_id] = record
            self._owner_handles.setdefault(owner, []).append(handle_id)
            self._stats["pins"] += 1
            return self._public_handle(record)

    def resolve(self, handle_id: str, *, now=None) -> ResolvedIdentity:
        with self._lock:
            record = self._find_record(handle_id)
            if record is None:
                raise ProcError("PROC_HANDLE_UNKNOWN", handle_id)
            if record.reason is not None:
                self._stats["stale"] += 1
                raise ProcError("PROC_HANDLE_STALE", record.reason)
            moment = self._now(now)
            record.last_used = moment
            reason = self._classify(record)
            if reason is not None:
                self._retire(record, reason)
                self._stats["stale"] += 1
                raise ProcError("PROC_HANDLE_STALE", reason)
            proc = self._processes[record.pid]
            is_zombie = proc["state"] == "zombie"
            record.state = "zombie" if is_zombie else "live"
            return ResolvedIdentity(
                handle_id=handle_id,
                pid=record.pid,
                start_time=record.start_time,
                namespace=record.namespace,
                state=record.state,
                exe=None if is_zombie else proc["exe"],
                cwd=None if is_zombie else proc["cwd"],
                available=not is_zombie,
            )

    def still_alive(self, handle_id: str, *, now=None) -> bool:
        with self._lock:
            record = self._find_record(handle_id)
            if record is None:
                return False
            if record.reason is not None:
                return False
            record.last_used = self._now(now)
            reason = self._classify(record)
            if reason is not None:
                self._retire(record, reason)
                return False
            return True

    def invalid_reason(self, handle_id: str) -> str | None:
        with self._lock:
            record = self._find_record(handle_id)
            if record is None:
                raise ProcError("PROC_HANDLE_UNKNOWN", handle_id)
            return record.reason

    def release(self, handle_id: str, *, now=None) -> bool:
        with self._lock:
            record = self._handles.pop(handle_id, None)
            if record is None:
                return False
            record.last_used = self._now(now)
            self._retire(record, "released")
            self._stats["releases"] += 1
            return True

    def release_owner(self, owner: str, *, now=None) -> int:
        with self._lock:
            ids = self._owner_handles.pop(owner, [])
            moment = self._now(now)
            for handle_id in ids:
                record = self._handles.pop(handle_id)
                record.last_used = moment
                record.reason = "released"
                self._dead[handle_id] = record
            if ids:
                self._stats["releases"] += len(ids)
            return len(ids)

    def handles_for(self, owner: str) -> list[str]:
        with self._lock:
            return list(self._owner_handles.get(owner, ()))

    def reap_idle(self, now=None) -> int:
        with self._lock:
            moment = self._now(now)
            expired = [
                handle_id for handle_id, record in self._handles.items()
                if moment - record.last_used > self.idle_timeout
            ]
            for handle_id in expired:
                record = self._handles[handle_id]
                record.last_used = moment
                self._retire(record, "idle_reaped")
            if expired:
                self._stats["reaped"] += len(expired)
            return len(expired)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "processes": copy.deepcopy(list(self._processes.values())),
                "handles": {
                    "next_seq": self._next_seq,
                    "entries": [
                        {
                            "handle_id": record.handle_id,
                            "owner": record.owner,
                            "pid": record.pid,
                            "start_time": record.start_time,
                            "namespace": record.namespace,
                            "pinned_at": record.pinned_at,
                            "last_used": record.last_used,
                            "state": record.state,
                            "reason": record.reason,
                        }
                        for record in [
                            *self._handles.values(),
                            *self._dead.values(),
                        ]
                    ],
                },
                "stats": {
                    **copy.deepcopy(self._stats),
                    "live_handles": len(self._handles),
                },
            }

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict):
            raise ProcError("PROC_SNAPSHOT_INVALID", "state_not_mapping")
        for field in ("processes", "handles", "stats"):
            if field not in state:
                raise ProcError("PROC_SNAPSHOT_INVALID", "missing_field:" + field)

        raw_processes = state["processes"]
        if not isinstance(raw_processes, (list, tuple)):
            raise ProcError("PROC_SNAPSHOT_INVALID", "bad_type:processes")
        processes: dict[int, dict] = {}
        for row in raw_processes:
            try:
                clean = self._validate_row(row)
            except ProcError as exc:
                raise ProcError("PROC_SNAPSHOT_INVALID", exc.detail)
            processes[clean["pid"]] = clean

        raw_handles = state["handles"]
        if not isinstance(raw_handles, dict) or not isinstance(
                raw_handles.get("entries"), list):
            raise ProcError("PROC_SNAPSHOT_INVALID", "bad_type:handles")
        if "next_seq" not in raw_handles or not self._is_int(
                raw_handles["next_seq"]):
            raise ProcError("PROC_SNAPSHOT_INVALID", "bad_type:next_seq")
        handles: dict[str, _Handle] = {}
        dead: dict[str, _Handle] = {}
        owner_handles: dict[str, list[str]] = {}
        seen: set[str] = set()
        for entry in raw_handles["entries"]:
            if not isinstance(entry, dict):
                raise ProcError("PROC_SNAPSHOT_INVALID", "handle_not_mapping")
            for field in ("handle_id", "owner", "pid", "start_time",
                          "namespace", "pinned_at", "last_used", "state"):
                if field not in entry:
                    raise ProcError("PROC_SNAPSHOT_INVALID",
                                    "missing_handle_field:" + field)
            if not isinstance(entry["handle_id"], str) \
                    or not isinstance(entry["owner"], str) \
                    or not isinstance(entry["namespace"], str) \
                    or entry["state"] not in ("live", "zombie"):
                raise ProcError("PROC_SNAPSHOT_INVALID", "bad_handle_type")
            if "reason" in entry and entry["reason"] is not None \
                    and not isinstance(entry["reason"], str):
                raise ProcError("PROC_SNAPSHOT_INVALID", "bad_handle_reason")
            for field in ("pid", "start_time", "pinned_at", "last_used"):
                if not self._is_int(entry[field]):
                    raise ProcError("PROC_SNAPSHOT_INVALID",
                                    "bad_handle_type:" + field)
            handle_id = entry["handle_id"]
            if handle_id in seen:
                raise ProcError("PROC_SNAPSHOT_INVALID", "duplicate_handle")
            seen.add(handle_id)
            record = _Handle(
                handle_id=handle_id,
                owner=entry["owner"],
                pid=entry["pid"],
                start_time=entry["start_time"],
                namespace=entry["namespace"],
                pinned_at=entry["pinned_at"],
                last_used=entry["last_used"],
                state=entry["state"],
                reason=entry.get("reason"),
            )
            if record.reason is None:
                handles[handle_id] = record
                owner_handles.setdefault(entry["owner"], []).append(handle_id)
            else:
                dead[handle_id] = record

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict):
            raise ProcError("PROC_SNAPSHOT_INVALID", "bad_type:stats")
        stats = {}
        for field in ("pins", "releases", "evictions", "stale", "reaped",
                      "pids_ingested"):
            if field not in raw_stats or not self._is_int(raw_stats[field]):
                raise ProcError("PROC_SNAPSHOT_INVALID", "bad_stat:" + field)
            stats[field] = raw_stats[field]

        restored = copy.deepcopy({
            "processes": processes,
            "handles": handles,
            "dead": dead,
            "owner_handles": owner_handles,
            "next_seq": raw_handles["next_seq"],
            "stats": stats,
        })
        with self._lock:
            self._processes = restored["processes"]
            self._handles = restored["handles"]
            self._dead = restored["dead"]
            self._owner_handles = restored["owner_handles"]
            self._next_seq = restored["next_seq"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        with self._lock:
            return {
                **self._stats,
                "live_handles": len(self._handles),
            }


@dataclass
class _Handle:
    handle_id: str
    owner: str
    pid: int
    start_time: int
    namespace: str
    pinned_at: int
    last_used: int
    state: str
    reason: str | None = None
