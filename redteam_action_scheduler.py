"""Red team action scheduler: per-asset exclusion, maintenance windows, cancellation."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class SchedulerError(ValueError):
    """Raised when a scheduler operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_MODES = ("destructive", "readonly")
_STATES = ("queued", "running", "done", "cancelled")
_STAT_KEYS = ("enqueued", "granted", "blocked", "released", "cancelled",
              "dropped_steps", "restores")
_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = ("version", "actions", "active", "timeline", "stats")


@dataclass(frozen=True)
class Action:
    action_id: str
    asset_id: str
    mode: str
    window_start: int
    window_end: int
    steps: tuple[str, ...]
    state: str
    enqueue_seq: int


@dataclass(frozen=True)
class Grant:
    action_id: str
    asset_id: str
    mode: str
    granted: bool
    reason: str
    started_at: int | None


@dataclass(frozen=True)
class CancelResult:
    action_id: str
    released: bool
    dropped_steps: tuple[str, ...]
    state: str


@dataclass(frozen=True)
class TimelineRow:
    action_id: str
    asset_id: str
    mode: str
    started_at: int
    state: str


class _Record:
    """Mutable internal state for one enqueued action."""

    __slots__ = ("action_id", "asset_id", "mode", "window_start", "window_end",
                 "planned_steps", "dispatched_steps", "state", "started_at",
                 "enqueue_seq")

    def __init__(self, action_id, asset_id, mode, window_start, window_end,
                 planned_steps, enqueue_seq):
        self.action_id = action_id
        self.asset_id = asset_id
        self.mode = mode
        self.window_start = window_start
        self.window_end = window_end
        self.planned_steps = list(planned_steps)
        self.dispatched_steps = []
        self.state = "queued"
        self.started_at = None
        self.enqueue_seq = enqueue_seq


class RedteamActionScheduler:
    """Sequence red team actions against shared assets inside maintenance windows."""

    def __init__(self, *, max_actions: int = 32, max_steps: int = 8) -> None:
        self.max_actions = max_actions
        self.max_steps = max_steps
        self._lock = threading.RLock()
        self._actions: dict[str, _Record] = {}
        self._active: dict[str, set[str]] = {}
        self._timeline: list[dict] = []
        self._stats = {key: 0 for key in _STAT_KEYS}
        self._next_seq = 0

    @staticmethod
    def _valid_identity(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def enqueue(self, action_id: str, asset_id: str, *, mode: str = "destructive",
                window_start: int = 0, window_end: int = 10,
                steps: tuple[str, ...] = ()) -> Action:
        with self._lock:
            if not self._valid_identity(action_id) or not self._valid_identity(asset_id):
                raise SchedulerError("RT_INVALID_ACTION",
                                     {"action_id": action_id, "asset_id": asset_id})
            if action_id in self._actions:
                raise SchedulerError("RT_DUPLICATE_ACTION", action_id)
            if mode not in _MODES:
                raise SchedulerError("RT_INVALID_MODE", mode)
            if window_end <= window_start:
                raise SchedulerError("RT_INVALID_WINDOW", (window_start, window_end))
            if len(self._actions) >= self.max_actions:
                raise SchedulerError("RT_CAPACITY_EXCEEDED", self.max_actions)
            record = _Record(action_id, asset_id, mode, window_start, window_end,
                             tuple(steps), self._next_seq)
            self._next_seq += 1
            self._actions[action_id] = record
            self._stats["enqueued"] += 1
            return Action(action_id=action_id, asset_id=asset_id, mode=mode,
                          window_start=window_start, window_end=window_end,
                          steps=tuple(record.planned_steps), state=record.state,
                          enqueue_seq=record.enqueue_seq)

    def acquire_asset(self, action_id: str, *, at: int = 0) -> Grant:
        with self._lock:
            record = self._actions.get(action_id)
            if record is None:
                raise SchedulerError("RT_UNKNOWN_ACTION", action_id)
            if record.state == "cancelled":
                raise SchedulerError("RT_ACTION_CANCELLED", action_id)
            if record.state == "done":
                raise SchedulerError("RT_ACTION_CLOSED", action_id)
            if record.state == "running":
                return Grant(action_id, record.asset_id, record.mode, True,
                             "already_held", record.started_at)
            if at < record.window_start or at >= record.window_end:
                return Grant(action_id, record.asset_id, record.mode, False,
                             "window_closed", None)
            if record.mode == "destructive" and self._destructive_conflict(record, at):
                self._stats["blocked"] += 1
                return Grant(action_id, record.asset_id, record.mode, False,
                             "asset_busy", None)
            record.state = "running"
            record.started_at = at
            self._active.setdefault(record.asset_id, set()).add(action_id)
            self._timeline.append({"action_id": action_id, "started_at": at})
            self._stats["granted"] += 1
            return Grant(action_id, record.asset_id, record.mode, True,
                         "granted", at)

    def _destructive_conflict(self, record: _Record, at: int) -> bool:
        for other in self._actions.values():
            if (other.action_id == record.action_id
                    or other.asset_id != record.asset_id
                    or other.mode != "destructive"):
                continue
            if other.state == "running":
                return True
            if other.state != "queued" or at >= other.window_end:
                continue
            if (other.window_start, other.enqueue_seq) < (
                    record.window_start, record.enqueue_seq):
                return True
        return False

    def _release(self, record: _Record) -> None:
        holders = self._active.get(record.asset_id)
        if holders is not None:
            holders.discard(record.action_id)
            if not holders:
                del self._active[record.asset_id]
        record.state = "done"

    def release_asset(self, action_id: str) -> bool:
        with self._lock:
            record = self._actions.get(action_id)
            if record is None or record.state != "running":
                return False
            self._release(record)
            self._stats["released"] += 1
            return True

    def cancel(self, action_id: str, *, at: int = 0) -> CancelResult:
        with self._lock:
            record = self._actions.get(action_id)
            if record is None:
                raise SchedulerError("RT_UNKNOWN_ACTION", action_id)
            if record.state == "cancelled":
                return CancelResult(action_id, False, (), "cancelled")
            released = False
            if record.state == "running":
                self._release(record)
                self._stats["released"] += 1
                released = True
            dropped = tuple(record.dispatched_steps)
            record.dispatched_steps.clear()
            record.planned_steps.clear()
            record.state = "cancelled"
            self._stats["cancelled"] += 1
            self._stats["dropped_steps"] += len(dropped)
            return CancelResult(action_id, released, dropped, "cancelled")

    def dispatch_step(self, action_id: str, step: str) -> tuple[str, ...]:
        with self._lock:
            record = self._actions.get(action_id)
            if record is None:
                raise SchedulerError("RT_UNKNOWN_ACTION", action_id)
            if record.state == "cancelled":
                raise SchedulerError("RT_ACTION_CANCELLED", action_id)
            if len(record.dispatched_steps) >= self.max_steps:
                raise SchedulerError("RT_STEP_LIMIT", self.max_steps)
            if step in record.planned_steps:
                record.planned_steps.remove(step)
            record.dispatched_steps.append(step)
            return tuple(record.dispatched_steps)

    def steps_for(self, action_id: str) -> tuple[str, ...]:
        with self._lock:
            record = self._actions.get(action_id)
            if record is None:
                return ()
            return tuple(record.dispatched_steps)

    def active_for(self, asset_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._active.get(asset_id, ())))

    def timeline(self) -> tuple[TimelineRow, ...]:
        with self._lock:
            entries = sorted(self._timeline,
                             key=lambda entry: (entry["started_at"],
                                                entry["action_id"]))
            rows = []
            for entry in entries:
                record = self._actions[entry["action_id"]]
                rows.append(TimelineRow(
                    action_id=record.action_id,
                    asset_id=record.asset_id,
                    mode=record.mode,
                    started_at=entry["started_at"],
                    state=record.state,
                ))
            return tuple(rows)

    def state_of(self, action_id: str) -> str | None:
        with self._lock:
            record = self._actions.get(action_id)
            return record.state if record is not None else None

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "actions": [
                    {
                        "action_id": record.action_id,
                        "asset_id": record.asset_id,
                        "mode": record.mode,
                        "window_start": record.window_start,
                        "window_end": record.window_end,
                        "planned_steps": list(record.planned_steps),
                        "dispatched_steps": list(record.dispatched_steps),
                        "state": record.state,
                        "started_at": record.started_at,
                        "enqueue_seq": record.enqueue_seq,
                    }
                    for record in self._actions.values()
                ],
                "active": {asset: sorted(ids)
                           for asset, ids in self._active.items()},
                "timeline": [dict(entry) for entry in self._timeline],
                "stats": dict(self._stats),
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            actions, active, timeline, stats = self._validate_snapshot(state)
            self._actions = {}
            self._active = {}
            self._timeline = []
            self._next_seq = 0
            for item in actions:
                record = _Record(item["action_id"], item["asset_id"],
                                 item["mode"], item["window_start"],
                                 item["window_end"], item["planned_steps"],
                                 item["enqueue_seq"])
                record.dispatched_steps = list(item["dispatched_steps"])
                record.state = item["state"]
                record.started_at = item["started_at"]
                self._actions[record.action_id] = record
                self._next_seq = max(self._next_seq, record.enqueue_seq + 1)
            for asset_id, holders in active.items():
                self._active[asset_id] = set(holders)
            self._timeline = [dict(entry) for entry in timeline]
            self._stats = dict(stats)
            self._stats["restores"] += 1

    @staticmethod
    def _validate_snapshot(state: object):
        def invalid(detail: object) -> SchedulerError:
            return SchedulerError("RT_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state.keys()) != set(_SNAPSHOT_KEYS):
            raise invalid("missing snapshot keys")
        if state["version"] != _SNAPSHOT_VERSION:
            raise invalid("unsupported version")
        actions = state["actions"]
        active = state["active"]
        timeline = state["timeline"]
        stats = state["stats"]
        if not isinstance(actions, list):
            raise invalid("actions must be a list")
        if not isinstance(active, dict) or not isinstance(timeline, list):
            raise invalid("malformed active/timeline")
        if (not isinstance(stats, dict) or set(stats.keys()) != set(_STAT_KEYS)
                or any(not isinstance(stats[key], int) for key in _STAT_KEYS)):
            raise invalid("malformed stats")

        action_ids = set()
        for item in actions:
            if not isinstance(item, dict):
                raise invalid("malformed action")
            required = {"action_id": str, "asset_id": str, "mode": str,
                        "window_start": int, "window_end": int,
                        "planned_steps": list, "dispatched_steps": list,
                        "state": str, "enqueue_seq": int}
            for field, kind in required.items():
                if field not in item or not isinstance(item[field], kind):
                    raise invalid(f"action field {field}")
            if "started_at" not in item or not (
                    item["started_at"] is None
                    or isinstance(item["started_at"], int)):
                raise invalid("action field started_at")
            if item["mode"] not in _MODES or item["state"] not in _STATES:
                raise invalid("bad mode/state")
            if item["window_end"] <= item["window_start"]:
                raise invalid("bad window")
            if item["action_id"] in action_ids:
                raise invalid("duplicate action")
            action_ids.add(item["action_id"])

        for asset_id, holders in active.items():
            if not isinstance(asset_id, str) or not isinstance(holders, list):
                raise invalid("malformed active entry")
            for holder in holders:
                if holder not in action_ids:
                    raise invalid("active holder unknown")

        by_id = {item["action_id"]: item for item in actions}
        for asset_id, holders in active.items():
            for holder in holders:
                if by_id[holder]["state"] != "running":
                    raise invalid("active holder not running")
        for item in actions:
            if item["state"] == "running":
                holders = active.get(item["asset_id"], [])
                if item["action_id"] not in holders:
                    raise invalid("running action not active")

        for entry in timeline:
            if (not isinstance(entry, dict)
                    or not isinstance(entry.get("action_id"), str)
                    or not isinstance(entry.get("started_at"), int)
                    or entry["action_id"] not in action_ids):
                raise invalid("malformed timeline entry")

        return actions, active, timeline, stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset(self) -> None:
        with self._lock:
            self._actions = {}
            self._active = {}
            self._timeline = []
            self._stats = {key: 0 for key in _STAT_KEYS}
            self._next_seq = 0
