"""Real time scheduling admission control.

The guard keeps a tree of budget groups, admits real time reservations while
the group and every ancestor still have room, queues the overflow when asked
to, and demotes a process that tripped the watchdog back to the normal policy
with a cooldown.  Reservations are released exactly once.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

RT_POLICIES = ("fifo", "rr")
OTHER_POLICY = "other"
DEFAULT_PERIOD_US = 1_000_000

_STAT_KEYS = ("groups", "admitted", "queued", "rejected", "released",
              "demotions", "restores")
_SNAPSHOT_KEYS = {"groups", "reservations", "queue", "cooldown", "sequence",
                  "stats"}


class RtSchedError(ValueError):
    """Refusal raised by the scheduling guard."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class GroupBudget:
    name: str
    limit_us: int
    used_us: int
    available_us: int
    over_us: int


@dataclass(frozen=True)
class Admission:
    pid: int
    group: str
    policy: str
    budget_us: int
    status: str
    sequence: int


@dataclass(frozen=True)
class Demotion:
    pid: int
    policy: str
    reason: str
    released_us: int
    cooldown_until_us: int


@dataclass
class _Group:
    parent: str | None
    limit_us: int


class RtSchedGuard:
    """Admit, queue, release and demote real time scheduling requests."""

    def __init__(self, *, period_us: int = DEFAULT_PERIOD_US,
                 watchdog_cooldown_us: int = 5_000_000) -> None:
        self.period_us = period_us
        self.watchdog_cooldown_us = watchdog_cooldown_us
        self._lock = threading.RLock()
        self._groups = {}
        self._reservations = {}
        self._queue = []
        self._cooldown = {}
        self._sequence = 0
        self._stats = {"groups": 0, "admitted": 0, "queued": 0, "rejected": 0,
                       "released": 0, "demotions": 0, "restores": 0}

    @staticmethod
    def _valid_budget(value: object) -> bool:
        return (isinstance(value, int) and not isinstance(value, bool)
                and value > 0)

    @staticmethod
    def _valid_counter(value: object) -> bool:
        return (isinstance(value, int) and not isinstance(value, bool)
                and value >= 0)

    def _require_group(self, name: str) -> _Group:
        try:
            return self._groups[name]
        except (KeyError, TypeError):
            raise RtSchedError("RT_GROUP_UNKNOWN") from None

    def _is_in_subtree(self, group: str, root: str) -> bool:
        current = group
        while current is not None:
            if current == root:
                return True
            current = self._groups[current].parent
        return False

    def _used_locked(self, name: str) -> int:
        return sum(
            reservation.budget_us
            for reservation in self._reservations.values()
            if self._is_in_subtree(reservation.group, name)
        )

    def _own_available_locked(self, name: str) -> int:
        group = self._groups[name]
        return max(0, group.limit_us - self._used_locked(name))

    def _admission_available_locked(self, name: str) -> int:
        group = self._groups[name]
        own_remaining = self._own_available_locked(name)
        if group.parent is None:
            return own_remaining
        return min(own_remaining,
                   self._admission_available_locked(group.parent))

    def _budget_locked(self, name: str) -> GroupBudget:
        group = self._groups[name]
        used = self._used_locked(name)
        return GroupBudget(
            name=name,
            limit_us=group.limit_us,
            used_us=used,
            available_us=self._own_available_locked(name),
            over_us=max(0, used - group.limit_us),
        )

    def _next_sequence_locked(self) -> int:
        self._sequence += 1
        return self._sequence

    def _quota_error(self, group: str, requested: int,
                     available: int) -> RtSchedError:
        self._stats["rejected"] += 1
        return RtSchedError("RT_QUOTA_EXCEEDED", {
            "group": group,
            "requested": requested,
            "available": available,
        })

    def _cooldown_active_locked(self, pid: int, now_us: int) -> bool:
        until = self._cooldown.get(pid, 0)
        if now_us < until:
            return True
        if pid in self._cooldown:
            del self._cooldown[pid]
        return False

    @staticmethod
    def _admission_dict(admission: Admission) -> dict:
        return {
            "pid": admission.pid,
            "group": admission.group,
            "policy": admission.policy,
            "budget_us": admission.budget_us,
            "status": admission.status,
            "sequence": admission.sequence,
        }

    @staticmethod
    def _normalise_pid(value: object) -> int:
        if isinstance(value, bool):
            raise ValueError("boolean pid")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                pass
        raise ValueError("invalid pid")

    def _admission_from_snapshot(self, raw: object, *, expected_status: str,
                                 groups: dict) -> Admission:
        if not isinstance(raw, dict):
            raise ValueError("admission must be a mapping")
        required = {"pid", "group", "policy", "budget_us", "status", "sequence"}
        if not required.issubset(raw):
            raise ValueError("admission is missing fields")

        pid = raw["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise ValueError("invalid admission pid")
        group = raw["group"]
        if not isinstance(group, str) or group not in groups:
            raise ValueError("invalid admission group")
        policy = raw["policy"]
        if policy not in RT_POLICIES and policy != OTHER_POLICY:
            raise ValueError("invalid admission policy")
        budget_us = raw["budget_us"]
        if not self._valid_counter(budget_us):
            raise ValueError("invalid admission budget")
        if policy in RT_POLICIES and budget_us <= 0:
            raise ValueError("invalid realtime budget")
        status = raw["status"]
        if status != expected_status:
            raise ValueError("invalid admission status")
        sequence = raw["sequence"]
        if not self._valid_counter(sequence):
            raise ValueError("invalid admission sequence")
        if status == "admitted" and sequence <= 0:
            raise ValueError("invalid admitted sequence")
        return Admission(pid, group, policy, budget_us, status, sequence)

    def create_group(self, name: str, *, parent: str | None = None,
                     budget_us: int) -> GroupBudget:
        """Create a budget group below ``parent`` and return its budget."""
        with self._lock:
            if name in self._groups:
                raise RtSchedError("RT_GROUP_EXISTS")
            if parent is not None and parent not in self._groups:
                raise RtSchedError("RT_GROUP_UNKNOWN")
            if not self._valid_budget(budget_us):
                raise RtSchedError("RT_INVALID_BUDGET")

            self._groups[name] = _Group(parent=parent, limit_us=budget_us)
            self._stats["groups"] += 1
            return self._budget_locked(name)

    def group_budget(self, name: str) -> GroupBudget:
        """Return the current budget view of ``name``."""
        with self._lock:
            self._require_group(name)
            return self._budget_locked(name)

    def set_group_budget(self, name: str, budget_us: int) -> GroupBudget:
        """Replace the limit of ``name`` and return the new budget view."""
        with self._lock:
            group = self._require_group(name)
            if not self._valid_budget(budget_us):
                raise RtSchedError("RT_INVALID_BUDGET")
            group.limit_us = budget_us
            return self._budget_locked(name)

    def admit(self, pid: int, *, group: str, policy: str, budget_us: int,
              now_us: int, allow_queue: bool = False) -> Admission:
        """Admit a real time request, queue it, or refuse it."""
        with self._lock:
            if policy not in RT_POLICIES:
                raise RtSchedError("RT_INVALID_POLICY")
            if not self._valid_budget(budget_us):
                raise RtSchedError("RT_INVALID_BUDGET")
            self._require_group(group)

            if self._cooldown_active_locked(pid, now_us):
                self._queue = [row for row in self._queue if row.pid != pid]
                admission = Admission(
                    pid=pid,
                    group=group,
                    policy=OTHER_POLICY,
                    budget_us=0,
                    status="admitted",
                    sequence=self._next_sequence_locked(),
                )
                self._reservations[pid] = admission
                self._stats["admitted"] += 1
                return admission

            current = self._reservations.get(pid)
            if current is not None:
                if current.policy == policy:
                    delta = budget_us - current.budget_us
                    if delta > 0:
                        available = self._admission_available_locked(
                            current.group)
                        if delta > available:
                            raise self._quota_error(
                                current.group, budget_us, available)
                    updated = Admission(
                        pid=pid,
                        group=current.group,
                        policy=policy,
                        budget_us=budget_us,
                        status="admitted",
                        sequence=current.sequence,
                    )
                    self._reservations[pid] = updated
                    return updated

                delta = budget_us - current.budget_us
                if delta > 0:
                    available = self._admission_available_locked(
                        current.group)
                    if delta > available:
                        raise self._quota_error(
                            current.group, budget_us, available)
                updated = Admission(
                    pid=pid,
                    group=current.group,
                    policy=policy,
                    budget_us=budget_us,
                    status="admitted",
                    sequence=current.sequence,
                )
                self._reservations[pid] = updated
                return updated

            queued_index = next(
                (index for index, row in enumerate(self._queue)
                 if row.pid == pid),
                None,
            )
            if queued_index is not None:
                queued = self._queue[queued_index]
                updated = Admission(
                    pid=pid,
                    group=queued.group if queued.policy == policy else group,
                    policy=policy,
                    budget_us=budget_us,
                    status="queued",
                    sequence=queued.sequence,
                )
                self._queue[queued_index] = updated
                return updated

            available = self._admission_available_locked(group)
            if not self._queue and budget_us <= available:
                admission = Admission(
                    pid=pid,
                    group=group,
                    policy=policy,
                    budget_us=budget_us,
                    status="admitted",
                    sequence=self._next_sequence_locked(),
                )
                self._reservations[pid] = admission
                self._stats["admitted"] += 1
                return admission

            if allow_queue:
                admission = Admission(
                    pid=pid,
                    group=group,
                    policy=policy,
                    budget_us=budget_us,
                    status="queued",
                    sequence=self._next_sequence_locked(),
                )
                self._queue.append(admission)
                self._stats["queued"] += 1
                return admission

            raise self._quota_error(group, budget_us, available)

    def release(self, pid: int, *, now_us: int) -> int:
        """Release the reservation of ``pid`` and return the freed budget."""
        with self._lock:
            reservation = self._reservations.pop(pid, None)
            if reservation is None or reservation.policy == OTHER_POLICY:
                return 0
            self._stats["released"] += 1
            return reservation.budget_us

    def reservation_of(self, pid: int) -> Admission | None:
        """Return the active admission of ``pid`` or ``None``."""
        with self._lock:
            return self._reservations.get(pid)

    def admissions(self) -> tuple:
        """Return every active admission ordered by sequence."""
        with self._lock:
            return tuple(sorted(self._reservations.values(),
                                key=lambda row: row.sequence))

    def queued(self) -> tuple:
        """Return the queued requests in arrival order."""
        with self._lock:
            return tuple(self._queue)

    def pump(self, now_us: int) -> tuple:
        """Promote every queued request that now fits, keeping FIFO order."""
        with self._lock:
            promoted = []
            waiting = []
            for request in self._queue:
                available = self._admission_available_locked(request.group)
                if request.budget_us <= available:
                    admission = Admission(
                        pid=request.pid,
                        group=request.group,
                        policy=request.policy,
                        budget_us=request.budget_us,
                        status="admitted",
                        sequence=request.sequence,
                    )
                    self._reservations[request.pid] = admission
                    self._stats["admitted"] += 1
                    promoted.append(admission)
                else:
                    waiting.append(request)
            self._queue = waiting
            return tuple(promoted)

    def watchdog(self, pid: int, *, now_us: int,
                 reason: str = "overrun") -> Demotion:
        """Demote ``pid`` to the normal policy and start its cooldown."""
        with self._lock:
            reservation = self._reservations.pop(pid, None)
            released = 0
            if reservation is not None and reservation.policy != OTHER_POLICY:
                released = reservation.budget_us

            self._queue = [row for row in self._queue if row.pid != pid]
            until = now_us + self.watchdog_cooldown_us
            self._cooldown[pid] = until
            self._stats["demotions"] += 1
            return Demotion(
                pid=pid,
                policy=OTHER_POLICY,
                reason=reason,
                released_us=released,
                cooldown_until_us=until,
            )

    def cooldown_until(self, pid: int) -> int:
        """Return the absolute cooldown deadline of ``pid`` (0 when none)."""
        with self._lock:
            return self._cooldown.get(pid, 0)

    def snapshot(self) -> dict:
        """Return a detached snapshot of the whole state."""
        with self._lock:
            return copy.deepcopy({
                "groups": {
                    name: {
                        "parent": group.parent,
                        "budget_us": group.limit_us,
                    }
                    for name, group in self._groups.items()
                },
                "reservations": {
                    pid: self._admission_dict(admission)
                    for pid, admission in self._reservations.items()
                },
                "queue": [
                    self._admission_dict(admission)
                    for admission in self._queue
                ],
                "cooldown": dict(self._cooldown),
                "sequence": self._sequence,
                "stats": dict(self._stats),
            })

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise ValueError("snapshot must be a mapping")
                if set(state) != _SNAPSHOT_KEYS:
                    raise ValueError("snapshot keys are invalid")

                raw_groups = state["groups"]
                if not isinstance(raw_groups, dict):
                    raise ValueError("groups must be a mapping")
                groups = {}
                for name, raw in raw_groups.items():
                    if not isinstance(name, str) or not isinstance(raw, dict):
                        raise ValueError("invalid group")
                    parent = raw.get("parent")
                    if parent is not None and not isinstance(parent, str):
                        raise ValueError("invalid group parent")
                    if "budget_us" in raw:
                        budget_us = raw["budget_us"]
                    else:
                        budget_us = raw.get("limit_us")
                    if not self._valid_budget(budget_us):
                        raise ValueError("invalid group budget")
                    groups[name] = _Group(parent=parent, limit_us=budget_us)

                for name, group in groups.items():
                    if group.parent is not None and group.parent not in groups:
                        raise ValueError("unknown group parent")
                    seen = set()
                    current = name
                    while current is not None:
                        if current in seen:
                            raise ValueError("group cycle")
                        seen.add(current)
                        current = groups[current].parent

                raw_reservations = state["reservations"]
                if not isinstance(raw_reservations, dict):
                    raise ValueError("reservations must be a mapping")
                reservations = {}
                for key, raw in raw_reservations.items():
                    key_pid = self._normalise_pid(key)
                    admission = self._admission_from_snapshot(
                        raw, expected_status="admitted", groups=groups)
                    if admission.pid != key_pid:
                        raise ValueError("reservation pid mismatch")
                    if admission.pid in reservations:
                        raise ValueError("duplicate reservation pid")
                    reservations[admission.pid] = admission

                raw_queue = state["queue"]
                if not isinstance(raw_queue, list):
                    raise ValueError("queue must be a list")
                queue = []
                queue_pids = set()
                for raw in raw_queue:
                    admission = self._admission_from_snapshot(
                        raw, expected_status="queued", groups=groups)
                    if admission.pid in reservations:
                        raise ValueError("queued pid is already reserved")
                    if admission.pid in queue_pids:
                        raise ValueError("duplicate queued pid")
                    queue_pids.add(admission.pid)
                    queue.append(admission)

                raw_cooldown = state["cooldown"]
                if not isinstance(raw_cooldown, dict):
                    raise ValueError("cooldown must be a mapping")
                cooldown = {}
                for key, until in raw_cooldown.items():
                    pid = self._normalise_pid(key)
                    if not self._valid_counter(until):
                        raise ValueError("invalid cooldown deadline")
                    if pid in cooldown:
                        raise ValueError("duplicate cooldown pid")
                    cooldown[pid] = until

                sequence = state["sequence"]
                if not self._valid_counter(sequence):
                    raise ValueError("invalid sequence")
                max_sequence = max(
                    [row.sequence for row in reservations.values()]
                    + [row.sequence for row in queue] + [0])
                if sequence < max_sequence:
                    raise ValueError("sequence predates entries")

                raw_stats = state["stats"]
                if not isinstance(raw_stats, dict):
                    raise ValueError("stats must be a mapping")
                if set(raw_stats) != set(_STAT_KEYS):
                    raise ValueError("stats keys are invalid")
                stats = {}
                for key in _STAT_KEYS:
                    value = raw_stats[key]
                    if not self._valid_counter(value):
                        raise ValueError("invalid stat counter")
                    stats[key] = value
            except (KeyError, TypeError, ValueError):
                raise RtSchedError("RT_SNAPSHOT_INVALID") from None

            self._groups = groups
            self._reservations = reservations
            self._queue = queue
            self._cooldown = cooldown
            self._sequence = sequence
            self._stats = stats
            self._stats["restores"] += 1

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return dict(self._stats)
