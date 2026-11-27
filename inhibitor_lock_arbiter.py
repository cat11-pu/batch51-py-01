"""Inhibitor lock arbitration.

Sleep, shutdown and idle inhibitors are tracked as lock records with a mode
(block or delay), a set of ``what`` flags, a holder and a priority.  Delay
locks only extend a shutdown countdown; block locks veto it.  Holders that
stop sending heartbeats are reclaimed on ``expire``.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

WHAT_FLAGS = ("idle", "handle-lid-switch", "handle-power-key", "shutdown",
              "sleep")
WHAT_FLAG_SET = frozenset(WHAT_FLAGS)
MODES = ("block", "delay")
STAT_KEYS = ("acquired", "merged", "released", "expired", "blocked_queries",
             "cancelled", "deadline_updates", "restores")
SNAPSHOT_VERSION = 1


class InhibitorError(ValueError):
    """Refusal raised while acquiring, releasing or restoring inhibitors."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Inhibitor:
    """One inhibitor lock."""

    lock_id: str
    holder: str
    mode: str
    what: tuple
    delay: int
    priority: int
    reason: str
    acquired_at: int


@dataclass(frozen=True)
class Arbitration:
    """The answer to one arbitration query."""

    status: str
    blockers: tuple
    delayers: tuple
    delay_total: int
    deadline: int | None


class InhibitorLockArbiter:
    """Arbitrate block and delay inhibitors for sleep, shutdown and idle."""

    def __init__(self, *, max_locks: int = 256,
                 max_locks_per_holder: int = 8,
                 delay_cap: int = 300,
                 holder_ttl: int = 30) -> None:
        self.max_locks = max_locks
        self.max_locks_per_holder = max_locks_per_holder
        self.delay_cap = delay_cap
        self.holder_ttl = holder_ttl
        self._lock = threading.RLock()
        self._locks = {}
        self._holders = {}
        self._countdown = None
        self._next_id = 1
        self._stats = {key: 0 for key in STAT_KEYS}

    @staticmethod
    def _normalize_what(what, *, allow_empty: bool = False) -> tuple:
        if isinstance(what, str):
            values = [what]
        else:
            try:
                values = list(what)
            except TypeError as exc:
                raise InhibitorError(
                    "INHIBITOR_INVALID_REQUEST", {"what": what}
                ) from exc

        if not values and not allow_empty:
            raise InhibitorError(
                "INHIBITOR_INVALID_REQUEST", {"what": what}
            )
        if any(not isinstance(value, str) or value not in WHAT_FLAG_SET
               for value in values):
            raise InhibitorError(
                "INHIBITOR_INVALID_REQUEST", {"what": what}
            )
        return tuple(sorted(set(values)))

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _holder_lock_count(self, holder: str) -> int:
        return sum(1 for lock in self._locks.values()
                   if lock.holder == holder)

    def _shutdown_delay_total(self) -> int:
        total = sum(lock.delay for lock in self._locks.values()
                    if lock.mode == "delay" and "shutdown" in lock.what)
        return min(total, self.delay_cap)

    def _refresh_countdown_deadline(self) -> None:
        if self._countdown is None:
            return
        delay_total = self._shutdown_delay_total()
        base = self._countdown["deadline"] - self._countdown["delay_total"]
        self._countdown["delay_total"] = delay_total
        self._countdown["deadline"] = base + delay_total
        self._stats["deadline_updates"] += 1

    def _countdown_result(self) -> dict:
        if self._countdown is None:
            return {
                "active": False,
                "deadline": None,
                "delay_total": 0,
                "blockers": (),
            }
        return {
            "active": self._countdown["active"],
            "deadline": self._countdown["deadline"],
            "delay_total": self._countdown["delay_total"],
            "blockers": tuple(self._countdown["blockers"]),
        }

    def _arbitrate(self, what: tuple, *, now: int) -> Arbitration:
        blockers = []
        delayers = []
        requested = set(what)
        for order, lock in enumerate(self._locks.values()):
            if not requested.intersection(lock.what):
                continue
            if lock.mode == "block":
                blockers.append(lock.lock_id)
            else:
                delayers.append((order, lock))

        delayers.sort(key=lambda item: (-item[1].priority, item[0]))
        delay_total = min(
            sum(lock.delay for _, lock in delayers), self.delay_cap
        )
        status = ("blocked" if blockers else
                  "delayed" if delayers else "allowed")
        deadline = now + delay_total if delayers else None
        return Arbitration(
            status=status,
            blockers=tuple(blockers),
            delayers=tuple(lock.lock_id for _, lock in delayers),
            delay_total=delay_total,
            deadline=deadline,
        )

    def acquire(self, holder: str, what, *, mode: str = "block",
                delay: int = 0, priority: int = 0, reason: str = "",
                now: int = 0) -> Inhibitor:
        """Take an inhibitor lock for ``holder``."""
        if (not isinstance(holder, str) or not holder.strip()
                or mode not in MODES or not self._is_int(delay)
                or not self._is_int(priority) or not isinstance(reason, str)
                or not self._is_int(now)):
            raise InhibitorError(
                "INHIBITOR_INVALID_REQUEST",
                {"holder": holder, "mode": mode, "delay": delay},
            )

        flags = self._normalize_what(what)
        if mode == "block" and delay != 0:
            raise InhibitorError(
                "INHIBITOR_INVALID_REQUEST", {"delay": delay}
            )
        if mode == "delay" and delay <= 0:
            raise InhibitorError(
                "INHIBITOR_INVALID_REQUEST", {"delay": delay}
            )

        with self._lock:
            for lock in self._locks.values():
                if (lock.holder == holder and lock.mode == mode
                        and lock.what == flags):
                    self._stats["merged"] += 1
                    return lock

            if len(self._locks) >= self.max_locks:
                raise InhibitorError(
                    "INHIBITOR_CAPACITY", {"limit": self.max_locks}
                )
            if self._holder_lock_count(holder) >= self.max_locks_per_holder:
                raise InhibitorError(
                    "INHIBITOR_HOLDER_LIMIT",
                    {"holder": holder, "limit": self.max_locks_per_holder},
                )

            lock = Inhibitor(
                lock_id=f"inh-{self._next_id}",
                holder=holder,
                mode=mode,
                what=flags,
                delay=delay,
                priority=priority,
                reason=reason,
                acquired_at=now,
            )
            self._next_id += 1
            self._locks[lock.lock_id] = lock
            self._holders[holder] = {
                "last_heartbeat": now,
                "gone": False,
            }
            self._stats["acquired"] += 1

            if "shutdown" in flags:
                if mode == "block" and self._countdown is not None:
                    self._countdown = None
                    self._stats["cancelled"] += 1
                elif mode == "delay" and self._countdown is not None:
                    self._refresh_countdown_deadline()

            return lock

    def release(self, lock_id: str) -> bool:
        """Release one lock and report whether it existed."""
        with self._lock:
            try:
                lock = self._locks.pop(lock_id, None)
            except TypeError:
                return False
            if lock is None:
                return False

            self._stats["released"] += 1
            if self._holder_lock_count(lock.holder) == 0:
                self._holders.pop(lock.holder, None)

            if (self._countdown is not None and lock.mode == "delay"
                    and "shutdown" in lock.what):
                self._refresh_countdown_deadline()
            return True

    def heartbeat(self, holder: str, *, now: int = 0) -> int:
        """Refresh the holder lease and return how many locks it owns."""
        with self._lock:
            count = self._holder_lock_count(holder)
            if count:
                self._holders[holder] = {
                    "last_heartbeat": now,
                    "gone": False,
                }
            return count

    def mark_holder_gone(self, holder: str) -> int:
        """Mark a holder as gone without reclaiming its locks yet."""
        with self._lock:
            count = self._holder_lock_count(holder)
            if count:
                state = self._holders.setdefault(
                    holder, {"last_heartbeat": 0, "gone": False}
                )
                state["gone"] = True
            return count

    def expire(self, *, now: int = 0) -> int:
        """Reclaim locks whose holder is gone or whose lease ran out."""
        with self._lock:
            stale_holders = set()
            for holder, state in self._holders.items():
                if (state["gone"]
                        or now - state["last_heartbeat"] >= self.holder_ttl):
                    stale_holders.add(holder)

            expired_locks = [
                lock for lock in self._locks.values()
                if lock.holder in stale_holders
                or lock.holder not in self._holders
            ]
            if not expired_locks:
                return 0

            expired_ids = {lock.lock_id for lock in expired_locks}
            for lock_id in expired_ids:
                del self._locks[lock_id]

            expired_holders = {lock.holder for lock in expired_locks}
            for holder in expired_holders:
                if self._holder_lock_count(holder) == 0:
                    self._holders.pop(holder, None)

            self._stats["expired"] += len(expired_locks)
            if (self._countdown is not None
                    and any(lock.mode == "delay"
                            and "shutdown" in lock.what
                            for lock in expired_locks)):
                self._refresh_countdown_deadline()
            return len(expired_locks)

    def query(self, what, *, now: int = 0) -> Arbitration:
        """Return the arbitration result for the requested ``what`` flags."""
        flags = self._normalize_what(what, allow_empty=True)
        with self._lock:
            result = self._arbitrate(flags, now=now)
            if result.status == "blocked":
                self._stats["blocked_queries"] += 1
            return result

    def begin_shutdown(self, *, now: int = 0, grace: int = 60) -> dict:
        """Start a shutdown countdown and return its state."""
        with self._lock:
            if self._countdown is not None:
                raise InhibitorError("INHIBITOR_ALREADY_SCHEDULED")

            result = self._arbitrate(("shutdown",), now=now)
            if result.blockers:
                raise InhibitorError(
                    "INHIBITOR_BLOCKED", {"blockers": result.blockers}
                )

            delay_total = min(
                sum(lock.delay for lock in self._locks.values()
                    if lock.mode == "delay" and "shutdown" in lock.what),
                self.delay_cap,
            )
            self._countdown = {
                "active": True,
                "deadline": now + grace + delay_total,
                "delay_total": delay_total,
                "blockers": (),
            }
            return self._countdown_result()

    def countdown(self) -> dict:
        """Return the current shutdown countdown state."""
        with self._lock:
            return self._countdown_result()

    def lock_state(self, lock_id: str):
        """Return one lock record or None when it is unknown."""
        with self._lock:
            try:
                return self._locks.get(lock_id)
            except TypeError:
                return None

    def locks(self, *, holder: str | None = None) -> tuple:
        """Return lock records in acquisition order."""
        with self._lock:
            if holder is None:
                return tuple(self._locks.values())
            return tuple(lock for lock in self._locks.values()
                         if lock.holder == holder)

    def snapshot(self) -> dict:
        """Return a detached snapshot of locks, holders and countdown."""
        with self._lock:
            locks = [
                {
                    "lock_id": lock.lock_id,
                    "holder": lock.holder,
                    "mode": lock.mode,
                    "what": list(lock.what),
                    "delay": lock.delay,
                    "priority": lock.priority,
                    "reason": lock.reason,
                    "acquired_at": lock.acquired_at,
                }
                for lock in self._locks.values()
            ]
            holders = copy.deepcopy(self._holders)
            countdown = copy.deepcopy(self._countdown)
            if countdown is not None:
                countdown["blockers"] = list(countdown["blockers"])
            return {
                "version": SNAPSHOT_VERSION,
                "locks": locks,
                "holders": holders,
                "countdown": countdown,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        if not isinstance(state, dict):
            raise InhibitorError("INHIBITOR_SNAPSHOT_INVALID")
        required = {"version", "locks", "holders", "countdown", "stats"}
        if (set(state) != required or not self._is_int(state.get("version"))
                or state.get("version") != SNAPSHOT_VERSION):
            raise InhibitorError("INHIBITOR_SNAPSHOT_INVALID")
        if not isinstance(state["locks"], list):
            raise InhibitorError("INHIBITOR_SNAPSHOT_INVALID")
        if not isinstance(state["holders"], dict):
            raise InhibitorError("INHIBITOR_SNAPSHOT_INVALID")

        restored_locks = {}
        restored_holders = {}
        restored_stats = {}
        restored_countdown = None
        try:
            for item in state["locks"]:
                if not isinstance(item, dict):
                    raise ValueError
                expected = {
                    "lock_id", "holder", "mode", "what", "delay", "priority",
                    "reason", "acquired_at",
                }
                if set(item) != expected:
                    raise ValueError

                lock_id = item["lock_id"]
                holder = item["holder"]
                mode = item["mode"]
                flags = self._normalize_what(item["what"])
                delay = item["delay"]
                priority = item["priority"]
                reason = item["reason"]
                acquired_at = item["acquired_at"]
                if (not isinstance(lock_id, str) or not lock_id
                        or not isinstance(holder, str) or not holder
                        or mode not in MODES
                        or not self._is_int(delay)
                        or not self._is_int(priority)
                        or not isinstance(reason, str)
                        or not self._is_int(acquired_at)
                        or lock_id in restored_locks
                        or (mode == "block" and delay != 0)
                        or (mode == "delay" and delay <= 0)):
                    raise ValueError

                lock = Inhibitor(
                    lock_id=lock_id,
                    holder=holder,
                    mode=mode,
                    what=flags,
                    delay=delay,
                    priority=priority,
                    reason=reason,
                    acquired_at=acquired_at,
                )
                restored_locks[lock_id] = lock

            if len(restored_locks) > self.max_locks:
                raise ValueError

            for holder, details in state["holders"].items():
                if (not isinstance(holder, str) or not holder
                        or not isinstance(details, dict)
                        or set(details) != {"last_heartbeat", "gone"}
                        or not self._is_int(details["last_heartbeat"])
                        or not isinstance(details["gone"], bool)):
                    raise ValueError
                restored_holders[holder] = {
                    "last_heartbeat": details["last_heartbeat"],
                    "gone": details["gone"],
                }

            holder_counts = {}
            signatures = set()
            for lock in restored_locks.values():
                if lock.holder not in restored_holders:
                    raise ValueError
                signature = (lock.holder, lock.mode, lock.what)
                if signature in signatures:
                    raise ValueError
                signatures.add(signature)
                holder_counts[lock.holder] = (
                    holder_counts.get(lock.holder, 0) + 1
                )
            if any(count > self.max_locks_per_holder
                   for count in holder_counts.values()):
                raise ValueError

            countdown = state["countdown"]
            if countdown is not None:
                if not isinstance(countdown, dict):
                    raise ValueError
                if set(countdown) != {
                    "active", "deadline", "delay_total", "blockers",
                }:
                    raise ValueError
                active = countdown["active"]
                deadline = countdown["deadline"]
                delay_total = countdown["delay_total"]
                blockers = countdown["blockers"]
                if (not isinstance(active, bool)
                        or not isinstance(blockers, (list, tuple))
                        or any(not isinstance(blocker, str)
                               for blocker in blockers)
                        or not self._is_int(delay_total)
                        or delay_total < 0):
                    raise ValueError
                if active:
                    if not self._is_int(deadline):
                        raise ValueError
                elif deadline is not None:
                    raise ValueError
                restored_countdown = {
                    "active": active,
                    "deadline": deadline,
                    "delay_total": delay_total,
                    "blockers": tuple(blockers),
                }

            stats = state["stats"]
            if (not isinstance(stats, dict) or set(stats) != set(STAT_KEYS)
                    or any(not self._is_int(stats[key]) or stats[key] < 0
                           for key in STAT_KEYS)):
                raise ValueError
            restored_stats = {key: stats[key] for key in STAT_KEYS}
        except (TypeError, ValueError, InhibitorError) as exc:
            raise InhibitorError("INHIBITOR_SNAPSHOT_INVALID") from exc

        with self._lock:
            self._locks = restored_locks
            self._holders = restored_holders
            self._countdown = restored_countdown
            self._stats = restored_stats
            next_id = 1
            for lock_id in restored_locks:
                if lock_id.startswith("inh-"):
                    suffix = lock_id[4:]
                    if suffix.isdigit():
                        next_id = max(next_id, int(suffix) + 1)
            while f"inh-{next_id}" in restored_locks:
                next_id += 1
            self._next_id = next_id

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return dict(self._stats)
