"""Port I/O bitmap governance: interval merge, difference revoke, fork/exec reset, IOPL downgrade."""

from __future__ import annotations

import threading
from dataclasses import dataclass

PORT_MIN = 0
PORT_MAX = 65535
IOPL_BITMAP = 1
IOPL_ALL = 3
SNAPSHOT_VERSION = 1

_EVENT_COUNTERS = (
    "grants",
    "revokes",
    "forks",
    "exec_resets",
    "iopl_changes",
)


class IoportError(ValueError):
    """Raised when a port permission operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PortRange:
    start: int
    end: int


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    level: int
    ranges: tuple[tuple[int, int], ...]
    inherited: bool


@dataclass
class _ProcessState:
    ranges: tuple[tuple[int, int], ...] = ()
    level: int = 0
    inherited: bool = False


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _merge_ranges(
    ranges: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    """Return the canonical union of closed port intervals."""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    return tuple(merged)


def _subtract_range(
    ranges: tuple[tuple[int, int], ...], start: int, end: int
) -> tuple[tuple[int, int], ...]:
    """Return ``ranges`` minus the closed interval ``[start, end]``."""
    remaining: list[tuple[int, int]] = []
    for old_start, old_end in ranges:
        if old_end < start or old_start > end:
            remaining.append((old_start, old_end))
            continue
        if old_start < start:
            remaining.append((old_start, start - 1))
        if old_end > end:
            remaining.append((end + 1, old_end))
    return tuple(remaining)


class IopermRangeGuard:
    """Keep per-process port bitmaps, the IOPL level and fork/exec inheritance rules."""

    def __init__(self, *, max_ranges_per_process: int = 8,
                 max_ranges_total: int = 32) -> None:
        if not _is_int(max_ranges_per_process) or max_ranges_per_process < 0:
            raise ValueError("max_ranges_per_process must be a non-negative integer")
        if not _is_int(max_ranges_total) or max_ranges_total < 0:
            raise ValueError("max_ranges_total must be a non-negative integer")
        self.max_ranges_per_process = max_ranges_per_process
        self.max_ranges_total = max_ranges_total
        self._lock = threading.RLock()
        self._processes: dict[int, _ProcessState] = {}
        self._counters = {key: 0 for key in _EVENT_COUNTERS}

    @staticmethod
    def _validate_pid(pid: int) -> None:
        if not _is_int(pid) or pid <= 0:
            raise IoportError("IOPORT_INVALID_PID", {"pid": pid})

    @staticmethod
    def _validate_range(start: int, end: int) -> None:
        detail = {"start": start, "end": end}
        if not _is_int(start) or not _is_int(end):
            raise IoportError("IOPORT_INVALID_RANGE", detail)
        if start < PORT_MIN or end > PORT_MAX or start > end:
            raise IoportError("IOPORT_INVALID_RANGE", detail)

    @staticmethod
    def _validate_port(port: int) -> None:
        if not _is_int(port) or not PORT_MIN <= port <= PORT_MAX:
            raise IoportError("IOPORT_INVALID_RANGE", {"port": port})

    def _total_range_count(self) -> int:
        return sum(len(state.ranges) for state in self._processes.values())

    def _check_limits(
        self,
        pid: int,
        old_ranges: tuple[tuple[int, int], ...],
        new_ranges: tuple[tuple[int, int], ...],
    ) -> None:
        if len(new_ranges) > self.max_ranges_per_process:
            raise IoportError(
                "IOPORT_LIMIT_EXCEEDED",
                {
                    "scope": "process",
                    "pid": pid,
                    "ranges": len(new_ranges),
                    "limit": self.max_ranges_per_process,
                },
            )
        new_total = self._total_range_count() - len(old_ranges) + len(new_ranges)
        if new_total > self.max_ranges_total:
            raise IoportError(
                "IOPORT_LIMIT_EXCEEDED",
                {
                    "scope": "total",
                    "ranges": new_total,
                    "limit": self.max_ranges_total,
                },
            )

    @staticmethod
    def _snapshot_process(pid: int, state: _ProcessState) -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=pid,
            level=state.level,
            ranges=tuple(state.ranges),
            inherited=state.inherited,
        )

    def grant_range(self, pid: int, start: int, end: int, *,
                    cap_rawio: bool = True, now: int | None = None) -> tuple:
        del now
        self._validate_pid(pid)
        self._validate_range(start, end)
        with self._lock:
            if not cap_rawio:
                raise IoportError("IOPORT_CAP_MISSING", {"cap": "CAP_SYS_RAWIO"})

            state = self._processes.get(pid)
            old_ranges = state.ranges if state is not None else ()
            new_ranges = _merge_ranges(old_ranges + ((start, end),))
            self._check_limits(pid, old_ranges, new_ranges)

            if state is None:
                self._processes[pid] = _ProcessState(ranges=new_ranges)
            else:
                state.ranges = new_ranges
            self._counters["grants"] += 1
            return new_ranges

    def revoke_range(self, pid: int, start: int, end: int) -> tuple:
        self._validate_pid(pid)
        self._validate_range(start, end)
        with self._lock:
            state = self._processes.get(pid)
            if state is None:
                raise IoportError("IOPORT_UNKNOWN_PROCESS", {"pid": pid})

            old_ranges = state.ranges
            new_ranges = _subtract_range(old_ranges, start, end)
            self._check_limits(pid, old_ranges, new_ranges)

            state.ranges = new_ranges
            self._counters["revokes"] += 1
            return new_ranges

    def revoke_all(self, pid: int) -> int:
        self._validate_pid(pid)
        with self._lock:
            state = self._processes.get(pid)
            if state is None:
                raise IoportError("IOPORT_UNKNOWN_PROCESS", {"pid": pid})

            revoked = len(state.ranges)
            state.ranges = ()
            self._counters["revokes"] += 1
            return revoked

    def set_iopl(self, pid: int, level: int, *,
                 cap_rawio: bool = True) -> int:
        self._validate_pid(pid)
        if not _is_int(level) or level not in (0, IOPL_ALL):
            raise IoportError("IOPORT_INVALID_LEVEL", {"level": level})
        with self._lock:
            if level == IOPL_ALL and not cap_rawio:
                raise IoportError("IOPORT_CAP_MISSING", {"cap": "CAP_SYS_RAWIO"})

            state = self._processes.get(pid)
            if state is None:
                state = _ProcessState()
                self._processes[pid] = state
            state.level = level
            self._counters["iopl_changes"] += 1
            return level

    def fork_child(self, parent_pid: int, child_pid: int, *,
                   inherit: bool = False) -> ProcessSnapshot:
        self._validate_pid(parent_pid)
        self._validate_pid(child_pid)
        with self._lock:
            if child_pid in self._processes:
                raise IoportError("IOPORT_PID_EXISTS", {"pid": child_pid})
            parent = self._processes.get(parent_pid)
            if parent is None:
                raise IoportError(
                    "IOPORT_UNKNOWN_PROCESS", {"pid": parent_pid}
                )

            if inherit:
                child_ranges = tuple(parent.ranges)
                self._check_limits(child_pid, (), child_ranges)
            else:
                child_ranges = ()

            child = _ProcessState(
                ranges=child_ranges,
                level=0,
                inherited=bool(inherit),
            )
            self._processes[child_pid] = child
            self._counters["forks"] += 1
            return self._snapshot_process(child_pid, child)

    def exec_reset(self, pid: int) -> ProcessSnapshot:
        self._validate_pid(pid)
        with self._lock:
            state = self._processes.get(pid)
            if state is None:
                raise IoportError("IOPORT_UNKNOWN_PROCESS", {"pid": pid})

            state.ranges = ()
            state.level = 0
            state.inherited = False
            self._counters["exec_resets"] += 1
            return self._snapshot_process(pid, state)

    def allowed(self, pid: int, port: int) -> bool:
        self._validate_pid(pid)
        self._validate_port(port)
        with self._lock:
            state = self._processes.get(pid)
            if state is None:
                return False
            if state.level == IOPL_ALL:
                return True
            return any(start <= port <= end for start, end in state.ranges)

    def ranges(self, pid: int) -> tuple:
        self._validate_pid(pid)
        with self._lock:
            state = self._processes.get(pid)
            if state is None:
                raise IoportError("IOPORT_UNKNOWN_PROCESS", {"pid": pid})
            return tuple(state.ranges)

    def process_level(self, pid: int) -> int:
        self._validate_pid(pid)
        with self._lock:
            state = self._processes.get(pid)
            if state is None:
                raise IoportError("IOPORT_UNKNOWN_PROCESS", {"pid": pid})
            return state.level

    def processes(self) -> list[ProcessSnapshot]:
        with self._lock:
            return [
                self._snapshot_process(pid, self._processes[pid])
                for pid in sorted(self._processes)
            ]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "processes": {
                    pid: {
                        "ranges": list(self._processes[pid].ranges),
                        "level": self._processes[pid].level,
                        "inherited": self._processes[pid].inherited,
                    }
                    for pid in sorted(self._processes)
                },
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                processes, counters = self._parse_snapshot(state)
            except (KeyError, TypeError, ValueError):
                raise IoportError("IOPORT_SNAPSHOT_INVALID") from None

            self._processes = processes
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            result = {"processes": len(self._processes)}
            result.update(self._counters)
            return result

    def _parse_snapshot(
        self, state: object
    ) -> tuple[dict[int, _ProcessState], dict[str, int]]:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a mapping")
        if set(state) != {"version", "processes", "counters"}:
            raise ValueError("snapshot keys are invalid")
        if state["version"] != SNAPSHOT_VERSION or not _is_int(state["version"]):
            raise ValueError("snapshot version is invalid")

        raw_processes = state["processes"]
        if not isinstance(raw_processes, dict):
            raise ValueError("snapshot processes must be a mapping")

        processes: dict[int, _ProcessState] = {}
        total_ranges = 0
        for raw_pid, raw in raw_processes.items():
            if _is_int(raw_pid):
                pid = raw_pid
            elif isinstance(raw_pid, str) and raw_pid.isdigit():
                pid = int(raw_pid)
            else:
                raise ValueError("snapshot pid is invalid")
            if pid <= 0 or pid in processes:
                raise ValueError("snapshot pid is invalid")
            if not isinstance(raw, dict):
                raise ValueError("snapshot process is invalid")
            if set(raw) != {"ranges", "level", "inherited"}:
                raise ValueError("snapshot process keys are invalid")

            level = raw["level"]
            inherited = raw["inherited"]
            if not _is_int(level) or level not in (0, IOPL_ALL):
                raise ValueError("snapshot level is invalid")
            if not isinstance(inherited, bool):
                raise ValueError("snapshot inherited flag is invalid")

            raw_ranges = raw["ranges"]
            if not isinstance(raw_ranges, (list, tuple)):
                raise ValueError("snapshot ranges are invalid")
            ranges: list[tuple[int, int]] = []
            for item in raw_ranges:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise ValueError("snapshot range is invalid")
                start, end = item
                self._validate_range(start, end)
                ranges.append((start, end))

            canonical = _merge_ranges(tuple(ranges))
            if canonical != tuple(ranges):
                raise ValueError("snapshot ranges are not canonical")
            if len(canonical) > self.max_ranges_per_process:
                raise ValueError("snapshot process range limit exceeded")
            total_ranges += len(canonical)
            if total_ranges > self.max_ranges_total:
                raise ValueError("snapshot total range limit exceeded")

            processes[pid] = _ProcessState(
                ranges=canonical,
                level=level,
                inherited=inherited,
            )

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise ValueError("snapshot counters must be a mapping")
        counter_keys = set(raw_counters)
        if counter_keys not in (
            set(_EVENT_COUNTERS),
            set(_EVENT_COUNTERS) | {"processes"},
        ):
            raise ValueError("snapshot counter keys are invalid")
        counters: dict[str, int] = {}
        for key in _EVENT_COUNTERS:
            value = raw_counters[key]
            if not _is_int(value) or value < 0:
                raise ValueError("snapshot counter is invalid")
            counters[key] = value
        if "processes" in raw_counters:
            process_count = raw_counters["processes"]
            if (not _is_int(process_count) or process_count < 0
                    or process_count != len(processes)):
                raise ValueError("snapshot process counter is invalid")

        return processes, counters
