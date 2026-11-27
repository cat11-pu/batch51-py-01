"""Port I/O bitmap governance: interval merge, difference revoke, fork/exec reset, IOPL downgrade."""

from __future__ import annotations

import threading
from dataclasses import dataclass

PORT_MIN = 0
PORT_MAX = 65535
IOPL_BITMAP = 1
IOPL_ALL = 3


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


class IopermRangeGuard:
    """Keep per-process port bitmaps, the IOPL level and fork/exec inheritance rules."""

    def __init__(self, *, max_ranges_per_process: int = 8,
                 max_ranges_total: int = 32) -> None:
        self.max_ranges_per_process = max_ranges_per_process
        self.max_ranges_total = max_ranges_total
        self._lock = threading.RLock()

    def grant_range(self, pid: int, start: int, end: int, *,
                    cap_rawio: bool = True, now: int | None = None) -> tuple:
        raise NotImplementedError

    def revoke_range(self, pid: int, start: int, end: int) -> tuple:
        raise NotImplementedError

    def revoke_all(self, pid: int) -> int:
        raise NotImplementedError

    def set_iopl(self, pid: int, level: int, *,
                 cap_rawio: bool = True) -> int:
        raise NotImplementedError

    def fork_child(self, parent_pid: int, child_pid: int, *,
                   inherit: bool = False) -> ProcessSnapshot:
        raise NotImplementedError

    def exec_reset(self, pid: int) -> ProcessSnapshot:
        raise NotImplementedError

    def allowed(self, pid: int, port: int) -> bool:
        raise NotImplementedError

    def ranges(self, pid: int) -> tuple:
        raise NotImplementedError

    def process_level(self, pid: int) -> int:
        raise NotImplementedError

    def processes(self) -> list[ProcessSnapshot]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
