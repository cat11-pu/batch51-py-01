"""PTY session allocator: tenant quota, session leader binding, orphan reclaim."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

_DEVICE_PATTERN = re.compile(r"^pts/[0-9]+$")

STATES = ("free", "allocated", "bound", "releasing")


class PtyError(ValueError):
    """Raised when the allocator refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    tenant: str | None
    session_id: str | None
    leader_pid: int | None
    leader_start: int | None
    state: str
    generation: int


class PtySessionAllocator:
    """Pool of pseudo terminal device ids with tenant leases and leader binding."""

    def __init__(self, *, devices=("pts/0", "pts/1", "pts/2", "pts/3"),
                 max_per_tenant: int = 4) -> None:
        self.max_per_tenant = int(max_per_tenant)
        self._lock = threading.RLock()
        self._records: dict[str, DeviceRecord] = {}
        self._holders: dict[str, list[tuple[int, int, str]]] = {}
        self._stats = {
            "allocations": 0,
            "bindings": 0,
            "releases": 0,
            "flushed": 0,
            "reclaimed": 0,
            "refused": 0,
        }
        for device_id in devices:
            self._records[device_id] = DeviceRecord(
                device_id=device_id,
                tenant=None,
                session_id=None,
                leader_pid=None,
                leader_start=None,
                state="free",
                generation=0,
            )
            self._holders[device_id] = []

    def add_device(self, device_id: str) -> int:
        raise NotImplementedError

    def allocate(self, tenant: str, *, device_id: str | None = None,
                 now: int | None = None) -> DeviceRecord:
        raise NotImplementedError

    def bind_session(self, device_id: str, *, session_id: str, leader_pid: int,
                     leader_start: int, now: int | None = None) -> DeviceRecord:
        raise NotImplementedError

    def hold(self, device_id: str, *, pid: int, start: int,
             role: str = "child") -> None:
        raise NotImplementedError

    def release(self, device_id: str, *, now: int | None = None) -> bool:
        raise NotImplementedError

    def flush_release(self, device_id: str, *, alive=None) -> bool:
        raise NotImplementedError

    def reclaim_orphans(self, *, alive, now: int | None = None) -> tuple[str, ...]:
        raise NotImplementedError

    def usage(self, tenant: str) -> int:
        raise NotImplementedError

    def lookup(self, device_id: str) -> DeviceRecord | None:
        raise NotImplementedError

    def records_for(self, tenant: str) -> tuple[DeviceRecord, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
