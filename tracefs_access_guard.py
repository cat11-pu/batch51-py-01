"""Trace interface governance: instance isolation, probe whitelist, slow-reader quotas."""

from __future__ import annotations

import threading
from dataclasses import dataclass

KPROBE = "kprobe"
UPROBE = "uprobe"
PROBE_KINDS = (KPROBE, UPROBE)

PROBE_WHITELIST = {
    "vfs_read": (0, 64),
    "do_sys_openat2": (0, 32),
    "tcp_sendmsg": (0, 128),
    "__x64_sys_write": (0, 0),
}


class TraceError(ValueError):
    """Raised when a tracing operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TraceInstance:
    name: str
    tenant: str
    buffer_size_kb: int
    filter: str | None
    active: bool


@dataclass(frozen=True)
class ProbeRecord:
    probe_id: str
    instance: str
    kind: str
    symbol: str
    offset: int
    filter: str
    enabled: bool


@dataclass(frozen=True)
class ReaderHandle:
    reader_id: str
    instance: str
    tenant: str
    lost: int
    closed: bool


class TracefsAccessGuard:
    """Own tracefs instances, whitelisted probes and per-reader ring buffers."""

    def __init__(self, *, max_instances: int = 8,
                 max_probes_per_instance: int = 16, max_probes_total: int = 64,
                 max_readers_per_instance: int = 4, max_readers_total: int = 16,
                 reader_capacity: int = 8) -> None:
        self.max_instances = max_instances
        self.max_probes_per_instance = max_probes_per_instance
        self.max_probes_total = max_probes_total
        self.max_readers_per_instance = max_readers_per_instance
        self.max_readers_total = max_readers_total
        self.reader_capacity = reader_capacity
        self._lock = threading.RLock()

    def create_instance(self, name: str, *, tenant: str,
                        buffer_size_kb: int = 1024,
                        filter: str | None = None) -> TraceInstance:
        raise NotImplementedError

    def destroy_instance(self, name: str, *, force: bool = False) -> dict:
        raise NotImplementedError

    def instances(self, tenant: str | None = None) -> list[TraceInstance]:
        raise NotImplementedError

    def register_probe(self, instance: str, *, symbol: str, kind: str = KPROBE,
                       offset: int = 0, filter: str = "") -> ProbeRecord:
        raise NotImplementedError

    def probes(self, instance: str) -> list[ProbeRecord]:
        raise NotImplementedError

    def describe(self, probe_id: str) -> dict:
        raise NotImplementedError

    def enable_event(self, instance: str, event: str, *,
                     enable: bool = True) -> int:
        raise NotImplementedError

    def attach_reader(self, instance: str, *, tenant: str,
                      reader_id: str | None = None) -> ReaderHandle:
        raise NotImplementedError

    def detach_reader(self, reader_id: str) -> bool:
        raise NotImplementedError

    def emit_event(self, instance: str, event: str, *, count: int = 1) -> dict:
        raise NotImplementedError

    def read(self, reader_id: str, *, max_events: int = 64) -> list[str]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
