"""mDNS service name conflict governance for the local link."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
PROBING = "probing"
ANNOUNCED = "announced"
CONFLICT = "conflict"


class MdnsError(ValueError):
    """Raised when an mDNS name operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class InstanceRecord:
    instance: str
    name: str
    service_type: str
    port: int
    iface: str
    target: str
    unique: bool


@dataclass(frozen=True)
class ProbeState:
    name: str
    service_type: str
    iface: str
    state: str
    remaining: int
    next_probe_at: int | None
    announced_at: int | None


class MdnsConflictGuard:
    """Track per-interface names through probing, announcing and defence."""

    def __init__(self, *, probe_count: int = 3, probe_interval: int = 250,
                 max_records_per_interface: int = 64) -> None:
        self.probe_count = probe_count
        self.probe_interval = probe_interval
        self.max_records_per_interface = max_records_per_interface
        self._lock = threading.RLock()
        self._instances: dict[str, InstanceRecord] = {}
        self._states: dict[tuple[str, str, str], dict] = {}
        self._flushed: dict[str, set[str]] = {}
        self._stats = {
            "probes": 0,
            "announced": 0,
            "conflicts": 0,
            "released": 0,
            "refreshed": 0,
            "flushed": 0,
        }

    def register_instance(self, instance: str, *, name: str, service_type: str,
                          port: int, iface: str, target: str | None = None,
                          unique: bool = True, now=None) -> InstanceRecord:
        raise NotImplementedError

    def instance_record(self, instance: str) -> InstanceRecord | None:
        raise NotImplementedError

    def begin_probe(self, name: str, service_type: str, iface: str,
                    now=None) -> ProbeState:
        raise NotImplementedError

    def probe_state(self, name: str, service_type: str,
                    iface: str) -> ProbeState | None:
        raise NotImplementedError

    def tick(self, now=None) -> int:
        raise NotImplementedError

    def announce(self, name: str, service_type: str, iface: str,
                 now=None) -> bool:
        raise NotImplementedError

    def observe(self, record, iface: str, now=None) -> str:
        raise NotImplementedError

    def resolve(self, name: str, service_type: str,
                iface: str) -> tuple[InstanceRecord, ...]:
        raise NotImplementedError

    def defend(self, name: str, service_type: str, iface: str) -> str:
        raise NotImplementedError

    def mark_cache_flush(self, name: str, service_type: str, iface: str) -> int:
        raise NotImplementedError

    def take_flushed(self, iface: str) -> tuple[InstanceRecord, ...]:
        raise NotImplementedError

    def records_for(self, iface: str) -> tuple[InstanceRecord, ...]:
        raise NotImplementedError

    def release(self, name: str, service_type: str, iface: str) -> bool:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError
