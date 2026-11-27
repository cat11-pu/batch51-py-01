"""Scheduler affinity warden: tenant ceilings, online sets, reconcile with fallback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SchedError(ValueError):
    """Raised when the warden refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProcessAffinity:
    pid: int
    tenant: str
    desired: frozenset
    effective: frozenset
    epoch: int


_STATS_KEYS = ("registered", "applied", "rejected", "migrated",
               "fallback", "failed", "hotplug")

_SNAPSHOT_KEYS = ("tenants", "online", "processes", "stats")


class _ProcessRecord:
    """Mutable per-process state, only touched under the warden lock."""

    __slots__ = ("tenant", "desired", "effective", "epoch", "history")

    def __init__(self, tenant: str, desired: frozenset,
                 effective: frozenset) -> None:
        self.tenant = tenant
        self.desired = desired
        self.effective = effective
        self.epoch = 0
        self.history = []


class SchedAffinityWarden:
    """Keep tenant cpu ceilings, the online set and per-process affinity."""

    def __init__(self, *, cpus=(0, 1, 2, 3)) -> None:
        self.cpus = tuple(sorted(set(cpus)))
        self._possible = frozenset(self.cpus)
        self._lock = threading.RLock()
        self._online = frozenset(self.cpus)
        self._tenants: dict[str, frozenset] = {}
        self._processes: dict[int, _ProcessRecord] = {}
        self._stats = {key: 0 for key in _STATS_KEYS}

    @staticmethod
    def _view(pid: int, record: _ProcessRecord) -> ProcessAffinity:
        return ProcessAffinity(pid=pid, tenant=record.tenant,
                               desired=record.desired,
                               effective=record.effective,
                               epoch=record.epoch)

    def _check_known(self, requested: frozenset) -> None:
        unknown = requested - self._possible
        if unknown:
            self._stats["rejected"] += 1
            raise SchedError("SCHED_CPU_UNKNOWN", sorted(unknown))

    def set_allowed(self, tenant: str, cpus) -> tuple[int, ...]:
        with self._lock:
            requested = frozenset(cpus)
            self._check_known(requested)
            allowed = requested & self._online
            if not allowed:
                self._stats["rejected"] += 1
                raise SchedError("SCHED_EMPTY_SET",
                                 {"tenant": tenant, "requested": sorted(requested)})
            self._tenants[tenant] = allowed
            return tuple(sorted(allowed))

    def allowed_for(self, tenant: str) -> tuple[int, ...]:
        with self._lock:
            allowed = self._tenants.get(tenant)
            if allowed is None:
                raise SchedError("SCHED_UNKNOWN_TENANT", tenant)
            return tuple(sorted(allowed))

    def set_online(self, cpus) -> tuple[int, ...]:
        with self._lock:
            requested = frozenset(cpus)
            self._check_known(requested)
            self._online = requested
            self._stats["hotplug"] += 1
            return tuple(sorted(requested))

    def register_process(self, pid: int, tenant: str, cpus) -> ProcessAffinity:
        with self._lock:
            allowed = self._tenants.get(tenant)
            if allowed is None:
                self._stats["rejected"] += 1
                raise SchedError("SCHED_UNKNOWN_TENANT", tenant)
            if pid in self._processes:
                self._stats["rejected"] += 1
                raise SchedError("SCHED_DUPLICATE_PID", pid)
            desired = frozenset(cpus)
            effective = desired & allowed & self._online
            if not effective:
                self._stats["rejected"] += 1
                raise SchedError("SCHED_EMPTY_SET",
                                 {"pid": pid, "requested": sorted(desired)})
            record = _ProcessRecord(tenant, desired, effective)
            self._processes[pid] = record
            self._stats["registered"] += 1
            return self._view(pid, record)

    def unregister_process(self, pid: int) -> bool:
        with self._lock:
            return self._processes.pop(pid, None) is not None

    def apply(self, pid: int, cpus) -> ProcessAffinity:
        with self._lock:
            record = self._processes.get(pid)
            if record is None:
                self._stats["rejected"] += 1
                raise SchedError("SCHED_UNKNOWN_PID", pid)
            requested = frozenset(cpus)
            self._check_known(requested)
            allowed = self._tenants.get(record.tenant, frozenset())
            effective = requested & allowed & self._online
            if not effective:
                self._stats["rejected"] += 1
                raise SchedError("SCHED_EMPTY_SET",
                                 {"pid": pid, "requested": sorted(requested)})
            record.desired = requested
            record.effective = effective
            record.epoch += 1
            record.history.append({
                "epoch": record.epoch,
                "desired": tuple(sorted(requested)),
                "effective": tuple(sorted(effective)),
                "reason": "apply",
            })
            self._stats["applied"] += 1
            return self._view(pid, record)

    def effective_set(self, pid: int) -> frozenset:
        with self._lock:
            record = self._processes.get(pid)
            if record is None:
                raise SchedError("SCHED_UNKNOWN_PID", pid)
            return record.effective

    def reconcile(self) -> dict:
        with self._lock:
            counts = {"checked": 0, "migrated": 0, "fallback": 0, "failed": 0}
            for pid in sorted(self._processes):
                record = self._processes[pid]
                counts["checked"] += 1
                allowed = self._tenants.get(record.tenant, frozenset())
                direct = record.desired & allowed & self._online
                if direct:
                    new_effective = direct
                    reason = "reconcile"
                else:
                    fallback = record.effective & allowed & self._online
                    if fallback:
                        new_effective = fallback
                        reason = "fallback"
                        counts["fallback"] += 1
                    else:
                        new_effective = frozenset()
                        reason = "failed"
                        counts["failed"] += 1
                if new_effective != record.effective:
                    record.effective = new_effective
                    record.epoch += 1
                    record.history.append({
                        "epoch": record.epoch,
                        "desired": tuple(sorted(record.desired)),
                        "effective": tuple(sorted(new_effective)),
                        "reason": reason,
                    })
                    counts["migrated"] += 1
            for key in ("migrated", "fallback", "failed"):
                self._stats[key] += counts[key]
            return counts

    def history(self, pid: int) -> list[dict]:
        with self._lock:
            record = self._processes.get(pid)
            if record is None:
                raise SchedError("SCHED_UNKNOWN_PID", pid)
            return [dict(entry) for entry in record.history]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "tenants": {name: sorted(allowed)
                            for name, allowed in self._tenants.items()},
                "online": sorted(self._online),
                "processes": {
                    str(pid): {
                        "pid": pid,
                        "tenant": record.tenant,
                        "desired": sorted(record.desired),
                        "effective": sorted(record.effective),
                        "epoch": record.epoch,
                        "history": [
                            {"epoch": entry["epoch"],
                             "desired": list(entry["desired"]),
                             "effective": list(entry["effective"]),
                             "reason": entry["reason"]}
                            for entry in record.history
                        ],
                    }
                    for pid, record in self._processes.items()
                },
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        tenants, online, processes, stats = self._parse_snapshot(state)
        with self._lock:
            self._tenants = tenants
            self._online = online
            self._processes = processes
            self._stats = stats

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _snapshot_cpus(self, value, where: str) -> frozenset:
        if not isinstance(value, (list, tuple)):
            raise SchedError("SCHED_SNAPSHOT_INVALID", where)
        cpus = []
        for item in value:
            if not self._is_int(item) or item not in self._possible:
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            cpus.append(item)
        return frozenset(cpus)

    def _parse_snapshot(self, state):
        if not isinstance(state, dict) or set(state) != set(_SNAPSHOT_KEYS):
            raise SchedError("SCHED_SNAPSHOT_INVALID", "top-level keys")
        raw_tenants = state["tenants"]
        raw_online = state["online"]
        raw_processes = state["processes"]
        raw_stats = state["stats"]
        if not isinstance(raw_tenants, dict) or not isinstance(raw_processes, dict):
            raise SchedError("SCHED_SNAPSHOT_INVALID", "tenants/processes")
        if not isinstance(raw_stats, dict):
            raise SchedError("SCHED_SNAPSHOT_INVALID", "stats")

        tenants = {}
        for name, cpus in raw_tenants.items():
            if not isinstance(name, str):
                raise SchedError("SCHED_SNAPSHOT_INVALID", "tenant name")
            tenants[name] = self._snapshot_cpus(cpus, f"tenants[{name!r}]")
        online = self._snapshot_cpus(raw_online, "online")

        processes = {}
        for key, entry in raw_processes.items():
            where = f"processes[{key!r}]"
            if not isinstance(key, str) or not isinstance(entry, dict):
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            if set(entry) != {"pid", "tenant", "desired", "effective",
                              "epoch", "history"}:
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            pid = entry["pid"]
            if not self._is_int(pid) or str(pid) != key:
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            if not isinstance(entry["tenant"], str) or entry["tenant"] not in tenants:
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            if not self._is_int(entry["epoch"]) or entry["epoch"] < 0:
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            desired = self._snapshot_cpus(entry["desired"], where)
            effective = self._snapshot_cpus(entry["effective"], where)
            raw_history = entry["history"]
            if not isinstance(raw_history, list):
                raise SchedError("SCHED_SNAPSHOT_INVALID", where)
            record = _ProcessRecord(entry["tenant"], desired, effective)
            record.epoch = entry["epoch"]
            for item in raw_history:
                if (not isinstance(item, dict)
                        or set(item) != {"epoch", "desired", "effective", "reason"}
                        or not self._is_int(item["epoch"])
                        or not isinstance(item["reason"], str)):
                    raise SchedError("SCHED_SNAPSHOT_INVALID", where)
                record.history.append({
                    "epoch": item["epoch"],
                    "desired": tuple(sorted(
                        self._snapshot_cpus(item["desired"], where))),
                    "effective": tuple(sorted(
                        self._snapshot_cpus(item["effective"], where))),
                    "reason": item["reason"],
                })
            processes[pid] = record

        stats = {}
        for name in _STATS_KEYS:
            value = raw_stats.get(name)
            if not self._is_int(value) or value < 0:
                raise SchedError("SCHED_SNAPSHOT_INVALID", "stats")
            stats[name] = value
        return tenants, online, processes, stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
