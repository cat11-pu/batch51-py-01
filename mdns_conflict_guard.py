"""mDNS service name conflict governance for the local link."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, replace

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
        with self._lock:
            if not isinstance(name, str) or not name:
                raise MdnsError("MDNS_INVALID_INSTANCE",
                                {"reason": "empty name", "instance": instance})
            if not isinstance(port, int) or isinstance(port, bool) or port < 1:
                raise MdnsError("MDNS_INVALID_INSTANCE",
                                {"reason": "invalid port", "port": port,
                                 "instance": instance})
            if instance in self._instances:
                raise MdnsError("MDNS_NAME_TAKEN",
                                {"reason": "instance already registered",
                                 "instance": instance})

            on_iface = [row for row in self._instances.values()
                        if row.iface == iface]
            if len(on_iface) >= self.max_records_per_interface:
                raise MdnsError("MDNS_CAPACITY_EXCEEDED",
                                {"iface": iface,
                                 "limit": self.max_records_per_interface})

            key = (name, service_type, iface)
            holders = [row for row in self._instances.values()
                       if (row.name, row.service_type, row.iface) == key]
            if unique and holders:
                raise MdnsError("MDNS_NAME_TAKEN",
                                {"name": name, "service_type": service_type,
                                 "iface": iface})
            if not unique and any(row.unique for row in holders):
                raise MdnsError("MDNS_NAME_TAKEN",
                                {"name": name, "service_type": service_type,
                                 "iface": iface})

            record = InstanceRecord(
                instance=instance, name=name, service_type=service_type,
                port=port, iface=iface,
                target=target if target is not None else name,
                unique=unique)
            self._instances[instance] = record
            return record

    def instance_record(self, instance: str) -> InstanceRecord | None:
        with self._lock:
            return self._instances.get(instance)

    def begin_probe(self, name: str, service_type: str, iface: str,
                    now=None) -> ProbeState:
        with self._lock:
            key = (name, service_type, iface)
            if key in self._states:
                raise MdnsError("MDNS_NAME_TAKEN",
                                {"name": name, "service_type": service_type,
                                 "iface": iface})
            moment = 0 if now is None else now
            self._states[key] = {
                "state": PROBING,
                "remaining": self.probe_count,
                "next_probe_at": moment + self.probe_interval,
                "announced_at": None,
            }
            return self._to_probe_state(key, self._states[key])

    def probe_state(self, name: str, service_type: str,
                    iface: str) -> ProbeState | None:
        with self._lock:
            key = (name, service_type, iface)
            entry = self._states.get(key)
            if entry is None:
                return None
            return self._to_probe_state(key, entry)

    def tick(self, now=None) -> int:
        with self._lock:
            moment = 0 if now is None else now
            advanced = 0
            for entry in self._states.values():
                if entry["state"] != PROBING:
                    continue
                due = entry["next_probe_at"]
                if due is None or moment < due:
                    continue
                entry["remaining"] -= 1
                self._stats["probes"] += 1
                advanced += 1
                if entry["remaining"] <= 0:
                    entry["state"] = ANNOUNCED
                    entry["announced_at"] = moment
                    entry["next_probe_at"] = None
                    self._stats["announced"] += 1
                else:
                    entry["next_probe_at"] = moment + self.probe_interval
            return advanced

    def announce(self, name: str, service_type: str, iface: str,
                 now=None) -> bool:
        with self._lock:
            entry = self._states.get((name, service_type, iface))
            if entry is None or entry["state"] != ANNOUNCED:
                return False
            entry["announced_at"] = 0 if now is None else now
            return True

    def observe(self, record, iface: str, now=None) -> str:
        with self._lock:
            name = record["name"]
            service_type = record["service_type"]
            target = record["target"]
            port = record["port"]

            local = sorted(
                (row for row in self._instances.values()
                 if row.iface == iface
                 and row.name == name
                 and row.service_type == service_type),
                key=lambda row: row.instance)
            if not local:
                self._stats["refreshed"] += 1
                return "refreshed"

            if all(row.target == target and row.port == port
                   for row in local):
                return "duplicate"

            victim = next(row for row in local
                          if row.target != target or row.port != port)
            old_key = (victim.name, victim.service_type, victim.iface)
            new_name = f"{victim.name}-2"
            new_key = (new_name, victim.service_type, victim.iface)
            renamed = replace(victim, name=new_name)
            self._instances[victim.instance] = renamed
            self._states.pop(old_key, None)
            moment = 0 if now is None else now
            self._states[new_key] = {
                "state": PROBING,
                "remaining": self.probe_count,
                "next_probe_at": moment + self.probe_interval,
                "announced_at": None,
            }
            self._stats["conflicts"] += 1
            return CONFLICT

    def resolve(self, name: str, service_type: str,
                iface: str) -> tuple[InstanceRecord, ...]:
        with self._lock:
            return tuple(sorted(
                (row for row in self._instances.values()
                 if row.iface == iface
                 and row.name == name
                 and row.service_type == service_type),
                key=lambda row: row.instance))

    def defend(self, name: str, service_type: str, iface: str) -> str:
        with self._lock:
            entry = self._states.get((name, service_type, iface))
            if entry is not None and entry["state"] == ANNOUNCED:
                return "defend"
            return "ignore"

    def mark_cache_flush(self, name: str, service_type: str,
                         iface: str) -> int:
        with self._lock:
            matches = [row for row in self._instances.values()
                       if row.iface == iface
                       and row.name == name
                       and row.service_type == service_type]
            marked = self._flushed.setdefault(iface, set())
            for row in matches:
                marked.add(row.instance)
            return len(matches)

    def take_flushed(self, iface: str) -> tuple[InstanceRecord, ...]:
        with self._lock:
            marked = self._flushed.get(iface)
            if not marked:
                self._flushed.pop(iface, None)
                return ()
            records = tuple(sorted(
                (self._instances[instance] for instance in marked
                 if instance in self._instances),
                key=lambda row: row.instance))
            marked.clear()
            self._flushed.pop(iface, None)
            self._stats["flushed"] += len(records)
            return records

    def records_for(self, iface: str) -> tuple[InstanceRecord, ...]:
        with self._lock:
            return tuple(sorted(
                (row for row in self._instances.values()
                 if row.iface == iface),
                key=lambda row: row.instance))

    def release(self, name: str, service_type: str, iface: str) -> bool:
        with self._lock:
            key = (name, service_type, iface)
            victims = [instance for instance, row in self._instances.items()
                       if (row.name, row.service_type, row.iface) == key]
            if not victims and key not in self._states:
                return False
            for instance in victims:
                del self._instances[instance]
                marked = self._flushed.get(iface)
                if marked is not None:
                    marked.discard(instance)
            self._states.pop(key, None)
            self._stats["released"] += 1
            return True

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "instances": copy.deepcopy(self._instances),
                "states": copy.deepcopy(self._states),
                "flushed": copy.deepcopy(self._flushed),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state) -> None:
        if not isinstance(state, dict):
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "snapshot must be a dict"})
        required = {"version", "instances", "states", "flushed", "stats"}
        if set(state) != required:
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "snapshot keys mismatch",
                             "keys": sorted(state)})
        if state["version"] != SNAPSHOT_VERSION:
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "unsupported version",
                             "version": state["version"]})
        if not isinstance(state["instances"], dict):
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "instances must be a dict"})
        if not all(isinstance(key, str) and isinstance(row, InstanceRecord)
                   for key, row in state["instances"].items()):
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "invalid instances payload"})
        if not isinstance(state["states"], dict):
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "states must be a dict"})
        state_keys = {"state", "remaining", "next_probe_at", "announced_at"}
        for key, entry in state["states"].items():
            if (not isinstance(key, tuple) or len(key) != 3
                    or not all(isinstance(part, str) for part in key)
                    or not isinstance(entry, dict)
                    or set(entry) != state_keys
                    or entry["state"] not in (PROBING, ANNOUNCED)
                    or not isinstance(entry["remaining"], int)
                    or isinstance(entry["remaining"], bool)
                    or (entry["next_probe_at"] is not None
                        and not isinstance(entry["next_probe_at"], int))
                    or (entry["announced_at"] is not None
                        and not isinstance(entry["announced_at"], int))):
                raise MdnsError("MDNS_SNAPSHOT_INVALID",
                                {"reason": "invalid probe state", "key": key})
        if not isinstance(state["flushed"], dict) or not all(
                isinstance(iface, str) and isinstance(marked, set)
                and all(isinstance(instance, str) for instance in marked)
                for iface, marked in state["flushed"].items()):
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "invalid flushed payload"})
        stats_keys = {"probes", "announced", "conflicts",
                      "released", "refreshed", "flushed"}
        if (not isinstance(state["stats"], dict)
                or set(state["stats"]) != stats_keys
                or not all(isinstance(value, int)
                           and not isinstance(value, bool)
                           for value in state["stats"].values())):
            raise MdnsError("MDNS_SNAPSHOT_INVALID",
                            {"reason": "invalid stats payload"})

        with self._lock:
            self._instances = copy.deepcopy(state["instances"])
            self._states = copy.deepcopy(state["states"])
            self._flushed = copy.deepcopy(state["flushed"])
            self._stats = copy.deepcopy(state["stats"])

    def _to_probe_state(self, key: tuple[str, str, str],
                        entry: dict) -> ProbeState:
        return ProbeState(
            name=key[0], service_type=key[1], iface=key[2],
            state=entry["state"], remaining=entry["remaining"],
            next_probe_at=entry["next_probe_at"],
            announced_at=entry["announced_at"])
