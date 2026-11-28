"""BPF map pin registry: tenant ownership, reference counting, orphan reclaim."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, replace


class BpfError(ValueError):
    """Raised when the registry refuses a pin operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_STAT_KEYS = ("pinned", "opened", "closed", "unpinned", "reclaimed",
              "quarantined", "refused")

_SNAPSHOT_VERSION = 1


@dataclass(frozen=True)
class PinRecord:
    path: str
    tenant: str
    map_id: str
    owner_pid: int
    owner_start: int
    refcount: int
    generation: int


def _is_positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_valid_path(path) -> bool:
    if not isinstance(path, str) or not path:
        return False
    if not path.startswith("/") or path.endswith("/"):
        return False
    return not any(ch.isspace() for ch in path)


def _is_non_empty_str(value) -> bool:
    return isinstance(value, str) and len(value) > 0


class BpfMapPinRegistry:
    """Registry of pinned map paths with tenant ownership and open handles."""

    def __init__(self, *, max_pins: int = 32) -> None:
        self.max_pins = int(max_pins)
        self._lock = threading.RLock()
        self._pins: dict[str, PinRecord] = {}
        self._handles: dict[str, dict] = {}
        self._grants: dict[str, set[str]] = {}
        self._quarantine: set[str] = set()
        self._generations: dict[str, int] = {}
        self._next_handle = 1
        self._stats = {key: 0 for key in _STAT_KEYS}

    def _refuse(self, code: str, detail=None):
        self._stats["refused"] += 1
        raise BpfError(code, detail)

    @staticmethod
    def _validate_pin_args(path, tenant, map_id, owner_pid, owner_start) -> bool:
        return (_is_valid_path(path)
                and _is_non_empty_str(tenant)
                and _is_non_empty_str(map_id)
                and _is_positive_int(owner_pid)
                and _is_positive_int(owner_start))

    def pin(self, path: str, *, tenant: str, map_id: str, owner_pid: int,
            owner_start: int) -> PinRecord:
        with self._lock:
            if not self._validate_pin_args(path, tenant, map_id, owner_pid,
                                           owner_start):
                self._refuse("BPF_INVALID_REQUEST",
                             {"path": path, "tenant": tenant})
            if path in self._pins:
                self._refuse("BPF_PIN_EXISTS", path)
            if len(self._pins) >= self.max_pins:
                self._refuse("BPF_PIN_LIMIT", path)
            generation = self._generations.get(path, 0) + 1
            self._generations[path] = generation
            record = PinRecord(path=path, tenant=tenant, map_id=map_id,
                               owner_pid=owner_pid, owner_start=owner_start,
                               refcount=0, generation=generation)
            self._pins[path] = record
            self._quarantine.discard(path)
            self._stats["pinned"] += 1
            return record

    def lookup(self, path: str) -> PinRecord | None:
        with self._lock:
            return self._pins.get(path)

    def list_pins(self, tenant: str) -> tuple[PinRecord, ...]:
        with self._lock:
            return tuple(record for path, record in sorted(self._pins.items())
                         if record.tenant == tenant)

    def open_pinned(self, path: str, *, tenant: str, pid: int,
                    start: int) -> str:
        with self._lock:
            if not (_is_non_empty_str(tenant) and _is_positive_int(pid)
                    and _is_positive_int(start)):
                self._refuse("BPF_INVALID_REQUEST",
                             {"path": path, "tenant": tenant})
            record = self._pins.get(path)
            if record is None:
                self._refuse("BPF_PIN_NOT_FOUND", path)
            if tenant != record.tenant and tenant not in self._grants.get(path, ()):
                self._refuse("BPF_TENANT_DENIED",
                             {"path": path, "tenant": tenant})
            handle_id = f"h{self._next_handle}"
            self._next_handle += 1
            self._handles[handle_id] = {
                "path": path, "tenant": tenant, "pid": pid, "start": start,
            }
            self._pins[path] = replace(record, refcount=record.refcount + 1)
            self._stats["opened"] += 1
            return handle_id

    def close_handle(self, handle_id: str) -> bool:
        with self._lock:
            handle = self._handles.pop(handle_id, None)
            if handle is None:
                return False
            record = self._pins.get(handle["path"])
            if record is not None and record.refcount > 0:
                self._pins[handle["path"]] = replace(
                    record, refcount=record.refcount - 1)
            self._stats["closed"] += 1
            return True

    def refcount(self, path: str) -> int:
        with self._lock:
            record = self._pins.get(path)
            return record.refcount if record is not None else 0

    def openers(self, path: str) -> tuple[tuple[int, int, str], ...]:
        with self._lock:
            rows = [(h["pid"], h["start"], h["tenant"])
                    for h in self._handles.values() if h["path"] == path]
            rows.sort()
            return tuple(rows)

    def grant_cross_tenant(self, path: str, tenant: str) -> None:
        with self._lock:
            if not _is_non_empty_str(tenant):
                self._refuse("BPF_INVALID_REQUEST", tenant)
            if path not in self._pins:
                self._refuse("BPF_PIN_NOT_FOUND", path)
            self._grants.setdefault(path, set()).add(tenant)

    def unpin(self, path: str, *, tenant: str) -> bool:
        with self._lock:
            record = self._pins.get(path)
            if record is None:
                return False
            if tenant != record.tenant:
                self._refuse("BPF_TENANT_DENIED",
                             {"path": path, "tenant": tenant})
            if record.refcount > 0:
                self._refuse("BPF_PIN_BUSY", path)
            del self._pins[path]
            self._grants.pop(path, None)
            self._stats["unpinned"] += 1
            return True

    def _drop_pin(self, path: str) -> None:
        self._pins.pop(path, None)
        self._grants.pop(path, None)
        stale_handles = [hid for hid, h in self._handles.items()
                         if h["path"] == path]
        for hid in stale_handles:
            del self._handles[hid]

    def reclaim_orphans(self, alive) -> tuple[str, ...]:
        with self._lock:
            reclaimed = []
            for path, record in sorted(self._pins.items()):
                if record.refcount > 0:
                    continue
                if not alive(record.owner_pid, record.owner_start):
                    reclaimed.append(path)
            for path in reclaimed:
                self._drop_pin(path)
            self._stats["reclaimed"] += len(reclaimed)
            return tuple(reclaimed)

    def scan(self, present_paths) -> dict:
        with self._lock:
            present = set(present_paths)
            stale = sorted(path for path in self._pins if path not in present)
            for path in stale:
                self._drop_pin(path)
            newly = sorted(path for path in present
                           if path not in self._pins
                           and path not in self._quarantine)
            self._quarantine.update(newly)
            self._stats["quarantined"] += len(newly)
            return {"stale": tuple(stale), "quarantined": tuple(newly)}

    def quarantined(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._quarantine))

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "pins": {path: {
                    "path": record.path,
                    "tenant": record.tenant,
                    "map_id": record.map_id,
                    "owner_pid": record.owner_pid,
                    "owner_start": record.owner_start,
                    "refcount": record.refcount,
                    "generation": record.generation,
                } for path, record in self._pins.items()},
                "handles": {hid: dict(handle)
                            for hid, handle in self._handles.items()},
                "grants": {path: sorted(tenants)
                           for path, tenants in self._grants.items()},
                "quarantine": sorted(self._quarantine),
                "next_handle": self._next_handle,
                "stats": dict(self._stats),
            })

    @staticmethod
    def _validate_snapshot(state) -> bool:
        if not isinstance(state, dict):
            return False
        if set(state) != {"version", "pins", "handles", "grants",
                          "quarantine", "next_handle", "stats"}:
            return False
        if state["version"] != _SNAPSHOT_VERSION:
            return False
        pins = state["pins"]
        if not isinstance(pins, dict):
            return False
        pin_fields = {"path", "tenant", "map_id", "owner_pid", "owner_start",
                      "refcount", "generation"}
        for path, entry in pins.items():
            if not _is_valid_path(path) or not isinstance(entry, dict):
                return False
            if set(entry) != pin_fields:
                return False
            if entry["path"] != path:
                return False
            if not (_is_non_empty_str(entry["tenant"])
                    and _is_non_empty_str(entry["map_id"])):
                return False
            if not (_is_positive_int(entry["owner_pid"])
                    and _is_positive_int(entry["owner_start"])):
                return False
            refcount = entry["refcount"]
            if (not isinstance(refcount, int) or isinstance(refcount, bool)
                    or refcount < 0):
                return False
            if not _is_positive_int(entry["generation"]):
                return False
        handles = state["handles"]
        if not isinstance(handles, dict):
            return False
        for handle_id, handle in handles.items():
            if not _is_non_empty_str(handle_id) or not isinstance(handle, dict):
                return False
            if set(handle) != {"path", "tenant", "pid", "start"}:
                return False
            if handle["path"] not in pins:
                return False
            if not (_is_non_empty_str(handle["tenant"])
                    and _is_positive_int(handle["pid"])
                    and _is_positive_int(handle["start"])):
                return False
        for path, entry in pins.items():
            live = sum(1 for handle in handles.values()
                       if handle["path"] == path)
            if live != entry["refcount"]:
                return False
        grants = state["grants"]
        if not isinstance(grants, dict):
            return False
        for path, tenants in grants.items():
            if path not in pins or not isinstance(tenants, (list, tuple)):
                return False
            if any(not _is_non_empty_str(tenant) for tenant in tenants):
                return False
        quarantine = state["quarantine"]
        if not isinstance(quarantine, (list, tuple)):
            return False
        if any(not isinstance(path, str) for path in quarantine):
            return False
        if any(path in pins for path in quarantine):
            return False
        next_handle = state["next_handle"]
        if (not isinstance(next_handle, int) or isinstance(next_handle, bool)
                or next_handle < 1):
            return False
        stats = state["stats"]
        if not isinstance(stats, dict) or set(stats) != set(_STAT_KEYS):
            return False
        for value in stats.values():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return False
        return True

    def restore(self, state: dict) -> None:
        with self._lock:
            if not self._validate_snapshot(state):
                raise BpfError("BPF_SNAPSHOT_INVALID", state)
            pins = {}
            for path, entry in state["pins"].items():
                pins[path] = PinRecord(
                    path=entry["path"], tenant=entry["tenant"],
                    map_id=entry["map_id"], owner_pid=entry["owner_pid"],
                    owner_start=entry["owner_start"],
                    refcount=entry["refcount"], generation=entry["generation"])
            self._pins = pins
            self._handles = {hid: dict(handle)
                             for hid, handle in state["handles"].items()}
            self._grants = {path: set(tenants)
                            for path, tenants in state["grants"].items()}
            self._quarantine = set(state["quarantine"])
            self._generations = {path: record.generation
                                 for path, record in pins.items()}
            self._next_handle = state["next_handle"]
            self._stats = dict(state["stats"])

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
