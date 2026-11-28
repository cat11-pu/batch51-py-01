"""PTY session allocator: tenant quota, session leader binding, orphan reclaim."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import re
import threading

_DEVICE_PATTERN = re.compile(r"^pts/[0-9]+$")

STATES = ("free", "allocated", "bound", "releasing")
_ACTIVE_STATES = ("allocated", "bound")
_RECORD_FIELDS = (
    "device_id",
    "tenant",
    "session_id",
    "leader_pid",
    "leader_start",
    "state",
    "generation",
)
_STATS_KEYS = (
    "allocations",
    "bindings",
    "releases",
    "flushed",
    "reclaimed",
    "refused",
)
_SNAPSHOT_VERSION = 1


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
        if not self._is_int(max_per_tenant) or max_per_tenant <= 0:
            raise PtyError("PTY_INVALID_REQUEST", "max_per_tenant")
        if isinstance(devices, (str, bytes)):
            raise PtyError("PTY_INVALID_REQUEST", "devices")
        try:
            initial_devices = tuple(devices)
        except TypeError as exc:
            raise PtyError("PTY_INVALID_REQUEST", "devices") from exc

        seen: set[str] = set()
        for device_id in initial_devices:
            self._validate_device_id(device_id)
            if device_id in seen:
                raise PtyError("PTY_DEVICE_EXISTS", device_id)
            seen.add(device_id)

        self.max_per_tenant = max_per_tenant
        self._lock = threading.RLock()
        self._records: dict[str, DeviceRecord] = {}
        self._holders: dict[str, list[tuple[int, int, str]]] = {}
        self._stats = {key: 0 for key in _STATS_KEYS}
        for device_id in initial_devices:
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
        with self._guarded():
            self._validate_device_id(device_id)
            if device_id in self._records:
                raise PtyError("PTY_DEVICE_EXISTS", device_id)
            record = self._free_record(device_id, generation=0)
            self._records[device_id] = record
            self._holders[device_id] = []
            return record.generation

    def allocate(self, tenant: str, *, device_id: str | None = None,
                 now: int | None = None) -> DeviceRecord:
        with self._guarded():
            self._validate_tenant(tenant)
            self._validate_now(now)
            if device_id is not None:
                self._validate_device_id(device_id)

            active = self._tenant_usage(tenant)
            if device_id is not None:
                record = self._records.get(device_id)
                if record is None:
                    raise PtyError("PTY_DEVICE_UNKNOWN", device_id)
                if record.state != "free":
                    if record.tenant == tenant and record.state in _ACTIVE_STATES:
                        return record
                    raise PtyError("PTY_DEVICE_BUSY", device_id)
                if active >= self.max_per_tenant:
                    raise PtyError("PTY_TENANT_QUOTA", tenant)
                return self._allocate_record(record, tenant)

            if active >= self.max_per_tenant:
                raise PtyError("PTY_TENANT_QUOTA", tenant)

            free_records = (
                record for record in self._records.values()
                if record.state == "free"
            )
            try:
                record = min(free_records, key=lambda item: self._device_key(
                    item.device_id))
            except ValueError as exc:
                raise PtyError("PTY_POOL_EXHAUSTED") from exc
            return self._allocate_record(record, tenant)

    def bind_session(self, device_id: str, *, session_id: str, leader_pid: int,
                     leader_start: int, now: int | None = None) -> DeviceRecord:
        with self._guarded():
            self._validate_device_id(device_id)
            self._validate_session_id(session_id)
            self._validate_pid(leader_pid)
            self._validate_start(leader_start)
            self._validate_now(now)

            record = self._records.get(device_id)
            if record is None:
                raise PtyError("PTY_DEVICE_UNKNOWN", device_id)
            if record.state != "allocated":
                raise PtyError("PTY_STATE_INVALID", record.state)
            if any(
                other.device_id != device_id
                and other.session_id == session_id
                for other in self._records.values()
            ):
                raise PtyError("PTY_SESSION_CONFLICT", session_id)

            bound = replace(
                record,
                session_id=session_id,
                leader_pid=leader_pid,
                leader_start=leader_start,
                state="bound",
            )
            self._records[device_id] = bound
            self._stats["bindings"] += 1
            return bound

    def hold(self, device_id: str, *, pid: int, start: int,
             role: str = "child") -> None:
        with self._guarded():
            self._validate_device_id(device_id)
            self._validate_pid(pid)
            self._validate_start(start)
            if not isinstance(role, str) or not role:
                raise PtyError("PTY_INVALID_REQUEST", "role")

            record = self._records.get(device_id)
            if record is None:
                raise PtyError("PTY_DEVICE_UNKNOWN", device_id)
            if record.state == "free":
                raise PtyError("PTY_STATE_INVALID", record.state)

            holder = (pid, start, role)
            if holder not in self._holders[device_id]:
                self._holders[device_id].append(holder)

    def release(self, device_id: str, *, now: int | None = None) -> bool:
        with self._guarded():
            self._validate_device_id(device_id)
            self._validate_now(now)

            record = self._records.get(device_id)
            if record is None:
                raise PtyError("PTY_DEVICE_UNKNOWN", device_id)
            if record.state not in _ACTIVE_STATES:
                return False

            self._records[device_id] = replace(record, state="releasing")
            self._stats["releases"] += 1
            return True

    def flush_release(self, device_id: str, *, alive=None) -> bool:
        with self._guarded():
            self._validate_device_id(device_id)
            if alive is not None and not callable(alive):
                raise PtyError("PTY_INVALID_REQUEST", "alive")

            record = self._records.get(device_id)
            if record is None:
                raise PtyError("PTY_DEVICE_UNKNOWN", device_id)
            if record.state != "releasing":
                return False

            has_tracked_processes = (
                record.leader_pid is not None
                or bool(self._holders[device_id])
            )
            if alive is None:
                if has_tracked_processes:
                    self._stats["refused"] += 1
                    return False
            else:
                if self._leader_is_alive(record, alive):
                    self._stats["refused"] += 1
                    return False
                if any(alive(pid, start)
                       for pid, start, _role in self._holders[device_id]):
                    self._stats["refused"] += 1
                    return False

            self._records[device_id] = self._free_record(
                device_id, generation=record.generation + 1)
            self._holders[device_id] = []
            self._stats["flushed"] += 1
            return True

    def reclaim_orphans(self, *, alive, now: int | None = None) -> tuple[str, ...]:
        with self._guarded():
            if not callable(alive):
                raise PtyError("PTY_INVALID_REQUEST", "alive")
            self._validate_now(now)

            reclaimable: list[str] = []
            for record in self._records.values():
                if (record.state not in ("bound", "releasing")
                        or record.leader_pid is None):
                    continue
                if self._leader_is_alive(record, alive):
                    continue
                if any(alive(pid, start)
                       for pid, start, _role
                       in self._holders[record.device_id]):
                    continue
                reclaimable.append(record.device_id)

            for device_id in reclaimable:
                record = self._records[device_id]
                self._records[device_id] = self._free_record(
                    device_id, generation=record.generation + 1)
                self._holders[device_id] = []
                self._stats["reclaimed"] += 1

            return tuple(sorted(reclaimable, key=self._device_key))

    def usage(self, tenant: str) -> int:
        with self._guarded():
            self._validate_tenant(tenant)
            return self._tenant_usage(tenant)

    def lookup(self, device_id: str) -> DeviceRecord | None:
        with self._guarded():
            self._validate_device_id(device_id)
            return self._records.get(device_id)

    def records_for(self, tenant: str) -> tuple[DeviceRecord, ...]:
        with self._guarded():
            self._validate_tenant(tenant)
            records = (
                record for record in self._records.values()
                if record.tenant == tenant
            )
            return tuple(sorted(
                records, key=lambda item: self._device_key(item.device_id)))

    def snapshot(self) -> dict:
        with self._guarded():
            devices = {
                device_id: {
                    "device_id": record.device_id,
                    "tenant": record.tenant,
                    "session_id": record.session_id,
                    "leader_pid": record.leader_pid,
                    "leader_start": record.leader_start,
                    "state": record.state,
                    "generation": record.generation,
                }
                for device_id, record in sorted(
                    self._records.items(),
                    key=lambda item: self._device_key(item[0]),
                )
            }
            return {
                "version": _SNAPSHOT_VERSION,
                "devices": devices,
                "stats": dict(self._stats),
                "max_per_tenant": self.max_per_tenant,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            records, stats, max_per_tenant = self._parse_snapshot(state)
            self._records = records
            self._holders = {device_id: [] for device_id in records}
            self._stats = stats
            self.max_per_tenant = max_per_tenant

    def stats(self) -> dict:
        with self._guarded():
            return dict(self._stats)

    @contextmanager
    def _guarded(self):
        with self._lock:
            try:
                yield
            except PtyError:
                self._stats["refused"] += 1
                raise

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _validate_device_id(cls, device_id: object) -> None:
        if not isinstance(device_id, str) or _DEVICE_PATTERN.fullmatch(
                device_id) is None:
            raise PtyError("PTY_INVALID_REQUEST", device_id)

    @classmethod
    def _validate_tenant(cls, tenant: object) -> None:
        if (not isinstance(tenant, str) or not tenant
                or tenant != tenant.strip()):
            raise PtyError("PTY_INVALID_REQUEST", tenant)

    @classmethod
    def _validate_session_id(cls, session_id: object) -> None:
        if not isinstance(session_id, str) or not session_id.strip():
            raise PtyError("PTY_INVALID_REQUEST", session_id)

    @classmethod
    def _validate_pid(cls, pid: object) -> None:
        if not cls._is_int(pid) or pid <= 0:
            raise PtyError("PTY_INVALID_REQUEST", pid)

    @classmethod
    def _validate_start(cls, start: object) -> None:
        if not cls._is_int(start) or start < 0:
            raise PtyError("PTY_INVALID_REQUEST", start)

    @classmethod
    def _validate_now(cls, now: object) -> None:
        if now is not None and (not cls._is_int(now) or now < 0):
            raise PtyError("PTY_INVALID_REQUEST", now)

    @staticmethod
    def _device_key(device_id: str) -> tuple[int, str]:
        return int(device_id[4:]), device_id

    @classmethod
    def _free_record(cls, device_id: str, *, generation: int) -> DeviceRecord:
        return DeviceRecord(
            device_id=device_id,
            tenant=None,
            session_id=None,
            leader_pid=None,
            leader_start=None,
            state="free",
            generation=generation,
        )

    def _tenant_usage(self, tenant: str) -> int:
        return sum(
            record.tenant == tenant and record.state in _ACTIVE_STATES
            for record in self._records.values()
        )

    def _allocate_record(self, record: DeviceRecord, tenant: str) -> DeviceRecord:
        allocated = replace(
            record,
            tenant=tenant,
            session_id=None,
            leader_pid=None,
            leader_start=None,
            state="allocated",
            generation=max(1, record.generation),
        )
        self._records[record.device_id] = allocated
        self._stats["allocations"] += 1
        return allocated

    @staticmethod
    def _leader_is_alive(record: DeviceRecord, alive) -> bool:
        if record.leader_pid is None or record.leader_start is None:
            return False
        return bool(alive(record.leader_pid, record.leader_start))

    def _parse_snapshot(
        self, state: object,
    ) -> tuple[dict[str, DeviceRecord], dict[str, int], int]:
        def invalid(detail: object = None):
            raise PtyError("PTY_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            invalid("state")
        if set(state) != {"version", "devices", "stats", "max_per_tenant"}:
            invalid("keys")
        version = state["version"]
        if not self._is_int(version) or version != _SNAPSHOT_VERSION:
            invalid("version")

        max_per_tenant = state["max_per_tenant"]
        if not self._is_int(max_per_tenant) or max_per_tenant <= 0:
            invalid("max_per_tenant")

        stats_value = state["stats"]
        if not isinstance(stats_value, dict) or set(stats_value) != set(_STATS_KEYS):
            invalid("stats")
        stats: dict[str, int] = {}
        for key in _STATS_KEYS:
            value = stats_value[key]
            if not self._is_int(value) or value < 0:
                invalid("stats")
            stats[key] = value

        devices_value = state["devices"]
        if not isinstance(devices_value, dict):
            invalid("devices")

        records: dict[str, DeviceRecord] = {}
        sessions: set[str] = set()
        for device_id, raw in devices_value.items():
            try:
                self._validate_device_id(device_id)
            except PtyError:
                invalid("device_id")
            if not isinstance(raw, dict) or set(raw) != set(_RECORD_FIELDS):
                invalid(device_id)
            if raw["device_id"] != device_id:
                invalid(device_id)

            tenant = raw["tenant"]
            session_id = raw["session_id"]
            leader_pid = raw["leader_pid"]
            leader_start = raw["leader_start"]
            device_state = raw["state"]
            generation = raw["generation"]

            if device_state not in STATES:
                invalid("state")
            if not self._is_int(generation) or generation < 0:
                invalid("generation")

            try:
                if device_state == "free":
                    if (tenant is not None or session_id is not None
                            or leader_pid is not None
                            or leader_start is not None):
                        invalid("free")
                else:
                    self._validate_tenant(tenant)
                    if generation < 1:
                        invalid("generation")
                    if device_state == "allocated":
                        if (session_id is not None or leader_pid is not None
                                or leader_start is not None):
                            invalid("allocated")
                    elif device_state == "bound":
                        self._validate_session_id(session_id)
                        self._validate_pid(leader_pid)
                        self._validate_start(leader_start)
                    else:
                        if session_id is None:
                            if (leader_pid is not None
                                    or leader_start is not None):
                                invalid("releasing")
                        else:
                            self._validate_session_id(session_id)
                            self._validate_pid(leader_pid)
                            self._validate_start(leader_start)
            except PtyError:
                invalid(device_id)

            if session_id is not None:
                if session_id in sessions:
                    invalid("session_id")
                sessions.add(session_id)

            records[device_id] = DeviceRecord(
                device_id=device_id,
                tenant=tenant,
                session_id=session_id,
                leader_pid=leader_pid,
                leader_start=leader_start,
                state=device_state,
                generation=generation,
            )

        active_by_tenant: dict[str, int] = {}
        for record in records.values():
            if record.state in _ACTIVE_STATES:
                tenant = record.tenant
                active_by_tenant[tenant] = active_by_tenant.get(tenant, 0) + 1
        if any(count > max_per_tenant for count in active_by_tenant.values()):
            invalid("quota")

        return records, stats, max_per_tenant
