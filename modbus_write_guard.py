"""Admission gate for Modbus write requests handled by an industrial gateway."""

from __future__ import annotations

import copy
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace

READ_FUNCTIONS = (1, 2, 3, 4)
WRITE_FUNCTIONS = (5, 6, 15, 16)
SNAPSHOT_VERSION = 1

_MISSING = object()
_SNAPSHOT_KEYS = {
    "version",
    "devices",
    "admissions",
    "values",
    "seq_marks",
    "stats",
}
_STAT_KEYS = {
    "admitted",
    "denied",
    "committed",
    "rolled_back",
    "registers_written",
    "replayed",
    "expired",
}
_ADMISSION_STATES = {"pending", "committed", "rolled_back", "denied"}


class ModbusError(ValueError):
    """Raised when a request cannot be handled by the guard at all."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceRecord:
    device_id: str
    slave_id: int
    tenant: str
    readable: tuple[int, int]
    writable: tuple[int, int]
    function_codes: tuple[int, ...]


@dataclass(frozen=True)
class Admission:
    request_id: str
    client_id: str
    seq: int
    device_id: str
    function_code: int
    address: int
    count: int
    values: tuple[int, ...]
    allowed: bool
    exception_code: int
    replayed: bool
    registers: tuple[int, ...]

    # Internal bookkeeping.  It travels with snapshots so replay, expiry and
    # rollback continue to work after a restart.
    _state: str = "pending"
    _created_at: float | None = None
    _touched_at: float | None = None
    _before: tuple[tuple[int, int | None], ...] = ()
    _before_marks: tuple[tuple[int, int | None], ...] = ()
    _fingerprint: tuple | None = None
    _alias_of: str | None = None


class ModbusWriteGuard:
    """Keep per-device write policy, admissions and committed register values."""

    def __init__(self, *, max_registers_per_write: int = 16,
                 retry_window: int = 8, max_devices: int = 64) -> None:
        self.max_registers_per_write = max_registers_per_write
        self.retry_window = retry_window
        self.max_devices = max_devices
        self._lock = threading.RLock()
        self._devices: dict[str, DeviceRecord] = {}
        self._admissions: dict[str, Admission] = {}
        self._values: dict[str, dict[int, int]] = {}
        self._seq_marks: dict[str, dict[int, int]] = {}
        self._stats = {
            "admitted": 0,
            "denied": 0,
            "committed": 0,
            "rolled_back": 0,
            "registers_written": 0,
            "replayed": 0,
            "expired": 0,
        }

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _clock(now):
        return time.monotonic() if now is None else now

    @staticmethod
    def _field(request, name):
        if isinstance(request, Mapping):
            return request.get(name, _MISSING)
        return getattr(request, name, _MISSING)

    @classmethod
    def _range(cls, value, detail):
        try:
            start, end = tuple(value)
        except (TypeError, ValueError):
            raise ModbusError("MODBUS_DEVICE_INVALID", detail) from None
        if (not cls._is_int(start) or not cls._is_int(end)
                or start < 0 or end < 0 or start > end):
            raise ModbusError("MODBUS_DEVICE_INVALID", detail)
        return (start, end)

    def register_device(self, device_id: str, *, slave_id: int, tenant: str,
                        readable, writable,
                        function_codes=WRITE_FUNCTIONS,
                        now=None) -> DeviceRecord:
        del now  # registration time is not part of the public record
        if not self._is_int(slave_id):
            raise ModbusError("MODBUS_DEVICE_INVALID", "slave_id")
        readable_range = self._range(readable, "readable")
        writable_range = self._range(writable, "writable")
        try:
            codes = tuple(sorted(set(function_codes)))
        except TypeError:
            raise ModbusError("MODBUS_DEVICE_INVALID", "function_codes") from None
        if any(not self._is_int(code) for code in codes):
            raise ModbusError("MODBUS_DEVICE_INVALID", "function_codes")

        with self._lock:
            if device_id in self._devices:
                raise ModbusError("MODBUS_DEVICE_EXISTS", device_id)
            if len(self._devices) >= self.max_devices:
                raise ModbusError("MODBUS_CAPACITY_EXCEEDED", device_id)
            record = DeviceRecord(
                device_id=device_id,
                slave_id=slave_id,
                tenant=tenant,
                readable=readable_range,
                writable=writable_range,
                function_codes=codes,
            )
            self._devices[device_id] = record
            return record

    def device_record(self, device_id: str) -> DeviceRecord | None:
        with self._lock:
            return self._devices.get(device_id)

    def _parse_request(self, request):
        fields = {}
        for name in ("client_id", "request_id", "seq", "device_id",
                     "function_code", "address", "count"):
            value = self._field(request, name)
            if value is _MISSING:
                raise ModbusError("MODBUS_INVALID_REQUEST", name)
            fields[name] = value

        if (fields["client_id"] is None or fields["request_id"] is None
                or fields["device_id"] is None):
            raise ModbusError("MODBUS_INVALID_REQUEST", "identifier")
        try:
            hash(fields["client_id"])
            hash(fields["request_id"])
            hash(fields["device_id"])
        except TypeError:
            raise ModbusError("MODBUS_INVALID_REQUEST", "identifier") from None

        if not self._is_int(fields["seq"]):
            raise ModbusError("MODBUS_INVALID_REQUEST", "seq")
        if not self._is_int(fields["function_code"]):
            raise ModbusError("MODBUS_INVALID_REQUEST", "function_code")
        if not self._is_int(fields["address"]):
            raise ModbusError("MODBUS_INVALID_REQUEST", "address")
        if not self._is_int(fields["count"]) or fields["count"] < 1:
            raise ModbusError("MODBUS_INVALID_REQUEST", "count")

        function_code = fields["function_code"]
        raw_values = self._field(request, "values")
        if raw_values is _MISSING or raw_values is None:
            if function_code in WRITE_FUNCTIONS:
                raise ModbusError("MODBUS_INVALID_REQUEST", "values")
            values = ()
        else:
            if isinstance(raw_values, (str, bytes, bytearray)):
                raise ModbusError("MODBUS_INVALID_REQUEST", "values")
            try:
                values = tuple(raw_values)
            except TypeError:
                raise ModbusError("MODBUS_INVALID_REQUEST", "values") from None
            if any(not self._is_int(value) for value in values):
                raise ModbusError("MODBUS_INVALID_REQUEST", "values")

        return (
            fields["client_id"],
            fields["request_id"],
            fields["seq"],
            fields["device_id"],
            function_code,
            fields["address"],
            fields["count"],
            values,
        )

    def _within_window(self, timestamp, now) -> bool:
        return timestamp is None or now - timestamp <= self.retry_window

    def _fingerprint(self, client_id, device_id, function_code, address,
                     count, values, seq):
        return (client_id, device_id, function_code, address, count, values, seq)

    def _remove_admission(self, request_id) -> None:
        self._admissions.pop(request_id, None)
        for other_id, admission in list(self._admissions.items()):
            if admission._alias_of == request_id:
                self._admissions.pop(other_id, None)

    def _mark_replayed(self, admission: Admission) -> Admission:
        replayed = replace(admission, replayed=True)
        self._admissions[admission.request_id] = replayed
        self._stats["replayed"] += 1
        return replayed

    def _make_alias(self, prior: Admission, request_id, fingerprint) -> Admission:
        canonical_id = prior._alias_of or prior.request_id
        canonical = self._admissions.get(canonical_id, prior)
        alias = Admission(
            request_id=request_id,
            client_id=prior.client_id,
            seq=prior.seq,
            device_id=prior.device_id,
            function_code=prior.function_code,
            address=prior.address,
            count=prior.count,
            values=prior.values,
            allowed=prior.allowed,
            exception_code=prior.exception_code,
            replayed=True,
            registers=prior.registers,
            _state=canonical._state,
            _created_at=canonical._created_at,
            _touched_at=canonical._touched_at,
            _before=canonical._before,
            _before_marks=canonical._before_marks,
            _fingerprint=fingerprint,
            _alias_of=canonical_id,
        )
        self._admissions[request_id] = alias
        self._stats["replayed"] += 1
        return alias

    def _store_admission(self, admission: Admission) -> Admission:
        self._admissions[admission.request_id] = admission
        return admission

    def admit(self, request, now=None) -> Admission:
        with self._lock:
            (client_id, request_id, seq, device_id, function_code,
             address, count, values) = self._parse_request(request)
            now_value = self._clock(now)

            device = self._devices.get(device_id)
            if device is None:
                raise ModbusError("MODBUS_UNKNOWN_DEVICE", device_id)

            is_write = function_code in WRITE_FUNCTIONS
            fingerprint = None
            if is_write:
                fingerprint = self._fingerprint(
                    client_id, device_id, function_code, address,
                    count, values, seq,
                )

            existing = self._admissions.get(request_id)
            if existing is not None:
                if fingerprint is None or existing._fingerprint != fingerprint:
                    raise ModbusError("MODBUS_INVALID_REQUEST", request_id)
                if self._within_window(existing._created_at, now_value):
                    return self._mark_replayed(existing)
                self._remove_admission(request_id)

            if fingerprint is not None:
                prior = None
                for candidate in self._admissions.values():
                    if (candidate._alias_of is None
                            and candidate._fingerprint == fingerprint
                            and self._within_window(
                                candidate._created_at, now_value)):
                        prior = candidate
                        break
                if prior is not None:
                    return self._make_alias(prior, request_id, fingerprint)

            registers = ()
            exception_code = 0

            if function_code in READ_FUNCTIONS:
                last = address + count - 1
                if address < device.readable[0] or last > device.readable[1]:
                    exception_code = 2
                else:
                    registers = tuple(range(address, last + 1))
            elif is_write:
                if function_code not in device.function_codes:
                    exception_code = 1
                elif count > self.max_registers_per_write:
                    exception_code = 3
                elif len(values) != count:
                    exception_code = 3
                elif any(value < 0 or value > 0xFFFF for value in values):
                    exception_code = 3
                else:
                    last = address + count - 1
                    if (address < device.writable[0]
                            or last > device.writable[1]):
                        exception_code = 2
                    else:
                        registers = tuple(range(address, last + 1))
            else:
                exception_code = 1

            allowed = exception_code == 0
            state = "pending" if allowed else "denied"
            admission = Admission(
                request_id=request_id,
                client_id=client_id,
                seq=seq,
                device_id=device_id,
                function_code=function_code,
                address=address,
                count=count,
                values=values,
                allowed=allowed,
                exception_code=exception_code,
                replayed=False,
                registers=registers,
                _state=state,
                _created_at=now_value,
                _touched_at=now_value,
                _fingerprint=fingerprint,
            )
            self._stats["admitted" if allowed else "denied"] += 1
            return self._store_admission(admission)

    def _resolve(self, request_id):
        admission = self._admissions.get(request_id)
        if admission is None:
            raise ModbusError("MODBUS_UNKNOWN_REQUEST", request_id)
        if admission._alias_of is not None:
            canonical = self._admissions.get(admission._alias_of)
            if canonical is None:
                raise ModbusError("MODBUS_UNKNOWN_REQUEST", request_id)
            return canonical
        return admission

    def translate(self, request_id: str) -> dict:
        with self._lock:
            admission = self._admissions.get(request_id)
            if admission is None:
                raise ModbusError("MODBUS_UNKNOWN_REQUEST", request_id)
            device = self._devices[admission.device_id]
            return {
                "slave_id": device.slave_id,
                "function_code": admission.function_code,
                "address": admission.address,
                "count": admission.count,
                "values": admission.values,
                "exception_code": admission.exception_code,
            }

    def _mirror_aliases(self, canonical: Admission) -> None:
        for request_id, admission in list(self._admissions.items()):
            if admission._alias_of == canonical.request_id:
                self._admissions[request_id] = replace(
                    admission,
                    _state=canonical._state,
                    _touched_at=canonical._touched_at,
                    _before=canonical._before,
                    _before_marks=canonical._before_marks,
                )

    def commit(self, request_id: str, now=None) -> int:
        with self._lock:
            now_value = self._clock(now)
            admission = self._resolve(request_id)

            if not admission.allowed:
                raise ModbusError("MODBUS_REQUEST_DENIED", request_id)
            if admission._state != "pending":
                raise ModbusError("MODBUS_REQUEST_COMMITTED", request_id)

            if admission.function_code in READ_FUNCTIONS:
                committed = replace(
                    admission,
                    _state="committed",
                    _touched_at=now_value,
                )
                self._admissions[admission.request_id] = committed
                self._mirror_aliases(committed)
                self._stats["committed"] += 1
                return 0

            marks = self._seq_marks.get(admission.device_id, {})
            for register in admission.registers:
                if register in marks and admission.seq < marks[register]:
                    raise ModbusError(
                        "MODBUS_STALE_SEQUENCE",
                        (request_id, register, marks[register]),
                    )

            values = self._values.setdefault(admission.device_id, {})
            before = tuple(
                (register, values.get(register))
                for register in admission.registers
            )
            before_marks = tuple(
                (register, marks.get(register))
                for register in admission.registers
            )

            for register, value in zip(admission.registers, admission.values):
                values[register] = value
            for register in admission.registers:
                marks[register] = admission.seq
            self._seq_marks[admission.device_id] = marks

            committed = replace(
                admission,
                _state="committed",
                _touched_at=now_value,
                _before=before,
                _before_marks=before_marks,
            )
            self._admissions[admission.request_id] = committed
            self._mirror_aliases(committed)
            self._stats["committed"] += 1
            self._stats["registers_written"] += admission.count
            return admission.count

    def rollback(self, request_id: str, now=None) -> bool:
        with self._lock:
            now_value = self._clock(now)
            admission = self._resolve(request_id)

            if not admission.allowed:
                raise ModbusError("MODBUS_REQUEST_DENIED", request_id)
            if admission._state == "pending":
                return False
            if admission._state == "rolled_back":
                return False
            if admission._state != "committed":
                raise ModbusError("MODBUS_UNKNOWN_REQUEST", request_id)
            if admission.function_code in READ_FUNCTIONS:
                return False

            marks = self._seq_marks.get(admission.device_id, {})
            for register in admission.registers:
                if register in marks and marks[register] > admission.seq:
                    raise ModbusError(
                        "MODBUS_ROLLBACK_CONFLICT",
                        (request_id, register, marks[register]),
                    )

            values = self._values.setdefault(admission.device_id, {})
            for register, previous in admission._before:
                if previous is None:
                    values.pop(register, None)
                else:
                    values[register] = previous
            for register, previous_mark in admission._before_marks:
                if previous_mark is None:
                    marks.pop(register, None)
                else:
                    marks[register] = previous_mark
            if not values:
                self._values.pop(admission.device_id, None)
            if not marks:
                self._seq_marks.pop(admission.device_id, None)
            else:
                self._seq_marks[admission.device_id] = marks

            rolled_back = replace(
                admission,
                _state="rolled_back",
                _touched_at=now_value,
            )
            self._admissions[admission.request_id] = rolled_back
            self._mirror_aliases(rolled_back)
            self._stats["rolled_back"] += 1
            return True

    def result_for(self, request_id: str) -> Admission | None:
        with self._lock:
            return self._admissions.get(request_id)

    def pending_for(self, client_id: str) -> tuple[str, ...]:
        with self._lock:
            pending = [
                admission for admission in self._admissions.values()
                if (admission.client_id == client_id
                    and admission.allowed
                    and admission._state == "pending"
                    and admission._alias_of is None)
            ]
            pending.sort(key=lambda admission: admission.seq)
            return tuple(admission.request_id for admission in pending)

    def device_values(self, device_id: str) -> dict:
        with self._lock:
            return dict(self._values.get(device_id, {}))

    def exception_log(self, device_id: str) -> tuple[tuple[str, int], ...]:
        with self._lock:
            denied = [
                admission for admission in self._admissions.values()
                if (admission.device_id == device_id
                    and not admission.allowed
                    and admission._alias_of is None)
            ]
            denied.sort(key=lambda admission: admission.seq)
            return tuple(
                (admission.request_id, admission.exception_code)
                for admission in denied
            )

    def expire_results(self, now) -> int:
        with self._lock:
            now_value = self._clock(now)
            expired = set()
            for request_id, admission in self._admissions.items():
                if admission._state not in {"committed", "rolled_back",
                                            "denied"}:
                    continue
                if not self._within_window(admission._touched_at, now_value):
                    expired.add(request_id)
            for request_id, admission in self._admissions.items():
                if admission._alias_of in expired:
                    expired.add(request_id)
            for request_id in expired:
                self._admissions.pop(request_id, None)
            self._stats["expired"] += len(expired)
            return len(expired)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "devices": copy.deepcopy(self._devices),
                "admissions": copy.deepcopy(self._admissions),
                "values": copy.deepcopy(self._values),
                "seq_marks": copy.deepcopy(self._seq_marks),
                "stats": copy.deepcopy(self._stats),
            }

    @classmethod
    def _invalid_snapshot(cls, detail=None):
        raise ModbusError("MODBUS_SNAPSHOT_INVALID", detail)

    @classmethod
    def _valid_before(cls, value) -> bool:
        if not isinstance(value, tuple):
            return False
        for item in value:
            if not isinstance(item, tuple) or len(item) != 2:
                return False
            register, previous = item
            if not cls._is_int(register):
                return False
            if previous is not None and not cls._is_int(previous):
                return False
        return True

    @classmethod
    def _validate_device(cls, key, record) -> None:
        if not isinstance(record, DeviceRecord) or record.device_id != key:
            cls._invalid_snapshot("devices")
        if not cls._is_int(record.slave_id):
            cls._invalid_snapshot("devices")
        if (not isinstance(record.readable, tuple)
                or len(record.readable) != 2
                or not all(cls._is_int(value) and value >= 0
                           for value in record.readable)):
            cls._invalid_snapshot("devices")
        if record.readable[0] > record.readable[1]:
            cls._invalid_snapshot("devices")
        if (not isinstance(record.writable, tuple)
                or len(record.writable) != 2
                or not all(cls._is_int(value) and value >= 0
                           for value in record.writable)):
            cls._invalid_snapshot("devices")
        if record.writable[0] > record.writable[1]:
            cls._invalid_snapshot("devices")
        if (not isinstance(record.function_codes, tuple)
                or not all(cls._is_int(code)
                           for code in record.function_codes)):
            cls._invalid_snapshot("devices")

    @classmethod
    def _validate_admission(cls, key, admission) -> None:
        if not isinstance(admission, Admission) or admission.request_id != key:
            cls._invalid_snapshot("admissions")
        if not isinstance(admission.allowed, bool):
            cls._invalid_snapshot("admissions")
        if not isinstance(admission.replayed, bool):
            cls._invalid_snapshot("admissions")
        for name in ("seq", "function_code", "address", "count",
                     "exception_code"):
            if not cls._is_int(getattr(admission, name)):
                cls._invalid_snapshot("admissions")
        for name in ("client_id", "device_id"):
            try:
                hash(getattr(admission, name))
            except TypeError:
                cls._invalid_snapshot("admissions")
        if (not isinstance(admission.values, tuple)
                or not all(cls._is_int(value) for value in admission.values)):
            cls._invalid_snapshot("admissions")
        if (not isinstance(admission.registers, tuple)
                or not all(cls._is_int(value)
                           for value in admission.registers)):
            cls._invalid_snapshot("admissions")
        if admission._state not in _ADMISSION_STATES:
            cls._invalid_snapshot("admissions")
        for name in ("_created_at", "_touched_at"):
            value = getattr(admission, name)
            if value is not None and not isinstance(value, (int, float)):
                cls._invalid_snapshot("admissions")
        if not cls._valid_before(admission._before):
            cls._invalid_snapshot("admissions")
        if not cls._valid_before(admission._before_marks):
            cls._invalid_snapshot("admissions")
        if (admission._fingerprint is not None
                and not isinstance(admission._fingerprint, tuple)):
            cls._invalid_snapshot("admissions")
        if admission._alias_of is not None:
            try:
                hash(admission._alias_of)
            except TypeError:
                cls._invalid_snapshot("admissions")

    @classmethod
    def _validate_register_map(cls, value, *, bounded: bool) -> None:
        if not isinstance(value, dict):
            cls._invalid_snapshot("values")
        for device_id, registers in value.items():
            try:
                hash(device_id)
            except TypeError:
                cls._invalid_snapshot("values")
            if not isinstance(registers, dict):
                cls._invalid_snapshot("values")
            for register, register_value in registers.items():
                if not cls._is_int(register) or not cls._is_int(register_value):
                    cls._invalid_snapshot("values")
                if bounded and not 0 <= register_value <= 0xFFFF:
                    cls._invalid_snapshot("values")

    def restore(self, state) -> None:
        with self._lock:
            if not isinstance(state, Mapping):
                self._invalid_snapshot("state")
            if set(state.keys()) != _SNAPSHOT_KEYS:
                self._invalid_snapshot("keys")
            version = state.get("version")
            if not self._is_int(version) or version != SNAPSHOT_VERSION:
                self._invalid_snapshot("version")

            try:
                devices = copy.deepcopy(state["devices"])
                admissions = copy.deepcopy(state["admissions"])
                values = copy.deepcopy(state["values"])
                seq_marks = copy.deepcopy(state["seq_marks"])
                stats = copy.deepcopy(state["stats"])
            except Exception:
                self._invalid_snapshot("copy")

            if not isinstance(devices, dict):
                self._invalid_snapshot("devices")
            if not isinstance(admissions, dict):
                self._invalid_snapshot("admissions")
            self._validate_register_map(values, bounded=True)
            self._validate_register_map(seq_marks, bounded=False)
            if not isinstance(stats, dict) or set(stats.keys()) != _STAT_KEYS:
                self._invalid_snapshot("stats")
            if any(not self._is_int(value) or value < 0
                   for value in stats.values()):
                self._invalid_snapshot("stats")
            for key, record in devices.items():
                self._validate_device(key, record)
            for key, admission in admissions.items():
                self._validate_admission(key, admission)
                if admission.device_id not in devices:
                    self._invalid_snapshot("admissions")
                if (admission._alias_of is not None
                        and admission._alias_of not in admissions):
                    self._invalid_snapshot("admissions")
            if any(device_id not in devices for device_id in values):
                self._invalid_snapshot("values")
            if any(device_id not in devices for device_id in seq_marks):
                self._invalid_snapshot("seq_marks")

            self._devices = devices
            self._admissions = admissions
            self._values = values
            self._seq_marks = seq_marks
            self._stats = stats
