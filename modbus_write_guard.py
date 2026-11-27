"""Admission gate for Modbus write requests handled by an industrial gateway."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

READ_FUNCTIONS = (1, 2, 3, 4)
WRITE_FUNCTIONS = (5, 6, 15, 16)
SNAPSHOT_VERSION = 1


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
        self._states: dict[str, str] = {}
        self._before: dict[str, dict[int, int | None]] = {}
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

    def register_device(self, device_id: str, *, slave_id: int, tenant: str,
                        readable, writable,
                        function_codes=WRITE_FUNCTIONS,
                        now=None) -> DeviceRecord:
        raise NotImplementedError

    def device_record(self, device_id: str) -> DeviceRecord | None:
        raise NotImplementedError

    def admit(self, request, now=None) -> Admission:
        raise NotImplementedError

    def translate(self, request_id: str) -> dict:
        raise NotImplementedError

    def commit(self, request_id: str, now=None) -> int:
        raise NotImplementedError

    def rollback(self, request_id: str, now=None) -> bool:
        raise NotImplementedError

    def result_for(self, request_id: str) -> Admission | None:
        raise NotImplementedError

    def pending_for(self, client_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def device_values(self, device_id: str) -> dict:
        raise NotImplementedError

    def exception_log(self, device_id: str) -> tuple[tuple[str, int], ...]:
        raise NotImplementedError

    def expire_results(self, now) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError
