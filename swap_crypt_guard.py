"""Encrypted swap lifecycle: key binding, writeback drain, and hibernate resume checks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SwapError(ValueError):
    """Raised when a swap lifecycle request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_DISABLED = "disabled"
STATE_ENABLED = "enabled"
STATE_DRAINING = "draining"

SNAPSHOT_VERSION = 1
MAX_DIRTY_PAGES = 1 << 30
MAX_RECOVERIES = 1 << 20

_COUNTER_NAMES = ("enables", "disables", "rotations", "resumes",
                  "idempotent", "deferred", "zeroized", "recovered")

_DEVICE_FIELDS = ("device", "state", "key_id", "cipher", "size_pages",
                  "resume_offset", "generation", "dirty_pages")


@dataclass(frozen=True)
class SwapState:
    device: str
    state: str
    key_id: str | None
    cipher: str | None
    size_pages: int
    resume_offset: int
    generation: int
    dirty_pages: int


@dataclass
class _DeviceRecord:
    device: str
    state: str
    key_id: str | None
    cipher: str | None
    size_pages: int
    resume_offset: int
    generation: int
    dirty_pages: int

    def to_state(self) -> SwapState:
        return SwapState(device=self.device, state=self.state,
                         key_id=self.key_id, cipher=self.cipher,
                         size_pages=self.size_pages,
                         resume_offset=self.resume_offset,
                         generation=self.generation,
                         dirty_pages=self.dirty_pages)

    def to_dict(self) -> dict:
        return {"device": self.device, "state": self.state,
                "key_id": self.key_id, "cipher": self.cipher,
                "size_pages": self.size_pages,
                "resume_offset": self.resume_offset,
                "generation": self.generation,
                "dirty_pages": self.dirty_pages}


class SwapCryptGuard:
    """Track encrypted swap devices, their keys, and pending writeback."""

    def __init__(self, *, max_devices: int = 8) -> None:
        if (isinstance(max_devices, bool) or not isinstance(max_devices, int)
                or max_devices < 1):
            raise SwapError("SWAP_INVALID_REQUEST",
                            {"max_devices": max_devices})
        self.max_devices = max_devices
        self._lock = threading.RLock()
        self._devices: dict[str, _DeviceRecord] = {}
        self._counters = {name: 0 for name in _COUNTER_NAMES}

    @staticmethod
    def _require_text(value: object, field: str) -> None:
        if not isinstance(value, str) or not value:
            raise SwapError("SWAP_INVALID_REQUEST", {field: value})

    @staticmethod
    def _require_int(value: object, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise SwapError("SWAP_INVALID_REQUEST", {field: value})
        return value

    def _get_record(self, device: str) -> _DeviceRecord:
        record = self._devices.get(device)
        if record is None:
            raise SwapError("SWAP_DEVICE_UNKNOWN", {"device": device})
        return record

    def _ensure_key_free(self, device: str, key_id: str) -> None:
        for other in self._devices.values():
            if (other.device != device and other.state != STATE_DISABLED
                    and other.key_id == key_id):
                raise SwapError("SWAP_KEY_CONFLICT",
                                {"key_id": key_id, "bound_to": other.device})

    def _ensure_capacity(self, device: str) -> None:
        active = sum(1 for record in self._devices.values()
                     if record.state != STATE_DISABLED)
        current = self._devices.get(device)
        if current is None or current.state == STATE_DISABLED:
            active += 1
        if active > self.max_devices:
            raise SwapError("SWAP_CAPACITY_EXCEEDED",
                            {"max_devices": self.max_devices})

    def _finalize_disable(self, record: _DeviceRecord) -> None:
        record.state = STATE_DISABLED
        record.key_id = None
        record.cipher = None
        record.generation += 1
        self._counters["disables"] += 1
        self._counters["zeroized"] += 1

    def enable(self, device: str, *, size_pages: int, key_id: str,
               cipher: str, resume_offset: int, now: int) -> SwapState:
        with self._lock:
            self._require_text(device, "device")
            self._require_text(key_id, "key_id")
            self._require_text(cipher, "cipher")
            size_pages = self._require_int(size_pages, "size_pages")
            resume_offset = self._require_int(resume_offset, "resume_offset")
            if size_pages <= 0:
                raise SwapError("SWAP_INVALID_REQUEST",
                                {"size_pages": size_pages})
            if not 0 <= resume_offset < size_pages:
                raise SwapError("SWAP_INVALID_REQUEST",
                                {"resume_offset": resume_offset,
                                 "size_pages": size_pages})

            record = self._devices.get(device)
            if record is not None and record.state != STATE_DISABLED:
                if (record.state == STATE_ENABLED
                        and record.size_pages == size_pages
                        and record.key_id == key_id
                        and record.cipher == cipher
                        and record.resume_offset == resume_offset):
                    self._counters["idempotent"] += 1
                    return record.to_state()
                raise SwapError(
                    "SWAP_INVALID_REQUEST",
                    {"device": device,
                     "detail": "device already active; disable it first"})

            self._ensure_key_free(device, key_id)
            self._ensure_capacity(device)

            if record is None:
                record = _DeviceRecord(device=device, state=STATE_ENABLED,
                                       key_id=key_id, cipher=cipher,
                                       size_pages=size_pages,
                                       resume_offset=resume_offset,
                                       generation=0, dirty_pages=0)
                self._devices[device] = record
            else:
                record.state = STATE_ENABLED
                record.key_id = key_id
                record.cipher = cipher
                record.size_pages = size_pages
                record.resume_offset = resume_offset
                record.dirty_pages = 0
            record.generation += 1
            self._counters["enables"] += 1
            return record.to_state()

    def disable(self, device: str, *, now: int) -> SwapState:
        with self._lock:
            record = self._get_record(device)
            if record.state == STATE_DISABLED:
                return record.to_state()
            if record.state == STATE_DRAINING:
                return record.to_state()
            if record.dirty_pages > 0:
                record.state = STATE_DRAINING
                self._counters["deferred"] += 1
                return record.to_state()
            self._finalize_disable(record)
            return record.to_state()

    def mark_dirty(self, device: str, pages: int) -> int:
        with self._lock:
            record = self._get_record(device)
            pages = self._require_int(pages, "pages")
            if record.state == STATE_DISABLED:
                raise SwapError("SWAP_NOT_ENABLED", {"device": device})
            if record.state == STATE_DRAINING and pages > 0:
                raise SwapError(
                    "SWAP_INVALID_REQUEST",
                    {"device": device,
                     "detail": "device is draining; writes refused"})
            dirty = record.dirty_pages + pages
            if dirty < 0:
                raise SwapError("SWAP_INVALID_REQUEST",
                                {"device": device, "pages": pages,
                                 "dirty_pages": record.dirty_pages})
            if dirty > MAX_DIRTY_PAGES:
                raise SwapError("SWAP_CAPACITY_EXCEEDED",
                                {"device": device,
                                 "max_dirty_pages": MAX_DIRTY_PAGES})
            record.dirty_pages = dirty
            if record.state == STATE_DRAINING and dirty == 0:
                self._finalize_disable(record)
            return record.dirty_pages

    def rotate_key(self, device: str, *, new_key_id: str,
                   cipher: str | None = None, now: int) -> SwapState:
        with self._lock:
            record = self._get_record(device)
            self._require_text(new_key_id, "new_key_id")
            if cipher is not None:
                self._require_text(cipher, "cipher")
            if record.state != STATE_ENABLED:
                raise SwapError("SWAP_NOT_ENABLED", {"device": device})
            if record.dirty_pages > 0:
                raise SwapError(
                    "SWAP_INVALID_REQUEST",
                    {"device": device,
                     "detail": "dirty pages pending; drain before rotation"})
            self._ensure_key_free(device, new_key_id)
            record.key_id = new_key_id
            if cipher is not None:
                record.cipher = cipher
            record.generation += 1
            self._counters["rotations"] += 1
            return record.to_state()

    def resume(self, device: str, *, image_device: str, image_offset: int) -> bool:
        with self._lock:
            record = self._get_record(device)
            if record.state != STATE_ENABLED:
                raise SwapError("SWAP_NOT_ENABLED", {"device": device})
            if image_device != record.device or image_offset != record.resume_offset:
                raise SwapError(
                    "SWAP_INVALID_REQUEST",
                    {"device": device, "image_device": image_device,
                     "image_offset": image_offset,
                     "expected_offset": record.resume_offset})
            self._counters["resumes"] += 1
            return True

    def status(self, device: str) -> SwapState:
        with self._lock:
            return self._get_record(device).to_state()

    def devices(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._devices))

    def pending_writeback(self) -> dict:
        with self._lock:
            return {name: record.dirty_pages
                    for name, record in sorted(self._devices.items())
                    if record.dirty_pages > 0}

    def recover(self) -> tuple[str, ...]:
        with self._lock:
            cleaned = sorted(name for name, record in self._devices.items()
                             if record.state == STATE_DRAINING)
            if not cleaned:
                return ()
            if self._counters["recovered"] + len(cleaned) > MAX_RECOVERIES:
                raise SwapError("SWAP_CAPACITY_EXCEEDED",
                                {"max_recoveries": MAX_RECOVERIES})
            for name in cleaned:
                record = self._devices[name]
                record.state = STATE_DISABLED
                record.key_id = None
                record.cipher = None
                record.dirty_pages = 0
                self._counters["recovered"] += 1
            return tuple(cleaned)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "devices": {name: record.to_dict()
                            for name, record in sorted(self._devices.items())},
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            devices, counters = self._validate_snapshot(state)
            self._devices = devices
            self._counters = counters

    @staticmethod
    def _validate_snapshot(state: object) -> tuple[dict, dict]:
        invalid = SwapError("SWAP_SNAPSHOT_INVALID", {"state": state})
        if not isinstance(state, dict):
            raise invalid
        if set(state) != {"version", "devices", "counters"}:
            raise invalid
        version = state["version"]
        if isinstance(version, bool) or version != SNAPSHOT_VERSION:
            raise invalid
        raw_devices = state["devices"]
        raw_counters = state["counters"]
        if not isinstance(raw_devices, dict) or not isinstance(raw_counters, dict):
            raise invalid
        if set(raw_counters) != set(_COUNTER_NAMES):
            raise invalid
        counters = {}
        for name, value in raw_counters.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise invalid
            counters[name] = value

        devices: dict[str, _DeviceRecord] = {}
        bound_keys: dict[str, str] = {}
        for name, entry in raw_devices.items():
            if not isinstance(name, str) or not name or not isinstance(entry, dict):
                raise invalid
            if set(entry) != set(_DEVICE_FIELDS):
                raise invalid
            device = entry["device"]
            record_state = entry["state"]
            key_id = entry["key_id"]
            cipher = entry["cipher"]
            size_pages = entry["size_pages"]
            resume_offset = entry["resume_offset"]
            generation = entry["generation"]
            dirty_pages = entry["dirty_pages"]
            if device != name or not isinstance(device, str):
                raise invalid
            if record_state not in (STATE_DISABLED, STATE_ENABLED, STATE_DRAINING):
                raise invalid
            for text in (key_id, cipher):
                if text is not None and (not isinstance(text, str) or not text):
                    raise invalid
            if record_state == STATE_DISABLED and (key_id is not None
                                                   or cipher is not None):
                raise invalid
            if record_state != STATE_DISABLED and (key_id is None
                                                   or cipher is None):
                raise invalid
            for number in (size_pages, resume_offset, generation, dirty_pages):
                if isinstance(number, bool) or not isinstance(number, int):
                    raise invalid
            if size_pages <= 0 or not 0 <= resume_offset < size_pages:
                raise invalid
            if generation < 1 or not 0 <= dirty_pages <= MAX_DIRTY_PAGES:
                raise invalid
            if record_state != STATE_DISABLED:
                owner = bound_keys.get(key_id)
                if owner is not None and owner != name:
                    raise invalid
                bound_keys[key_id] = name
            devices[name] = _DeviceRecord(
                device=name, state=record_state, key_id=key_id, cipher=cipher,
                size_pages=size_pages, resume_offset=resume_offset,
                generation=generation, dirty_pages=dirty_pages)
        return devices, counters

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
