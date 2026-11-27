"""Session-scoped access governance for capture devices: grants, exclusive streams, privacy indicator."""

from __future__ import annotations

import threading
from dataclasses import dataclass

CAMERA = "camera"
MICROPHONE = "microphone"
KINDS = (CAMERA, MICROPHONE)

READ = "read"
WRITE = "write"
MODES = (READ, WRITE)


class MediaAccessError(ValueError):
    """Raised when a device access operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceInfo:
    device_id: str
    kind: str
    present: bool


@dataclass(frozen=True)
class AccessGrant:
    session: str
    kind: str
    devices: tuple[str, ...]
    revision: int
    granted_at: str | None


@dataclass(frozen=True)
class StreamHandle:
    stream_id: str
    session: str
    device_id: str
    kind: str
    mode: str
    shared: bool
    live: bool


class MediaDeviceAccessGuard:
    """Track per-session grants, exclusive capture streams and the in-use indicator."""

    def __init__(self, *, max_streams_per_session: int = 4,
                 max_streams_total: int = 16) -> None:
        self.max_streams_per_session = max_streams_per_session
        self.max_streams_total = max_streams_total
        self._lock = threading.RLock()

    def register_device(self, device_id: str, kind: str, *,
                        present: bool = True) -> DeviceInfo:
        raise NotImplementedError

    def unplug_device(self, device_id: str) -> int:
        raise NotImplementedError

    def enumerate_devices(self, *, kind: str | None = None) -> list[DeviceInfo]:
        raise NotImplementedError

    def request_access(self, session: str, kind: str, devices=None, *,
                       now: str | None = None) -> AccessGrant:
        raise NotImplementedError

    def open_stream(self, session: str, device_id: str, *, mode: str = READ,
                    shared: bool = False, now: str | None = None) -> StreamHandle:
        raise NotImplementedError

    def close_stream(self, stream_id: str) -> bool:
        raise NotImplementedError

    def revoke(self, session: str, kind: str | None = None, *,
               now: str | None = None) -> int:
        raise NotImplementedError

    def end_session(self, session: str, *, now: str | None = None) -> dict:
        raise NotImplementedError

    def indicator_state(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
