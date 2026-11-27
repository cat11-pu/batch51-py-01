"""Input device grab guard.

Logical input devices are registered with their event nodes, capabilities and
physical path.  One session at a time may grab a device; grabs carry a lease
so a crashed process is reclaimed, and a hot-plugged device is rebound along
its physical path.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

PURPOSES = ("hotkey-capture", "keyboard-capture", "pointer-capture")
STAT_KEYS = ("registered", "grabbed", "merged", "ungrabbed", "expired",
             "session_releases")


class InputGrabError(ValueError):
    """Refusal raised while registering devices or taking grabs."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceInfo:
    """One logical input device."""

    device_id: str
    physical_path: str
    nodes: tuple
    inode: int
    capabilities: tuple
    keyboard: bool
    present: bool


@dataclass(frozen=True)
class GrabHandle:
    """One exclusive grab of a logical device."""

    grab_id: str
    device_id: str
    session: str
    pid: int
    purpose: str
    started_at: int
    lease_expires: int
    stale: bool


class InputDeviceGrabGuard:
    """Track /dev/input devices and exclusive grabs per session."""

    def __init__(self, *, max_devices: int = 64, max_grabs: int = 32,
                 max_grabs_per_session: int = 4,
                 lease_ttl: int = 30) -> None:
        self.max_devices = max_devices
        self.max_grabs = max_grabs
        self.max_grabs_per_session = max_grabs_per_session
        self.lease_ttl = lease_ttl
        self._lock = threading.RLock()
        self._devices = {}
        self._grabs = {}
        self._sessions = {}
        self._next_device = 1
        self._next_grab = 1
        self._stats = {key: 0 for key in STAT_KEYS}

    def register_device(self, physical_path: str, *, event_nodes,
                        capabilities, inode: int,
                        keyboard: bool = False) -> DeviceInfo:
        """Register one logical input device and return it."""
        raise NotImplementedError

    def unplug(self, device_id: str) -> bool:
        """Mark a device as unplugged and report whether it was present."""
        raise NotImplementedError

    def rebind(self, device_id: str, *, event_node: str, inode: int,
               session: str, now: int = 0) -> DeviceInfo:
        """Rebind a reinserted device along its physical path."""
        raise NotImplementedError

    def grab(self, device_id: str, *, session: str, pid: int, purpose: str,
             now: int = 0, authorized: bool = False) -> GrabHandle:
        """Take an exclusive grab of ``device_id`` for ``session``."""
        raise NotImplementedError

    def ungrab(self, grab_id: str, *, session: str | None = None) -> bool:
        """Release one grab and report whether it existed."""
        raise NotImplementedError

    def release_session(self, session: str) -> int:
        """Release every grab owned by ``session`` and return the count."""
        raise NotImplementedError

    def heartbeat(self, grab_id: str, *, now: int = 0) -> int:
        """Renew one grab lease and return the new expiry."""
        raise NotImplementedError

    def expire(self, *, now: int = 0) -> int:
        """Reclaim grabs whose lease expired and return the count."""
        raise NotImplementedError

    def set_session_locked(self, session: str, locked: bool) -> None:
        """Record whether a session is currently locked."""
        raise NotImplementedError

    def delivery_target(self, grab_id: str):
        """Return the session allowed to receive keys, or None."""
        raise NotImplementedError

    def device_state(self, device_id: str) -> dict:
        """Return presence and holder information for one device."""
        raise NotImplementedError

    def session_state(self, session: str) -> dict:
        """Return lock state and grab ids for one session."""
        raise NotImplementedError

    def enumerate(self) -> tuple:
        """Return the registered devices in registration order."""
        raise NotImplementedError

    def grabs(self, *, session: str | None = None) -> tuple:
        """Return grab handles in grab order, optionally for one session."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of devices, grabs and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
