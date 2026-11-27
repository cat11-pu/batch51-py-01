"""Loop device lifecycle guard.

The guard manages loop devices: it binds a backing file, records the file
signature (device, inode, modified time, size), tracks holders, invalidates
partition scans on reconfiguration and reclaims autoclear devices.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

DEVICE_PREFIX = "loop"
STAT_KEYS = ("attaches", "detaches", "reclaimed", "reused", "drift_refused",
             "touched", "scans", "restores")


class LoopError(ValueError):
    """Refusal raised while binding, opening or restoring loop devices."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BackingFile:
    """One observed state of a backing file on disk."""

    path: str
    dev: int
    inode: int
    mtime_ns: int
    size: int


@dataclass(frozen=True)
class LoopBinding:
    """A bound loop device."""

    loop: str
    path: str
    dev: int
    inode: int
    size: int
    offset: int
    size_limit: int
    read_only: bool
    autoclear: bool
    generation: int


@dataclass(frozen=True)
class LoopStatus:
    """A detached view of one loop device."""

    loop: str
    attached: bool
    path: str | None = None
    offset: int = 0
    size_limit: int = 0
    read_only: bool = False
    autoclear: bool = False
    holders: tuple = ()
    pending_detach: bool = False
    partitions: tuple = ()
    generation: int = 0
    touched: bool = False


class LoopDeviceGuard:
    """Bind backing files to loop devices and police their lifetime."""

    def __init__(self, *, max_devices: int = 64,
                 max_bindings_per_file: int = 4,
                 autoclear_default: bool = False) -> None:
        self.max_devices = max_devices
        self.max_bindings_per_file = max_bindings_per_file
        self.autoclear_default = autoclear_default
        self._lock = threading.RLock()
        self._next_index = 0
        self._devices = {}
        self._observations = {}
        self._stats = {key: 0 for key in STAT_KEYS}

    def observe_file(self, path: str, *, dev: int, inode: int,
                     mtime_ns: int, size: int) -> BackingFile:
        """Record the current on-disk signature of ``path``."""
        raise NotImplementedError

    def attach(self, path: str, *, offset: int = 0, sizelimit: int | None = None,
               read_only: bool = False,
               autoclear: bool | None = None) -> LoopBinding:
        """Bind ``path`` to the next loop device and return the binding."""
        raise NotImplementedError

    def detach(self, loop: str, *, holder: str | None = None) -> bool:
        """Detach ``loop``; refuse when a manual device is still held."""
        raise NotImplementedError

    def reconfigure(self, loop: str, *, offset: int | None = None,
                    sizelimit: int | None = None,
                    read_only: bool | None = None) -> LoopBinding:
        """Change the offset, size limit or access mode of ``loop``."""
        raise NotImplementedError

    def reclaim(self, *, now: int = 0) -> int:
        """Reclaim unheld autoclear devices and return how many were freed."""
        raise NotImplementedError

    def status(self, loop: str) -> LoopStatus:
        """Return a detached status view, attached=False for unknown loops."""
        raise NotImplementedError

    def open_device(self, loop: str, *, holder: str) -> LoopStatus:
        """Re-validate the backing file and register ``holder``."""
        raise NotImplementedError

    def close_device(self, loop: str, *, holder: str) -> int:
        """Drop ``holder`` and return the remaining holder count."""
        raise NotImplementedError

    def holders(self, loop: str) -> tuple:
        """Return the sorted holders of ``loop``."""
        raise NotImplementedError

    def bindings_for(self, path: str) -> tuple:
        """Return the bindings that share one backing path."""
        raise NotImplementedError

    def record_partitions(self, loop: str, partitions) -> tuple:
        """Store an external partition scan result for ``loop``."""
        raise NotImplementedError

    def scan_partitions(self, loop: str) -> tuple:
        """Return the cached partition scan result."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of devices, observations and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
