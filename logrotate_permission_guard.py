"""Log rotation permission guard.

Rotation plans derive the owner, group and mode of the replacement file,
refuse symbolic links, keep archive files no looser than the original, and
track generations so a failed job never leaves half-written archives behind.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

ROTATIONS = ("create", "copytruncate")
COUNTER_KEYS = ("rotated", "compressed", "refused", "failed", "planned",
                "restores")
FINDING_CODES = ("ROT_FILE_MISSING", "ROT_SYMLINK", "ROT_OWNER_MISMATCH",
                 "ROT_MODE_MISMATCH", "ROT_PERM_LOOSER")


class RotateError(ValueError):
    """Refusal raised while planning, rotating or restoring log files."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FileState:
    """One file known to the guard."""

    path: str
    owner: str
    group: str
    mode: int
    size: int
    inode: int
    generation: int = 0
    rotation: str = ""
    compress: bool = False
    su_user: str | None = None
    su_group: str | None = None
    world_writable_dir: bool = False
    immutable: bool = False
    symlink_target: str | None = None


@dataclass(frozen=True)
class PlannedRotation:
    """One line of a rotation plan."""

    path: str
    archive: str
    rotation: str
    owner: str
    group: str
    mode: int
    size: int
    compress: bool


@dataclass(frozen=True)
class RotationResult:
    """The outcome of rotating one log file."""

    path: str
    archive: str
    generation: int
    owner: str
    group: str
    mode: int
    inode: int
    compress: bool


class LogrotatePermissionGuard:
    """Plan and perform log rotations while policing file permissions."""

    def __init__(self, *, umask: int = 0o022, max_files_per_run: int = 32,
                 max_bytes_per_run: int = 8 * 1024 * 1024,
                 compress_mask: int = 0o700) -> None:
        self.umask = umask
        self.max_files_per_run = max_files_per_run
        self.max_bytes_per_run = max_bytes_per_run
        self.compress_mask = compress_mask
        self._lock = threading.RLock()
        self._files = {}
        self._logs = {}
        self._findings = {}
        self._counters = {key: 0 for key in COUNTER_KEYS}
        self._next_inode = 1000

    def register_logfile(self, path: str, *, owner: str, group: str, mode: int,
                         rotation: str = "create", su_user: str | None = None,
                         su_group: str | None = None,
                         world_writable_dir: bool = False,
                         immutable: bool = False,
                         symlink_target: str | None = None,
                         size: int = 1024,
                         compress: bool = True) -> FileState:
        """Register a log file and its rotation policy."""
        raise NotImplementedError

    def place_file(self, path: str, *, owner: str, group: str, mode: int,
                   size: int = 0) -> FileState:
        """Record an arbitrary file such as a compressed archive."""
        raise NotImplementedError

    def stat(self, path: str):
        """Return the recorded state of ``path`` or None."""
        raise NotImplementedError

    def stat_log(self, path: str) -> FileState:
        """Return the state of a registered log file."""
        raise NotImplementedError

    def generation(self, path: str) -> int:
        """Return the rotation generation of a registered log file."""
        raise NotImplementedError

    def archive_path(self, path: str, generation: int | None = None) -> str:
        """Return the archive path of ``path`` for a generation."""
        raise NotImplementedError

    def plan(self, paths) -> tuple:
        """Build rotation plans without touching any file."""
        raise NotImplementedError

    def rotate(self, path: str) -> RotationResult:
        """Rotate one log file and return the result."""
        raise NotImplementedError

    def rotate_batch(self, paths) -> tuple:
        """Rotate several log files after checking the per-run limits."""
        raise NotImplementedError

    def compress(self, path: str, *, generation: int | None = None) -> dict:
        """Compress one archive and return its new state."""
        raise NotImplementedError

    def verify(self, path: str) -> tuple:
        """Return permission findings for one registered log file."""
        raise NotImplementedError

    def report(self) -> dict:
        """Return operation counters and the accumulated findings."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of files, findings and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError
