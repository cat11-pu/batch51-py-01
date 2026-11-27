"""NFS export table governance.

The guard parses an exports table, resolves the export that governs a mount
request, derives the effective option set for one client and refuses mounts
that would escape the granted options.  Reloads are versioned so a mount
decision always sees one complete table.
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass

KNOWN_OPTIONS = ("rw", "ro", "sync", "async", "root_squash", "no_root_squash",
                 "all_squash", "no_all_squash", "subtree_check",
                 "no_subtree_check", "secure", "insecure", "nosuid", "noexec")
PSEUDO_ROOTS = ("/proc", "/sys", "/dev")
DEFAULT_OPTIONS = ("ro", "sync", "root_squash", "subtree_check")


class NfsExportError(ValueError):
    """Refusal raised while loading a table or restoring a snapshot."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClientSpec:
    pattern: str
    options: tuple


@dataclass(frozen=True)
class ExportEntry:
    path: str
    clients: tuple
    line: int


@dataclass(frozen=True)
class MountDecision:
    allowed: bool
    reason: str
    path: str
    client_ip: str
    options: tuple
    export_path: str | None
    version: int


class NfsExportGuard:
    """Resolve exports, options and mount authorisations for NFS clients."""

    def __init__(self, *, source: str = "/etc/exports") -> None:
        self.source = source
        self._lock = threading.RLock()
        self._version = 0
        self._entries = ()
        self._mounts = []
        self._stats = {"loads": 0, "failed_loads": 0, "authorizations": 0,
                       "denials": 0, "mounts": 0, "restores": 0}

    def load_exports(self, text: str, *, source: str | None = None) -> int:
        """Parse ``text``, install the table and return the new version."""
        raise NotImplementedError

    def entries(self) -> tuple:
        """Return the installed export entries in file order."""
        raise NotImplementedError

    def current_version(self) -> int:
        """Return the installed table version (0 before the first load)."""
        raise NotImplementedError

    def match_export(self, path: str, client_ip: str) -> ExportEntry | None:
        """Return the most specific export governing ``path`` for the client."""
        raise NotImplementedError

    def specificity(self, entry: ExportEntry, client_ip: str) -> int:
        """Rank how specifically ``entry`` names ``client_ip``."""
        raise NotImplementedError

    def effective_options(self, path: str, client_ip: str) -> tuple:
        """Return the effective options of ``path`` for the client, sorted."""
        raise NotImplementedError

    def authorize(self, *, path: str, client_ip: str,
                  request: str = "ro") -> MountDecision:
        """Decide whether the client may mount ``path`` with ``request``."""
        raise NotImplementedError

    def register_mount(self, *, client_ip: str, path: str) -> None:
        """Record that the client currently has ``path`` mounted."""
        raise NotImplementedError

    def verify_mount(self, *, client_ip: str, path: str) -> bool:
        """Re-check a recorded mount against the installed table."""
        raise NotImplementedError

    def mounts(self) -> tuple:
        """Return the recorded mounts in registration order."""
        raise NotImplementedError

    def audit(self) -> dict:
        """Summarise the installed table: pseudo paths, duplicates, conflicts."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the table, mounts and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
