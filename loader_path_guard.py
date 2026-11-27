"""Loader search-path governance for dynamically linked executables.

The guard merges the loader configuration with the hints recorded in a binary
and the caller supplied environment, then decides whether every directory on
the resulting search path may be trusted.  Configuration refreshes are
versioned so a concurrent resolution never mixes two tables and the decision
cache is invalidated as soon as the version moves.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

DEFAULT_ROOT = "/"
WORLD_WRITABLE_FLAG = 0o002


class LoaderPathError(ValueError):
    """Refusal raised while loading configuration or expanding a path."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BinaryHint:
    path: str
    rpath: tuple = ()
    runpath: tuple = ()
    needed: tuple = ()


@dataclass(frozen=True)
class Rejection:
    path: str
    code: str


@dataclass(frozen=True)
class LoadDecision:
    allowed: bool
    version: int
    path: tuple
    rejections: tuple


class LoaderPathGuard:
    """Compute effective library search paths and admit or reject them."""

    def __init__(self, *, allowed_root: str = DEFAULT_ROOT,
                 world_writable_dirs=None) -> None:
        self.allowed_root = allowed_root
        self._world_writable = set(world_writable_dirs or ())
        self._lock = threading.RLock()
        self._version = 0
        self._dirs = ()
        self._cache = {}
        self._stats = {"config_loads": 0, "failed_loads": 0, "resolutions": 0,
                       "cache_hits": 0, "rejections": 0, "restores": 0}

    def load_config(self, search_dirs, *, source: str = "/etc/ld.so.conf.d") -> int:
        """Normalise ``search_dirs``, install the table and bump the version."""
        raise NotImplementedError

    def current_version(self) -> int:
        """Return the installed configuration version (0 before first load)."""
        raise NotImplementedError

    def config_dirs(self) -> tuple:
        """Return the installed configuration directories in order."""
        raise NotImplementedError

    def expand_origin(self, pattern: str, *, binary_path: str,
                      allowed_root: str | None = None) -> str:
        """Expand ``$ORIGIN`` against the directory holding ``binary_path``."""
        raise NotImplementedError

    def resolve_search_path(self, hint: BinaryHint, *, env=()) -> tuple:
        """Return the trusted directories in loader precedence order."""
        raise NotImplementedError

    def check_binary(self, hint: BinaryHint, *, env=()) -> LoadDecision:
        """Resolve the search path and return the admission decision."""
        raise NotImplementedError

    def explain(self, hint: BinaryHint, *, env=()) -> dict:
        """Return the per-source contributions before de-duplication."""
        raise NotImplementedError

    def mark_world_writable(self, path: str) -> None:
        """Record ``path`` as world writable so it can never be trusted."""
        raise NotImplementedError

    def is_world_writable(self, path: str) -> bool:
        """Report whether ``path`` was recorded as world writable."""
        raise NotImplementedError

    def cache_key(self, hint: BinaryHint, *, env=()) -> tuple:
        """Return the stable cache key for one resolution."""
        raise NotImplementedError

    def invalidate_cache(self) -> int:
        """Drop every cached decision and return how many were dropped."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the configuration and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
