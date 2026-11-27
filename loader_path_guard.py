"""Loader search-path governance for dynamically linked executables.

The guard merges the loader configuration with the hints recorded in a binary
and the caller supplied environment, then decides whether every directory on
the resulting search path may be trusted.  Configuration refreshes are
versioned so a concurrent resolution never mixes two tables and the decision
cache is invalidated as soon as the version moves.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_ROOT = "/"
WORLD_WRITABLE_FLAG = 0o002
STAT_KEYS = (
    "config_loads",
    "failed_loads",
    "resolutions",
    "cache_hits",
    "rejections",
    "restores",
)


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


class _SnapshotState(dict):
    """Snapshot mapping with private decision-replay metadata."""


class LoaderPathGuard:
    """Compute effective library search paths and admit or reject them."""

    def __init__(self, *, allowed_root: str = DEFAULT_ROOT,
                 world_writable_dirs=None) -> None:
        self.allowed_root = self._normalise_root(allowed_root)
        if isinstance(world_writable_dirs, str):
            world_writable_dirs = (world_writable_dirs,)
        self._world_writable = {
            self._normalise_marked_path(path)
            for path in (world_writable_dirs or ())
        }
        self._lock = threading.RLock()
        self._version = 0
        self._dirs = ()
        self._cache = {}
        self._restored_decisions = {}
        self._decision_history = {}
        self._stats = {key: 0 for key in STAT_KEYS}

    def load_config(self, search_dirs, *, source: str = "/etc/ld.so.conf.d") -> int:
        """Normalise ``search_dirs``, install the table and bump the version."""
        try:
            if isinstance(search_dirs, str):
                raise LoaderPathError("LDG_CONFIG_INVALID", search_dirs)
            dirs = tuple(
                self._normalise_config_entry(path) for path in search_dirs
            )
            if not dirs:
                raise LoaderPathError("LDG_CONFIG_INVALID", "empty search table")
        except LoaderPathError:
            with self._lock:
                self._stats["failed_loads"] += 1
            raise
        except TypeError as exc:
            with self._lock:
                self._stats["failed_loads"] += 1
            raise LoaderPathError("LDG_CONFIG_INVALID", exc) from exc

        with self._lock:
            self._dirs = dirs
            self._version += 1
            self._stats["config_loads"] += 1
            self._cache.clear()
            self._restored_decisions.clear()
            self._decision_history.clear()
            return self._version

    def current_version(self) -> int:
        """Return the installed configuration version (0 before first load)."""
        with self._lock:
            return self._version

    def config_dirs(self) -> tuple:
        """Return the installed configuration directories in order."""
        with self._lock:
            return self._dirs

    def expand_origin(self, pattern: str, *, binary_path: str,
                      allowed_root: str | None = None) -> str:
        """Expand ``$ORIGIN`` against the directory holding ``binary_path``."""
        root = self.allowed_root if allowed_root is None else allowed_root
        return self._expand_origin(pattern, binary_path, root)

    def resolve_search_path(self, hint: BinaryHint, *, env=()) -> tuple:
        """Return the trusted directories in loader precedence order."""
        env_entries = self._as_entries(env)
        with self._lock:
            return self._decision_locked(hint, env_entries).path

    def check_binary(self, hint: BinaryHint, *, env=()) -> LoadDecision:
        """Resolve the search path and return the admission decision."""
        env_entries = self._as_entries(env)
        with self._lock:
            return self._decision_locked(hint, env_entries)

    def explain(self, hint: BinaryHint, *, env=()) -> dict:
        """Return the per-source contributions before de-duplication."""
        env_entries = self._as_entries(env)
        rpath = self._as_entries(hint.rpath)
        runpath = self._as_entries(hint.runpath)
        with self._lock:
            config = self._dirs

        if runpath:
            return {
                "env": self._explain_entries(env_entries, hint.path),
                "runpath": self._explain_entries(runpath, hint.path),
                "rpath": (),
                "config": self._explain_entries(config, hint.path),
            }
        if rpath:
            return {
                "env": self._explain_entries(env_entries, hint.path),
                "runpath": (),
                "rpath": self._explain_entries(rpath, hint.path),
                "config": self._explain_entries(config, hint.path),
            }
        return {
            "env": self._explain_entries(env_entries, hint.path),
            "runpath": (),
            "rpath": (),
            "config": self._explain_entries(config, hint.path),
        }

    def mark_world_writable(self, path: str) -> None:
        """Record ``path`` as world writable so it can never be trusted."""
        marked = self._normalise_marked_path(path)
        with self._lock:
            self._world_writable.add(marked)
            self._cache.clear()
            self._restored_decisions.clear()

    def is_world_writable(self, path: str) -> bool:
        """Report whether ``path`` was recorded as world writable."""
        try:
            marked = self._normalise_marked_path(path)
        except (TypeError, ValueError):
            return False
        with self._lock:
            return marked in self._world_writable

    def cache_key(self, hint: BinaryHint, *, env=()) -> tuple:
        """Return the stable cache key for one resolution."""
        env_entries = self._as_entries(env)
        with self._lock:
            return self._cache_key_locked(hint, env_entries)

    def invalidate_cache(self) -> int:
        """Drop every cached decision and return how many were dropped."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._restored_decisions.clear()
            self._decision_history.clear()
            return count

    def snapshot(self) -> dict:
        """Return a detached snapshot of the configuration and counters."""
        with self._lock:
            state = _SnapshotState({
                "version": self._version,
                "dirs": list(self._dirs),
                "world_writable": sorted(self._world_writable),
                "stats": dict(self._stats),
            })
            state.cache_entries = tuple(self._cache.items())
            state.last_decisions = dict(self._decision_history)
            state.decision_signature = (
                self._version,
                self._dirs,
                tuple(sorted(self._world_writable)),
            )
            return state

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        try:
            (version, dirs, world_writable, restored_stats,
             cache, last_decisions) = self._validate_state(state)
        except (KeyError, TypeError, ValueError) as exc:
            raise LoaderPathError("LDG_SNAPSHOT_INVALID", exc) from exc

        with self._lock:
            self._version = version
            self._dirs = dirs
            self._world_writable = world_writable
            self._stats = restored_stats
            self._stats["restores"] += 1
            self._cache.clear()
            self._cache.update(cache)
            self._restored_decisions = last_decisions
            self._decision_history = dict(last_decisions)

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _normalise_root(root) -> str:
        if root is None:
            root = DEFAULT_ROOT
        if not isinstance(root, str) or not root.strip():
            raise LoaderPathError("INVALID_ALLOWED_ROOT", root)
        normalised = os.path.normpath(root.strip())
        if normalised.startswith("//"):
            normalised = "/" + normalised.lstrip("/")
        if not os.path.isabs(normalised):
            raise LoaderPathError("INVALID_ALLOWED_ROOT", root)
        return normalised

    @classmethod
    def _normalise_config_entry(cls, path) -> str:
        if not isinstance(path, str):
            raise LoaderPathError("LDG_CONFIG_INVALID", path)
        value = path.strip()
        if value:
            while len(value) > 1 and value.endswith("/"):
                value = value[:-1]
        if not value or not os.path.isabs(value):
            raise LoaderPathError("LDG_CONFIG_INVALID", path)
        return value

    @classmethod
    def _normalise_marked_path(cls, path) -> str:
        if not isinstance(path, str) or not path.strip():
            raise LoaderPathError("INVALID_PATH", path)
        value = path.strip()
        normalised = os.path.normpath(value)
        if normalised.startswith("//"):
            normalised = "/" + normalised.lstrip("/")
        if normalised == ".":
            return value
        return normalised

    @staticmethod
    def _as_entries(values) -> tuple:
        if values is None:
            return ()
        if isinstance(values, str):
            return (values,)
        return tuple(values)

    @staticmethod
    def _freeze(value):
        if isinstance(value, Mapping):
            return tuple(
                sorted((LoaderPathGuard._freeze(key),
                        LoaderPathGuard._freeze(item))
                       for key, item in value.items())
            )
        if isinstance(value, (list, tuple)):
            return tuple(LoaderPathGuard._freeze(item) for item in value)
        if isinstance(value, (set, frozenset)):
            return tuple(
                sorted(LoaderPathGuard._freeze(item) for item in value)
            )
        return value

    def _cache_key_locked(self, hint: BinaryHint, env: tuple) -> tuple:
        return (
            self._version,
            self.allowed_root,
            self._freeze(getattr(hint, "path", hint)),
            self._freeze(getattr(hint, "rpath", ())),
            self._freeze(getattr(hint, "runpath", ())),
            self._freeze(getattr(hint, "needed", ())),
            self._freeze(env),
            tuple(sorted(self._world_writable)),
        )

    def _hint_key_locked(self, hint: BinaryHint) -> tuple:
        return (
            self.allowed_root,
            self._freeze(getattr(hint, "path", hint)),
            self._freeze(getattr(hint, "rpath", ())),
            self._freeze(getattr(hint, "runpath", ())),
            self._freeze(getattr(hint, "needed", ())),
        )

    @staticmethod
    def _origin_directory(binary_path) -> str:
        if not isinstance(binary_path, str) or not binary_path:
            raise LoaderPathError("INVALID_PATH", binary_path)
        binary = os.path.normpath(binary_path)
        origin = os.path.dirname(binary)
        return origin or os.curdir

    @staticmethod
    def _lexically_escapes_root(path: str, root: str) -> bool:
        """Return True when raw ``path`` traverses above ``root``."""
        root = os.path.normpath(root)
        if root == os.sep:
            return False
        if not os.path.isabs(path):
            return True

        root_parts = tuple(
            part for part in root.split(os.sep) if part not in ("", ".")
        )
        path_parts = tuple(
            part for part in path.split(os.sep) if part not in ("", ".")
        )
        if path_parts[:len(root_parts)] != root_parts:
            return True

        depth = len(root_parts)
        for part in path_parts[len(root_parts):]:
            if part == "..":
                depth -= 1
                if depth < len(root_parts):
                    return True
            else:
                depth += 1
        return False

    def _expand_origin(self, pattern, binary_path, allowed_root) -> str:
        if not isinstance(pattern, str):
            raise LoaderPathError("RELATIVE_PATH", pattern)
        root = self._normalise_root(allowed_root)
        origin = self._origin_directory(binary_path)
        expanded = pattern.replace("${ORIGIN}", origin).replace("$ORIGIN", origin)
        if not os.path.isabs(expanded):
            raise LoaderPathError("RELATIVE_PATH", expanded)
        if self._lexically_escapes_root(expanded, root):
            raise LoaderPathError("PATH_ESCAPE", expanded)
        normalised = os.path.normpath(expanded)
        if normalised.startswith("//"):
            normalised = "/" + normalised.lstrip("/")
        return normalised

    @staticmethod
    def _normalise_search_entry(entry: str) -> str:
        if not os.path.isabs(entry):
            raise LoaderPathError("RELATIVE_PATH", entry)
        normalised = os.path.normpath(entry)
        if normalised.startswith("//"):
            normalised = "/" + normalised.lstrip("/")
        return normalised

    @staticmethod
    def _has_origin(entry: str) -> bool:
        return "$ORIGIN" in entry or "${ORIGIN}" in entry

    def _ordered_entries(self, hint: BinaryHint, env: tuple) -> tuple:
        rpath = self._as_entries(getattr(hint, "rpath", ()))
        runpath = self._as_entries(getattr(hint, "runpath", ()))
        if runpath:
            return (
                tuple(("env", entry) for entry in env)
                + tuple(("runpath", entry) for entry in runpath)
                + tuple(("config", entry) for entry in self._dirs)
            )
        if rpath:
            return (
                tuple(("rpath", entry) for entry in rpath)
                + tuple(("env", entry) for entry in env)
                + tuple(("config", entry) for entry in self._dirs)
            )
        return (
            tuple(("env", entry) for entry in env)
            + tuple(("config", entry) for entry in self._dirs)
        )

    def _scan_entries(self, hint: BinaryHint, env: tuple) -> tuple:
        trusted = []
        seen = set()
        rejections = []

        for _source, entry in self._ordered_entries(hint, env):
            if not isinstance(entry, str):
                rejections.append(Rejection(str(entry), "RELATIVE_PATH"))
                continue

            shown = entry.strip()
            try:
                if self._has_origin(shown):
                    path = self._expand_origin(
                        shown, hint.path, self.allowed_root
                    )
                else:
                    path = self._normalise_search_entry(shown)
            except LoaderPathError as exc:
                rejections.append(Rejection(shown, exc.code))
                continue

            if path in self._world_writable:
                rejections.append(Rejection(path, "WORLD_WRITABLE"))
                continue
            if path not in seen:
                seen.add(path)
                trusted.append(path)

        return tuple(trusted), tuple(rejections)

    def _decision_locked(self, hint: BinaryHint, env: tuple) -> LoadDecision:
        key = self._cache_key_locked(hint, env)
        cached = self._cache.get(key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        hint_key = self._hint_key_locked(hint)
        restored = self._restored_decisions.get(hint_key)
        if (restored is not None
                and restored.version == self._version
                and not any(path in self._world_writable
                            for path in restored.path)):
            self._stats["cache_hits"] += 1
            self._cache[key] = restored
            self._decision_history[hint_key] = restored
            return restored

        path, rejections = self._scan_entries(hint, env)
        decision = LoadDecision(
            allowed=not rejections,
            version=self._version,
            path=path,
            rejections=rejections,
        )
        self._stats["resolutions"] += 1
        self._stats["rejections"] += len(rejections)
        self._cache[key] = decision
        self._decision_history[hint_key] = decision
        return decision

    def _explain_entries(self, entries, binary_path: str) -> tuple:
        explained = []
        origin = self._origin_directory(binary_path)
        for entry in entries:
            if not isinstance(entry, str):
                explained.append(entry)
                continue
            expanded = (
                entry.strip()
                .replace("${ORIGIN}", origin)
                .replace("$ORIGIN", origin)
            )
            explained.append(os.path.normpath(expanded))
        return tuple(explained)

    @staticmethod
    def _validate_state(state):
        if not isinstance(state, Mapping):
            raise TypeError("state must be a mapping")
        required = {"version", "dirs", "world_writable", "stats"}
        if not required.issubset(state):
            raise KeyError("missing snapshot keys")

        version = state["version"]
        if type(version) is not int or version < 0:
            raise TypeError("version must be a non-negative integer")

        raw_dirs = state["dirs"]
        if not isinstance(raw_dirs, (list, tuple)):
            raise TypeError("dirs must be a sequence")
        dirs = tuple(
            LoaderPathGuard._normalise_config_entry(path) for path in raw_dirs
        )

        raw_world = state["world_writable"]
        if not isinstance(raw_world, (list, tuple, set, frozenset)):
            raise TypeError("world_writable must be a collection")
        world_writable = {
            LoaderPathGuard._normalise_marked_path(path) for path in raw_world
        }

        raw_stats = state["stats"]
        if not isinstance(raw_stats, Mapping):
            raise TypeError("stats must be a mapping")
        if not set(STAT_KEYS).issubset(raw_stats):
            raise KeyError("stats keys are incomplete")
        stats = {}
        for key in STAT_KEYS:
            value = raw_stats[key]
            if type(value) is not int or value < 0:
                raise TypeError("stats values must be non-negative integers")
            stats[key] = value

        cache = {}
        last_decisions = {}
        signature = (version, dirs, tuple(sorted(world_writable)))
        if getattr(state, "decision_signature", None) == signature:
            raw_cache = getattr(state, "cache_entries", ())
            if isinstance(raw_cache, tuple):
                for item in raw_cache:
                    if (not isinstance(item, tuple) or len(item) != 2
                            or not isinstance(item[1], LoadDecision)):
                        continue
                    cache[item[0]] = item[1]

            raw_last = getattr(state, "last_decisions", {})
            if isinstance(raw_last, Mapping):
                for hint_key, decision in raw_last.items():
                    if isinstance(decision, LoadDecision):
                        last_decisions[hint_key] = decision

        return version, dirs, world_writable, stats, cache, last_decisions
