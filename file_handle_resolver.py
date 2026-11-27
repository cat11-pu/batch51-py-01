"""File handle resolver: mount namespaces, capability checks, generation-safe cache."""

from __future__ import annotations

import copy
import posixpath
import threading
from collections import OrderedDict
from dataclasses import dataclass


class FhError(ValueError):
    """Raised when the resolver refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Resolution:
    handle_id: str
    mount_id: str
    namespace: str
    path: str
    inode: int
    generation: int
    kind: str


_STAT_KEYS = (
    "resolves",
    "authorized",
    "denied",
    "hidden",
    "stale",
    "cache_hits",
    "cache_misses",
    "evictions",
    "invalidations",
)


class FileHandleResolver:
    """Resolve mount id plus file handle back to a path under access control."""

    def __init__(self, *, cache_size: int = 16) -> None:
        try:
            capacity = int(cache_size)
        except (TypeError, ValueError):
            capacity = 0
        self.cache_size = max(0, capacity)
        self._lock = threading.RLock()
        self._mounts: dict[str, dict] = {}
        self._callers: dict[str, dict] = {}
        self._objects: dict[str, dict] = {}
        self._cache: OrderedDict[tuple[str, int], Resolution] = OrderedDict()
        self._stats = {key: 0 for key in _STAT_KEYS}

    # ------------------------------------------------------------------
    # Validation helpers

    @staticmethod
    def _raise(code: str, detail: object = None) -> None:
        raise FhError(code, detail)

    @classmethod
    def _normalize_path(cls, path: object, *, detail: object = None) -> str:
        if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            cls._raise("FILEHANDLE_PATH_INVALID", path if detail is None else detail)
        normalized = posixpath.normpath(path)
        if normalized.startswith("//"):
            normalized = "/" + normalized.lstrip("/")
        if not normalized.startswith("/"):
            cls._raise("FILEHANDLE_PATH_INVALID", path if detail is None else detail)
        return normalized

    @staticmethod
    def _contains(root: str, path: str) -> bool:
        if root == "/":
            return path.startswith("/")
        return path == root or path.startswith(root + "/")

    @classmethod
    def _path_under_root(cls, path: str, root: str) -> bool:
        return cls._contains(root, path)

    @staticmethod
    def _caller_namespace(callers: dict, caller: str) -> str | None:
        record = callers.get(caller)
        if record is None:
            return None
        return record.get("namespace")

    @staticmethod
    def _has_capability(callers: dict, caller: str, mount_id: str,
                        path: str) -> bool:
        record = callers.get(caller)
        if record is None:
            return False
        for grant in record.get("grants", ()):
            grant_mount = grant.get("mount_id")
            if grant_mount is not None and grant_mount != mount_id:
                continue
            if FileHandleResolver._contains(grant.get("path_prefix", "/"), path):
                return True
        return False

    def _live_path_taken(self, mount_id: str, path: str,
                         *, exclude: str | None = None) -> bool:
        for handle_id, obj in self._objects.items():
            if handle_id == exclude or obj["deleted"]:
                continue
            if obj["mount_id"] == mount_id and obj["path"] == path:
                return True
        return False

    # ------------------------------------------------------------------
    # Cache helpers

    def _cache_put(self, key: tuple[str, int], value: Resolution) -> None:
        capacity = max(0, self.cache_size)
        if capacity == 0:
            return
        if key in self._cache:
            self._cache.move_to_end(key)
            self._cache[key] = value
            return
        while len(self._cache) >= capacity:
            self._cache.popitem(last=False)
            self._stats["evictions"] += 1
        self._cache[key] = value

    def _drop_handle_cache(self, handle_id: str) -> int:
        keys = [key for key in self._cache if key[0] == handle_id]
        for key in keys:
            del self._cache[key]
        if keys:
            self._stats["invalidations"] += len(keys)
        return len(keys)

    # ------------------------------------------------------------------
    # Mounts, callers, and objects

    def add_mount(self, mount_id: str, namespace: str, *, root: str = "/") -> None:
        with self._lock:
            if mount_id in self._mounts:
                self._raise("FILEHANDLE_DUPLICATE_MOUNT", mount_id)
            normalized_root = self._normalize_path(root)

            # A removed mount id may be reused, but old objects must not be
            # revived under the new mount instance.
            orphaned = [
                handle_id for handle_id, obj in self._objects.items()
                if obj["mount_id"] == mount_id
            ]
            for handle_id in orphaned:
                self._drop_handle_cache(handle_id)
                del self._objects[handle_id]

            self._mounts[mount_id] = {
                "namespace": namespace,
                "root": normalized_root,
            }

    def remove_mount(self, mount_id: str) -> bool:
        with self._lock:
            if mount_id not in self._mounts:
                return False
            del self._mounts[mount_id]
            for handle_id, obj in self._objects.items():
                if obj["mount_id"] == mount_id:
                    self._drop_handle_cache(handle_id)
            return True

    def enter_namespace(self, caller: str, namespace: str) -> None:
        with self._lock:
            record = self._callers.get(caller)
            if record is None:
                self._callers[caller] = {
                    "namespace": namespace,
                    "grants": [],
                }
            else:
                record["namespace"] = namespace

    def grant(self, caller: str, mount_id: str | None = None, *,
              path_prefix: str = "/") -> None:
        prefix = self._normalize_path(path_prefix)
        with self._lock:
            record = self._callers.get(caller)
            if record is None:
                record = {"namespace": None, "grants": []}
                self._callers[caller] = record
            grant_entry = {
                "mount_id": mount_id,
                "path_prefix": prefix,
            }
            if grant_entry not in record["grants"]:
                record["grants"].append(grant_entry)

    def add_object(self, handle_id: str, *, mount_id: str, path: str,
                   inode: int, generation: int = 1,
                   kind: str = "file") -> str:
        with self._lock:
            if handle_id in self._objects:
                self._raise("FILEHANDLE_DUPLICATE", handle_id)
            mount = self._mounts.get(mount_id)
            if mount is None:
                self._raise("FILEHANDLE_UNKNOWN_MOUNT", mount_id)
            normalized_path = self._normalize_path(path)
            if not self._path_under_root(normalized_path, mount["root"]):
                self._raise("FILEHANDLE_PATH_INVALID", path)
            if self._live_path_taken(mount_id, normalized_path):
                self._raise("FILEHANDLE_DUPLICATE_PATH", normalized_path)

            self._objects[handle_id] = {
                "handle_id": handle_id,
                "mount_id": mount_id,
                "path": normalized_path,
                "inode": inode,
                "generation": generation,
                "kind": kind,
                "deleted": False,
            }
            return handle_id

    def rename(self, handle_id: str, new_path: str) -> None:
        with self._lock:
            obj = self._objects.get(handle_id)
            if obj is None:
                self._raise("FILEHANDLE_UNKNOWN", handle_id)
            mount = self._mounts.get(obj["mount_id"])
            if mount is None:
                self._raise("FILEHANDLE_UNKNOWN_MOUNT", obj["mount_id"])
            if obj["deleted"]:
                self._raise("FILEHANDLE_STALE", handle_id)

            normalized_path = self._normalize_path(new_path)
            if not self._path_under_root(normalized_path, mount["root"]):
                self._raise("FILEHANDLE_PATH_INVALID", new_path)
            if self._live_path_taken(obj["mount_id"], normalized_path,
                                     exclude=handle_id):
                self._raise("FILEHANDLE_DUPLICATE_PATH", normalized_path)

            obj["path"] = normalized_path
            self._drop_handle_cache(handle_id)

    def unlink(self, handle_id: str) -> None:
        with self._lock:
            obj = self._objects.get(handle_id)
            if obj is None:
                self._raise("FILEHANDLE_UNKNOWN", handle_id)
            obj["deleted"] = True
            self._drop_handle_cache(handle_id)

    def recycle(self, handle_id: str, *, path: str,
                inode: int | None = None) -> int:
        with self._lock:
            obj = self._objects.get(handle_id)
            if obj is None:
                self._raise("FILEHANDLE_UNKNOWN", handle_id)
            mount = self._mounts.get(obj["mount_id"])
            if mount is None:
                self._raise("FILEHANDLE_UNKNOWN_MOUNT", obj["mount_id"])

            normalized_path = self._normalize_path(path)
            if not self._path_under_root(normalized_path, mount["root"]):
                self._raise("FILEHANDLE_PATH_INVALID", path)
            if self._live_path_taken(obj["mount_id"], normalized_path,
                                     exclude=handle_id):
                self._raise("FILEHANDLE_DUPLICATE_PATH", normalized_path)

            obj["path"] = normalized_path
            if inode is not None:
                obj["inode"] = inode
            obj["generation"] += 1
            obj["deleted"] = False
            self._drop_handle_cache(handle_id)
            return obj["generation"]

    # ------------------------------------------------------------------
    # Resolution and authorization

    def resolve(self, caller: str, handle_id: str) -> Resolution:
        with self._lock:
            obj = self._objects.get(handle_id)
            if obj is None:
                self._raise("FILEHANDLE_UNKNOWN", handle_id)
            mount = self._mounts.get(obj["mount_id"])
            if mount is None:
                self._raise("FILEHANDLE_UNKNOWN_MOUNT", obj["mount_id"])

            caller_namespace = self._caller_namespace(self._callers, caller)
            if caller_namespace is None or caller_namespace != mount["namespace"]:
                self._stats["hidden"] += 1
                self._raise("FILEHANDLE_MOUNT_HIDDEN", obj["mount_id"])

            if obj["deleted"]:
                self._stats["stale"] += 1
                self._raise("FILEHANDLE_STALE", handle_id)

            if not self._has_capability(self._callers, caller,
                                        obj["mount_id"], obj["path"]):
                self._stats["denied"] += 1
                self._raise("FILEHANDLE_ACCESS_DENIED", handle_id)

            key = (handle_id, obj["generation"])
            cached = self._cache.get(key)
            if cached is not None and cached.path == obj["path"]:
                self._cache.move_to_end(key)
                self._stats["cache_hits"] += 1
                self._stats["resolves"] += 1
                return cached
            if cached is not None:
                del self._cache[key]

            self._stats["cache_misses"] += 1
            resolution = Resolution(
                handle_id=handle_id,
                mount_id=obj["mount_id"],
                namespace=mount["namespace"],
                path=obj["path"],
                inode=obj["inode"],
                generation=obj["generation"],
                kind=obj["kind"],
            )
            self._cache_put(key, resolution)
            self._stats["resolves"] += 1
            return resolution

    def authorize(self, caller: str, handle_id: str) -> bool:
        with self._lock:
            obj = self._objects.get(handle_id)
            if obj is None:
                self._raise("FILEHANDLE_UNKNOWN", handle_id)
            mount = self._mounts.get(obj["mount_id"])
            if mount is None:
                self._raise("FILEHANDLE_UNKNOWN_MOUNT", obj["mount_id"])

            caller_namespace = self._caller_namespace(self._callers, caller)
            if caller_namespace is None or caller_namespace != mount["namespace"]:
                self._stats["hidden"] += 1
                self._raise("FILEHANDLE_MOUNT_HIDDEN", obj["mount_id"])

            if obj["deleted"]:
                return False
            if self._has_capability(self._callers, caller,
                                    obj["mount_id"], obj["path"]):
                self._stats["authorized"] += 1
                return True
            return False

    def describe(self, handle_id: str) -> dict:
        with self._lock:
            obj = self._objects.get(handle_id)
            if obj is None:
                self._raise("FILEHANDLE_UNKNOWN", handle_id)
            mount = self._mounts.get(obj["mount_id"])
            return {
                "handle_id": obj["handle_id"],
                "mount_id": obj["mount_id"],
                "namespace": mount["namespace"] if mount is not None else None,
                "path": obj["path"],
                "inode": obj["inode"],
                "generation": obj["generation"],
                "kind": obj["kind"],
                "deleted": obj["deleted"],
            }

    # ------------------------------------------------------------------
    # Cache control, snapshots, and statistics

    def invalidate(self, handle_id: str | None = None) -> int:
        with self._lock:
            if handle_id is None:
                removed = len(self._cache)
                self._cache.clear()
                if removed:
                    self._stats["invalidations"] += removed
            else:
                removed = self._drop_handle_cache(handle_id)
            return removed

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "mounts": copy.deepcopy({
                    mount_id: {
                        "namespace": mount["namespace"],
                        "root": mount["root"],
                    }
                    for mount_id, mount in self._mounts.items()
                }),
                "callers": copy.deepcopy({
                    caller: {
                        "namespace": record["namespace"],
                        "grants": [
                            {
                                "mount_id": grant["mount_id"],
                                "path_prefix": grant["path_prefix"],
                            }
                            for grant in record["grants"]
                        ],
                    }
                    for caller, record in self._callers.items()
                }),
                "objects": copy.deepcopy({
                    handle_id: {
                        "handle_id": obj["handle_id"],
                        "mount_id": obj["mount_id"],
                        "path": obj["path"],
                        "inode": obj["inode"],
                        "generation": obj["generation"],
                        "kind": obj["kind"],
                        "deleted": obj["deleted"],
                    }
                    for handle_id, obj in self._objects.items()
                }),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            parsed = self._parse_snapshot(state)
            self._mounts = parsed["mounts"]
            self._callers = parsed["callers"]
            self._objects = parsed["objects"]
            self._stats = parsed["stats"]
            self._cache.clear()

    def _parse_snapshot(self, state: dict) -> dict:
        invalid = "FILEHANDLE_SNAPSHOT_INVALID"
        if not isinstance(state, dict):
            self._raise(invalid, "snapshot must be a mapping")
        for key in ("mounts", "callers", "objects", "stats"):
            if key not in state or not isinstance(state[key], dict):
                self._raise(invalid, "missing or invalid %s" % key)

        mounts: dict[str, dict] = {}
        try:
            for mount_id, raw in state["mounts"].items():
                if not isinstance(mount_id, str) or not isinstance(raw, dict):
                    self._raise(invalid, "invalid mount entry")
                namespace = raw.get("namespace")
                root = raw.get("root")
                if not isinstance(namespace, str) or not isinstance(root, str):
                    self._raise(invalid, "invalid mount fields")
                normalized_root = self._normalize_path(root)
                if "mount_id" in raw and raw["mount_id"] != mount_id:
                    self._raise(invalid, "mount id mismatch")
                mounts[mount_id] = {
                    "namespace": namespace,
                    "root": normalized_root,
                }
        except FhError as exc:
            if exc.code == invalid:
                raise
            self._raise(invalid, exc.detail)

        callers: dict[str, dict] = {}
        try:
            for caller, raw in state["callers"].items():
                if not isinstance(caller, str):
                    self._raise(invalid, "invalid caller id")
                if isinstance(raw, str):
                    namespace = raw
                    raw_grants = []
                elif isinstance(raw, dict):
                    namespace = raw.get("namespace")
                    if namespace is not None and not isinstance(namespace, str):
                        self._raise(invalid, "invalid caller namespace")
                    raw_grants = raw.get("grants", raw.get("capabilities", []))
                    if not isinstance(raw_grants, list):
                        self._raise(invalid, "invalid caller grants")
                else:
                    self._raise(invalid, "invalid caller entry")

                grants = []
                for raw_grant in raw_grants:
                    if not isinstance(raw_grant, dict):
                        self._raise(invalid, "invalid grant entry")
                    grant_mount = raw_grant.get("mount_id")
                    if grant_mount is not None and not isinstance(grant_mount, str):
                        self._raise(invalid, "invalid grant mount")
                    prefix = self._normalize_path(
                        raw_grant.get("path_prefix", "/"))
                    grants.append({
                        "mount_id": grant_mount,
                        "path_prefix": prefix,
                    })
                callers[caller] = {
                    "namespace": namespace,
                    "grants": grants,
                }
        except FhError as exc:
            if exc.code == invalid:
                raise
            self._raise(invalid, exc.detail)

        objects: dict[str, dict] = {}
        live_paths: set[tuple[str, str]] = set()
        try:
            for handle_id, raw in state["objects"].items():
                if not isinstance(handle_id, str) or not isinstance(raw, dict):
                    self._raise(invalid, "invalid object entry")
                if "handle_id" in raw and raw["handle_id"] != handle_id:
                    self._raise(invalid, "handle id mismatch")
                if "mount_id" not in raw or "path" not in raw or "inode" not in raw:
                    self._raise(invalid, "missing object fields")

                mount_id = raw["mount_id"]
                path = raw["path"]
                inode = raw["inode"]
                generation = raw.get("generation", 1)
                kind = raw.get("kind", "file")
                deleted = raw.get("deleted", False)

                if not isinstance(mount_id, str):
                    self._raise(invalid, "invalid object mount")
                normalized_path = self._normalize_path(path)
                if (not isinstance(inode, int) or isinstance(inode, bool)
                        or not isinstance(generation, int)
                        or isinstance(generation, bool)
                        or not isinstance(kind, str)
                        or not isinstance(deleted, bool)):
                    self._raise(invalid, "invalid object fields")

                mount = mounts.get(mount_id)
                if mount is not None and not self._path_under_root(
                        normalized_path, mount["root"]):
                    self._raise(invalid, "object outside mount root")
                if not deleted:
                    path_key = (mount_id, normalized_path)
                    if path_key in live_paths:
                        self._raise(invalid, "duplicate object path")
                    live_paths.add(path_key)

                objects[handle_id] = {
                    "handle_id": handle_id,
                    "mount_id": mount_id,
                    "path": normalized_path,
                    "inode": inode,
                    "generation": generation,
                    "kind": kind,
                    "deleted": deleted,
                }
        except FhError as exc:
            if exc.code == invalid:
                raise
            self._raise(invalid, exc.detail)

        stats = {}
        for key in _STAT_KEYS:
            value = state["stats"].get(key)
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                self._raise(invalid, "invalid stats")
            stats[key] = value

        return {
            "mounts": mounts,
            "callers": callers,
            "objects": objects,
            "stats": stats,
        }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
