"""Archive xattr sync: capability retention, strip-before-write, atomic replace."""

from __future__ import annotations

import copy
import fnmatch
import threading
from dataclasses import dataclass


_TRUST_LEVELS = frozenset({"trusted", "untrusted"})
_CONFLICTS = frozenset({"policy", "source"})
_STAT_KEYS = frozenset(
    {"applied", "written", "stripped", "replaced", "plans", "refused"}
)
_SNAPSHOT_KEYS = frozenset(
    {
        "version",
        "objects",
        "paths",
        "next_object",
        "trust",
        "policies",
        "operations",
        "temps",
        "next_temp",
        "stats",
    }
)
_SNAPSHOT_VERSION = 1


class XattrError(ValueError):
    """Raised when an xattr plan or apply request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AttrPlan:
    path: str
    keep: tuple[tuple[str, str], ...]
    strip: tuple[str, ...]


class XattrCapabilitySync:
    """Decide which archive attributes survive and apply them atomically."""

    def __init__(self, *, max_attrs: int = 32,
                 temp_prefix: str = ".xattr-tmp-") -> None:
        self.max_attrs = int(max_attrs)
        self.temp_prefix = temp_prefix
        self._lock = threading.RLock()
        self._objects: dict[int, dict[str, str]] = {}
        self._paths: dict[str, int] = {}
        self._next_object = 1
        self._trust: dict[str, str] = {}
        self._policies: dict[str, dict] = {
            "/": {"allow": ("*",), "conflict": "policy"},
        }
        self._operations: list[tuple] = []
        self._temps: dict[str, dict] = {}
        self._next_temp = 1
        self._stats = {
            "applied": 0,
            "written": 0,
            "stripped": 0,
            "replaced": 0,
            "plans": 0,
            "refused": 0,
        }

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _refuse(self, code: str, detail: object = None) -> None:
        self._stats["refused"] += 1
        raise XattrError(code, detail)

    def _invalid(self, detail: object = None) -> None:
        self._refuse("XATTR_INVALID_REQUEST", detail)

    def _check_path(self, path: object, field: str = "path") -> str:
        if not isinstance(path, str) or not path.startswith("/"):
            self._invalid({field: path})
        return path

    def _check_source(self, source: object) -> str:
        if (not isinstance(source, str) or source == ""
                or source.strip() == ""):
            self._invalid({"source": source})
        return source

    def _normalize_attrs(self, attrs: object) -> dict[str, str]:
        if attrs is None:
            self._invalid({"attrs": attrs})
        if isinstance(attrs, dict):
            items = list(attrs.items())
        else:
            try:
                items = list(attrs)
            except TypeError:
                self._invalid({"attrs": attrs})
        normalized: dict[str, str] = {}
        for item in items:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                self._invalid({"attrs": attrs})
            name, value = item
            if not isinstance(name, str) or not isinstance(value, str):
                self._invalid({"attr": name if isinstance(name, str) else item})
            normalized[name] = value
        return normalized

    def _check_attr_count(self, attrs: dict[str, str]) -> None:
        if len(attrs) > self.max_attrs:
            self._refuse(
                "XATTR_ATTR_LIMIT",
                {"max_attrs": self.max_attrs, "count": len(attrs)},
            )

    def _normalize_allow(self, allow: object) -> tuple[str, ...]:
        if isinstance(allow, str):
            patterns = (allow,)
        else:
            try:
                patterns = tuple(allow)
            except TypeError:
                self._invalid({"allow": allow})
        for pattern in patterns:
            if not isinstance(pattern, str):
                self._invalid({"allow": allow})
        return patterns

    def _policy_for(self, path: str) -> dict:
        matched = None
        for prefix, policy in self._policies.items():
            if path.startswith(prefix):
                if matched is None or len(prefix) > len(matched[0]):
                    matched = (prefix, policy)
        if matched is None:
            return {"allow": ("*",), "conflict": "policy"}
        return matched[1]

    @staticmethod
    def _allowed(name: str, policy: dict) -> bool:
        return any(fnmatch.fnmatchcase(name, pattern)
                   for pattern in policy["allow"])

    def _decide(self, attrs: dict[str, str], source: str,
                policy: dict) -> tuple[tuple[tuple[str, str], ...],
                                       tuple[str, ...]]:
        level = self._trust.get(source, "untrusted")
        keep: list[tuple[str, str]] = []
        strip: list[str] = []
        for name, value in sorted(attrs.items()):
            allowed = self._allowed(name, policy)
            if level == "trusted":
                retained = allowed
            else:
                retained = allowed and name.startswith("user.")
            if retained:
                keep.append((name, value))
            else:
                strip.append(name)
        return tuple(keep), tuple(strip)

    def _replace_object(self, object_id: int, attrs: dict[str, str]) -> None:
        """Install a fully-prepared attribute mapping as one atomic commit."""
        self._objects[object_id] = attrs

    # ------------------------------------------------------------------
    # Trust and policy configuration
    # ------------------------------------------------------------------
    def set_source_trust(self, source: str, level: str) -> None:
        with self._lock:
            self._check_source(source)
            if not isinstance(level, str) or level not in _TRUST_LEVELS:
                self._invalid({"level": level})
            self._trust[source] = level

    def set_path_policy(self, prefix: str, *, allow,
                        conflict: str = "policy") -> None:
        with self._lock:
            if not isinstance(prefix, str) or not prefix.startswith("/"):
                self._invalid({"prefix": prefix})
            if not isinstance(conflict, str) or conflict not in _CONFLICTS:
                self._invalid({"conflict": conflict})
            patterns = self._normalize_allow(allow)
            self._policies[prefix] = {
                "allow": patterns,
                "conflict": conflict,
            }

    # ------------------------------------------------------------------
    # Planning and applying
    # ------------------------------------------------------------------
    def plan_xattr(self, path: str, attrs, *, source: str) -> AttrPlan:
        with self._lock:
            self._check_path(path)
            self._check_source(source)
            normalized = self._normalize_attrs(attrs)
            self._check_attr_count(normalized)
            policy = self._policy_for(path)
            keep, strip = self._decide(normalized, source, policy)
            self._stats["plans"] += 1
            return AttrPlan(path=path, keep=keep, strip=strip)

    def apply(self, path: str, attrs, *,
              source: str) -> tuple[tuple[str, str], ...]:
        with self._lock:
            self._check_path(path)
            self._check_source(source)
            normalized = self._normalize_attrs(attrs)
            self._check_attr_count(normalized)

            object_id = self._paths.get(path)
            current = (self._objects[object_id]
                       if object_id is not None else {})
            policy = self._policy_for(path)
            keep, strip_names = self._decide(normalized, source, policy)

            new_attrs = dict(current)
            operations: list[tuple] = []
            stripped = 0
            written = 0

            # Strips are committed before any write becomes visible.
            for name in strip_names:
                if name in new_attrs:
                    del new_attrs[name]
                    operations.append(("strip", path, name))
                    stripped += 1

            for name, value in keep:
                if name not in new_attrs:
                    new_attrs[name] = value
                    operations.append(("write", path, name, value))
                    written += 1
                elif (new_attrs[name] != value
                      and policy["conflict"] == "source"):
                    new_attrs[name] = value
                    operations.append(("write", path, name, value))
                    written += 1

            # The per-object cap is checked before anything is committed.
            if len(new_attrs) > self.max_attrs:
                self._refuse(
                    "XATTR_ATTR_LIMIT",
                    {"max_attrs": self.max_attrs,
                     "count": len(new_attrs)},
                )

            if object_id is None:
                object_id = self._next_object
                self._replace_object(object_id, new_attrs)
                self._next_object = object_id + 1
                self._paths[path] = object_id
            else:
                self._replace_object(object_id, new_attrs)

            operations.append(("replace", path))
            self._operations.extend(operations)
            self._stats["applied"] += 1
            self._stats["written"] += written
            self._stats["stripped"] += stripped
            self._stats["replaced"] += 1

            return tuple((name, new_attrs[name]) for name, _ in keep)

    def strip(self, path: str, names) -> int:
        with self._lock:
            self._check_path(path)
            if isinstance(names, str):
                raw_names = [names]
            else:
                try:
                    raw_names = list(names)
                except TypeError:
                    self._invalid({"names": names})

            requested: list[str] = []
            seen: set[str] = set()
            for name in raw_names:
                if not isinstance(name, str):
                    self._invalid({"name": name})
                if name not in seen:
                    seen.add(name)
                    requested.append(name)

            object_id = self._paths.get(path)
            if object_id is None:
                return 0

            current = self._objects[object_id]
            new_attrs = dict(current)
            operations: list[tuple] = []
            for name in requested:
                if name in new_attrs:
                    del new_attrs[name]
                    operations.append(("strip", path, name))

            if operations:
                self._replace_object(object_id, new_attrs)
                self._operations.extend(operations)
                self._stats["stripped"] += len(operations)
            return len(operations)

    # ------------------------------------------------------------------
    # Path/object bookkeeping
    # ------------------------------------------------------------------
    def inspect(self, path: str) -> tuple[tuple[str, str], ...] | None:
        with self._lock:
            self._check_path(path)
            object_id = self._paths.get(path)
            if object_id is None:
                return None
            return tuple(sorted(self._objects[object_id].items()))

    def touch(self, path: str) -> bool:
        with self._lock:
            self._check_path(path)
            if path in self._paths:
                return False
            object_id = self._next_object
            self._replace_object(object_id, {})
            self._next_object = object_id + 1
            self._paths[path] = object_id
            return True

    def add_hardlink(self, path: str, existing_path: str) -> None:
        with self._lock:
            self._check_path(path)
            self._check_path(existing_path, field="existing_path")
            object_id = self._paths.get(existing_path)
            if object_id is None:
                self._invalid({"existing_path": existing_path})
            if path in self._paths:
                if self._paths[path] != object_id:
                    self._invalid({"path": path, "reason": "exists"})
                return None
            self._paths[path] = object_id
            return None

    def link_targets(self, path: str) -> tuple[str, ...]:
        with self._lock:
            self._check_path(path)
            object_id = self._paths.get(path)
            if object_id is None:
                return ()
            return tuple(sorted(
                target for target, target_object in self._paths.items()
                if target_object == object_id
            ))

    def remove_path(self, path: str) -> bool:
        with self._lock:
            self._check_path(path)
            object_id = self._paths.pop(path, None)
            if object_id is None:
                return False
            if object_id not in self._paths.values():
                self._objects.pop(object_id, None)
            return True

    # ------------------------------------------------------------------
    # Staged writes and crash recovery
    # ------------------------------------------------------------------
    def begin_write(self, path: str, attrs, *, source: str) -> str:
        with self._lock:
            self._check_path(path)
            self._check_source(source)
            normalized = self._normalize_attrs(attrs)
            self._check_attr_count(normalized)

            number = self._next_temp
            temp_id = f"{self.temp_prefix}{number}"
            while temp_id in self._temps:
                number += 1
                temp_id = f"{self.temp_prefix}{number}"
            self._next_temp = number + 1
            self._temps[temp_id] = {
                "path": path,
                "attrs": dict(normalized),
                "source": source,
            }
            return temp_id

    def commit_temp(self, temp_id: str) -> bool:
        with self._lock:
            if not isinstance(temp_id, str):
                return False
            temp = self._temps.get(temp_id)
            if temp is None:
                return False
            self.apply(temp["path"], temp["attrs"], source=temp["source"])
            del self._temps[temp_id]
            return True

    def pending_temp_files(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._temps))

    def cleanup_temp(self) -> int:
        with self._lock:
            count = len(self._temps)
            self._temps.clear()
            return count

    # ------------------------------------------------------------------
    # Audit state
    # ------------------------------------------------------------------
    def operations(self) -> tuple[tuple, ...]:
        with self._lock:
            return tuple(self._operations)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "objects": copy.deepcopy(self._objects),
                "paths": copy.deepcopy(self._paths),
                "next_object": self._next_object,
                "trust": copy.deepcopy(self._trust),
                "policies": copy.deepcopy(self._policies),
                "operations": copy.deepcopy(self._operations),
                "temps": copy.deepcopy(self._temps),
                "next_temp": self._next_temp,
                "stats": copy.deepcopy(self._stats),
            }

    def _snapshot_invalid(self, detail: object = None) -> None:
        raise XattrError("XATTR_SNAPSHOT_INVALID", detail)

    def restore(self, state: dict) -> None:
        with self._lock:
            validated = self._validate_snapshot(state)
            self._objects = validated["objects"]
            self._paths = validated["paths"]
            self._next_object = validated["next_object"]
            self._trust = validated["trust"]
            self._policies = validated["policies"]
            self._operations = validated["operations"]
            self._temps = validated["temps"]
            self._next_temp = validated["next_temp"]
            self._stats = validated["stats"]

    def _validate_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            self._snapshot_invalid({"state": state})
        if set(state) != _SNAPSHOT_KEYS:
            self._snapshot_invalid({"keys": list(state)})
        if (not self._is_int(state.get("version"))
                or state["version"] != _SNAPSHOT_VERSION):
            self._snapshot_invalid({"version": state.get("version")})

        raw_objects = state.get("objects")
        if not isinstance(raw_objects, dict):
            self._snapshot_invalid({"objects": raw_objects})
        objects: dict[int, dict[str, str]] = {}
        for object_id, raw_attrs in raw_objects.items():
            if not self._is_int(object_id) or object_id < 1:
                self._snapshot_invalid({"object_id": object_id})
            if not isinstance(raw_attrs, dict):
                self._snapshot_invalid({"attrs": raw_attrs})
            if len(raw_attrs) > self.max_attrs:
                self._snapshot_invalid(
                    {"object_id": object_id, "count": len(raw_attrs)}
                )
            attrs: dict[str, str] = {}
            for name, value in raw_attrs.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    self._snapshot_invalid(
                        {"object_id": object_id, "attr": name}
                    )
                attrs[name] = value
            objects[object_id] = attrs

        raw_paths = state.get("paths")
        if not isinstance(raw_paths, dict):
            self._snapshot_invalid({"paths": raw_paths})
        paths: dict[str, int] = {}
        for path, object_id in raw_paths.items():
            if not isinstance(path, str) or not path.startswith("/"):
                self._snapshot_invalid({"path": path})
            if not self._is_int(object_id) or object_id not in objects:
                self._snapshot_invalid(
                    {"path": path, "object_id": object_id}
                )
            paths[path] = object_id

        next_object = state.get("next_object")
        if not self._is_int(next_object) or next_object < 1:
            self._snapshot_invalid({"next_object": next_object})
        if objects and next_object <= max(objects):
            self._snapshot_invalid({"next_object": next_object})

        raw_trust = state.get("trust")
        if not isinstance(raw_trust, dict):
            self._snapshot_invalid({"trust": raw_trust})
        trust: dict[str, str] = {}
        for source, level in raw_trust.items():
            if not isinstance(source, str) or not source:
                self._snapshot_invalid({"source": source})
            if not isinstance(level, str) or level not in _TRUST_LEVELS:
                self._snapshot_invalid(
                    {"source": source, "level": level}
                )
            trust[source] = level

        raw_policies = state.get("policies")
        if not isinstance(raw_policies, dict):
            self._snapshot_invalid({"policies": raw_policies})
        policies: dict[str, dict] = {}
        for prefix, raw_policy in raw_policies.items():
            if not isinstance(prefix, str) or not prefix.startswith("/"):
                self._snapshot_invalid({"prefix": prefix})
            if not isinstance(raw_policy, dict):
                self._snapshot_invalid({"policy": raw_policy})
            if set(raw_policy) != {"allow", "conflict"}:
                self._snapshot_invalid(
                    {"prefix": prefix, "policy": raw_policy}
                )
            raw_allow = raw_policy["allow"]
            if isinstance(raw_allow, str):
                allow = (raw_allow,)
            elif isinstance(raw_allow, (list, tuple, set, frozenset)):
                allow = tuple(raw_allow)
            else:
                self._snapshot_invalid(
                    {"prefix": prefix, "allow": raw_allow}
                )
            if any(not isinstance(pattern, str) for pattern in allow):
                self._snapshot_invalid(
                    {"prefix": prefix, "allow": raw_allow}
                )
            conflict = raw_policy["conflict"]
            if not isinstance(conflict, str) or conflict not in _CONFLICTS:
                self._snapshot_invalid(
                    {"prefix": prefix, "conflict": conflict}
                )
            policies[prefix] = {
                "allow": allow,
                "conflict": conflict,
            }

        raw_operations = state.get("operations")
        if not isinstance(raw_operations, (list, tuple)):
            self._snapshot_invalid({"operations": raw_operations})
        operations: list[tuple] = []
        for operation in raw_operations:
            if not isinstance(operation, (list, tuple)) or not operation:
                self._snapshot_invalid({"operation": operation})
            action = operation[0]
            if action == "strip":
                if len(operation) != 3:
                    self._snapshot_invalid({"operation": operation})
                _, path, name = operation
                if (not isinstance(path, str)
                        or not path.startswith("/")
                        or not isinstance(name, str)):
                    self._snapshot_invalid({"operation": operation})
                operations.append(("strip", path, name))
            elif action == "write":
                if len(operation) != 4:
                    self._snapshot_invalid({"operation": operation})
                _, path, name, value = operation
                if (not isinstance(path, str)
                        or not path.startswith("/")
                        or not isinstance(name, str)
                        or not isinstance(value, str)):
                    self._snapshot_invalid({"operation": operation})
                operations.append(("write", path, name, value))
            elif action == "replace":
                if len(operation) != 2:
                    self._snapshot_invalid({"operation": operation})
                _, path = operation
                if not isinstance(path, str) or not path.startswith("/"):
                    self._snapshot_invalid({"operation": operation})
                operations.append(("replace", path))
            else:
                self._snapshot_invalid({"operation": operation})

        raw_temps = state.get("temps")
        if not isinstance(raw_temps, dict):
            self._snapshot_invalid({"temps": raw_temps})
        temps: dict[str, dict] = {}
        for temp_id, raw_temp in raw_temps.items():
            if not isinstance(temp_id, str) or not temp_id:
                self._snapshot_invalid({"temp_id": temp_id})
            if not isinstance(raw_temp, dict):
                self._snapshot_invalid({"temp": raw_temp})
            if set(raw_temp) != {"path", "attrs", "source"}:
                self._snapshot_invalid(
                    {"temp_id": temp_id, "temp": raw_temp}
                )
            path = raw_temp["path"]
            if not isinstance(path, str) or not path.startswith("/"):
                self._snapshot_invalid(
                    {"temp_id": temp_id, "path": path}
                )
            raw_attrs = raw_temp["attrs"]
            if not isinstance(raw_attrs, dict):
                self._snapshot_invalid(
                    {"temp_id": temp_id, "attrs": raw_attrs}
                )
            if len(raw_attrs) > self.max_attrs:
                self._snapshot_invalid(
                    {"temp_id": temp_id, "count": len(raw_attrs)}
                )
            attrs = {}
            for name, value in raw_attrs.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    self._snapshot_invalid(
                        {"temp_id": temp_id, "attr": name}
                    )
                attrs[name] = value
            source = raw_temp["source"]
            if not isinstance(source, str) or not source:
                self._snapshot_invalid(
                    {"temp_id": temp_id, "source": source}
                )
            temps[temp_id] = {
                "path": path,
                "attrs": attrs,
                "source": source,
            }

        next_temp = state.get("next_temp")
        if not self._is_int(next_temp) or next_temp < 1:
            self._snapshot_invalid({"next_temp": next_temp})
        for temp_id in temps:
            if temp_id.startswith(self.temp_prefix):
                suffix = temp_id[len(self.temp_prefix):]
                if suffix.isdigit() and next_temp <= int(suffix):
                    self._snapshot_invalid({"next_temp": next_temp})

        raw_stats = state.get("stats")
        if not isinstance(raw_stats, dict) or set(raw_stats) != _STAT_KEYS:
            self._snapshot_invalid({"stats": raw_stats})
        stats: dict[str, int] = {}
        for name in _STAT_KEYS:
            value = raw_stats[name]
            if not self._is_int(value) or value < 0:
                self._snapshot_invalid({"stat": name, "value": value})
            stats[name] = value

        return {
            "objects": objects,
            "paths": paths,
            "next_object": next_object,
            "trust": trust,
            "policies": policies,
            "operations": operations,
            "temps": temps,
            "next_temp": next_temp,
            "stats": stats,
        }
