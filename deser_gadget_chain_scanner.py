"""Serialization stream walker with type allowlist and gadget chain depth checks."""

from __future__ import annotations

import copy
import json
import struct
import threading
from dataclasses import dataclass


DANGEROUS_TYPES = frozenset({
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "java.lang.reflect.Method",
    "javax.naming.InitialContext",
    "java.util.PriorityQueue",
})

FORMAT_MAGIC = {
    b"JSE1": "java-serial-v1",
    b"PKL2": "pickle-proto2",
    b"MPK1": "msgpack-map",
}

ORIGINS = ("local", "vendor")
PURPOSES = ("data", "exec")


class DeserError(ValueError):
    """Raised when a stream or a type registration is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class WalkResult:
    format: str
    root: str
    visited: tuple
    depth: int
    truncated: bool
    denied: tuple
    dangling: tuple = ()


def _grade(origin: str, purpose: str) -> str:
    if origin == "local" and purpose == "data":
        return "trusted"
    return "reviewed"


def _is_dangerous(type_name: str) -> bool:
    return (
        type_name in DANGEROUS_TYPES
        or type_name.startswith("java.lang.reflect.")
    )


class DeserGadgetChainScanner:
    """Sniff the stream header, walk the object graph and grade each type."""

    def __init__(self, *, max_depth: int = 8, allowlist: dict | None = None) -> None:
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._allowlist: dict[str, dict] = {}
        for name, entry in (allowlist or {}).items():
            if (
                not isinstance(name, str)
                or not isinstance(entry, dict)
                or entry.get("origin") not in ORIGINS
                or entry.get("purpose") not in PURPOSES
                or (entry.get("origin") == "vendor" and entry.get("purpose") == "exec")
            ):
                raise DeserError("DESER_INVALID_ARGUMENT", name)
            self._allowlist[name] = {"origin": entry["origin"], "purpose": entry["purpose"]}
        self._stats = {"walks": 0, "objects": 0, "denied": 0, "restores": 0}
        self._last: WalkResult | None = None

    # ------------------------------------------------------------------
    # Allowlist management
    # ------------------------------------------------------------------

    def register_type(self, type_name: str, *, origin: str, purpose: str) -> str:
        with self._lock:
            if origin not in ORIGINS:
                raise DeserError("DESER_INVALID_ARGUMENT", origin)
            if purpose not in PURPOSES:
                raise DeserError("DESER_INVALID_ARGUMENT", purpose)
            if origin == "vendor" and purpose == "exec":
                raise DeserError("DESER_TYPE_DENIED", type_name)
            self._allowlist[type_name] = {"origin": origin, "purpose": purpose}
            return _grade(origin, purpose)

    def revoke_type(self, type_name: str) -> bool:
        with self._lock:
            return self._allowlist.pop(type_name, None) is not None

    def check_allowlist(self, type_name: str) -> str:
        with self._lock:
            entry = self._allowlist.get(type_name)
            if entry is None:
                raise DeserError("DESER_TYPE_DENIED", type_name)
            return _grade(entry["origin"], entry["purpose"])

    # ------------------------------------------------------------------
    # Stream parsing
    # ------------------------------------------------------------------

    def sniff_format(self, stream: bytes) -> str:
        with self._lock:
            if not isinstance(stream, bytes) or len(stream) < 4:
                raise DeserError("DESER_UNKNOWN_FORMAT", None)
            fmt = FORMAT_MAGIC.get(stream[:4])
            if fmt is None:
                raise DeserError("DESER_UNKNOWN_FORMAT", stream[:4])
            return fmt

    def _parse_stream(self, stream: bytes) -> dict:
        """Parse header + body. Truncation never raises; bad magic does."""
        if not isinstance(stream, bytes) or len(stream) < 4:
            raise DeserError("DESER_UNKNOWN_FORMAT", None)
        magic = stream[:4]
        fmt = FORMAT_MAGIC.get(magic)
        if fmt is None:
            raise DeserError("DESER_UNKNOWN_FORMAT", magic)

        if len(stream) < 8:
            truncated = True
            declared = 0
            body = b""
        else:
            truncated = False
            declared = struct.unpack(">I", stream[4:8])[0]
            body = stream[8:]
        if len(body) != declared:
            truncated = True
        available = body[:declared]

        root = None
        records: dict[str, dict] = {}
        fragments = available.split(b"\n")
        if fragments and fragments[-1] == b"":
            fragments.pop()

        for index, fragment in enumerate(fragments):
            try:
                payload = json.loads(fragment.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                truncated = True
                break
            if not isinstance(payload, dict):
                truncated = True
                break
            if index == 0 and "root" in payload:
                root = payload["root"]
                continue
            if not (
                isinstance(payload.get("id"), str)
                and isinstance(payload.get("type"), str)
                and isinstance(payload.get("fields"), dict)
            ):
                truncated = True
                break
            object_id = payload["id"]
            if object_id not in records:
                records[object_id] = {
                    "type": payload["type"],
                    "fields": payload["fields"],
                }

        if not isinstance(root, str):
            truncated = True

        return {
            "format": fmt,
            "root": root,
            "records": records,
            "truncated": truncated,
        }

    def _walk(self, parsed: dict) -> dict:
        records = parsed["records"]
        root = parsed["root"]
        visited: list[str] = []
        dangling: list[str] = []
        denied: list[str] = []
        seen: set[str] = set()
        deepest = 0

        def visit(object_id: str, level: int) -> None:
            nonlocal deepest
            seen.add(object_id)
            visited.append(object_id)
            deepest = max(deepest, level)
            type_name = records[object_id]["type"]
            if type_name not in self._allowlist and type_name not in denied:
                denied.append(type_name)
            if level >= self.max_depth:
                return
            children: list[str] = []
            for _field, value in sorted(records[object_id]["fields"].items()):
                if not isinstance(value, str):
                    continue
                if value in records:
                    if value not in seen:
                        children.append(value)
                else:
                    dangling.append(value)
            for child in reversed(children):
                stack.append((child, level + 1))

        stack: list[tuple[str, int]] = []
        if isinstance(root, str) and root in records and self.max_depth >= 1:
            visit(root, 1)
        while stack:
            object_id, level = stack.pop()
            if object_id in seen:
                continue
            visit(object_id, level)

        return {
            "visited": tuple(visited),
            "depth": deepest,
            "dangling": tuple(dangling),
            "denied": tuple(denied),
        }

    def _analyze(self, stream: bytes) -> dict:
        parsed = self._parse_stream(stream)
        walked = self._walk(parsed)
        parsed.update(walked)
        return parsed

    def _reachable_count(self, records: dict, start_id: str) -> int:
        seen: set[str] = set()
        stack = [(start_id, 1)]
        while stack:
            object_id, level = stack.pop()
            if object_id in seen or level > self.max_depth:
                continue
            if object_id not in records:
                continue
            seen.add(object_id)
            for value in records[object_id]["fields"].values():
                if (
                    isinstance(value, str)
                    and value in records
                    and value not in seen
                ):
                    stack.append((value, level + 1))
        return len(seen)

    # ------------------------------------------------------------------
    # Public scanning API
    # ------------------------------------------------------------------

    def walk_objects(self, stream: bytes) -> WalkResult:
        with self._lock:
            analyzed = self._analyze(stream)
            result = WalkResult(
                format=analyzed["format"],
                root=analyzed["root"],
                visited=analyzed["visited"],
                depth=analyzed["depth"],
                truncated=analyzed["truncated"],
                denied=analyzed["denied"],
                dangling=analyzed["dangling"],
            )
            self._stats["walks"] += 1
            self._stats["objects"] += len(analyzed["records"])
            self._stats["denied"] += len(analyzed["denied"])
            self._last = result
            return result

    def chain_depth(self, stream: bytes, start_id: str | None = None) -> int:
        with self._lock:
            analyzed = self._analyze(stream)
            records = analyzed["records"]
            if start_id is not None:
                if start_id not in records:
                    raise DeserError("DESER_UNKNOWN_OBJECT", start_id)
                return self._reachable_count(records, start_id)
            starts = [
                object_id
                for object_id in analyzed["visited"]
                if _is_dangerous(records[object_id]["type"])
            ]
            if not starts:
                return 0
            return max(self._reachable_count(records, object_id) for object_id in starts)

    def dangerous_starts(self, stream: bytes) -> tuple:
        with self._lock:
            analyzed = self._analyze(stream)
            records = analyzed["records"]
            return tuple(
                object_id
                for object_id in analyzed["visited"]
                if _is_dangerous(records[object_id]["type"])
            )

    def report(self, stream: bytes) -> dict:
        with self._lock:
            analyzed = self._analyze(stream)
            records = analyzed["records"]
            starts = [
                object_id
                for object_id in analyzed["visited"]
                if _is_dangerous(records[object_id]["type"])
            ]
            chain = (
                max(self._reachable_count(records, object_id) for object_id in starts)
                if starts
                else 0
            )
            return {
                "format": analyzed["format"],
                "objects": len(records),
                "depth": analyzed["depth"],
                "chain_depth": chain,
                "starts": starts,
                "denied_types": sorted(set(analyzed["denied"])),
                "dangling": list(analyzed["dangling"]),
                "truncated": analyzed["truncated"],
                "allowed": len(analyzed["denied"]) == 0,
            }

    def describe_object(self, stream: bytes, object_id: str) -> dict:
        with self._lock:
            analyzed = self._analyze(stream)
            record = analyzed["records"].get(object_id)
            if record is None:
                raise DeserError("DESER_UNKNOWN_OBJECT", object_id)
            entry = self._allowlist.get(record["type"])
            grade = _grade(entry["origin"], entry["purpose"]) if entry else None
            return {
                "type": record["type"],
                "field_count": len(record["fields"]),
                "grade": grade,
                "chain_start": _is_dangerous(record["type"]),
            }

    # ------------------------------------------------------------------
    # Snapshot / lifecycle
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "allowlist": copy.deepcopy(self._allowlist),
                "max_depth": self.max_depth,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            allowlist, max_depth, stats = self._validate_snapshot(state)
            self._allowlist = allowlist
            self.max_depth = max_depth
            self._stats = stats
            self._stats["restores"] += 1
            self._last = None

    def _validate_snapshot(self, state: dict):
        if not isinstance(state, dict):
            raise DeserError("DESER_SNAPSHOT_INVALID", None)
        if not set(("allowlist", "max_depth", "stats")).issubset(state.keys()):
            raise DeserError("DESER_SNAPSHOT_INVALID", "missing keys")
        raw_allowlist = state["allowlist"]
        raw_stats = state["stats"]
        if not isinstance(raw_allowlist, dict) or not isinstance(raw_stats, dict):
            raise DeserError("DESER_SNAPSHOT_INVALID", "bad container")
        if not isinstance(state["max_depth"], int) or isinstance(state["max_depth"], bool):
            raise DeserError("DESER_SNAPSHOT_INVALID", "bad max_depth")

        allowlist: dict[str, dict] = {}
        for name, entry in raw_allowlist.items():
            if (
                not isinstance(name, str)
                or not isinstance(entry, dict)
                or entry.get("origin") not in ORIGINS
                or entry.get("purpose") not in PURPOSES
                or (entry.get("origin") == "vendor" and entry.get("purpose") == "exec")
            ):
                raise DeserError("DESER_SNAPSHOT_INVALID", name)
            allowlist[name] = {
                "origin": entry["origin"],
                "purpose": entry["purpose"],
            }

        if not set(("walks", "objects", "denied", "restores")).issubset(raw_stats.keys()):
            raise DeserError("DESER_SNAPSHOT_INVALID", "bad stats keys")
        stats = {}
        for key in ("walks", "objects", "denied", "restores"):
            value = raw_stats[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise DeserError("DESER_SNAPSHOT_INVALID", key)
            stats[key] = value

        return copy.deepcopy(allowlist), state["max_depth"], stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset(self) -> None:
        with self._lock:
            self._stats = {"walks": 0, "objects": 0, "denied": 0, "restores": 0}
            self._last = None
