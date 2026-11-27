"""Merge a unit file and its drop-ins into one effective sandbox configuration."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass

UNIT_ORIGIN = "unit"
SNAPSHOT_VERSION = 1

DROPIN_NAME_RE = re.compile(r"\d{2}-[a-z0-9][a-z0-9_-]*\.conf")

SCALAR_DIRECTIVES = (
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "NoNewPrivileges",
    "PrivateDevices",
    "ProtectKernelTunables",
    "ProtectControlGroups",
)
LIST_DIRECTIVES = (
    "ReadWritePaths",
    "ReadOnlyPaths",
    "InaccessiblePaths",
    "SupplementaryGroups",
)
INTERSECT_DIRECTIVES = ("RestrictAddressFamilies",)
BOOLEAN_DIRECTIVES = ("ProtectHome", "PrivateTmp", "NoNewPrivileges", "PrivateDevices")
KNOWN_DIRECTIVES = SCALAR_DIRECTIVES + LIST_DIRECTIVES + INTERSECT_DIRECTIVES
PATH_DIRECTIVES = (
    "ReadWritePaths",
    "ReadOnlyPaths",
    "InaccessiblePaths",
)

STRICT_PROTECTED_PREFIXES = ("/usr", "/boot", "/etc")
YES_PROTECTED_PREFIXES = ("/usr", "/boot")
SYSTEM_WRITABLE_ROOTS = ("/var", "/run", "/tmp", "/data")

BOOLEAN_VALUES = frozenset(
    ("yes", "true", "1", "on", "no", "false", "0", "off")
)

_global_merge_lock = threading.RLock()


class SandboxUnitError(ValueError):
    """Raised when a unit or drop-in cannot be merged safely."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Directive:
    name: str
    value: str
    origin: str
    conflict: bool


@dataclass(frozen=True)
class MergeResult:
    directives: tuple[Directive, ...]
    warnings: tuple[str, ...]
    conflicts: tuple[str, ...]


class UnitSandboxMerger:
    """Apply main unit plus filename-ordered drop-ins to one effective sandbox view."""

    def __init__(self, *, max_dropins: int = 8,
                 max_directives: int = 256) -> None:
        self.max_dropins = max_dropins
        self.max_directives = max_directives
        self._lock = threading.RLock()
        self._unit: dict | None = None
        self._dropins: dict[str, dict] = {}
        self._counters = {"parses": 0, "merges": 0, "directives": 0}

    def _parse_lines(self, text: str) -> list[tuple[str, str]]:
        """Parse one file into directive pairs without mutating the caller's text."""
        if not isinstance(text, str):
            raise SandboxUnitError("SANDBOX_INVALID_VALUE", repr(text))
        lines: list[tuple[str, str]] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            if "=" not in line:
                raise SandboxUnitError("SANDBOX_INVALID_VALUE", line)
            name, value = line.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                raise SandboxUnitError("SANDBOX_INVALID_VALUE", line)
            if name in BOOLEAN_DIRECTIVES and value not in BOOLEAN_VALUES:
                raise SandboxUnitError(
                    "SANDBOX_INVALID_VALUE", f"{name}={value}")
            lines.append((name, value))
        if len(lines) > self.max_directives:
            raise SandboxUnitError(
                "SANDBOX_LIMIT_EXCEEDED",
                {"limit": self.max_directives, "count": len(lines)})
        return lines

    @staticmethod
    def _valid_dropin_name(filename: object) -> bool:
        return (
            isinstance(filename, str)
            and DROPIN_NAME_RE.fullmatch(filename) is not None
        )

    def _ordered_sources(self) -> list[tuple[str, list[tuple[str, str]]]]:
        sources: list[tuple[str, list[tuple[str, str]]]] = []
        if self._unit is not None:
            sources.append((self._unit["name"], self._unit["lines"]))
        for filename in sorted(self._dropins):
            sources.append((filename, self._dropins[filename]["lines"]))
        return sources

    def _compute(self) -> dict:
        """Build the effective view from scratch; no state is cached between calls."""
        scalar_values: dict[str, str] = {}
        list_values: dict[str, list[str]] = {}
        intersect_values: dict[str, list[str]] = {}
        last_origin: dict[str, str] = {}
        origin_table: dict[str, list[str]] = {}
        unknown_order: list[str] = []
        unknown_seen: set[str] = set()

        for origin, lines in self._ordered_sources():
            for name, value in lines:
                if name not in origin_table:
                    origin_table[name] = []
                if origin not in origin_table[name]:
                    origin_table[name].append(origin)
                last_origin[name] = origin
                if name not in KNOWN_DIRECTIVES and name not in unknown_seen:
                    unknown_seen.add(name)
                    unknown_order.append(name)

                if name in LIST_DIRECTIVES:
                    tokens = value.split()
                    bucket = list_values.setdefault(name, [])
                    if not tokens:
                        bucket.clear()
                    else:
                        for token in tokens:
                            if token not in bucket:
                                bucket.append(token)
                elif name in INTERSECT_DIRECTIVES:
                    tokens = value.split()
                    if name not in intersect_values:
                        ordered: list[str] = []
                        for token in tokens:
                            if token not in ordered:
                                ordered.append(token)
                        intersect_values[name] = ordered
                    else:
                        allowed = set(tokens)
                        intersect_values[name] = [
                            token
                            for token in intersect_values[name]
                            if token in allowed
                        ]
                else:
                    scalar_values[name] = value

        if len(origin_table) > self.max_directives:
            raise SandboxUnitError(
                "SANDBOX_LIMIT_EXCEEDED",
                {"limit": self.max_directives, "count": len(origin_table)})

        values: dict[str, str] = {}
        for name in scalar_values:
            values[name] = scalar_values[name]
        for name, tokens in list_values.items():
            values[name] = " ".join(tokens)
        for name, tokens in intersect_values.items():
            values[name] = " ".join(tokens)

        warnings = tuple(
            f"unknown directive: {name}" for name in unknown_order
        )
        conflicts = tuple(
            sorted(
                name
                for name, origins in origin_table.items()
                if len(origins) > 1
            )
        )
        return {
            "values": values,
            "last_origin": last_origin,
            "origins": origin_table,
            "warnings": warnings,
            "conflicts": conflicts,
            "unknown": unknown_seen,
        }

    def load_unit(self, text: str, *, name: str = "unit") -> int:
        with self._lock:
            lines = self._parse_lines(text)
            self._unit = {"name": name, "lines": lines}
            self._counters["parses"] += 1
            return len(lines)

    def add_dropin(self, filename: str, text: str) -> int:
        if not self._valid_dropin_name(filename):
            raise SandboxUnitError("SANDBOX_DROPIN_INVALID", filename)
        with self._lock:
            lines = self._parse_lines(text)
            is_replacement = filename in self._dropins
            if not is_replacement and len(self._dropins) >= self.max_dropins:
                raise SandboxUnitError(
                    "SANDBOX_LIMIT_EXCEEDED",
                    {"limit": self.max_dropins, "count": len(self._dropins) + 1})
            self._dropins[filename] = {"filename": filename, "lines": lines}
            self._counters["parses"] += 1
            return len(lines)

    def clear_dropins(self) -> int:
        with self._lock:
            removed = len(self._dropins)
            self._dropins.clear()
            return removed

    def merge(self) -> MergeResult:
        with _global_merge_lock:
            with self._lock:
                state = self._compute()
                conflicts = set(state["conflicts"])
                directives = tuple(
                    Directive(
                        name=name,
                        value=state["values"][name],
                        origin=state["last_origin"][name],
                        conflict=name in conflicts,
                    )
                    for name in sorted(state["values"])
                )
                result = MergeResult(
                    directives=directives,
                    warnings=state["warnings"],
                    conflicts=state["conflicts"],
                )
                self._counters["merges"] += 1
                self._counters["directives"] = len(directives)
                return result

    def effective(self, name: str) -> str | None:
        with self._lock:
            return self._compute()["values"].get(name)

    def origins(self, name: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._compute()["origins"].get(name, ()))

    def conflicts(self) -> tuple[str, ...]:
        with self._lock:
            return self._compute()["conflicts"]

    def resolve_paths(self, name: str) -> tuple[tuple[str, bool], ...]:
        if name not in KNOWN_DIRECTIVES:
            raise SandboxUnitError("SANDBOX_UNKNOWN_DIRECTIVE", name)
        if name not in PATH_DIRECTIVES:
            raise SandboxUnitError("SANDBOX_NOT_PATH_DIRECTIVE", name)
        with self._lock:
            raw_value = self._compute()["values"].get(name, "")
        entries: dict[str, bool] = {}
        for token in raw_value.split():
            allow_missing = False
            if token.startswith("-"):
                allow_missing = True
                token = token[1:]
            path = token.rstrip("/")
            if not path:
                continue
            entries[path] = entries.get(path, False) or allow_missing
        return tuple(sorted(entries.items()))

    @staticmethod
    def _is_within(path: str, roots: tuple[str, ...]) -> bool:
        return any(
            path == root or path.startswith(root + "/") for root in roots
        )

    def _protected_roots(self, mode: str | None) -> tuple[str, ...] | None:
        if mode in ("strict", "full"):
            return STRICT_PROTECTED_PREFIXES + SYSTEM_WRITABLE_ROOTS
        if mode == "yes":
            return YES_PROTECTED_PREFIXES + SYSTEM_WRITABLE_ROOTS
        return None

    def validate(self) -> tuple[str, ...]:
        with self._lock:
            state = self._compute()
            mode = state["values"].get("ProtectSystem")
            allowed_roots = self._protected_roots(mode)
            if allowed_roots is not None:
                for path, _allow_missing in self.resolve_paths("ReadWritePaths"):
                    if not self._is_within(path, allowed_roots):
                        raise SandboxUnitError("SANDBOX_PATH_ESCAPE", path)
            return state["warnings"]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "unit": copy.deepcopy(self._unit),
                "dropins": copy.deepcopy(list(self._dropins.values())),
                "counters": copy.deepcopy(self._counters),
            }

    @staticmethod
    def _validate_lines(lines: object) -> list[tuple[str, str]]:
        if not isinstance(lines, list):
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "lines")
        checked: list[tuple[str, str]] = []
        for pair in lines:
            if (
                not isinstance(pair, (list, tuple))
                or len(pair) != 2
                or not all(isinstance(part, str) for part in pair)
            ):
                raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "line")
            checked.append((pair[0], pair[1]))
        return checked

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict) or state.get("version") != SNAPSHOT_VERSION:
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "version")

        unit = state.get("unit")
        if not isinstance(unit, dict) or not isinstance(unit.get("name"), str):
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "unit")
        unit_lines = self._validate_lines(unit.get("lines"))
        if len(unit_lines) > self.max_directives:
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "unit limit")

        raw_dropins = state.get("dropins")
        if not isinstance(raw_dropins, list):
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "dropins")
        dropins: dict[str, dict] = {}
        for entry in raw_dropins:
            if not isinstance(entry, dict):
                raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "dropin")
            filename = entry.get("filename")
            if not self._valid_dropin_name(filename) or filename in dropins:
                raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "dropin name")
            lines = self._validate_lines(entry.get("lines"))
            if len(lines) > self.max_directives:
                raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "dropin limit")
            dropins[filename] = {"filename": filename, "lines": lines}
        if len(dropins) > self.max_dropins:
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "dropin limit")

        counters = state.get("counters")
        if not isinstance(counters, dict):
            raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", "counters")
        restored_counters: dict[str, int] = {}
        for key in ("parses", "merges", "directives"):
            value = counters.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SandboxUnitError("SANDBOX_SNAPSHOT_INVALID", key)
            restored_counters[key] = value

        with self._lock:
            self._unit = {"name": unit["name"], "lines": unit_lines}
            self._dropins = dropins
            self._counters = restored_counters

    def stats(self) -> dict:
        with self._lock:
            return {
                "parses": self._counters["parses"],
                "dropins": len(self._dropins),
                "merges": self._counters["merges"],
                "directives": self._counters["directives"],
            }
