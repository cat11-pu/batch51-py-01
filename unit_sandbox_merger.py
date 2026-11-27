"""Merge a unit file and its drop-ins into one effective sandbox configuration."""

from __future__ import annotations

import threading
from dataclasses import dataclass

UNIT_ORIGIN = "unit"

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

    def load_unit(self, text: str, *, name: str = "unit") -> int:
        raise NotImplementedError

    def add_dropin(self, filename: str, text: str) -> int:
        raise NotImplementedError

    def clear_dropins(self) -> int:
        raise NotImplementedError

    def merge(self) -> MergeResult:
        raise NotImplementedError

    def effective(self, name: str) -> str | None:
        raise NotImplementedError

    def origins(self, name: str) -> tuple[str, ...]:
        raise NotImplementedError

    def conflicts(self) -> tuple[str, ...]:
        raise NotImplementedError

    def resolve_paths(self, name: str) -> tuple[tuple[str, bool], ...]:
        raise NotImplementedError

    def validate(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
