"""Archive xattr sync: capability retention, strip-before-write, atomic replace."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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

    def set_source_trust(self, source: str, level: str) -> None:
        raise NotImplementedError

    def set_path_policy(self, prefix: str, *, allow, conflict: str = "policy") -> None:
        raise NotImplementedError

    def plan_xattr(self, path: str, attrs, *, source: str) -> AttrPlan:
        raise NotImplementedError

    def apply(self, path: str, attrs, *, source: str) -> tuple[tuple[str, str], ...]:
        raise NotImplementedError

    def strip(self, path: str, names) -> int:
        raise NotImplementedError

    def inspect(self, path: str) -> tuple[tuple[str, str], ...] | None:
        raise NotImplementedError

    def touch(self, path: str) -> bool:
        raise NotImplementedError

    def add_hardlink(self, path: str, existing_path: str) -> None:
        raise NotImplementedError

    def link_targets(self, path: str) -> tuple[str, ...]:
        raise NotImplementedError

    def remove_path(self, path: str) -> bool:
        raise NotImplementedError

    def begin_write(self, path: str, attrs, *, source: str) -> str:
        raise NotImplementedError

    def commit_temp(self, temp_id: str) -> bool:
        raise NotImplementedError

    def pending_temp_files(self) -> tuple[str, ...]:
        raise NotImplementedError

    def cleanup_temp(self) -> int:
        raise NotImplementedError

    def operations(self) -> tuple[tuple, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
