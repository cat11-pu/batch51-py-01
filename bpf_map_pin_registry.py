"""BPF map pin registry: tenant ownership, reference counting, orphan reclaim."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class BpfError(ValueError):
    """Raised when the registry refuses a pin operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PinRecord:
    path: str
    tenant: str
    map_id: str
    owner_pid: int
    owner_start: int
    refcount: int
    generation: int


class BpfMapPinRegistry:
    """Registry of pinned map paths with tenant ownership and open handles."""

    def __init__(self, *, max_pins: int = 32) -> None:
        self.max_pins = int(max_pins)
        self._lock = threading.RLock()
        self._pins: dict[str, PinRecord] = {}
        self._handles: dict[str, dict] = {}
        self._grants: dict[str, set[str]] = {}
        self._quarantine: set[str] = set()
        self._next_handle = 1
        self._stats = {
            "pinned": 0,
            "opened": 0,
            "closed": 0,
            "unpinned": 0,
            "reclaimed": 0,
            "quarantined": 0,
            "refused": 0,
        }

    def pin(self, path: str, *, tenant: str, map_id: str, owner_pid: int,
            owner_start: int) -> PinRecord:
        raise NotImplementedError

    def lookup(self, path: str) -> PinRecord | None:
        raise NotImplementedError

    def list_pins(self, tenant: str) -> tuple[PinRecord, ...]:
        raise NotImplementedError

    def open_pinned(self, path: str, *, tenant: str, pid: int,
                    start: int) -> str:
        raise NotImplementedError

    def close_handle(self, handle_id: str) -> bool:
        raise NotImplementedError

    def refcount(self, path: str) -> int:
        raise NotImplementedError

    def openers(self, path: str) -> tuple[tuple[int, int, str], ...]:
        raise NotImplementedError

    def grant_cross_tenant(self, path: str, tenant: str) -> None:
        raise NotImplementedError

    def unpin(self, path: str, *, tenant: str) -> bool:
        raise NotImplementedError

    def reclaim_orphans(self, alive) -> tuple[str, ...]:
        raise NotImplementedError

    def scan(self, present_paths) -> dict:
        raise NotImplementedError

    def quarantined(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
