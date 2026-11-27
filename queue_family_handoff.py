"""Queue family ownership tracking with release/acquire barrier bookkeeping."""

from __future__ import annotations

import threading
from dataclasses import dataclass

FAMILIES = ("graphics", "compute", "transfer")
KIND_FAMILIES = {"buffer": FAMILIES, "image": ("graphics", "compute")}


class HandoffError(ValueError):
    """Raised when a queue family handoff is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ResourceRecord:
    """One tracked resource and its current owning queue family."""

    handle: str
    kind: str
    size: int
    owner: str
    version: int
    sequence: int


@dataclass(frozen=True)
class PendingHandoff:
    """A release that has not been answered by an acquire yet."""

    handle: str
    source: str
    target: str
    release_sequence: int


@dataclass(frozen=True)
class Barrier:
    """One release or acquire barrier waiting for submission."""

    handle: str
    phase: str
    source: str
    target: str
    sequence: int


class QueueFamilyHandoff:
    """Track queue ownership, pending handoffs and barrier batches."""

    def __init__(self, *, max_resources: int = 256) -> None:
        self.max_resources = max_resources
        self._lock = threading.RLock()
        self._resources: dict = {}
        self._pending: dict = {}
        self._barriers: list = []
        self._last_submit = 0
        self._stats = {"resources": 0, "handoffs": 0, "barriers": 0,
                       "submitted": 0, "rejected": 0}

    def register_resource(self, handle: str, *, kind: str = "buffer",
                          size: int = 4096, owner: str = "graphics",
                          sequence: int = 0) -> ResourceRecord:
        raise NotImplementedError

    def release_to(self, handle: str, family: str, *, sequence: int):
        raise NotImplementedError

    def acquire_from(self, handle: str, family: str, *,
                     sequence: int) -> ResourceRecord:
        raise NotImplementedError

    def handoff_barriers(self) -> tuple:
        raise NotImplementedError

    def submit(self, sequence: int) -> int:
        raise NotImplementedError

    def pending_owner(self, handle: str):
        raise NotImplementedError

    def write_begin(self, handle: str, family: str, *,
                    sequence: int) -> ResourceRecord:
        raise NotImplementedError

    def owner_of(self, handle: str) -> str:
        raise NotImplementedError

    def version_of(self, handle: str) -> int:
        raise NotImplementedError

    def record_copy(self, handle: str, *, sequence: int) -> ResourceRecord:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
