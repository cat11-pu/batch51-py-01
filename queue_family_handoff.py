"""Queue family ownership tracking with release/acquire barrier bookkeeping."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

FAMILIES = ("graphics", "compute", "transfer")
KIND_FAMILIES = {"buffer": FAMILIES, "image": ("graphics", "compute")}
SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = frozenset(
    ("version", "resources", "pending", "barriers", "last_submit", "stats"))
STATS_KEYS = ("resources", "handoffs", "barriers", "submitted", "rejected")
PHASE_ORDER = {"release": 0, "acquire": 1}


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
        self._resources: dict[str, ResourceRecord] = {}
        self._pending: dict[str, PendingHandoff] = {}
        self._barriers: list[Barrier] = []
        self._last_submit = 0
        self._stats = {key: 0 for key in STATS_KEYS}

    def _reject(self, code: str, detail: object = None) -> HandoffError:
        """Build a handoff error and account for the rejected operation."""
        self._stats["rejected"] += 1
        return HandoffError(code, detail)

    @staticmethod
    def _family_allowed(kind: str, family: str) -> bool:
        return family in KIND_FAMILIES[kind]

    def _require(self, handle: str) -> ResourceRecord:
        try:
            return self._resources[handle]
        except KeyError:
            raise KeyError(handle) from None

    def register_resource(self, handle: str, *, kind: str = "buffer",
                          size: int = 4096, owner: str = "graphics",
                          sequence: int = 0) -> ResourceRecord:
        with self._lock:
            if not isinstance(handle, str) or not handle:
                raise self._reject("HANDOFF_INVALID_RESOURCE", handle)
            if kind not in KIND_FAMILIES:
                raise self._reject("HANDOFF_INVALID_RESOURCE", kind)
            if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                raise self._reject("HANDOFF_INVALID_RESOURCE", size)
            if not self._family_allowed(kind, owner):
                raise self._reject("HANDOFF_INVALID_FAMILY", owner)
            if handle in self._resources:
                raise self._reject("HANDOFF_DUPLICATE_RESOURCE", handle)
            if len(self._resources) >= self.max_resources:
                raise self._reject("HANDOFF_CAPACITY_EXCEEDED", self.max_resources)

            record = ResourceRecord(
                handle=handle, kind=kind, size=size, owner=owner,
                version=1, sequence=sequence)
            self._resources[handle] = record
            self._stats["resources"] = len(self._resources)
            return record

    def release_to(self, handle: str, family: str, *, sequence: int):
        with self._lock:
            record = self._require(handle)
            if not self._family_allowed(record.kind, family):
                raise self._reject("HANDOFF_INVALID_FAMILY", family)
            if sequence < record.sequence:
                raise self._reject(
                    "HANDOFF_SEQUENCE_REGRESS",
                    {"sequence": sequence, "last": record.sequence})
            if handle in self._pending:
                raise self._reject("HANDOFF_ALREADY_PENDING", handle)

            pending = PendingHandoff(
                handle=handle, source=record.owner, target=family,
                release_sequence=sequence)
            self._pending[handle] = pending
            if family != record.owner:
                self._barriers.append(Barrier(
                    handle=handle, phase="release", source=record.owner,
                    target=family, sequence=sequence))
                self._stats["barriers"] += 1
            return pending

    def acquire_from(self, handle: str, family: str, *,
                     sequence: int) -> ResourceRecord:
        with self._lock:
            record = self._require(handle)
            if not self._family_allowed(record.kind, family):
                raise self._reject("HANDOFF_INVALID_FAMILY", family)
            pending = self._pending.get(handle)
            if pending is None:
                raise self._reject("HANDOFF_NOT_PENDING", handle)
            if pending.target != family:
                raise self._reject(
                    "HANDOFF_FAMILY_MISMATCH",
                    {"expected": pending.target, "given": family})
            if sequence <= pending.release_sequence:
                raise self._reject(
                    "HANDOFF_SEQUENCE_REGRESS",
                    {"sequence": sequence,
                     "release": pending.release_sequence})

            del self._pending[handle]
            if pending.source != pending.target:
                record = ResourceRecord(
                    handle=record.handle, kind=record.kind, size=record.size,
                    owner=family, version=record.version + 1,
                    sequence=sequence)
                self._barriers.append(Barrier(
                    handle=handle, phase="acquire", source=pending.source,
                    target=family, sequence=sequence))
                self._stats["barriers"] += 1
                self._stats["handoffs"] += 1
            else:
                record = ResourceRecord(
                    handle=record.handle, kind=record.kind, size=record.size,
                    owner=family, version=record.version, sequence=sequence)
            self._resources[handle] = record
            return record

    def handoff_barriers(self) -> tuple:
        with self._lock:
            ordered = sorted(
                self._barriers,
                key=lambda barrier: (
                    barrier.sequence, barrier.handle,
                    PHASE_ORDER[barrier.phase]))
            return tuple(ordered)

    def submit(self, sequence: int) -> int:
        with self._lock:
            if sequence <= self._last_submit:
                raise self._reject(
                    "HANDOFF_SEQUENCE_REGRESS",
                    {"sequence": sequence, "last_submit": self._last_submit})

            keep = set()
            for handle, pending in self._pending.items():
                keep.add((handle, pending.release_sequence, "release"))

            committed = [
                barrier for barrier in self._barriers
                if (barrier.handle, barrier.sequence, barrier.phase) not in keep]
            self._barriers = [
                barrier for barrier in self._barriers
                if (barrier.handle, barrier.sequence, barrier.phase) in keep]
            self._last_submit = sequence
            self._stats["submitted"] += len(committed)
            return len(committed)

    def pending_owner(self, handle: str):
        with self._lock:
            if handle not in self._resources:
                raise KeyError(handle)
            return self._pending.get(handle)

    def write_begin(self, handle: str, family: str, *,
                    sequence: int) -> ResourceRecord:
        with self._lock:
            record = self._require(handle)
            if family not in FAMILIES:
                raise self._reject("HANDOFF_INVALID_FAMILY", family)
            if handle in self._pending or record.owner != family:
                raise self._reject("HANDOFF_NOT_ACQUIRED", handle)
            record = ResourceRecord(
                handle=record.handle, kind=record.kind, size=record.size,
                owner=record.owner, version=record.version, sequence=sequence)
            self._resources[handle] = record
            return record

    def owner_of(self, handle: str) -> str:
        with self._lock:
            return self._require(handle).owner

    def version_of(self, handle: str) -> int:
        with self._lock:
            return self._require(handle).version

    def record_copy(self, handle: str, *, sequence: int) -> ResourceRecord:
        with self._lock:
            record = self._require(handle)
            if handle in self._pending or record.owner != "transfer":
                raise self._reject("HANDOFF_NOT_ACQUIRED", handle)
            record = ResourceRecord(
                handle=record.handle, kind=record.kind, size=record.size,
                owner=record.owner, version=record.version, sequence=sequence)
            self._resources[handle] = record
            return record

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "resources": copy.deepcopy(self._resources),
                "pending": copy.deepcopy(self._pending),
                "barriers": copy.deepcopy(self._barriers),
                "last_submit": self._last_submit,
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                if not isinstance(state, dict) or frozenset(state) != SNAPSHOT_KEYS:
                    raise ValueError
                if state["version"] != SNAPSHOT_VERSION:
                    raise ValueError

                resources = state["resources"]
                pending = state["pending"]
                barriers = state["barriers"]
                stats = state["stats"]
                last_submit = state["last_submit"]

                if not isinstance(resources, dict) or not isinstance(pending, dict):
                    raise ValueError
                if not isinstance(barriers, (list, tuple)):
                    raise ValueError
                if not isinstance(stats, dict) or frozenset(stats) != frozenset(STATS_KEYS):
                    raise ValueError
                if not isinstance(last_submit, int) or isinstance(last_submit, bool):
                    raise ValueError

                checked_resources = {}
                for handle, record in resources.items():
                    if not isinstance(handle, str) or not handle:
                        raise ValueError
                    if not isinstance(record, ResourceRecord) or record.handle != handle:
                        raise ValueError
                    if record.kind not in KIND_FAMILIES:
                        raise ValueError
                    if not self._family_allowed(record.kind, record.owner):
                        raise ValueError
                    checked_resources[handle] = record
                if len(checked_resources) > self.max_resources:
                    raise ValueError

                checked_pending = {}
                for handle, pending_record in pending.items():
                    if handle not in checked_resources:
                        raise ValueError
                    if not isinstance(pending_record, PendingHandoff):
                        raise ValueError
                    if pending_record.handle != handle:
                        raise ValueError
                    if not self._family_allowed(
                            checked_resources[handle].kind, pending_record.target):
                        raise ValueError
                    checked_pending[handle] = pending_record

                checked_barriers = []
                for barrier in barriers:
                    if not isinstance(barrier, Barrier):
                        raise ValueError
                    if barrier.handle not in checked_resources:
                        raise ValueError
                    if barrier.phase not in PHASE_ORDER:
                        raise ValueError
                    checked_barriers.append(barrier)

                checked_stats = {}
                for key in STATS_KEYS:
                    value = stats[key]
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise ValueError
                    checked_stats[key] = value
            except (KeyError, TypeError, ValueError):
                raise self._reject("HANDOFF_SNAPSHOT_INVALID", state) from None

            self._resources = copy.deepcopy(checked_resources)
            self._pending = copy.deepcopy(checked_pending)
            self._barriers = copy.deepcopy(checked_barriers)
            self._last_submit = last_submit
            self._stats = copy.deepcopy(checked_stats)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
