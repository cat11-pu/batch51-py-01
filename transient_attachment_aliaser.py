"""Planner that aliases transient render attachments over a frame-local heap."""

from __future__ import annotations

import copy
import math
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


_VERSION = 1
_MODES = frozenset(("read", "write", "read_write"))
_KINDS = frozenset(("color", "depth"))
_STATE_KEYS = frozenset(
    ("version", "passes", "attachments", "uses", "plan", "stats")
)
_STAT_KEYS = ("passes", "attachments", "uses", "plans", "rejected")
_STAT_KEY_SET = frozenset(_STAT_KEYS)


@dataclass(frozen=True)
class PassRecord:
    """One declared render pass."""

    index: int
    name: str


@dataclass(frozen=True)
class AttachmentRecord:
    """One declared transient attachment."""

    name: str
    width: int
    height: int
    bytes_per_pixel: int
    kind: str
    external: bool
    backbuffer: bool


@dataclass(frozen=True)
class _Allocation:
    name: str
    offset: int
    size: int
    kind: str
    start: int | None
    end: int | None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object, label: str) -> int:
    if not _is_int(value) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not _is_int(value) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _valid_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _lifetime(uses: Iterable[tuple[int, str]]) -> tuple[int, int] | None:
    """Return the inclusive lifetime, extending a read/write tail by a pass."""

    uses = tuple(uses)
    if not uses:
        return None

    first = min(pass_index for pass_index, _ in uses)
    last = max(pass_index for pass_index, _ in uses)
    last_modes = {mode for pass_index, mode in uses if pass_index == last}
    if "read_write" in last_modes or {"read", "write"} <= last_modes:
        last += 1
    return first, last


class TransientAttachmentAliaser:
    """Assign heap offsets so disjoint attachment lifetimes share memory."""

    def __init__(self, *, heap_bytes: int = 1 << 20, alignment: int = 256,
                 max_passes: int = 64, max_attachments: int = 32) -> None:
        self.heap_bytes = _positive_int(heap_bytes, "heap_bytes")
        self.alignment = _positive_int(alignment, "alignment")
        self.max_passes = _positive_int(max_passes, "max_passes")
        self.max_attachments = _positive_int(
            max_attachments, "max_attachments"
        )

        self._lock = threading.RLock()
        self._passes: dict[int, PassRecord] = {}
        self._pass_names: set[str] = set()
        self._attachments: dict[str, AttachmentRecord] = {}
        self._uses: dict[str, list[tuple[int, str]]] = {}
        self._plan: dict[str, int] | None = None
        self._heap_usage = 0
        self._barriers: tuple[tuple[int, int, str, str], ...] = ()
        self._stats = {
            "passes": 0,
            "attachments": 0,
            "uses": 0,
            "plans": 0,
            "rejected": 0,
        }

    def _invalidate_plan(self) -> None:
        self._plan = None
        self._heap_usage = 0
        self._barriers = ()

    def declare_pass(self, index: int, name: str) -> PassRecord:
        with self._lock:
            try:
                index = _nonnegative_int(index, "pass index")
                name = _valid_name(name, "pass name")
                if index in self._passes:
                    raise ValueError(f"pass index {index!r} already declared")
                if name in self._pass_names:
                    raise ValueError(f"pass name {name!r} already declared")
                if len(self._passes) >= self.max_passes:
                    raise ValueError("maximum number of passes exceeded")
            except (TypeError, ValueError):
                self._stats["rejected"] += 1
                raise

            record = PassRecord(index, name)
            self._passes[index] = record
            self._pass_names.add(name)
            self._stats["passes"] = len(self._passes)
            self._invalidate_plan()
            return record

    def declare_attachment(self, name: str, *, width: int, height: int,
                           bytes_per_pixel: int = 4, kind: str = "color",
                           external: bool = False,
                           backbuffer: bool = False) -> AttachmentRecord:
        with self._lock:
            try:
                name = _valid_name(name, "attachment name")
                width = _positive_int(width, "width")
                height = _positive_int(height, "height")
                bytes_per_pixel = _positive_int(
                    bytes_per_pixel, "bytes_per_pixel"
                )
                if not isinstance(kind, str) or kind not in _KINDS:
                    raise ValueError("kind must be 'color' or 'depth'")
                if not isinstance(external, bool):
                    raise ValueError("external must be a boolean")
                if not isinstance(backbuffer, bool):
                    raise ValueError("backbuffer must be a boolean")
                if name in self._attachments:
                    raise ValueError(
                        f"attachment {name!r} already declared"
                    )
                if len(self._attachments) >= self.max_attachments:
                    raise ValueError("maximum number of attachments exceeded")
            except (TypeError, ValueError):
                self._stats["rejected"] += 1
                raise

            record = AttachmentRecord(
                name, width, height, bytes_per_pixel, kind,
                external, backbuffer,
            )
            self._attachments[name] = record
            self._uses[name] = []
            self._stats["attachments"] = len(self._attachments)
            self._invalidate_plan()
            return record

    def declare_use(self, name: str, pass_index: int,
                    mode: str = "write") -> None:
        with self._lock:
            try:
                if not isinstance(name, str) or name not in self._attachments:
                    raise KeyError(name)
                if not _is_int(pass_index) or pass_index < 0:
                    raise ValueError("pass index must be a non-negative integer")
                if pass_index not in self._passes:
                    raise KeyError(pass_index)
                if not isinstance(mode, str) or mode not in _MODES:
                    raise ValueError(
                        "mode must be 'read', 'write', or 'read_write'"
                    )
            except (KeyError, TypeError, ValueError):
                self._stats["rejected"] += 1
                raise

            self._uses[name].append((pass_index, mode))
            self._stats["uses"] += 1
            self._invalidate_plan()

    def _attachment_size(self, record: AttachmentRecord) -> int:
        row_stride = _align_up(record.width * record.bytes_per_pixel, 4)
        return _align_up(row_stride * record.height, self.alignment)

    @staticmethod
    def _temporally_disjoint(
        first: tuple[int, int], second: tuple[int, int]
    ) -> bool:
        return first[1] < second[0] or second[1] < first[0]

    def _same_memory_is_compatible(
        self,
        candidate: _Allocation,
        existing: _Allocation,
    ) -> bool:
        if candidate.start is None or existing.start is None:
            return True
        if not self._temporally_disjoint(
            (candidate.start, candidate.end),
            (existing.start, existing.end),
        ):
            return False
        if candidate.kind == existing.kind:
            return True

        if existing.end < candidate.start:
            earlier, later = existing, candidate
        else:
            earlier, later = candidate, existing
        return later.start - earlier.end - 1 >= 1

    @staticmethod
    def _memory_overlaps(first: _Allocation, second: _Allocation) -> bool:
        return (
            first.offset < second.offset + second.size
            and second.offset < first.offset + first.size
        )

    def _lowest_offset(
        self, candidate: _Allocation, placed: list[_Allocation]
    ) -> int:
        offsets = {0}
        offsets.update(item.offset + item.size for item in placed)
        for offset in sorted(offsets):
            candidate = _Allocation(
                candidate.name, offset, candidate.size, candidate.kind,
                candidate.start, candidate.end,
            )
            if all(
                not self._memory_overlaps(candidate, item)
                or self._same_memory_is_compatible(candidate, item)
                for item in placed
            ):
                return offset
        raise ValueError("unable to place attachment")

    def _linked_barriers(
        self,
        plan: Mapping[str, int],
        lifetimes: Mapping[str, tuple[int, int] | None],
    ) -> tuple[tuple[int, int, str, str], ...]:
        by_offset: dict[int, list[_Allocation]] = {}
        for name, record in self._attachments.items():
            if record.external or record.backbuffer:
                continue
            lifetime = lifetimes.get(name)
            if lifetime is None:
                continue
            allocation = _Allocation(
                name,
                plan[name],
                self._attachment_size(record),
                record.kind,
                lifetime[0],
                lifetime[1],
            )
            by_offset.setdefault(allocation.offset, []).append(allocation)

        barriers: list[tuple[int, int, str, str]] = []
        for offset, allocations in by_offset.items():
            ordered = sorted(
                allocations,
                key=lambda item: (item.start, item.end, item.name),
            )
            previous: _Allocation | None = None
            for allocation in ordered:
                if previous is not None and previous.kind != allocation.kind:
                    barriers.append(
                        (allocation.start, offset, allocation.name, "full")
                    )
                previous = allocation
        return tuple(sorted(barriers))

    def _compute_layout(
        self,
    ) -> tuple[dict[str, int], int, tuple[tuple[int, int, str, str], ...]]:
        lifetimes = {
            name: _lifetime(uses) for name, uses in self._uses.items()
        }
        aliases = []
        dedicated = []
        for name, record in self._attachments.items():
            size = self._attachment_size(record)
            if record.external or record.backbuffer:
                dedicated.append((name, record, size))
            else:
                lifetime = lifetimes[name]
                first = math.inf if lifetime is None else lifetime[0]
                aliases.append((first, name, record, size, lifetime))

        plan: dict[str, int] = {}
        placed: list[_Allocation] = []
        for _, name, record, size, lifetime in sorted(
            aliases, key=lambda item: item[0]
        ):
            if size > self.heap_bytes:
                raise ValueError("attachment does not fit in the heap")
            candidate = _Allocation(
                name,
                0,
                size,
                record.kind,
                None if lifetime is None else lifetime[0],
                None if lifetime is None else lifetime[1],
            )
            offset = self._lowest_offset(candidate, placed)
            allocation = _Allocation(
                name, offset, size, record.kind,
                candidate.start, candidate.end,
            )
            placed.append(allocation)
            plan[name] = offset

        alias_end = max(
            (item.offset + item.size for item in placed), default=0
        )
        if alias_end > self.heap_bytes:
            raise ValueError("heap capacity exceeded")

        cursor = alias_end
        for name, record, size in sorted(dedicated, key=lambda item: item[0]):
            if cursor + size > self.heap_bytes:
                raise ValueError("heap capacity exceeded")
            plan[name] = cursor
            cursor += size

        barriers = self._linked_barriers(plan, lifetimes)
        return plan, cursor, barriers

    def plan(self) -> dict:
        with self._lock:
            try:
                plan, usage, barriers = self._compute_layout()
            except ValueError:
                self._invalidate_plan()
                self._stats["rejected"] += 1
                raise

            self._plan = plan
            self._heap_usage = usage
            self._barriers = barriers
            self._stats["plans"] += 1
            return dict(plan)

    def offset_of(self, name: str) -> int:
        with self._lock:
            if not isinstance(name, str) or name not in self._attachments:
                raise KeyError(name)
            if self._plan is None:
                raise KeyError(name)
            return self._plan[name]

    def heap_usage(self) -> int:
        with self._lock:
            return self._heap_usage

    def attachment_state(self, name: str) -> AttachmentRecord:
        with self._lock:
            if not isinstance(name, str) or name not in self._attachments:
                raise KeyError(name)
            return self._attachments[name]

    def uses_of(self, name: str) -> tuple:
        with self._lock:
            if not isinstance(name, str) or name not in self._uses:
                raise KeyError(name)
            return tuple(
                sorted(self._uses[name], key=lambda item: item[0])
            )

    def barriers(self) -> tuple:
        with self._lock:
            return tuple(self._barriers)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _VERSION,
                "passes": copy.deepcopy(self._passes),
                "attachments": copy.deepcopy(self._attachments),
                "uses": copy.deepcopy(self._uses),
                "plan": copy.deepcopy(self._plan),
                "stats": copy.deepcopy(self._stats),
            }

    @staticmethod
    def _snapshot_mapping(value: object, label: str) -> Mapping:
        if not isinstance(value, Mapping):
            raise ValueError(f"snapshot {label} must be a mapping")
        return value

    def _parse_passes(self, raw: object) -> dict[int, PassRecord]:
        if isinstance(raw, Mapping):
            entries = list(raw.items())
        elif isinstance(raw, (list, tuple)):
            entries = []
            for item in raw:
                if isinstance(item, PassRecord):
                    entries.append((item.index, item))
                elif isinstance(item, Mapping):
                    if "index" not in item or "name" not in item:
                        raise ValueError("invalid pass record")
                    entries.append((item["index"], item))
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    entries.append((item[0], item))
                else:
                    raise ValueError("invalid pass record")
        else:
            raise ValueError("snapshot passes must be a mapping or sequence")

        passes: dict[int, PassRecord] = {}
        names: set[str] = set()
        for key, value in entries:
            if isinstance(value, PassRecord):
                index, name = value.index, value.name
            elif isinstance(value, Mapping):
                if "index" not in value or "name" not in value:
                    raise ValueError("invalid pass record")
                index, name = value["index"], value["name"]
            elif isinstance(value, (list, tuple)) and len(value) == 2:
                index, name = value
            elif isinstance(value, str):
                index, name = key, value
            else:
                raise ValueError("invalid pass record")

            index = _nonnegative_int(index, "pass index")
            name = _valid_name(name, "pass name")
            if index != key or index in passes or name in names:
                raise ValueError("duplicate or inconsistent pass record")
            if len(passes) >= self.max_passes:
                raise ValueError("maximum number of passes exceeded")
            passes[index] = PassRecord(index, name)
            names.add(name)
        return passes

    def _parse_attachments(
        self, raw: object
    ) -> dict[str, AttachmentRecord]:
        if isinstance(raw, Mapping):
            entries = list(raw.items())
        elif isinstance(raw, (list, tuple)):
            entries = []
            for item in raw:
                if isinstance(item, AttachmentRecord):
                    entries.append((item.name, item))
                elif isinstance(item, Mapping):
                    if "name" not in item:
                        raise ValueError("invalid attachment record")
                    entries.append((item["name"], item))
                else:
                    raise ValueError("invalid attachment record")
        else:
            raise ValueError(
                "snapshot attachments must be a mapping or sequence"
            )

        attachments: dict[str, AttachmentRecord] = {}
        for key, value in entries:
            if isinstance(value, AttachmentRecord):
                record = value
            elif isinstance(value, Mapping):
                required = {
                    "name", "width", "height", "bytes_per_pixel",
                    "kind", "external", "backbuffer",
                }
                if not required <= set(value):
                    raise ValueError("invalid attachment record")
                record = AttachmentRecord(
                    value["name"],
                    value["width"],
                    value["height"],
                    value["bytes_per_pixel"],
                    value["kind"],
                    value["external"],
                    value["backbuffer"],
                )
            else:
                raise ValueError("invalid attachment record")

            key = _valid_name(key, "attachment name")
            name = _valid_name(record.name, "attachment name")
            width = _positive_int(record.width, "width")
            height = _positive_int(record.height, "height")
            bytes_per_pixel = _positive_int(
                record.bytes_per_pixel, "bytes_per_pixel"
            )
            kind = record.kind
            if not isinstance(kind, str) or kind not in _KINDS:
                raise ValueError("invalid attachment kind")
            if not isinstance(record.external, bool):
                raise ValueError("external must be a boolean")
            if not isinstance(record.backbuffer, bool):
                raise ValueError("backbuffer must be a boolean")
            if key != name or name in attachments:
                raise ValueError("duplicate or inconsistent attachment")
            if len(attachments) >= self.max_attachments:
                raise ValueError("maximum number of attachments exceeded")

            attachments[name] = AttachmentRecord(
                name, width, height, bytes_per_pixel, kind,
                record.external, record.backbuffer,
            )
        return attachments

    def _parse_uses(
        self,
        raw: object,
        passes: Mapping[int, PassRecord],
        attachments: Mapping[str, AttachmentRecord],
    ) -> dict[str, list[tuple[int, str]]]:
        uses: dict[str, list[tuple[int, str]]] = {
            name: [] for name in attachments
        }
        if isinstance(raw, Mapping):
            entries = raw.items()
        elif isinstance(raw, (list, tuple)):
            entries = None
        else:
            raise ValueError("snapshot uses must be a mapping or sequence")

        def add_use(name: object, pass_index: object, mode: object) -> None:
            if not isinstance(name, str) or name not in attachments:
                raise ValueError("use references an unknown attachment")
            if not _is_int(pass_index) or pass_index not in passes:
                raise ValueError("use references an unknown pass")
            if not isinstance(mode, str) or mode not in _MODES:
                raise ValueError("invalid use mode")
            uses[name].append((pass_index, mode))

        if entries is not None:
            for name, item_uses in entries:
                if not isinstance(name, str) or name not in attachments:
                    raise ValueError(
                        "use references an unknown attachment"
                    )
                if not isinstance(item_uses, (list, tuple)):
                    raise ValueError("invalid uses record")
                for item in item_uses:
                    if isinstance(item, Mapping):
                        if "pass_index" not in item or "mode" not in item:
                            raise ValueError("invalid use record")
                        add_use(name, item["pass_index"], item["mode"])
                    elif isinstance(item, (list, tuple)) and len(item) == 2:
                        add_use(name, item[0], item[1])
                    else:
                        raise ValueError("invalid use record")
        else:
            for item in raw:
                if isinstance(item, Mapping):
                    if not {"name", "pass_index", "mode"} <= set(item):
                        raise ValueError("invalid use record")
                    add_use(item["name"], item["pass_index"], item["mode"])
                elif isinstance(item, (list, tuple)) and len(item) == 3:
                    add_use(item[0], item[1], item[2])
                else:
                    raise ValueError("invalid use record")
        return uses

    def _parse_stats(self, raw: object) -> dict[str, int]:
        stats_map = self._snapshot_mapping(raw, "stats")
        if set(stats_map) != _STAT_KEY_SET:
            raise ValueError("invalid stats structure")
        stats = {}
        for key in _STAT_KEYS:
            stats[key] = _nonnegative_int(stats_map[key], f"stats.{key}")
        return stats

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                if not isinstance(state, Mapping):
                    raise ValueError("snapshot must be a mapping")
                if set(state) != _STATE_KEYS:
                    raise ValueError("invalid snapshot structure")
                if not _is_int(state["version"]) or state["version"] != _VERSION:
                    raise ValueError("unsupported snapshot version")

                passes = self._parse_passes(state["passes"])
                attachments = self._parse_attachments(state["attachments"])
                uses = self._parse_uses(
                    state["uses"], passes, attachments
                )
                stats = self._parse_stats(state["stats"])

                raw_plan = state["plan"]
                if raw_plan is None:
                    plan = None
                    usage = 0
                    barriers = ()
                else:
                    plan_map = self._snapshot_mapping(raw_plan, "plan")
                    if set(plan_map) != set(attachments):
                        raise ValueError("plan does not cover attachments")
                    plan = {}
                    for name, offset in plan_map.items():
                        if not isinstance(name, str) or name not in attachments:
                            raise ValueError("plan references unknown attachment")
                        plan[name] = _nonnegative_int(
                            offset, "plan offset"
                        )

                    previous_attachments = self._attachments
                    previous_uses = self._uses
                    self._attachments = attachments
                    self._uses = uses
                    try:
                        expected, usage, barriers = self._compute_layout()
                    finally:
                        self._attachments = previous_attachments
                        self._uses = previous_uses
                    if plan != expected:
                        raise ValueError("plan is inconsistent with state")
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, ValueError):
                    raise
                raise ValueError("invalid snapshot") from exc

            self._passes = passes
            self._pass_names = {record.name for record in passes.values()}
            self._attachments = attachments
            self._uses = uses
            self._plan = plan
            self._heap_usage = usage
            self._barriers = barriers
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
