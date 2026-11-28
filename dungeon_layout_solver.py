"""Deterministic dungeon layout generation with connectivity and key ordering."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections import deque
from dataclasses import dataclass
from typing import Any


REASON_OK = "DUNGEON_OK"
REASON_INVALID_REQUEST = "DUNGEON_INVALID_REQUEST"
REASON_MALFORMED = "DUNGEON_LAYOUT_MALFORMED"
REASON_KEY_ORDER = "DUNGEON_KEY_ORDER_UNSOLVABLE"
REASON_UNREACHABLE = "DUNGEON_UNREACHABLE_ROOMS"
REASON_BUDGET = "DUNGEON_BUDGET_EXCEEDED"
REASON_EXHAUSTED = "DUNGEON_REGENERATION_EXHAUSTED"
REASON_SNAPSHOT_INVALID = "DUNGEON_SNAPSHOT_INVALID"

DEFAULT_CONFIG = {
    "monster_budget": 12,
    "chest_budget": 4,
    "max_attempts": 4,
}

STAT_KEYS = ("generations", "regenerations", "validations")

SNAPSHOT_VERSION = 1


class DungeonError(ValueError):
    """Refusal raised by the dungeon layout solver."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Layout:
    seed: int
    attempt: int
    rooms: tuple
    entrance: str
    boss: str
    corridors: tuple
    doors: tuple
    keys: tuple
    monsters: tuple
    chests: tuple
    monster_budget: int
    chest_budget: int


LAYOUT_FIELDS = (
    "seed",
    "attempt",
    "rooms",
    "entrance",
    "boss",
    "corridors",
    "doors",
    "keys",
    "monsters",
    "chests",
    "monster_budget",
    "chest_budget",
)


@dataclass(frozen=True)
class ValidationReport:
    ok: bool
    reason: str
    reachable: tuple
    unreachable: tuple
    monster_total: int
    chest_total: int


@dataclass(frozen=True)
class RegenerateResult:
    ok: bool
    layout: Layout | None
    attempts: int
    reason: str


class _MalformedLayout(ValueError):
    """Internal signal used to turn malformed layout data into a report."""


@dataclass(frozen=True)
class _LayoutGraph:
    rooms: tuple[str, ...]
    room_set: frozenset[str]
    entrance: str
    boss: str
    corridors: tuple[tuple[str, str], ...]
    doors: tuple[tuple[str, str, str], ...]
    keys: tuple[tuple[str, str], ...]
    monsters: tuple[tuple[str, int], ...]
    chests: tuple[tuple[str, int], ...]
    monster_total: int
    chest_total: int
    monster_budget: int
    chest_budget: int


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_seed(seed: object) -> int:
    if not _is_int(seed):
        raise DungeonError(REASON_INVALID_REQUEST, {"seed": seed})
    return seed


def _require_budget(value: object, name: str) -> int:
    if not _is_int(value) or value < 0:
        raise DungeonError(REASON_INVALID_REQUEST, {name: value})
    return value


def _require_attempt_limit(value: object, name: str = "max_attempts") -> int:
    if not _is_int(value) or value <= 0:
        raise DungeonError(REASON_INVALID_REQUEST, {name: value})
    return value


def _seed_word(seed: int, *parts: object) -> int:
    digest = hashlib.sha256()
    digest.update(b"dungeon-layout-v1")
    digest.update(str(seed).encode("utf-8"))
    for part in parts:
        digest.update(b"\x00")
        digest.update(str(part).encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big")


def _entries(value: object, name: str) -> list[Any]:
    if not isinstance(value, (tuple, list)):
        raise _MalformedLayout(name)
    return list(value)


def _room_id(value: object, name: str = "room") -> str:
    if not isinstance(value, str):
        raise _MalformedLayout(name)
    return value


def _edge_pair(value: object, name: str) -> tuple[str, str]:
    items = _entries(value, name)
    if len(items) != 2:
        raise _MalformedLayout(name)
    left = _room_id(items[0], name)
    right = _room_id(items[1], name)
    if left == right:
        raise _MalformedLayout(name)
    return (left, right) if left < right else (right, left)


def _door_record(value: object) -> tuple[str, str, str]:
    items = _entries(value, "door")
    if len(items) != 3:
        raise _MalformedLayout("door")
    door_id = _room_id(items[0], "door")
    left = _room_id(items[1], "door")
    right = _room_id(items[2], "door")
    if left == right:
        raise _MalformedLayout("door")
    if right < left:
        left, right = right, left
    return (door_id, left, right)


def _key_record(value: object) -> tuple[str, str]:
    items = _entries(value, "key")
    if len(items) != 2:
        raise _MalformedLayout("key")
    return (_room_id(items[0], "key"), _room_id(items[1], "key"))


def _count_record(value: object, name: str) -> tuple[str, int]:
    items = _entries(value, name)
    if len(items) != 2:
        raise _MalformedLayout(name)
    room = _room_id(items[0], name)
    count = items[1]
    if not _is_int(count) or count < 0:
        raise _MalformedLayout(name)
    return (room, count)


def _parse_layout(layout: Layout) -> _LayoutGraph:
    rooms = tuple(_room_id(room) for room in _entries(layout.rooms, "rooms"))
    if not rooms:
        raise _MalformedLayout("rooms")
    if len(set(rooms)) != len(rooms):
        raise _MalformedLayout("rooms")
    room_set = frozenset(rooms)

    entrance = _room_id(layout.entrance, "entrance")
    boss = _room_id(layout.boss, "boss")
    if entrance not in room_set or boss not in room_set:
        raise _MalformedLayout("entrance/boss")

    corridors: list[tuple[str, str]] = []
    for value in _entries(layout.corridors, "corridors"):
        corridor = _edge_pair(value, "corridor")
        if corridor[0] not in room_set or corridor[1] not in room_set:
            raise _MalformedLayout("corridor")
        corridors.append(corridor)
    if len(set(corridors)) != len(corridors):
        raise _MalformedLayout("corridor")

    doors: list[tuple[str, str, str]] = []
    door_ids: set[str] = set()
    for value in _entries(layout.doors, "doors"):
        door = _door_record(value)
        if door[1] not in room_set or door[2] not in room_set:
            raise _MalformedLayout("door")
        if door[0] in door_ids or door in doors:
            raise _MalformedLayout("door")
        door_ids.add(door[0])
        doors.append(door)
    if len(set(doors)) != len(doors):
        raise _MalformedLayout("door")

    keys: list[tuple[str, str]] = []
    for value in _entries(layout.keys, "keys"):
        key = _key_record(value)
        if key[0] not in door_ids or key[1] not in room_set:
            raise _MalformedLayout("key")
        keys.append(key)

    monsters: list[tuple[str, int]] = []
    for value in _entries(layout.monsters, "monsters"):
        monster = _count_record(value, "monster")
        if monster[0] not in room_set:
            raise _MalformedLayout("monster")
        monsters.append(monster)

    chests: list[tuple[str, int]] = []
    for value in _entries(layout.chests, "chests"):
        chest = _count_record(value, "chest")
        if chest[0] not in room_set:
            raise _MalformedLayout("chest")
        chests.append(chest)

    if not _is_int(layout.seed) or not _is_int(layout.attempt) or layout.attempt < 1:
        raise _MalformedLayout("seed/attempt")
    if not _is_int(layout.monster_budget) or layout.monster_budget < 0:
        raise _MalformedLayout("monster_budget")
    if not _is_int(layout.chest_budget) or layout.chest_budget < 0:
        raise _MalformedLayout("chest_budget")

    return _LayoutGraph(
        rooms=tuple(sorted(rooms)),
        room_set=room_set,
        entrance=entrance,
        boss=boss,
        corridors=tuple(sorted(corridors)),
        doors=tuple(sorted(doors)),
        keys=tuple(sorted(keys)),
        monsters=tuple(sorted(monsters)),
        chests=tuple(sorted(chests)),
        monster_total=sum(count for _, count in monsters),
        chest_total=sum(count for _, count in chests),
        monster_budget=layout.monster_budget,
        chest_budget=layout.chest_budget,
    )


def _keys_by_door(graph: _LayoutGraph) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {door_id: [] for door_id, _, _ in graph.doors}
    for door_id, room in graph.keys:
        result[door_id].append(room)
    return {door_id: tuple(sorted(rooms)) for door_id, rooms in result.items()}


def _keys_by_room(graph: _LayoutGraph) -> dict[str, frozenset[str]]:
    result: dict[str, set[str]] = {}
    for door_id, room in graph.keys:
        result.setdefault(room, set()).add(door_id)
    return {room: frozenset(door_ids) for room, door_ids in result.items()}


def _reachable_rooms(graph: _LayoutGraph, *, open_all_doors: bool = False) -> set[str]:
    reachable = {graph.entrance}
    keys_by_door = _keys_by_door(graph)
    changed = True
    while changed:
        changed = False
        for left, right in graph.corridors:
            if left in reachable and right not in reachable:
                reachable.add(right)
                changed = True
            elif right in reachable and left not in reachable:
                reachable.add(left)
                changed = True
        for door_id, left, right in graph.doors:
            key_rooms = keys_by_door.get(door_id, ())
            can_open = open_all_doors or any(room in reachable for room in key_rooms)
            if not can_open:
                continue
            if left in reachable and right not in reachable:
                reachable.add(right)
                changed = True
            elif right in reachable and left not in reachable:
                reachable.add(left)
                changed = True
    return reachable


def _key_order_unsolvable(graph: _LayoutGraph) -> bool:
    reachable = _reachable_rooms(graph)
    keys_by_door = _keys_by_door(graph)
    open_reachable: set[str] | None = None
    for door_id, _, _ in graph.doors:
        key_rooms = keys_by_door.get(door_id, ())
        if not key_rooms or any(room in reachable for room in key_rooms):
            continue
        if open_reachable is None:
            open_reachable = _reachable_rooms(graph, open_all_doors=True)
        if any(room in open_reachable for room in key_rooms):
            return True
    return False


def _validate_layout(layout: Layout) -> ValidationReport:
    try:
        graph = _parse_layout(layout)
    except _MalformedLayout:
        return ValidationReport(False, REASON_MALFORMED, (), (), 0, 0)

    if _key_order_unsolvable(graph):
        return ValidationReport(
            False,
            REASON_KEY_ORDER,
            (),
            (),
            graph.monster_total,
            graph.chest_total,
        )

    reachable = _reachable_rooms(graph)
    unreachable = tuple(sorted(graph.room_set - reachable))
    if unreachable:
        return ValidationReport(
            False,
            REASON_UNREACHABLE,
            tuple(sorted(reachable)),
            unreachable,
            graph.monster_total,
            graph.chest_total,
        )

    if (
        graph.monster_total > graph.monster_budget
        or graph.chest_total > graph.chest_budget
    ):
        return ValidationReport(
            False,
            REASON_BUDGET,
            tuple(sorted(reachable)),
            (),
            graph.monster_total,
            graph.chest_total,
        )

    return ValidationReport(
        True,
        REASON_OK,
        tuple(sorted(reachable)),
        (),
        graph.monster_total,
        graph.chest_total,
    )


def _canonical_records(value: object, size: int, name: str) -> tuple[tuple, ...]:
    records: list[tuple] = []
    for entry in _entries(value, name):
        items = _entries(entry, name)
        if len(items) != size:
            raise DungeonError(REASON_INVALID_REQUEST, {name: entry})
        records.append(tuple(items))
    return tuple(sorted(records))


def _describe_body(layout: Layout) -> dict[str, Any]:
    if not isinstance(layout, Layout):
        raise DungeonError(REASON_INVALID_REQUEST, {"layout": layout})
    try:
        rooms = tuple(sorted(_room_id(room) for room in _entries(layout.rooms, "rooms")))
        corridors = tuple(
            sorted(
                tuple(sorted((_room_id(left), _room_id(right))))
                for left, right in _canonical_records(
                    layout.corridors, 2, "corridors"
                )
            )
        )
        doors = tuple(
            sorted(
                (
                    _room_id(door_id, "door"),
                    *sorted((_room_id(left, "door"), _room_id(right, "door"))),
                )
                for door_id, left, right in _canonical_records(
                    layout.doors, 3, "doors"
                )
            )
        )
        keys = _canonical_records(layout.keys, 2, "keys")
        monsters = _canonical_records(layout.monsters, 2, "monsters")
        chests = _canonical_records(layout.chests, 2, "chests")
        monster_total = sum(count for _, count in monsters)
        chest_total = sum(count for _, count in chests)
    except (_MalformedLayout, TypeError, ValueError):
        raise DungeonError(REASON_INVALID_REQUEST, {"layout": layout}) from None

    return {
        "seed": layout.seed,
        "attempt": layout.attempt,
        "entrance": layout.entrance,
        "boss": layout.boss,
        "rooms": rooms,
        "corridors": corridors,
        "doors": doors,
        "keys": keys,
        "monsters": monsters,
        "chests": chests,
        "monster_total": monster_total,
        "chest_total": chest_total,
        "monster_budget": layout.monster_budget,
        "chest_budget": layout.chest_budget,
    }


def _fingerprint(body: dict[str, Any]) -> str:
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:32]


def _snapshot_counter_value(value: object) -> bool:
    return _is_int(value) and value >= 0


def _layout_to_state(layout: Layout) -> dict[str, Any]:
    return {
        field: copy.deepcopy(getattr(layout, field))
        for field in LAYOUT_FIELDS
    }


def _layout_from_state(value: object) -> Layout:
    if not isinstance(value, dict) or set(value) != set(LAYOUT_FIELDS):
        raise _MalformedLayout("current")
    data = {
        field: copy.deepcopy(value[field])
        for field in LAYOUT_FIELDS
    }
    for field in ("rooms", "corridors", "doors", "keys", "monsters", "chests"):
        outer = data[field]
        if not isinstance(outer, (tuple, list)):
            continue
        data[field] = tuple(
            tuple(item) if isinstance(item, (tuple, list)) else item
            for item in outer
        )
    return Layout(**data)


class LayoutSolver:
    """Generate seeded layouts and prove that every room stays reachable."""

    def __init__(
        self,
        *,
        monster_budget: int = 12,
        chest_budget: int = 4,
        max_attempts: int = 4,
    ) -> None:
        self.monster_budget = _require_budget(monster_budget, "monster_budget")
        self.chest_budget = _require_budget(chest_budget, "chest_budget")
        self.max_attempts = _require_attempt_limit(max_attempts)
        self._lock = threading.RLock()
        self._current: Layout | None = None
        self._counters = dict.fromkeys(STAT_KEYS, 0)
        self._internal_validation_depth = 0

    def _generate_attempt(
        self,
        seed: int,
        attempt: int,
        monster_budget: int,
        chest_budget: int,
    ) -> Layout:
        chain_length = 4 + _seed_word(seed, attempt, "chain") % 3
        branch_count = 1 + _seed_word(seed, attempt, "branches") % 3
        main_rooms = [f"room-{index:02d}" for index in range(chain_length)]
        side_rooms = [f"room-{100 + index:02d}" for index in range(branch_count)]
        entrance = main_rooms[0]
        boss = main_rooms[-1]

        available_transitions = list(range(chain_length - 1))
        door_count = 1 + _seed_word(seed, attempt, "door-count") % 2
        door_count = min(door_count, len(available_transitions))
        locked_indexes: list[int] = []
        for index in range(door_count):
            position = _seed_word(seed, attempt, "door-index", index) % len(
                available_transitions
            )
            locked_indexes.append(available_transitions.pop(position))
        locked_indexes.sort()
        locked = set(locked_indexes)

        corridor_set: set[tuple[str, str]] = set()
        for index in range(chain_length - 1):
            if index in locked:
                continue
            left, right = main_rooms[index], main_rooms[index + 1]
            corridor_set.add((left, right) if left < right else (right, left))
        for index, side_room in enumerate(side_rooms):
            attach_at = _seed_word(seed, attempt, "branch", index) % chain_length
            main_room = main_rooms[attach_at]
            corridor_set.add(
                (main_room, side_room)
                if main_room < side_room
                else (side_room, main_room)
            )

        doors: list[tuple[str, str, str]] = []
        keys: list[tuple[str, str]] = []
        for door_number, transition in enumerate(locked_indexes):
            door_id = f"door-{door_number:02d}"
            left, right = main_rooms[transition], main_rooms[transition + 1]
            if right < left:
                left, right = right, left
            doors.append((door_id, left, right))
            key_room = main_rooms[
                _seed_word(seed, attempt, "key", door_number) % (transition + 1)
            ]
            keys.append((door_id, key_room))

        all_rooms = tuple(sorted((*main_rooms, *side_rooms)))
        monsters = self._allocate_counts(
            all_rooms,
            monster_budget,
            _seed_word(seed, attempt, "monster-total"),
            seed,
            attempt,
            "monster",
        )
        chests = self._allocate_counts(
            all_rooms,
            chest_budget,
            _seed_word(seed, attempt, "chest-total"),
            seed,
            attempt,
            "chest",
        )

        return Layout(
            seed=seed,
            attempt=attempt,
            rooms=all_rooms,
            entrance=entrance,
            boss=boss,
            corridors=tuple(sorted(corridor_set)),
            doors=tuple(sorted(doors)),
            keys=tuple(sorted(keys)),
            monsters=monsters,
            chests=chests,
            monster_budget=monster_budget,
            chest_budget=chest_budget,
        )

    @staticmethod
    def _allocate_counts(
        rooms: tuple[str, ...],
        budget: int,
        total_word: int,
        seed: int,
        attempt: int,
        kind: str,
    ) -> tuple[tuple[str, int], ...]:
        if budget == 0:
            return ()
        capacity = max(1, len(rooms) * 2)
        upper = min(budget, capacity)
        total = total_word % (upper + 1)
        counts = {room: 0 for room in rooms}
        for index in range(total):
            room = rooms[_seed_word(seed, attempt, kind, "item", index) % len(rooms)]
            counts[room] += 1
        return tuple((room, counts[room]) for room in rooms if counts[room])

    def generate(self, seed: int, *, monster_budget: int | None = None,
                 chest_budget: int | None = None) -> Layout:
        seed = _require_seed(seed)
        monster_budget = (
            self.monster_budget
            if monster_budget is None
            else _require_budget(monster_budget, "monster_budget")
        )
        chest_budget = (
            self.chest_budget
            if chest_budget is None
            else _require_budget(chest_budget, "chest_budget")
        )

        with self._lock:
            layout = self._generate_attempt(seed, 1, monster_budget, chest_budget)
            report = _validate_layout(layout)
            if not report.ok:
                raise DungeonError(report.reason, report)
            self._current = layout
            self._counters["generations"] += 1
            return layout

    def validate(self, layout: Layout) -> ValidationReport:
        if not isinstance(layout, Layout):
            raise DungeonError(REASON_INVALID_REQUEST, {"layout": layout})
        with self._lock:
            report = _validate_layout(layout)
            if self._internal_validation_depth == 0:
                self._counters["validations"] += 1
            return report

    def regenerate(self, seed: int, *, max_attempts: int | None = None,
                   monster_budget: int | None = None,
                   chest_budget: int | None = None) -> RegenerateResult:
        seed = _require_seed(seed)
        attempts_limit = (
            self.max_attempts
            if max_attempts is None
            else _require_attempt_limit(max_attempts)
        )
        monster_budget = (
            self.monster_budget
            if monster_budget is None
            else _require_budget(monster_budget, "monster_budget")
        )
        chest_budget = (
            self.chest_budget
            if chest_budget is None
            else _require_budget(chest_budget, "chest_budget")
        )

        with self._lock:
            self._counters["regenerations"] += 1
            for attempt in range(1, attempts_limit + 1):
                layout = self._generate_attempt(
                    seed, attempt, monster_budget, chest_budget
                )
                self._internal_validation_depth += 1
                try:
                    report = self.validate(layout)
                finally:
                    self._internal_validation_depth -= 1
                if report.ok:
                    self._current = layout
                    return RegenerateResult(True, layout, attempt, REASON_OK)
            return RegenerateResult(False, None, attempts_limit, REASON_EXHAUSTED)

    def describe(self, layout: Layout) -> dict:
        body = _describe_body(layout)
        return {**body, "fingerprint": _fingerprint(body)}

    def path_to(self, layout: Layout, target: str) -> tuple | None:
        if not isinstance(layout, Layout):
            raise DungeonError(REASON_INVALID_REQUEST, {"layout": layout})
        if not isinstance(target, str):
            return None
        try:
            graph = _parse_layout(layout)
        except _MalformedLayout:
            return None
        if target not in graph.room_set:
            return None

        keys_by_room = _keys_by_room(graph)
        adjacency: dict[str, list[tuple[str, str | None]]] = {
            room: [] for room in graph.rooms
        }
        for left, right in graph.corridors:
            adjacency[left].append((right, None))
            adjacency[right].append((left, None))
        for door_id, left, right in graph.doors:
            adjacency[left].append((right, door_id))
            adjacency[right].append((left, door_id))
        for edges in adjacency.values():
            edges.sort(key=lambda item: (item[0], item[1] or ""))

        start_keys = keys_by_room.get(graph.entrance, frozenset())
        start_state = (graph.entrance, start_keys)
        queue = deque([(graph.entrance, start_keys, (graph.entrance,))])
        seen = {start_state}
        while queue:
            room, keys, path = queue.popleft()
            if room == target:
                return path
            for neighbor, door_id in adjacency[room]:
                if door_id is not None and door_id not in keys:
                    continue
                next_keys = keys | keys_by_room.get(neighbor, frozenset())
                state = (neighbor, next_keys)
                if state in seen:
                    continue
                seen.add(state)
                queue.append((neighbor, next_keys, (*path, neighbor)))
        return None

    def current(self) -> Layout | None:
        with self._lock:
            return self._current

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "monster_budget": self.monster_budget,
                    "chest_budget": self.chest_budget,
                    "max_attempts": self.max_attempts,
                },
                "current": (
                    None
                    if self._current is None
                    else _layout_to_state(self._current)
                ),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, dict) or set(state) != {
                "version",
                "config",
                "current",
                "counters",
            }:
                raise _MalformedLayout("snapshot")
            if state["version"] != SNAPSHOT_VERSION or not _is_int(state["version"]):
                raise _MalformedLayout("version")

            config = state["config"]
            if not isinstance(config, dict) or set(config) != set(DEFAULT_CONFIG):
                raise _MalformedLayout("config")
            restored_monster_budget = _require_budget(
                config["monster_budget"], "monster_budget"
            )
            restored_chest_budget = _require_budget(
                config["chest_budget"], "chest_budget"
            )
            restored_max_attempts = _require_attempt_limit(
                config["max_attempts"], "max_attempts"
            )

            current = state["current"]
            if current is not None:
                if isinstance(current, Layout):
                    restored_current = _layout_from_state(_layout_to_state(current))
                else:
                    restored_current = _layout_from_state(current)
                report = _validate_layout(restored_current)
                if not report.ok:
                    raise _MalformedLayout("current")
            else:
                restored_current = None

            counters = state["counters"]
            if not isinstance(counters, dict) or set(counters) != set(STAT_KEYS):
                raise _MalformedLayout("counters")
            restored_counters = {}
            for key in STAT_KEYS:
                value = counters[key]
                if not _snapshot_counter_value(value):
                    raise _MalformedLayout("counters")
                restored_counters[key] = value
        except (DungeonError, _MalformedLayout, TypeError, ValueError):
            raise DungeonError(REASON_SNAPSHOT_INVALID, {"state": state}) from None

        with self._lock:
            self.monster_budget = restored_monster_budget
            self.chest_budget = restored_chest_budget
            self.max_attempts = restored_max_attempts
            self._current = restored_current
            self._counters = dict(restored_counters)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
