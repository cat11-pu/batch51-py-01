"""Quest phase visibility: exclusive groups, atomic switches, party phase sync."""

from __future__ import annotations

import copy
import threading
from collections import OrderedDict
from dataclasses import dataclass, field


class PhaseError(ValueError):
    """Raised when a phase visibility operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PhaseSpec:
    phase_id: str
    quest_id: str
    group: str
    priority: int


@dataclass(frozen=True)
class Transition:
    player: str
    applied: bool
    active: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class SyncResult:
    leader: str
    accepted: tuple[str, ...]
    rejected: tuple[str, ...]
    reason: str


@dataclass
class _PlayerState:
    map_id: str | None = None
    progress: dict[str, int] = field(default_factory=dict)
    active: dict[str, str] = field(default_factory=dict)


class PhaseVisibilityGuard:
    """Track which quest phases a player holds and which world objects they see."""

    _SNAPSHOT_VERSION = 1
    _STAT_KEYS = frozenset(
        {"phases", "objects", "players", "entries", "switches", "lookups"}
    )
    _SNAPSHOT_KEYS = frozenset(
        {"version", "phases", "objects", "players", "counters", "stats"}
    )

    def __init__(self, *, max_phases: int = 256, max_objects: int = 4096,
                 cache_size: int = 256) -> None:
        self.max_phases = max_phases
        self.max_objects = max_objects
        self.cache_size = cache_size
        self._lock = threading.RLock()
        self._phases: dict[str, PhaseSpec] = {}
        self._objects: dict[str, str | None] = {}
        self._players: dict[str, _PlayerState] = {}
        self._cache: OrderedDict[tuple[str, str], bool] = OrderedDict()
        self._switches = 0
        self._lookups = 0

    @staticmethod
    def _is_name(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _snapshot_invalid(cls, detail: object) -> None:
        raise PhaseError("PHASE_SNAPSHOT_INVALID", detail)

    def _player_state(
        self, player: str, *, create: bool = False
    ) -> _PlayerState | None:
        state = self._players.get(player)
        if state is None and create:
            state = _PlayerState()
            self._players[player] = state
        return state

    @staticmethod
    def _active_tuple(state: _PlayerState | None) -> tuple[str, ...]:
        if state is None:
            return ()
        return tuple(sorted(state.active.values()))

    def _transition(self, player: str, state: _PlayerState | None, *,
                    applied: bool, added: tuple[str, ...] = (),
                    removed: tuple[str, ...] = (), reason: str) -> Transition:
        return Transition(
            player=player,
            applied=applied,
            active=self._active_tuple(state),
            added=tuple(sorted(added)),
            removed=tuple(sorted(removed)),
            reason=reason,
        )

    def _cache_get(self, key: tuple[str, str]) -> bool | None:
        if key not in self._cache:
            return None
        value = self._cache.pop(key)
        self._cache[key] = value
        return value

    def _cache_put(self, key: tuple[str, str], value: bool) -> None:
        if self.cache_size <= 0:
            return
        self._cache.pop(key, None)
        while len(self._cache) >= self.cache_size:
            self._cache.popitem(last=False)
        self._cache[key] = value

    def _stats_unlocked(self) -> dict:
        return {
            "phases": len(self._phases),
            "objects": len(self._objects),
            "players": len(self._players),
            "entries": len(self._cache),
            "switches": self._switches,
            "lookups": self._lookups,
        }

    def register_phase(self, phase_id: str, *, quest_id: str, group: str,
                       priority: int = 0) -> PhaseSpec:
        """Define one quest phase and its exclusive group."""
        with self._lock:
            if (not self._is_name(phase_id) or not self._is_name(quest_id)
                    or not self._is_name(group)):
                raise PhaseError(
                    "PHASE_INVALID_NAME",
                    {"phase_id": phase_id, "quest_id": quest_id, "group": group},
                )
            if not self._is_int(priority):
                raise PhaseError("PHASE_INVALID_REQUEST", {"priority": priority})
            if phase_id in self._phases:
                raise PhaseError("PHASE_ALREADY_DEFINED", phase_id)
            if len(self._phases) >= self.max_phases:
                raise PhaseError("PHASE_CAPACITY_EXCEEDED", len(self._phases))

            spec = PhaseSpec(
                phase_id=phase_id,
                quest_id=quest_id,
                group=group,
                priority=priority,
            )
            self._phases[phase_id] = spec
            return spec

    def register_object(self, object_id: str, phase_id: str | None) -> None:
        """Bind one world object to a phase, or to every player when phase is None."""
        if not self._is_name(object_id):
            raise PhaseError("PHASE_INVALID_REQUEST", {"object_id": object_id})
        if phase_id == "":
            phase_id = None

        with self._lock:
            if object_id in self._objects:
                raise PhaseError("PHASE_OBJECT_EXISTS", object_id)
            if phase_id is not None:
                if not self._is_name(phase_id):
                    raise PhaseError("PHASE_UNKNOWN", phase_id)
                if phase_id not in self._phases:
                    raise PhaseError("PHASE_UNKNOWN", phase_id)
            if len(self._objects) >= self.max_objects:
                raise PhaseError(
                    "PHASE_OBJECT_CAPACITY_EXCEEDED", len(self._objects)
                )

            self._objects[object_id] = phase_id
            self._cache.clear()

    def set_map(self, player: str, map_id: str) -> None:
        """Record the map a player currently stands on."""
        if not self._is_name(player) or not self._is_name(map_id):
            raise PhaseError(
                "PHASE_INVALID_REQUEST",
                {"player": player, "map_id": map_id},
            )
        with self._lock:
            state = self._player_state(player, create=True)
            assert state is not None
            state.map_id = map_id

    def set_progress(self, player: str, quest_id: str, step: int) -> None:
        """Record one quest step of a player for party sync comparisons."""
        if (not self._is_name(player) or not self._is_name(quest_id)
                or not self._is_int(step)):
            raise PhaseError(
                "PHASE_INVALID_REQUEST",
                {"player": player, "quest_id": quest_id, "step": step},
            )
        with self._lock:
            state = self._player_state(player, create=True)
            assert state is not None
            state.progress[quest_id] = step

    def enter_phase(self, player: str, phase_id: str) -> Transition:
        """Add one phase, replacing a lower-priority phase of the same group."""
        if not self._is_name(player):
            raise PhaseError("PHASE_INVALID_REQUEST", {"player": player})
        with self._lock:
            target = self._phases.get(phase_id)
            if target is None:
                raise PhaseError("PHASE_UNKNOWN", phase_id)

            state = self._player_state(player, create=True)
            assert state is not None
            if phase_id in state.active.values():
                return self._transition(
                    player, state, applied=False, reason="PHASE_ALREADY_ACTIVE"
                )

            current_id = state.active.get(target.group)
            if current_id is not None:
                current = self._phases[current_id]
                if target.priority < current.priority:
                    return self._transition(
                        player, state, applied=False,
                        reason="PHASE_LOWER_PRIORITY",
                    )
                if target.priority == current.priority:
                    return self._transition(
                        player, state, applied=False,
                        reason="PHASE_PRIORITY_CONFLICT",
                    )

            removed = () if current_id is None else (current_id,)
            state.active[target.group] = phase_id
            self._switches += 1
            self._cache.clear()
            return self._transition(
                player, state, applied=True, added=(phase_id,), removed=removed,
                reason="PHASE_ENTERED" if current_id is None else "PHASE_SWITCHED",
            )

    def leave_phase(self, player: str, phase_id: str) -> Transition:
        """Drop one active phase and hide its objects again."""
        if not self._is_name(player):
            raise PhaseError("PHASE_INVALID_REQUEST", {"player": player})
        with self._lock:
            state = self._players.get(player)
            if state is None or phase_id not in state.active.values():
                return self._transition(
                    player, state, applied=False, reason="PHASE_NOT_ACTIVE"
                )

            group = self._phases[phase_id].group
            state.active.pop(group, None)
            self._switches += 1
            self._cache.clear()
            return self._transition(
                player, state, applied=True, removed=(phase_id,),
                reason="PHASE_LEFT",
            )

    def switch_phase(self, player: str, phase_id: str) -> Transition:
        """Atomically replace every active phase of the target group."""
        if not self._is_name(player):
            raise PhaseError("PHASE_INVALID_REQUEST", {"player": player})
        with self._lock:
            target = self._phases.get(phase_id)
            if target is None:
                raise PhaseError("PHASE_UNKNOWN", phase_id)

            state = self._player_state(player, create=True)
            assert state is not None
            if phase_id in state.active.values():
                return self._transition(
                    player, state, applied=False, reason="PHASE_ALREADY_ACTIVE"
                )

            old_id = state.active.get(target.group)
            removed = () if old_id is None else (old_id,)
            state.active[target.group] = phase_id
            self._switches += 1
            self._cache.clear()
            return self._transition(
                player, state, applied=True, added=(phase_id,), removed=removed,
                reason="PHASE_SWITCHED",
            )

    def visible_to(self, player: str, object_id: str) -> bool:
        """Whether one player may currently see one world object."""
        with self._lock:
            self._lookups += 1
            if not isinstance(player, str) or not isinstance(object_id, str):
                return False

            key = (player, object_id)
            cached = self._cache_get(key)
            if cached is not None:
                return cached

            if object_id not in self._objects:
                visible = False
            else:
                phase_id = self._objects[object_id]
                if phase_id is None:
                    visible = True
                else:
                    state = self._players.get(player)
                    visible = (
                        state is not None and phase_id in state.active.values()
                    )

            self._cache_put(key, visible)
            return visible

    def sync_party_phase(self, leader: str, members) -> SyncResult:
        """Push the leader phase set to party members on the same map and progress."""
        if (not self._is_name(leader) or not isinstance(members, list)
                or any(not self._is_name(member) for member in members)):
            raise PhaseError(
                "PHASE_INVALID_REQUEST",
                {"leader": leader, "members": members},
            )

        with self._lock:
            leader_state = self._players.get(leader)
            accepted: list[str] = []
            rejected: list[str] = []
            changed = False

            leader_active = {} if leader_state is None else leader_state.active
            for member in members:
                state = self._players.get(member)
                eligible = (
                    leader_state is not None
                    and state is not None
                    and state.map_id == leader_state.map_id
                    and state.progress == leader_state.progress
                )
                if not eligible:
                    rejected.append(member)
                    continue

                accepted.append(member)
                member_changed = False
                for group, phase_id in leader_active.items():
                    if state.active.get(group) != phase_id:
                        state.active[group] = phase_id
                        member_changed = True
                if member_changed:
                    self._switches += 1
                    changed = True

            if changed:
                self._cache.clear()

            if rejected and accepted:
                reason = "PARTY_SYNC_PARTIAL"
            elif rejected:
                reason = "PARTY_SYNC_REJECTED"
            else:
                reason = "PARTY_SYNCED"
            return SyncResult(
                leader=leader,
                accepted=tuple(sorted(accepted)),
                rejected=tuple(sorted(rejected)),
                reason=reason,
            )

    def active_phases(self, player: str) -> tuple[str, ...]:
        """Active phases of one player in lexicographic order."""
        with self._lock:
            return self._active_tuple(self._players.get(player))

    def remove_object(self, object_id: str) -> bool:
        """Delete one world object and invalidate any cached visibility answer."""
        with self._lock:
            if object_id not in self._objects:
                return False
            del self._objects[object_id]
            self._cache = OrderedDict(
                (key, value) for key, value in self._cache.items()
                if key[1] != object_id
            )
            return True

    def snapshot(self) -> dict:
        """Deep copy of phases, objects, player state and counters."""
        with self._lock:
            phases = {
                phase_id: {
                    "quest_id": spec.quest_id,
                    "group": spec.group,
                    "priority": spec.priority,
                }
                for phase_id, spec in self._phases.items()
            }
            players = {
                player: {
                    "map_id": state.map_id,
                    "progress": dict(state.progress),
                    "active": self._active_tuple(state),
                }
                for player, state in self._players.items()
            }
            counters = {
                "switches": self._switches,
                "lookups": self._lookups,
                "cache": [
                    [player, object_id, visible]
                    for (player, object_id), visible in self._cache.items()
                ],
            }
            state = {
                "version": self._SNAPSHOT_VERSION,
                "phases": phases,
                "objects": dict(self._objects),
                "players": players,
                "counters": counters,
                "stats": self._stats_unlocked(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        with self._lock:
            if (not isinstance(state, dict)
                    or set(state) != self._SNAPSHOT_KEYS
                    or type(state.get("version")) is not int
                    or state["version"] != self._SNAPSHOT_VERSION):
                self._snapshot_invalid("snapshot header")

            raw_phases = state["phases"]
            raw_objects = state["objects"]
            raw_players = state["players"]
            raw_counters = state["counters"]
            raw_stats = state["stats"]
            if (not isinstance(raw_phases, dict)
                    or not isinstance(raw_objects, dict)
                    or not isinstance(raw_players, dict)
                    or not isinstance(raw_counters, dict)
                    or not isinstance(raw_stats, dict)):
                self._snapshot_invalid("snapshot section type")
            if len(raw_phases) > self.max_phases:
                self._snapshot_invalid("phase capacity")
            if len(raw_objects) > self.max_objects:
                self._snapshot_invalid("object capacity")

            phases: dict[str, PhaseSpec] = {}
            for phase_id, raw in raw_phases.items():
                if not self._is_name(phase_id) or not isinstance(raw, dict):
                    self._snapshot_invalid("phase entry")
                quest_id = raw.get("quest_id")
                group = raw.get("group")
                priority = raw.get("priority")
                if (not self._is_name(quest_id) or not self._is_name(group)
                        or not self._is_int(priority)):
                    self._snapshot_invalid("phase fields")
                phases[phase_id] = PhaseSpec(
                    phase_id=phase_id, quest_id=quest_id, group=group,
                    priority=priority,
                )

            objects: dict[str, str | None] = {}
            for object_id, phase_id in raw_objects.items():
                if not self._is_name(object_id):
                    self._snapshot_invalid("object id")
                if phase_id == "":
                    phase_id = None
                if phase_id is not None:
                    if not self._is_name(phase_id) or phase_id not in phases:
                        self._snapshot_invalid("object phase")
                objects[object_id] = phase_id

            players: dict[str, _PlayerState] = {}
            for player, raw in raw_players.items():
                if not self._is_name(player) or not isinstance(raw, dict):
                    self._snapshot_invalid("player entry")
                map_id = raw.get("map_id")
                progress = raw.get("progress")
                active = raw.get("active")
                if map_id is not None and not self._is_name(map_id):
                    self._snapshot_invalid("player map")
                if not isinstance(progress, dict):
                    self._snapshot_invalid("player progress")
                if not isinstance(active, (list, tuple)):
                    self._snapshot_invalid("player active")

                clean_progress: dict[str, int] = {}
                for quest_id, step in progress.items():
                    if not self._is_name(quest_id) or not self._is_int(step):
                        self._snapshot_invalid("progress entry")
                    clean_progress[quest_id] = step

                active_by_group: dict[str, str] = {}
                seen_active: set[str] = set()
                for phase_id in active:
                    if not self._is_name(phase_id) or phase_id not in phases:
                        self._snapshot_invalid("active phase")
                    if phase_id in seen_active:
                        self._snapshot_invalid("duplicate active phase")
                    group = phases[phase_id].group
                    if group in active_by_group:
                        self._snapshot_invalid("conflicting active groups")
                    seen_active.add(phase_id)
                    active_by_group[group] = phase_id

                players[player] = _PlayerState(
                    map_id=map_id,
                    progress=clean_progress,
                    active=active_by_group,
                )

            switches = raw_counters.get("switches")
            lookups = raw_counters.get("lookups")
            if (not self._is_int(switches) or switches < 0
                    or not self._is_int(lookups) or lookups < 0):
                self._snapshot_invalid("counters")

            if set(raw_stats) != self._STAT_KEYS:
                self._snapshot_invalid("stats")
            for key in self._STAT_KEYS:
                value = raw_stats[key]
                if not self._is_int(value) or value < 0:
                    self._snapshot_invalid("stats")

            cache: OrderedDict[tuple[str, str], bool] = OrderedDict()
            raw_cache = raw_counters.get("cache", [])
            if not isinstance(raw_cache, list):
                self._snapshot_invalid("cache")
            for item in raw_cache:
                if (not isinstance(item, (list, tuple)) or len(item) != 3
                        or not isinstance(item[0], str)
                        or not isinstance(item[1], str)
                        or not isinstance(item[2], bool)):
                    self._snapshot_invalid("cache entry")
                if self.cache_size > 0 and len(cache) < self.cache_size:
                    cache[(item[0], item[1])] = item[2]

            self._phases = phases
            self._objects = objects
            self._players = players
            self._cache = cache
            self._switches = switches
            self._lookups = lookups

    def stats(self) -> dict:
        """Counters exposed to the world operations dashboard."""
        with self._lock:
            return self._stats_unlocked()
