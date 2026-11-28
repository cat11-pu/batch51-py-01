"""Federated room state: event DAG ingest, deterministic state resolution, soft failure."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
SUPPORTED_VERSIONS = ("9", "10", "11")
NON_STATE_TYPES = frozenset({
    "m.room.message",
    "m.room.encrypted",
    "m.encrypted",
    "m.reaction",
})
DEFAULT_POWER = {
    "users_default": 0,
    "events": {},
    "events_default": 0,
    "state_default": 50,
    "kick": 50,
    "ban": 50,
    "invite": 0,
}


class FederationError(ValueError):
    """Raised when a federation state operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class StateEntry:
    type: str
    state_key: str
    event_id: str
    sender: str


@dataclass(frozen=True)
class IngestResult:
    event_id: str
    status: str
    soft_failed: bool
    depth: int


@dataclass(frozen=True)
class AuthResult:
    allowed: bool
    reason: str
    required_power: int
    sender_power: int


class MatrixStateResolver:
    """Keep one federated room's event DAG, current state and auth chain."""

    def __init__(self, room_id: str, *, room_version: str = "9",
                 max_pending: int = 256, max_depth: int = 1024,
                 creator: str = "@admin:hs") -> None:
        self.room_id = room_id
        self.creator = creator
        self.max_pending = max_pending
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._version = room_version
        self._events: dict[str, dict] = {}
        self._pending: dict[str, dict] = {}
        self._heads: set[str] = set()
        self._state: dict[tuple[str, str], str] = {}
        self._soft_failed: set[str] = set()
        self._rejected: set[str] = set()
        self._depth: dict[str, int] = {}
        self._backfilled: set[str] = set()
        self._event_epoch: dict[str, int] = {}
        self._pending_epoch: dict[str, int] = {}
        self._pending_backfill: set[str] = set()
        self._soft_fail_reasons: dict[str, str] = {}
        self._epoch = 1
        self._tombstone_seq = 0
        self._stats = {
            "accepted": 0,
            "pending": 0,
            "rejected": 0,
            "duplicates": 0,
            "soft_failed": 0,
            "backfilled": 0,
            "upgraded": 0,
        }

    def ingest_event(self, event: dict) -> IngestResult:
        with self._lock:
            event_id = self._event_id(event)
            duplicate = self._duplicate_result(event_id)
            if duplicate is not None:
                return duplicate

            item = self._normalized_event(event)
            if self._dependencies_missing(item):
                return self._park(item, backfill=False)

            result = self._accept(item, backfill=False)
            self._drain_pending()
            return result

    def resolve_state(self) -> tuple[StateEntry, ...]:
        with self._lock:
            entries = []
            for key in sorted(self._state):
                event_id = self._state[key]
                event = self._events[event_id]
                entries.append(StateEntry(
                    key[0], key[1], event_id, event["sender"],
                ))
            return tuple(entries)

    def authorize(self, event: dict) -> AuthResult:
        with self._lock:
            if not isinstance(event, dict):
                raise FederationError("FEDERATION_INVALID_EVENT", event)
            if not isinstance(event.get("type"), str):
                raise FederationError("FEDERATION_INVALID_EVENT", event)
            if not isinstance(event.get("sender"), str):
                raise FederationError("FEDERATION_INVALID_EVENT", event)
            return self._authorize_with_view(
                event, self._auth_view(event),
            )

    def soft_fail(self, event_id: str, reason: str) -> bool:
        with self._lock:
            if event_id not in self._events:
                raise FederationError("FEDERATION_UNKNOWN_EVENT", event_id)
            if event_id in self._soft_failed:
                return False
            self._soft_fail_reasons[event_id] = reason
            self._mark_soft_failed(event_id)
            self._propagate_soft_failure(event_id)
            self._recompute_state()
            return True

    def backfill(self, events) -> int:
        with self._lock:
            if isinstance(events, (str, bytes, bytearray, dict)):
                raise FederationError("FEDERATION_INVALID_EVENT", events)
            try:
                raw_items = list(events)
            except TypeError as exc:
                raise FederationError(
                    "FEDERATION_INVALID_EVENT", events,
                ) from exc

            normalized = []
            for item in raw_items:
                self._event_id(item)
                normalized.append(self._normalized_event(item))

            before = len(self._backfilled)
            for item in normalized:
                event_id = item["event_id"]
                if self._is_duplicate(event_id):
                    self._stats["duplicates"] += 1
                    continue
                if self._dependencies_missing(item, check_auth=False):
                    self._park(item, backfill=True)
                else:
                    self._accept(item, backfill=True)
            self._drain_pending()
            return len(self._backfilled) - before

    def upgrade_room(self, new_version: str) -> str:
        with self._lock:
            if (
                not isinstance(new_version, str)
                or new_version not in SUPPORTED_VERSIONS
                or new_version == self._version
            ):
                raise FederationError(
                    "FEDERATION_INVALID_UPGRADE", new_version,
                )

            self._version = new_version
            self._epoch += 1
            self._tombstone_seq += 1
            heads = self._dag_heads_internal()
            depth = max(self._depth.values(), default=0) + 1
            event_id = (
                f"$tombstone:{self._tombstone_seq}:{new_version}"
            )
            tombstone = {
                "event_id": event_id,
                "type": "m.room.tombstone",
                "sender": self.creator,
                "room_id": self.room_id,
                "depth": depth,
                "prev_events": heads,
                "auth_events": [],
                "state_key": "",
                "content": {
                    "room_version": new_version,
                    "replacement_room": self.room_id,
                },
            }
            self._events[event_id] = tombstone
            self._depth[event_id] = depth
            self._event_epoch[event_id] = self._epoch
            self._stats["upgraded"] += 1
            self._recompute_state()
            return new_version

    def room_version(self) -> str:
        with self._lock:
            return self._version

    def event_depth(self, event_id: str) -> int:
        with self._lock:
            if event_id not in self._depth:
                raise FederationError("FEDERATION_UNKNOWN_EVENT", event_id)
            return self._depth[event_id]

    def pending_events(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._pending))

    def dag_heads(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._dag_heads_internal())

    def power_levels(self) -> dict:
        with self._lock:
            return self._power_context({})

    def snapshot(self) -> dict:
        with self._lock:
            heads = self._dag_heads_internal()
            return {
                "version": SNAPSHOT_VERSION,
                "room_id": self.room_id,
                "room_version": self._version,
                "events": copy.deepcopy(self._events),
                "pending": copy.deepcopy(self._pending),
                "heads": list(heads),
                "dag_heads": list(heads),
                "state": copy.deepcopy(self._state),
                "current_state": copy.deepcopy(self._state),
                "soft_failed": sorted(self._soft_failed),
                "rejected": sorted(self._rejected),
                "backfilled": sorted(self._backfilled),
                "stats": dict(self._stats),
                "depths": dict(self._depth),
                "event_epochs": dict(self._event_epoch),
                "pending_epochs": dict(self._pending_epoch),
                "pending_backfilled": sorted(self._pending_backfill),
                "soft_fail_reasons": dict(self._soft_fail_reasons),
                "epoch": self._epoch,
                "tombstone_seq": self._tombstone_seq,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._validated_snapshot(state)
            except FederationError:
                raise
            except Exception as exc:
                raise FederationError(
                    "FEDERATION_SNAPSHOT_INVALID", state,
                ) from exc

            self._version = restored["room_version"]
            self._events = restored["events"]
            self._pending = restored["pending"]
            self._depth = restored["depths"]
            self._event_epoch = restored["event_epochs"]
            self._pending_epoch = restored["pending_epochs"]
            self._pending_backfill = restored["pending_backfilled"]
            self._soft_failed = restored["soft_failed"]
            self._rejected = restored["rejected"]
            self._backfilled = restored["backfilled"]
            self._soft_fail_reasons = restored["soft_fail_reasons"]
            self._epoch = restored["epoch"]
            self._tombstone_seq = restored["tombstone_seq"]
            self._stats = restored["stats"]
            self._recompute_state()
            self._heads = set(self._dag_heads_internal())

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _event_id(self, event: object) -> str:
        if not isinstance(event, dict):
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        return event_id

    def _is_duplicate(self, event_id: str) -> bool:
        return event_id in self._events or event_id in self._pending

    def _duplicate_result(self, event_id: str) -> IngestResult | None:
        if not self._is_duplicate(event_id):
            return None
        self._stats["duplicates"] += 1
        return IngestResult(
            event_id,
            "duplicate",
            event_id in self._soft_failed,
            self._depth.get(event_id, 0),
        )

    def _normalized_event(self, event: dict) -> dict:
        item = copy.deepcopy(event)
        if not isinstance(item.get("type"), str):
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        if not isinstance(item.get("sender"), str):
            raise FederationError("FEDERATION_INVALID_EVENT", event)

        room_id = item.get("room_id", self.room_id)
        if room_id != self.room_id:
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        item["room_id"] = self.room_id

        for field in ("prev_events", "auth_events"):
            values = item.get(field, [])
            if not isinstance(values, (list, tuple)):
                raise FederationError("FEDERATION_INVALID_EVENT", event)
            if any(not isinstance(value, str) for value in values):
                raise FederationError("FEDERATION_INVALID_EVENT", event)
            item[field] = list(dict.fromkeys(values))

        if "state_key" in item and not isinstance(item["state_key"], str):
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        if not isinstance(item.get("content", {}), dict):
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        item["content"] = copy.deepcopy(item.get("content", {}))

        depth = item.get("depth")
        if depth is None:
            parent_depths = [
                self._depth[parent]
                for parent in item["prev_events"]
                if parent in self._depth
            ]
            depth = max(parent_depths, default=0) + 1
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise FederationError("FEDERATION_INVALID_EVENT", event)
        if depth > self.max_depth:
            raise FederationError("FEDERATION_DAG_LIMIT", depth)
        item["depth"] = depth
        return item

    def _declared_epoch(self, event: dict) -> int:
        declared = event.get("room_version")
        if declared is not None and str(declared) != self._version:
            return 0
        return self._epoch

    def _dependencies_missing(
        self, event: dict, *, check_auth: bool = True,
    ) -> bool:
        for parent in event["prev_events"]:
            if parent not in self._events:
                return True
        if check_auth:
            for auth_id in event["auth_events"]:
                if auth_id not in self._events:
                    return True
        return False

    def _park(self, event: dict, *, backfill: bool) -> IngestResult:
        if len(self._pending) >= self.max_pending:
            raise FederationError(
                "FEDERATION_PENDING_LIMIT", len(self._pending),
            )
        event_id = event["event_id"]
        self._pending[event_id] = copy.deepcopy(event)
        self._depth[event_id] = event["depth"]
        self._pending_epoch[event_id] = self._declared_epoch(event)
        if backfill:
            self._pending_backfill.add(event_id)
        self._stats["pending"] += 1
        return IngestResult(event_id, "pending", False, event["depth"])

    def _drain_pending(self) -> None:
        while True:
            ready = None
            for event_id in sorted(self._pending):
                event = self._pending[event_id]
                if not self._dependencies_missing(event):
                    ready = event_id
                    break
            if ready is None:
                return

            event = self._pending.pop(ready)
            epoch = self._pending_epoch.pop(ready, self._epoch)
            backfill = ready in self._pending_backfill
            self._pending_backfill.discard(ready)
            self._accept(event, backfill=backfill, epoch=epoch)

    def _accept(
        self, event: dict, *, backfill: bool, epoch: int | None = None,
    ) -> IngestResult:
        event_id = event["event_id"]
        depth = event["depth"]
        if epoch is None:
            epoch = self._declared_epoch(event)

        inherited_soft = (
            bool(event["prev_events"])
            and all(
                parent in self._soft_failed
                for parent in event["prev_events"]
            )
        )

        if not backfill:
            auth = self._authorize_with_view(event, self._auth_view(event))
            if not auth.allowed:
                self._store_event(event, epoch)
                self._rejected.add(event_id)
                self._stats["rejected"] += 1
                return IngestResult(event_id, "rejected", False, depth)

        self._store_event(event, epoch)
        if backfill:
            self._backfilled.add(event_id)
            self._stats["backfilled"] += 1
            return IngestResult(event_id, "accepted", False, depth)

        self._stats["accepted"] += 1
        if inherited_soft:
            self._mark_soft_failed(event_id)
        self._recompute_state()
        return IngestResult(
            event_id, "accepted", event_id in self._soft_failed, depth,
        )

    def _store_event(self, event: dict, epoch: int) -> None:
        event_id = event["event_id"]
        self._events[event_id] = copy.deepcopy(event)
        self._depth[event_id] = event["depth"]
        self._event_epoch[event_id] = epoch

    def _mark_soft_failed(self, event_id: str) -> bool:
        if event_id in self._soft_failed:
            return False
        self._soft_failed.add(event_id)
        self._stats["soft_failed"] += 1
        return True

    def _propagate_soft_failure(self, origin: str) -> None:
        children: dict[str, list[str]] = {}
        for event_id, event in self._events.items():
            for parent in event["prev_events"]:
                children.setdefault(parent, []).append(event_id)

        queue = [origin]
        while queue:
            parent = queue.pop()
            for child in sorted(children.get(parent, ())):
                if child in self._soft_failed:
                    continue
                parents = self._events[child]["prev_events"]
                if (
                    parents
                    and all(p in self._soft_failed for p in parents)
                    and self._mark_soft_failed(child)
                ):
                    queue.append(child)

    def _recompute_state(self) -> None:
        state: dict[tuple[str, str], str] = {}
        for event_id, event in self._events.items():
            if event_id in self._rejected or event_id in self._soft_failed:
                continue
            if event_id in self._backfilled:
                continue
            if self._event_epoch.get(event_id) != self._epoch:
                continue
            state_key = self._state_key(event)
            if state_key is None:
                continue
            key = (event["type"], state_key)
            current = state.get(key)
            if current is None:
                state[key] = event_id
                continue
            current_rank = (self._depth[current], current)
            candidate_rank = (self._depth[event_id], event_id)
            if candidate_rank > current_rank:
                state[key] = event_id
        self._state = state

    def _dag_heads_internal(self) -> list[str]:
        children = set()
        for event in self._events.values():
            children.update(event["prev_events"])
        return sorted(set(self._events) - children)

    def _auth_view(self, event: dict) -> dict[tuple[str, str], dict]:
        view: dict[tuple[str, str], dict] = {}
        for auth_id in event.get("auth_events", []):
            auth_event = self._events.get(auth_id)
            if auth_event is None:
                continue
            if auth_id in self._rejected or auth_id in self._soft_failed:
                continue
            state_key = self._state_key(auth_event)
            if state_key is None:
                continue
            key = (auth_event["type"], state_key)
            current = view.get(key)
            if current is None or (
                self._depth[auth_id], auth_id
            ) > (
                self._depth[current["event_id"]], current["event_id"]
            ):
                view[key] = auth_event
        return view

    def _state_key(self, event: dict) -> str | None:
        if event.get("type") in NON_STATE_TYPES:
            return None
        return event.get("state_key")

    def _lookup_auth_event(
        self, view: dict[tuple[str, str], dict], key: tuple[str, str],
    ) -> dict | None:
        event = view.get(key)
        if event is not None:
            return event
        event_id = self._state.get(key)
        if event_id is None:
            return None
        return self._events.get(event_id)

    def _power_context(
        self, view: dict[tuple[str, str], dict],
    ) -> dict:
        power_event = self._lookup_auth_event(
            view, ("m.room.power_levels", ""),
        )
        if power_event is None:
            power = copy.deepcopy(DEFAULT_POWER)
            create_event = self._lookup_auth_event(
                view, ("m.room.create", ""),
            )
            creator = self.creator
            if create_event is not None:
                content = create_event.get("content", {})
                if isinstance(content, dict):
                    creator = content.get("creator", creator)
            power["users"] = {creator: 100}
            return power

        power = copy.deepcopy(DEFAULT_POWER)
        content = power_event.get("content", {})
        if isinstance(content, dict):
            for key, value in content.items():
                power[key] = copy.deepcopy(value)
        if not isinstance(power.get("users"), dict):
            power["users"] = {}
        if not isinstance(power.get("events"), dict):
            power["events"] = {}
        return power

    def _level(self, power: dict, key: str, default: int) -> int:
        value = power.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            return default
        return value

    def _user_level(self, power: dict, user_id: str) -> int:
        users = power.get("users", {})
        if isinstance(users, dict) and user_id in users:
            value = users[user_id]
            if not isinstance(value, bool) and isinstance(value, int):
                return value
        return self._level(power, "users_default", 0)

    def _event_level(self, power: dict, event_type: str) -> int:
        events = power.get("events", {})
        if isinstance(events, dict) and event_type in events:
            value = events[event_type]
            if not isinstance(value, bool) and isinstance(value, int):
                return value
        return self._level(power, "state_default", 50)

    def _membership(
        self, view: dict[tuple[str, str], dict], user_id: str,
    ) -> str | None:
        member_event = self._lookup_auth_event(
            view, ("m.room.member", user_id),
        )
        if member_event is None:
            return None
        content = member_event.get("content", {})
        if not isinstance(content, dict):
            return None
        membership = content.get("membership")
        return membership if isinstance(membership, str) else None

    def _join_rule(
        self, view: dict[tuple[str, str], dict],
    ) -> str:
        join_rules = self._lookup_auth_event(
            view, ("m.room.join_rules", ""),
        )
        if join_rules is None:
            return "public"
        content = join_rules.get("content", {})
        if not isinstance(content, dict):
            return "public"
        rule = content.get("join_rule")
        return rule if isinstance(rule, str) else "public"

    def _grants_above_sender(
        self, event: dict, sender_power: int,
    ) -> bool:
        content = event.get("content", {})
        if not isinstance(content, dict):
            return True

        for section in ("users", "events"):
            values = content.get(section, {})
            if not isinstance(values, dict):
                return True
            for value in values.values():
                if isinstance(value, bool) or not isinstance(value, int):
                    return True
                if value > sender_power:
                    return True

        for key in (
            "users_default", "events_default", "state_default",
            "kick", "ban", "invite",
        ):
            if key not in content:
                continue
            value = content[key]
            if isinstance(value, bool) or not isinstance(value, int):
                return True
            if value > sender_power:
                return True
        return False

    def _authorize_with_view(
        self, event: dict, view: dict[tuple[str, str], dict],
    ) -> AuthResult:
        event_type = event["type"]
        sender = event["sender"]
        power = self._power_context(view)
        sender_power = self._user_level(power, sender)

        if event_type == "m.room.create":
            return AuthResult(True, "allowed", 0, sender_power)

        if event_type == "m.room.member":
            return self._authorize_membership(
                event, view, power, sender_power,
            )

        is_state = self._state_key(event) is not None
        if is_state:
            required = self._event_level(power, event_type)
        else:
            required = self._level(power, "events_default", 0)

        if self._membership(view, sender) != "join":
            return AuthResult(
                False, "not_joined", required, sender_power,
            )
        if sender_power < required:
            return AuthResult(
                False, "insufficient_power", required, sender_power,
            )
        if event_type == "m.room.power_levels":
            if self._grants_above_sender(event, sender_power):
                return AuthResult(
                    False, "insufficient_power", required, sender_power,
                )
        return AuthResult(True, "allowed", required, sender_power)

    def _authorize_membership(
        self, event: dict, view: dict[tuple[str, str], dict],
        power: dict, sender_power: int,
    ) -> AuthResult:
        sender = event["sender"]
        target = event.get("state_key")
        content = event.get("content", {})
        membership = (
            content.get("membership")
            if isinstance(content, dict) else None
        )
        sender_membership = self._membership(view, sender)
        state_default = self._level(power, "state_default", 50)

        if membership == "join":
            if target != sender:
                if sender_membership != "join":
                    return AuthResult(
                        False, "not_joined", state_default, sender_power,
                    )
                return AuthResult(
                    False, "membership_denied",
                    state_default, sender_power,
                )
            if sender_membership == "join":
                return AuthResult(True, "allowed", 0, sender_power)
            if sender_membership == "ban":
                return AuthResult(
                    False, "membership_denied", 0, sender_power,
                )
            if sender_membership == "invite":
                return AuthResult(True, "allowed", 0, sender_power)
            if self._join_rule(view) == "invite":
                return AuthResult(
                    False, "membership_denied", 0, sender_power,
                )
            return AuthResult(True, "allowed", 0, sender_power)

        if membership == "invite":
            required = self._level(power, "invite", 0)
            if sender_membership != "join":
                return AuthResult(
                    False, "not_joined", required, sender_power,
                )
            if sender_power < required:
                return AuthResult(
                    False, "insufficient_power", required, sender_power,
                )
            return AuthResult(True, "allowed", required, sender_power)

        if membership == "leave":
            if target == sender:
                return AuthResult(True, "allowed", 0, sender_power)
            required = self._level(power, "kick", 50)
            if sender_membership != "join":
                return AuthResult(
                    False, "not_joined", required, sender_power,
                )
            if sender_power < required:
                return AuthResult(
                    False, "insufficient_power", required, sender_power,
                )
            return AuthResult(True, "allowed", required, sender_power)

        if membership == "ban":
            required = self._level(power, "ban", 50)
            if sender_membership != "join":
                return AuthResult(
                    False, "not_joined", required, sender_power,
                )
            if sender_power < required:
                return AuthResult(
                    False, "insufficient_power", required, sender_power,
                )
            return AuthResult(True, "allowed", required, sender_power)

        if membership == "knock":
            if self._join_rule(view) == "invite":
                return AuthResult(
                    False, "membership_denied", 0, sender_power,
                )
            return AuthResult(True, "allowed", 0, sender_power)

        return AuthResult(
            False, "membership_denied", state_default, sender_power,
        )

    def _validated_snapshot(self, state: dict) -> dict:
        if not isinstance(state, dict):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)
        version = state.get("version")
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version != SNAPSHOT_VERSION
        ):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)

        room_version = state.get("room_version")
        if room_version not in SUPPORTED_VERSIONS:
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)

        events = state.get("events")
        pending = state.get("pending", {})
        if not isinstance(events, dict) or not isinstance(pending, dict):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)

        events_copy = copy.deepcopy(events)
        pending_copy = copy.deepcopy(pending)
        for source in (events_copy, pending_copy):
            for event_id, event in source.items():
                if not isinstance(event_id, str):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if not isinstance(event, dict):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if event.get("event_id") != event_id:
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if not isinstance(event.get("type"), str):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if not isinstance(event.get("sender"), str):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if "state_key" in event and not isinstance(
                    event["state_key"], str,
                ):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if not isinstance(event.get("content", {}), dict):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if not isinstance(event.get("prev_events"), list):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )
                if not isinstance(event.get("auth_events"), list):
                    raise FederationError(
                        "FEDERATION_SNAPSHOT_INVALID", state,
                    )

        depths = state.get("depths")
        if not isinstance(depths, dict):
            depths = {}
        depths = {
            event_id: event.get("depth")
            for event_id, event in {**events_copy, **pending_copy}.items()
        } | {
            event_id: depth
            for event_id, depth in depths.items()
            if event_id in events_copy or event_id in pending_copy
        }
        for event_id, depth in depths.items():
            if isinstance(depth, bool) or not isinstance(depth, int):
                raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)

        epoch = state.get("epoch", 1)
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)
        event_epochs = state.get("event_epochs")
        if not isinstance(event_epochs, dict):
            event_epochs = {
                event_id: epoch for event_id in events_copy
            }
        event_epochs = {
            event_id: event_epochs.get(event_id, epoch)
            for event_id in events_copy
        }
        pending_epochs = state.get("pending_epochs")
        if not isinstance(pending_epochs, dict):
            pending_epochs = {
                event_id: epoch for event_id in pending_copy
            }
        pending_epochs = {
            event_id: pending_epochs.get(event_id, epoch)
            for event_id in pending_copy
        }

        soft_failed = self._string_set(
            state.get("soft_failed", []), state,
        )
        rejected = self._string_set(
            state.get("rejected", []), state,
        )
        backfilled = self._string_set(
            state.get("backfilled", []), state,
        )
        pending_backfilled = self._string_set(
            state.get("pending_backfilled", []), state,
        )

        reasons = state.get("soft_fail_reasons", {})
        if not isinstance(reasons, dict):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)

        stats = dict(self._stats)
        supplied_stats = state.get("stats", {})
        if not isinstance(supplied_stats, dict):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)
        for key in stats:
            value = supplied_stats.get(key, stats[key])
            if isinstance(value, bool) or not isinstance(value, int):
                raise FederationError(
                    "FEDERATION_SNAPSHOT_INVALID", state,
                )
            stats[key] = value

        tombstone_seq = state.get("tombstone_seq", 0)
        if isinstance(tombstone_seq, bool) or not isinstance(
            tombstone_seq, int,
        ):
            raise FederationError("FEDERATION_SNAPSHOT_INVALID", state)

        return {
            "room_version": room_version,
            "events": events_copy,
            "pending": pending_copy,
            "depths": depths,
            "event_epochs": event_epochs,
            "pending_epochs": pending_epochs,
            "pending_backfilled": pending_backfilled,
            "soft_failed": soft_failed,
            "rejected": rejected,
            "backfilled": backfilled,
            "soft_fail_reasons": copy.deepcopy(reasons),
            "epoch": epoch,
            "tombstone_seq": tombstone_seq,
            "stats": stats,
        }

    def _string_set(self, value: object, snapshot: dict) -> set[str]:
        if isinstance(value, (set, frozenset, list, tuple)):
            if all(isinstance(item, str) for item in value):
                return set(value)
        raise FederationError("FEDERATION_SNAPSHOT_INVALID", snapshot)
