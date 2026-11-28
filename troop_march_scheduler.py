"""部队行军调度：路径耗时、同格到达排队、加速与中途召回。"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

MARCH_STATES = ("marching", "returning", "resolved")
SNAPSHOT_VERSION = 1

_ACTIVE_STATES = ("marching", "returning")
_DEFAULT_COUNTERS = {
    "dispatched": 0,
    "resolved": 0,
    "recalled": 0,
    "speed_ups": 0,
    "speedup_minutes": 0,
    "speedup_refunded_ms": 0,
    "failed_arrivals": 0,
    "rejected": 0,
}


class MarchError(ValueError):
    """Raised when a march operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class March:
    troop_id: str
    player: str
    origin: tuple[int, int]
    target: tuple[int, int]
    speed: int
    troops: int
    departed_at: int
    arrive_at: int
    seq: int
    state: str


@dataclass(frozen=True)
class ArrivalResult:
    troop_id: str
    tile: tuple[int, int]
    order: int
    state: str
    at: int
    next_troop: str | None


@dataclass(frozen=True)
class RecallResult:
    troop_id: str
    state: str
    progress: float
    return_arrive_at: int
    stamina_refund: int


@dataclass
class _MarchRecord:
    troop_id: str
    player: str
    origin: tuple[int, int]
    target: tuple[int, int]
    speed: int
    troops: int
    departed_at: int
    arrive_at: int
    seq: int
    state: str
    return_departed_at: int | None = None
    return_arrive_at: int | None = None
    settlement_order: int | None = None
    tile_next_order_at_dispatch: int | None = None
    recall_progress: float | None = None
    stamina_refund: int = 0
    failure: str | None = None
    target_captured: bool = False

    def public(self) -> March:
        return March(
            troop_id=self.troop_id,
            player=self.player,
            origin=self.origin,
            target=self.target,
            speed=self.speed,
            troops=self.troops,
            departed_at=self.departed_at,
            arrive_at=self.arrive_at,
            seq=self.seq,
            state=self.state,
        )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _non_empty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _coord(value: object) -> tuple[int, int] | None:
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        return None
    x, y = value
    if not _is_int(x) or not _is_int(y) or x < 0 or y < 0:
        return None
    return (x, y)


def _distance(origin: tuple[int, int], target: tuple[int, int]) -> int:
    return max(abs(origin[0] - target[0]), abs(origin[1] - target[1]))


def _duration(origin: tuple[int, int], target: tuple[int, int], speed: int) -> int:
    return (_distance(origin, target) * 1000 + speed - 1) // speed


class TroopMarchScheduler:
    """Plan marches on the world grid and settle same-tile arrivals in order."""

    def __init__(self, *, max_marches_per_player: int = 5,
                 tile_capacity: int = 3) -> None:
        if not _is_int(max_marches_per_player) or max_marches_per_player <= 0:
            raise MarchError("MARCH_INVALID_REQUEST", "max_marches_per_player")
        if not _is_int(tile_capacity) or tile_capacity <= 0:
            raise MarchError("MARCH_INVALID_REQUEST", "tile_capacity")
        self.max_marches_per_player = max_marches_per_player
        self.tile_capacity = tile_capacity
        self._lock = threading.RLock()
        self._marches: dict[str, _MarchRecord] = {}
        self._seq = 0
        self._counters = dict(_DEFAULT_COUNTERS)
        self._tile_next_order: dict[tuple[int, int], int] = {}
        self._captured_tiles: set[tuple[int, int]] = set()
        self._clock = 0

    def _reject(self, code: str, detail: object = None) -> None:
        self._counters["rejected"] += 1
        raise MarchError(code, detail)

    def _require_at(self, at: object) -> int:
        if not _is_int(at) or at < 0:
            self._reject("MARCH_INVALID_REQUEST", "at")
        return at

    def _record(self, troop_id: str) -> _MarchRecord:
        record = self._marches.get(troop_id)
        if record is None:
            self._reject("MARCH_UNKNOWN_TROOP", troop_id)
        return record

    def _touch_clock(self, at: int) -> None:
        if at > self._clock:
            self._clock = at

    def _active_inbound(self, tile: tuple[int, int]) -> list[_MarchRecord]:
        records = [
            record for record in self._marches.values()
            if record.state == "marching" and record.target == tile
        ]
        records.sort(key=lambda record: (record.arrive_at, record.seq))
        return records

    def _active_for_player(self, player: str) -> list[_MarchRecord]:
        records = [
            record for record in self._marches.values()
            if record.player == player and record.state in _ACTIVE_STATES
        ]
        records.sort(key=lambda record: record.seq)
        return records

    def _assign_queue_orders(self, tile: tuple[int, int],
                             records: list[_MarchRecord]) -> None:
        pending = [record for record in records if record.settlement_order is None]
        if not pending:
            return
        pending.sort(key=lambda record: (record.arrive_at, record.seq))
        next_order = self._tile_next_order.get(tile, 1)
        for record in pending:
            record.settlement_order = next_order
            next_order += 1
        self._tile_next_order[tile] = next_order

    def _next_in_queue(self, tile: tuple[int, int],
                       current: _MarchRecord) -> str | None:
        queue = self._active_inbound(tile)
        for index, record in enumerate(queue):
            if record.troop_id == current.troop_id:
                if index + 1 < len(queue):
                    return queue[index + 1].troop_id
                return None
        return None

    def dispatch(self, troop_id: str, player: str, *, origin: tuple[int, int],
                 target: tuple[int, int], speed: int, troops: int, at: int) -> March:
        """Send one troop and compute its absolute arrival timestamp."""
        with self._lock:
            if not _non_empty_text(troop_id) or not _non_empty_text(player):
                self._reject("MARCH_INVALID_REQUEST")
            origin_value = _coord(origin)
            target_value = _coord(target)
            if origin_value is None or target_value is None:
                self._reject("MARCH_INVALID_COORD")
            if not _is_int(speed) or not 1 <= speed <= 10:
                self._reject("MARCH_INVALID_SPEED", speed)
            if not _is_int(troops) or troops <= 0:
                self._reject("MARCH_INVALID_TROOPS", troops)
            if origin_value == target_value:
                self._reject("MARCH_INVALID_TARGET", target)
            at_value = self._require_at(at)

            existing = self._marches.get(troop_id)
            if existing is not None and existing.state in _ACTIVE_STATES:
                self._reject("MARCH_ALREADY_MARCHING", troop_id)
            if len(self._active_for_player(player)) >= self.max_marches_per_player:
                self._reject("MARCH_LIMIT_EXCEEDED", player)
            if len(self._active_inbound(target_value)) >= self.tile_capacity:
                self._reject(
                    "MARCH_LIMIT_EXCEEDED",
                    {"tile": target_value, "capacity": self.tile_capacity},
                )

            seq = self._seq + 1
            record = _MarchRecord(
                troop_id=troop_id,
                player=player,
                origin=origin_value,
                target=target_value,
                speed=speed,
                troops=troops,
                departed_at=at_value,
                arrive_at=at_value + _duration(origin_value, target_value, speed),
                seq=seq,
                state="marching",
                tile_next_order_at_dispatch=self._tile_next_order.get(
                    target_value, 1
                ),
                target_captured=target_value in self._captured_tiles,
            )
            self._marches[troop_id] = record
            self._seq = seq
            self._touch_clock(at_value)
            self._counters["dispatched"] += 1
            return record.public()

    def eta(self, troop_id: str) -> int:
        """Absolute arrival timestamp of one march."""
        with self._lock:
            record = self._record(troop_id)
            if record.state == "returning" and record.return_arrive_at is not None:
                return record.return_arrive_at
            return record.arrive_at

    def arrive_queue(self, tile: tuple[int, int], *, at: int) -> tuple[str, ...]:
        """Troops that have reached one tile by ``at`` in settlement order."""
        with self._lock:
            tile_value = _coord(tile)
            if tile_value is None:
                self._reject("MARCH_INVALID_COORD")
            at_value = self._require_at(at)
            self._touch_clock(at_value)
            records = [
                record for record in self._active_inbound(tile_value)
                if record.arrive_at <= at_value
            ]
            return tuple(record.troop_id for record in records)

    def speed_up(self, troop_id: str, seconds: int) -> int:
        """Spend speed-up items on one march and return the minutes charged."""
        with self._lock:
            record = self._record(troop_id)
            if record.state == "resolved":
                self._reject("MARCH_ALREADY_RESOLVED", troop_id)
            if record.state == "returning":
                self._reject("MARCH_ALREADY_RESOLVED", troop_id)
            if not _is_int(seconds) or seconds <= 0:
                self._reject("MARCH_INVALID_REQUEST", "seconds")

            remaining = record.arrive_at - self._clock
            if remaining <= 0:
                self._reject("MARCH_ALREADY_ARRIVED", troop_id)

            minutes = max(1, (seconds + 59) // 60)
            requested = seconds * 1_000
            billed = minutes * 60_000
            minimum_remaining = min(1_000, remaining)
            reduction = min(requested, remaining - minimum_remaining)
            if reduction < 0:
                reduction = 0
            record.arrive_at -= reduction
            refund = billed - reduction
            self._counters["speed_ups"] += 1
            self._counters["speedup_minutes"] += minutes
            self._counters["speedup_refunded_ms"] += refund
            return minutes

    def recall(self, troop_id: str, *, at: int) -> RecallResult:
        """Turn one march around and refund part of the stamina."""
        with self._lock:
            record = self._record(troop_id)
            if record.state != "marching":
                self._reject("MARCH_ALREADY_ARRIVED", troop_id)
            at_value = self._require_at(at)
            if at_value >= record.arrive_at:
                self._reject("MARCH_ALREADY_ARRIVED", troop_id)

            duration = record.arrive_at - record.departed_at
            elapsed = max(0, min(duration, at_value - record.departed_at))
            progress = elapsed / duration
            refund = int(record.troops * 0.5 * (1.0 - progress))

            record.state = "returning"
            record.return_departed_at = at_value
            record.return_arrive_at = at_value + elapsed
            record.recall_progress = progress
            record.stamina_refund = refund
            self._touch_clock(at_value)
            self._counters["recalled"] += 1
            return RecallResult(
                troop_id=troop_id,
                state=record.state,
                progress=progress,
                return_arrive_at=record.return_arrive_at,
                stamina_refund=refund,
            )

    def resolve_arrival(self, troop_id: str, *, at: int) -> ArrivalResult:
        """Settle one arrived march against the tile arrival queue."""
        with self._lock:
            record = self._record(troop_id)
            if record.state == "resolved" or record.state == "returning":
                self._reject("MARCH_ALREADY_RESOLVED", troop_id)
            at_value = self._require_at(at)
            if at_value < record.arrive_at:
                self._reject("MARCH_NOT_ARRIVED", troop_id)

            queue = self._active_inbound(record.target)
            next_troop = self._next_in_queue(record.target, record)

            if record.target in self._captured_tiles:
                duration = _duration(record.origin, record.target, record.speed)
                record.state = "returning"
                record.return_departed_at = at_value
                record.return_arrive_at = at_value + duration
                record.failure = "target_captured"
                record.target_captured = True
                self._touch_clock(at_value)
                self._counters["failed_arrivals"] += 1
                return ArrivalResult(
                    troop_id=troop_id,
                    tile=record.target,
                    order=0,
                    state=record.state,
                    at=at_value,
                    next_troop=next_troop,
                )

            eligible = [item for item in queue if item.arrive_at <= at_value]
            self._assign_queue_orders(record.target, eligible)
            order = record.settlement_order
            if order is None:
                order = 0
            record.state = "resolved"
            self._touch_clock(at_value)
            self._counters["resolved"] += 1
            return ArrivalResult(
                troop_id=troop_id,
                tile=record.target,
                order=order,
                state=record.state,
                at=at_value,
                next_troop=next_troop,
            )

    def march_of(self, troop_id: str) -> March | None:
        """Stored march record, or None when the troop id is unknown."""
        with self._lock:
            record = self._marches.get(troop_id)
            return None if record is None else record.public()

    def active_marches(self, player: str) -> tuple[str, ...]:
        """Troops of one player that are still in transit, in departure order."""
        with self._lock:
            return tuple(record.troop_id for record in self._active_for_player(player))

    def capture_tile(self, tile: tuple[int, int], *,
                     at: int | None = None) -> tuple[str, ...]:
        """Mark a tile as captured by an enemy and return its inbound troops."""
        with self._lock:
            tile_value = _coord(tile)
            if tile_value is None:
                self._reject("MARCH_INVALID_COORD")
            if at is not None:
                at_value = self._require_at(at)
                self._touch_clock(at_value)
            self._captured_tiles.add(tile_value)
            inbound = self._active_inbound(tile_value)
            for record in inbound:
                record.target_captured = True
            return tuple(record.troop_id for record in inbound)

    def mark_tile_captured(self, tile: tuple[int, int], *,
                           at: int | None = None) -> tuple[str, ...]:
        return self.capture_tile(tile, at=at)

    def set_tile_captured(self, tile: tuple[int, int], *,
                          at: int | None = None) -> tuple[str, ...]:
        return self.capture_tile(tile, at=at)

    def release_tile(self, tile: tuple[int, int]) -> None:
        with self._lock:
            tile_value = _coord(tile)
            if tile_value is None:
                self._reject("MARCH_INVALID_COORD")
            self._captured_tiles.discard(tile_value)
            for record in self._marches.values():
                if record.target == tile_value:
                    record.target_captured = False

    def snapshot(self) -> dict:
        """Deep-copied scheduler state for restart recovery."""
        with self._lock:
            marches = []
            for record in sorted(self._marches.values(),
                                 key=lambda item: item.seq):
                marches.append({
                    "troop_id": record.troop_id,
                    "player": record.player,
                    "origin": list(record.origin),
                    "target": list(record.target),
                    "speed": record.speed,
                    "troops": record.troops,
                    "departed_at": record.departed_at,
                    "arrive_at": record.arrive_at,
                    "seq": record.seq,
                    "state": record.state,
                    "return_departed_at": record.return_departed_at,
                    "return_arrive_at": record.return_arrive_at,
                    "settlement_order": record.settlement_order,
                    "tile_next_order_at_dispatch": (
                        record.tile_next_order_at_dispatch
                    ),
                    "recall_progress": record.recall_progress,
                    "stamina_refund": record.stamina_refund,
                    "failure": record.failure,
                    "target_captured": record.target_captured,
                    "clock": self._clock,
                })
            config = {
                "max_marches_per_player": self.max_marches_per_player,
                "tile_capacity": self.tile_capacity,
            }
            if self._captured_tiles:
                config["captured_tiles"] = [
                    list(tile) for tile in sorted(self._captured_tiles)
                ]
            return {
                "version": SNAPSHOT_VERSION,
                "config": config,
                "marches": marches,
                "seq": self._seq,
                "counters": copy.deepcopy(self._counters),
            }

    def restore(self, state: dict) -> None:
        """Replace the scheduler state from a snapshot, rejecting malformed payloads."""
        with self._lock:
            try:
                self._restore_locked(state)
            except MarchError:
                raise
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise MarchError("MARCH_SNAPSHOT_INVALID", str(exc)) from exc

    def _restore_locked(self, state: object) -> None:
        expected_keys = {"version", "config", "marches", "seq", "counters"}
        if not isinstance(state, dict) or set(state) != expected_keys:
            raise MarchError("MARCH_SNAPSHOT_INVALID")
        if not _is_int(state["version"]) or state["version"] != SNAPSHOT_VERSION:
            raise MarchError("MARCH_SNAPSHOT_INVALID", "version")

        config = state["config"]
        if not isinstance(config, dict):
            raise MarchError("MARCH_SNAPSHOT_INVALID", "config")
        max_marches = config.get("max_marches_per_player")
        tile_capacity = config.get("tile_capacity")
        if not _is_int(max_marches) or max_marches <= 0:
            raise MarchError("MARCH_SNAPSHOT_INVALID", "config")
        if not _is_int(tile_capacity) or tile_capacity <= 0:
            raise MarchError("MARCH_SNAPSHOT_INVALID", "config")
        raw_captured = config.get("captured_tiles", [])
        if not isinstance(raw_captured, list):
            raise MarchError("MARCH_SNAPSHOT_INVALID", "config")
        captured_tiles: set[tuple[int, int]] = set()
        for raw_tile in raw_captured:
            tile_value = _coord(raw_tile)
            if tile_value is None:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "config")
            captured_tiles.add(tile_value)

        raw_marches = state["marches"]
        if not isinstance(raw_marches, list):
            raise MarchError("MARCH_SNAPSHOT_INVALID", "marches")
        seq_value = state["seq"]
        if not _is_int(seq_value) or seq_value < 0:
            raise MarchError("MARCH_SNAPSHOT_INVALID", "seq")

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise MarchError("MARCH_SNAPSHOT_INVALID", "counters")
        counters = dict(_DEFAULT_COUNTERS)
        for key, value in raw_counters.items():
            if not isinstance(key, str) or not _is_int(value) or value < 0:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "counters")
            counters[key] = value

        marches: dict[str, _MarchRecord] = {}
        seen_seqs: set[int] = set()
        max_seq = 0
        tile_next: dict[tuple[int, int], int] = {}
        tile_orders: dict[tuple[int, int], set[int]] = {}
        clock = 0

        for raw in raw_marches:
            if not isinstance(raw, dict):
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march")
            troop_id = raw.get("troop_id")
            player = raw.get("player")
            if not _non_empty_text(troop_id) or not _non_empty_text(player):
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march")
            if troop_id in marches:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "duplicate troop")

            origin = _coord(raw.get("origin"))
            target = _coord(raw.get("target"))
            if origin is None or target is None or origin == target:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march coord")
            speed = raw.get("speed")
            troops = raw.get("troops")
            if not _is_int(speed) or not 1 <= speed <= 10:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march speed")
            if not _is_int(troops) or troops <= 0:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march troops")
            departed_at = raw.get("departed_at")
            arrive_at = raw.get("arrive_at")
            seq = raw.get("seq")
            march_state = raw.get("state")
            if not _is_int(departed_at) or departed_at < 0:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march time")
            if not _is_int(arrive_at) or arrive_at <= departed_at:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march time")
            if not _is_int(seq) or seq <= 0 or seq in seen_seqs:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march seq")
            if march_state not in MARCH_STATES:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "march state")
            seen_seqs.add(seq)
            max_seq = max(max_seq, seq)

            return_departed_at = raw.get("return_departed_at")
            return_arrive_at = raw.get("return_arrive_at")
            if return_departed_at is not None:
                if not _is_int(return_departed_at) or return_departed_at < 0:
                    raise MarchError("MARCH_SNAPSHOT_INVALID", "return time")
            if return_arrive_at is not None:
                if not _is_int(return_arrive_at) or return_arrive_at < 0:
                    raise MarchError("MARCH_SNAPSHOT_INVALID", "return time")
            if march_state == "returning":
                if return_departed_at is None or return_arrive_at is None:
                    raise MarchError("MARCH_SNAPSHOT_INVALID", "return time")
                if return_arrive_at < return_departed_at:
                    raise MarchError("MARCH_SNAPSHOT_INVALID", "return time")

            settlement_order = raw.get("settlement_order")
            if settlement_order is not None:
                if not _is_int(settlement_order) or settlement_order <= 0:
                    raise MarchError("MARCH_SNAPSHOT_INVALID", "settlement order")

            tile_next_at_dispatch = raw.get("tile_next_order_at_dispatch")
            if tile_next_at_dispatch is not None:
                if not _is_int(tile_next_at_dispatch) or tile_next_at_dispatch < 1:
                    raise MarchError(
                        "MARCH_SNAPSHOT_INVALID", "tile next order"
                    )

            recall_progress = raw.get("recall_progress")
            if recall_progress is not None:
                if (not isinstance(recall_progress, (int, float))
                        or isinstance(recall_progress, bool)
                        or not 0 <= recall_progress <= 1):
                    raise MarchError("MARCH_SNAPSHOT_INVALID", "recall progress")

            stamina_refund = raw.get("stamina_refund", 0)
            if not _is_int(stamina_refund) or stamina_refund < 0:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "stamina refund")
            failure = raw.get("failure")
            if failure is not None and not isinstance(failure, str):
                raise MarchError("MARCH_SNAPSHOT_INVALID", "failure")
            target_captured = raw.get("target_captured", False)
            if not isinstance(target_captured, bool):
                raise MarchError("MARCH_SNAPSHOT_INVALID", "captured")
            record_clock = raw.get("clock", 0)
            if not _is_int(record_clock) or record_clock < 0:
                raise MarchError("MARCH_SNAPSHOT_INVALID", "clock")

            record = _MarchRecord(
                troop_id=troop_id,
                player=player,
                origin=origin,
                target=target,
                speed=speed,
                troops=troops,
                departed_at=departed_at,
                arrive_at=arrive_at,
                seq=seq,
                state=march_state,
                return_departed_at=return_departed_at,
                return_arrive_at=return_arrive_at,
                settlement_order=settlement_order,
                tile_next_order_at_dispatch=tile_next_at_dispatch,
                recall_progress=recall_progress,
                stamina_refund=stamina_refund,
                failure=failure,
                target_captured=target_captured,
            )
            marches[troop_id] = record
            if settlement_order is not None:
                used_orders = tile_orders.setdefault(target, set())
                if settlement_order in used_orders:
                    raise MarchError(
                        "MARCH_SNAPSHOT_INVALID", "duplicate settlement order"
                    )
                used_orders.add(settlement_order)
                tile_next[target] = max(tile_next.get(target, 1),
                                        settlement_order + 1)
            if tile_next_at_dispatch is not None:
                tile_next[target] = max(
                    tile_next.get(target, 1), tile_next_at_dispatch
                )
            if target_captured:
                captured_tiles.add(target)
            clock = max(clock, departed_at)
            clock = max(clock, record_clock)
            if return_departed_at is not None:
                clock = max(clock, return_departed_at)

        if seq_value < max_seq:
            raise MarchError("MARCH_SNAPSHOT_INVALID", "seq")

        active_by_player: dict[str, int] = {}
        inbound_by_tile: dict[tuple[int, int], int] = {}
        for record in marches.values():
            if record.state in _ACTIVE_STATES:
                active_by_player[record.player] = (
                    active_by_player.get(record.player, 0) + 1
                )
            if record.state == "marching":
                inbound_by_tile[record.target] = (
                    inbound_by_tile.get(record.target, 0) + 1
                )
        if any(count > max_marches for count in active_by_player.values()):
            raise MarchError("MARCH_SNAPSHOT_INVALID", "player capacity")
        if any(count > tile_capacity for count in inbound_by_tile.values()):
            raise MarchError("MARCH_SNAPSHOT_INVALID", "tile capacity")

        self.max_marches_per_player = max_marches
        self.tile_capacity = tile_capacity
        self._marches = marches
        self._seq = seq_value
        self._counters = counters
        self._tile_next_order = tile_next
        self._captured_tiles = captured_tiles
        self._clock = clock

    def stats(self) -> dict:
        """Counters collected since the scheduler was created."""
        with self._lock:
            result = copy.deepcopy(self._counters)
            result["speedups"] = result.get("speed_ups", 0)
            result["recalls"] = result.get("recalled", 0)
            result["arrived"] = result.get("resolved", 0)
            return result
