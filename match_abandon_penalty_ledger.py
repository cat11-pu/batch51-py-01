"""Abandon penalty ledger: leave kinds, grace reconnect and settlement ladder."""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass, replace


KIND_VOLUNTARY = "voluntary"
KIND_DISCONNECT = "disconnect"
KIND_SERVER_FAULT = "server_fault"
KINDS = (KIND_VOLUNTARY, KIND_DISCONNECT, KIND_SERVER_FAULT)

POINTS_BY_KIND = {
    KIND_VOLUNTARY: 3,
    KIND_DISCONNECT: 1,
    KIND_SERVER_FAULT: 0,
}

TIER_CLEAN = "clean"
TIER_WATCH = "watch"
TIER_RESTRICTED = "restricted"
TIER_SUSPENDED = "suspended"

TIER_LADDER = (
    (6, TIER_SUSPENDED, 1800),
    (4, TIER_RESTRICTED, 900),
    (2, TIER_WATCH, 300),
    (0, TIER_CLEAN, 0),
)

DEFAULT_CONFIG = {
    "grace_window": 90,
    "provisional_cooldown": 300,
    "max_points": 12,
    "daily_decay": 1,
}

STAT_KEYS = (
    "leaves",
    "reconnects",
    "settlements",
    "duplicate_settlements",
    "waived_matches",
    "decayed_points",
)

SNAPSHOT_VERSION = 1
SECONDS_PER_DAY = 86400

_CONFIG_KEYS = frozenset(DEFAULT_CONFIG)
_RECORD_KEYS = frozenset(
    {"match_id", "player_id", "kind", "left_at", "reconnected_at", "exempt_reason"}
)
_SETTLEMENT_KEYS = frozenset({"settled_at", "awards", "rollback"})
_SETTLEMENT_BASE_KEYS = frozenset({"settled_at", "awards"})
_ROLLBACK_KEYS = frozenset({"delta", "decayed"})
_COOLDOWN_KEYS = frozenset({"provisional", "settlements"})
_SNAPSHOT_KEYS = frozenset(
    {"version", "config", "records", "points", "cooldowns", "settlements", "stats"}
)


class PenaltyError(ValueError):
    """Refusal raised by the abandon penalty ledger."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LeaveRecord:
    match_id: str
    player_id: str
    kind: str
    left_at: int
    reconnected_at: int | None = None
    exempt_reason: str | None = None


@dataclass(frozen=True)
class ReconnectOutcome:
    accepted: bool
    within_grace: bool
    cooldown_cleared: bool
    grace_remaining: int


@dataclass(frozen=True)
class Settlement:
    match_id: str
    settled_at: int
    awards: tuple
    duplicate: bool


@dataclass(frozen=True)
class WaiveResult:
    match_id: str
    reason: str
    rolled_back: tuple
    already_waived: bool


@dataclass(frozen=True)
class PlayerStanding:
    player_id: str
    points: int
    tier: str
    queue_block_until: int | None


def _is_int(value: object) -> bool:
    return type(value) is int


def _is_nonempty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _invalid(detail: object) -> PenaltyError:
    return PenaltyError("ABANDON_INVALID_REQUEST", detail)


def _tier_for_points(points: int) -> tuple[str, int]:
    for threshold, tier, cooldown in TIER_LADDER:
        if points >= threshold:
            return tier, cooldown
    return TIER_CLEAN, 0


class AbandonPenaltyLedger:
    """Accumulate abandon points per player and map them onto queue cooldowns."""

    def __init__(
        self,
        *,
        grace_window: int = 90,
        provisional_cooldown: int = 300,
        max_points: int = 12,
        daily_decay: int = 1,
    ) -> None:
        config = {
            "grace_window": grace_window,
            "provisional_cooldown": provisional_cooldown,
            "max_points": max_points,
            "daily_decay": daily_decay,
        }
        self._validate_config(config)
        self.grace_window = grace_window
        self.provisional_cooldown = provisional_cooldown
        self.max_points = max_points
        self.daily_decay = daily_decay
        self._lock = threading.RLock()
        self._records: dict[tuple[str, str], LeaveRecord] = {}
        self._points: dict[str, int] = {}
        self._provisional_cooldowns: dict[tuple[str, str], int] = {}
        self._settlement_cooldowns: dict[tuple[str, str], int] = {}
        self._settlements: dict[str, Settlement] = {}
        self._settlement_rollbacks: dict[str, dict[str, tuple[int, int]]] = {}
        self._stats: dict[str, int] = {key: 0 for key in STAT_KEYS}

    @staticmethod
    def _validate_config(config: object) -> None:
        if not isinstance(config, dict) or frozenset(config) != _CONFIG_KEYS:
            raise _invalid("config")
        for key in ("grace_window", "provisional_cooldown", "max_points", "daily_decay"):
            value = config[key]
            if not _is_int(value) or value < 0:
                raise _invalid(key)

    @staticmethod
    def _validate_match_id(match_id: object) -> None:
        if not _is_nonempty_str(match_id):
            raise _invalid("match_id")

    @staticmethod
    def _validate_player_id(player_id: object) -> None:
        if not _is_nonempty_str(player_id):
            raise _invalid("player_id")

    @staticmethod
    def _validate_at(at: object, *, field: str = "at") -> int:
        if not _is_int(at) or at < 0:
            raise _invalid(field)
        return at

    @staticmethod
    def _query_time(at: int | None) -> int:
        if at is None:
            return int(time.time())
        return AbandonPenaltyLedger._validate_at(at)

    def _records_for_match_locked(self, match_id: str) -> list[LeaveRecord]:
        return [
            record
            for (record_match, _), record in self._records.items()
            if record_match == match_id
        ]

    def _match_is_waived_locked(self, match_id: str) -> bool:
        records = self._records_for_match_locked(match_id)
        return bool(records) and all(
            record.exempt_reason is not None for record in records
        )

    def mark_leave(self, match_id: str, player_id: str, kind: str, *, at: int) -> LeaveRecord:
        self._validate_match_id(match_id)
        self._validate_player_id(player_id)
        if kind not in KINDS:
            raise _invalid("kind")
        self._validate_at(at)

        key = (match_id, player_id)
        with self._lock:
            existing = self._records.get(key)
            if existing is not None:
                return existing

            exempt_reason = KIND_SERVER_FAULT if kind == KIND_SERVER_FAULT else None
            record = LeaveRecord(
                match_id=match_id,
                player_id=player_id,
                kind=kind,
                left_at=at,
                exempt_reason=exempt_reason,
            )
            self._records[key] = record
            self._stats["leaves"] += 1
            if kind != KIND_SERVER_FAULT:
                until = at + self.provisional_cooldown
                previous = self._provisional_cooldowns.get(key)
                if previous is None or until > previous:
                    self._provisional_cooldowns[key] = until
            return record

    def mark_reconnect(self, match_id: str, player_id: str, *, at: int) -> ReconnectOutcome:
        self._validate_match_id(match_id)
        self._validate_player_id(player_id)
        self._validate_at(at)

        key = (match_id, player_id)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise PenaltyError(
                    "ABANDON_UNKNOWN_LEAVE",
                    {"match_id": match_id, "player_id": player_id},
                )

            elapsed = at - record.left_at
            accepted = 0 <= elapsed <= self.grace_window
            if not accepted:
                return ReconnectOutcome(
                    accepted=False,
                    within_grace=False,
                    cooldown_cleared=False,
                    grace_remaining=0,
                )

            first_acceptance = record.reconnected_at is None
            if first_acceptance:
                record = replace(record, reconnected_at=at)
                self._records[key] = record
                self._stats["reconnects"] += 1
            self._provisional_cooldowns.pop(key, None)
            return ReconnectOutcome(
                accepted=True,
                within_grace=True,
                cooldown_cleared=True,
                grace_remaining=self.grace_window - elapsed,
            )

    def _last_settlement_at_locked(self, player_id: str, current_match: str) -> int | None:
        latest: int | None = None
        for match_id, settlement in self._settlements.items():
            if match_id == current_match or self._match_is_waived_locked(match_id):
                continue
            if any(
                record.player_id == player_id
                for record in self._records_for_match_locked(match_id)
            ):
                if latest is None or settlement.settled_at > latest:
                    latest = settlement.settled_at
        return latest

    def _apply_decay_locked(self, player_id: str, *, at: int, current_match: str) -> int:
        points = self._points.get(player_id, 0)
        if points <= 0 or self.daily_decay <= 0:
            return points
        last = self._last_settlement_at_locked(player_id, current_match)
        if last is None or at <= last:
            return points
        elapsed_days = (at - last) // SECONDS_PER_DAY
        if elapsed_days <= 0:
            return points
        decayed = min(points, elapsed_days * self.daily_decay)
        self._points[player_id] = points - decayed
        self._stats["decayed_points"] += decayed
        return points - decayed

    def settle_match(self, match_id: str, *, at: int) -> Settlement:
        self._validate_match_id(match_id)
        self._validate_at(at)

        with self._lock:
            existing = self._settlements.get(match_id)
            if existing is not None:
                self._stats["duplicate_settlements"] += 1
                return replace(existing, duplicate=True)

            records = self._records_for_match_locked(match_id)
            if not records:
                raise PenaltyError("ABANDON_UNKNOWN_MATCH", {"match_id": match_id})

            awards = []
            rollback = {}
            for record in sorted(records, key=lambda row: row.player_id):
                if record.exempt_reason is not None:
                    continue
                pre_points = self._points.get(record.player_id, 0)
                current_points = self._apply_decay_locked(
                    record.player_id, at=at, current_match=match_id
                )
                gain = POINTS_BY_KIND[record.kind]
                applied = min(gain, max(0, self.max_points - current_points))
                self._points[record.player_id] = current_points + applied
                awards.append((record.player_id, applied))
                rollback[record.player_id] = (
                    current_points + applied - pre_points,
                    pre_points - current_points,
                )

                _, cooldown = _tier_for_points(current_points + applied)
                key = (match_id, record.player_id)
                if cooldown > 0:
                    self._settlement_cooldowns[key] = at + cooldown
                else:
                    self._settlement_cooldowns.pop(key, None)

            settlement = Settlement(
                match_id=match_id,
                settled_at=at,
                awards=tuple(awards),
                duplicate=False,
            )
            self._settlements[match_id] = settlement
            self._settlement_rollbacks[match_id] = rollback
            self._stats["settlements"] += 1
            return settlement

    def waive_match(self, match_id: str, reason: str, *, at: int) -> WaiveResult:
        self._validate_match_id(match_id)
        if not _is_nonempty_str(reason):
            raise _invalid("reason")
        self._validate_at(at)

        with self._lock:
            records = self._records_for_match_locked(match_id)
            if not records:
                raise PenaltyError("ABANDON_UNKNOWN_MATCH", {"match_id": match_id})
            if self._match_is_waived_locked(match_id):
                return WaiveResult(
                    match_id=match_id,
                    reason=reason,
                    rolled_back=(),
                    already_waived=True,
                )

            rolled_back = []
            settlement = self._settlements.get(match_id)
            if settlement is not None:
                rollback = self._settlement_rollbacks.get(match_id, {})
                for player_id, amount in settlement.awards:
                    delta, decayed = rollback.get(player_id, (amount, 0))
                    if delta or decayed:
                        self._points[player_id] = min(
                            self.max_points,
                            max(0, self._points.get(player_id, 0) - delta),
                        )
                        self._stats["decayed_points"] = max(
                            0, self._stats["decayed_points"] - decayed
                        )
                    if amount > 0:
                        rolled_back.append((player_id, amount))

            for record in records:
                key = (match_id, record.player_id)
                self._records[key] = replace(record, exempt_reason=reason)
                self._provisional_cooldowns.pop(key, None)
                self._settlement_cooldowns.pop(key, None)

            self._stats["waived_matches"] += 1
            return WaiveResult(
                match_id=match_id,
                reason=reason,
                rolled_back=tuple(sorted(rolled_back)),
                already_waived=False,
            )

    def penalty_of(self, player_id: str, *, at: int | None = None) -> int:
        self._validate_player_id(player_id)
        self._query_time(at)
        with self._lock:
            return self._points.get(player_id, 0)

    def tier_of(self, player_id: str, *, at: int | None = None) -> str:
        self._validate_player_id(player_id)
        self._query_time(at)
        with self._lock:
            tier, _ = _tier_for_points(self._points.get(player_id, 0))
            return tier

    def _queue_block_until_locked(self, player_id: str, at: int) -> int | None:
        ends = [
            until
            for (_, source_player), until in self._provisional_cooldowns.items()
            if source_player == player_id
        ]
        ends.extend(
            until
            for (_, source_player), until in self._settlement_cooldowns.items()
            if source_player == player_id
        )
        active = [until for until in ends if until > at]
        return max(active) if active else None

    def queue_block_until(self, player_id: str, *, at: int | None = None) -> int | None:
        self._validate_player_id(player_id)
        query_at = self._query_time(at)
        with self._lock:
            return self._queue_block_until_locked(player_id, query_at)

    def standing_of(self, player_id: str, *, at: int | None = None) -> PlayerStanding:
        self._validate_player_id(player_id)
        query_at = self._query_time(at)
        with self._lock:
            points = self._points.get(player_id, 0)
            tier, _ = _tier_for_points(points)
            return PlayerStanding(
                player_id=player_id,
                points=points,
                tier=tier,
                queue_block_until=self._queue_block_until_locked(player_id, query_at),
            )

    def records_for(self, match_id: str) -> tuple:
        self._validate_match_id(match_id)
        with self._lock:
            return tuple(
                sorted(
                    self._records_for_match_locked(match_id),
                    key=lambda row: row.player_id,
                )
            )

    def snapshot(self) -> dict:
        with self._lock:
            records = [
                {
                    "match_id": record.match_id,
                    "player_id": record.player_id,
                    "kind": record.kind,
                    "left_at": record.left_at,
                    "reconnected_at": record.reconnected_at,
                    "exempt_reason": record.exempt_reason,
                }
                for record in sorted(
                    self._records.values(),
                    key=lambda row: (row.match_id, row.player_id),
                )
            ]

            cooldown_players = sorted(
                {player_id for _, player_id in self._provisional_cooldowns}
                | {player_id for _, player_id in self._settlement_cooldowns}
            )
            cooldowns = {}
            for player_id in cooldown_players:
                provisional = {
                    match_id: until
                    for (match_id, source_player), until in sorted(
                        self._provisional_cooldowns.items()
                    )
                    if source_player == player_id
                }
                settlements = {
                    match_id: until
                    for (match_id, source_player), until in sorted(
                        self._settlement_cooldowns.items()
                    )
                    if source_player == player_id
                }
                cooldowns[player_id] = {
                    "provisional": provisional,
                    "settlements": settlements,
                }

            settlements = {
                match_id: {
                    "settled_at": settlement.settled_at,
                    "awards": [list(award) for award in settlement.awards],
                    "rollback": {
                        player_id: {
                            "delta": delta,
                            "decayed": decayed,
                        }
                        for player_id, (delta, decayed) in sorted(
                            self._settlement_rollbacks.get(match_id, {}).items()
                        )
                    },
                }
                for match_id, settlement in sorted(self._settlements.items())
            }
            return copy.deepcopy(
                {
                    "version": SNAPSHOT_VERSION,
                    "config": {
                        "grace_window": self.grace_window,
                        "provisional_cooldown": self.provisional_cooldown,
                        "max_points": self.max_points,
                        "daily_decay": self.daily_decay,
                    },
                    "records": records,
                    "points": dict(sorted(self._points.items())),
                    "cooldowns": cooldowns,
                    "settlements": settlements,
                    "stats": {key: self._stats[key] for key in STAT_KEYS},
                }
            )

    @staticmethod
    def _snapshot_invalid(detail: object) -> PenaltyError:
        return PenaltyError("ABANDON_SNAPSHOT_INVALID", detail)

    def _parse_snapshot_locked(self, state: object) -> tuple:
        if not isinstance(state, dict) or frozenset(state) != _SNAPSHOT_KEYS:
            raise self._snapshot_invalid("snapshot")

        version = state["version"]
        if not _is_int(version) or version != SNAPSHOT_VERSION:
            raise self._snapshot_invalid("version")

        config = state["config"]
        try:
            self._validate_config(config)
        except PenaltyError as exc:
            raise self._snapshot_invalid(exc.detail) from exc
        config = dict(config)

        raw_records = state["records"]
        if not isinstance(raw_records, list):
            raise self._snapshot_invalid("records")
        records: dict[tuple[str, str], LeaveRecord] = {}
        for raw in raw_records:
            if not isinstance(raw, dict) or frozenset(raw) != _RECORD_KEYS:
                raise self._snapshot_invalid("record")
            match_id = raw["match_id"]
            player_id = raw["player_id"]
            kind = raw["kind"]
            left_at = raw["left_at"]
            reconnected_at = raw["reconnected_at"]
            exempt_reason = raw["exempt_reason"]
            if not _is_nonempty_str(match_id) or not _is_nonempty_str(player_id):
                raise self._snapshot_invalid("record-id")
            if kind not in KINDS:
                raise self._snapshot_invalid("kind")
            if not _is_int(left_at) or left_at < 0:
                raise self._snapshot_invalid("left_at")
            if reconnected_at is not None:
                if (
                    not _is_int(reconnected_at)
                    or reconnected_at < left_at
                    or reconnected_at - left_at > config["grace_window"]
                ):
                    raise self._snapshot_invalid("reconnected_at")
            if exempt_reason is not None and not _is_nonempty_str(exempt_reason):
                raise self._snapshot_invalid("exempt_reason")
            key = (match_id, player_id)
            if key in records:
                raise self._snapshot_invalid("duplicate-record")
            records[key] = LeaveRecord(
                match_id=match_id,
                player_id=player_id,
                kind=kind,
                left_at=left_at,
                reconnected_at=reconnected_at,
                exempt_reason=exempt_reason,
            )

        raw_points = state["points"]
        if not isinstance(raw_points, dict):
            raise self._snapshot_invalid("points")
        points: dict[str, int] = {}
        known_players = {player_id for _, player_id in records}
        for player_id, value in raw_points.items():
            if (
                not _is_nonempty_str(player_id)
                or player_id not in known_players
                or not _is_int(value)
                or value < 0
                or value > config["max_points"]
            ):
                raise self._snapshot_invalid("points")
            points[player_id] = value

        raw_cooldowns = state["cooldowns"]
        if not isinstance(raw_cooldowns, dict):
            raise self._snapshot_invalid("cooldowns")
        provisional: dict[tuple[str, str], int] = {}
        settlement_cooldowns: dict[tuple[str, str], int] = {}
        for player_id, raw_sources in raw_cooldowns.items():
            if not _is_nonempty_str(player_id) or player_id not in known_players:
                raise self._snapshot_invalid("cooldowns-player")
            if _is_int(raw_sources):
                if raw_sources < 0:
                    raise self._snapshot_invalid("cooldowns")
                player_matches = sorted(
                    {
                        match_id
                        for (match_id, source_player), record in records.items()
                        if source_player == player_id
                        and record.reconnected_at is None
                        and record.exempt_reason is None
                    }
                )
                if not player_matches:
                    raise self._snapshot_invalid("cooldowns")
                for match_id in player_matches:
                    provisional[(match_id, player_id)] = raw_sources
                continue
            if not isinstance(raw_sources, dict) or frozenset(raw_sources) != _COOLDOWN_KEYS:
                raise self._snapshot_invalid("cooldowns")
            for source_name, target in (
                ("provisional", provisional),
                ("settlements", settlement_cooldowns),
            ):
                source_map = raw_sources[source_name]
                if not isinstance(source_map, dict):
                    raise self._snapshot_invalid("cooldowns")
                for match_id, until in source_map.items():
                    if (
                        not _is_nonempty_str(match_id)
                        or (match_id, player_id) not in records
                        or not _is_int(until)
                        or until < 0
                    ):
                        raise self._snapshot_invalid("cooldowns")
                    target[(match_id, player_id)] = until

        raw_settlements = state["settlements"]
        if not isinstance(raw_settlements, dict):
            raise self._snapshot_invalid("settlements")
        settlements: dict[str, Settlement] = {}
        settlement_rollbacks: dict[str, dict[str, tuple[int, int]]] = {}
        for match_id, raw in raw_settlements.items():
            if not _is_nonempty_str(match_id) or not any(
                record_match == match_id for record_match, _ in records
            ):
                raise self._snapshot_invalid("settlement-match")
            if not isinstance(raw, dict) or not _SETTLEMENT_BASE_KEYS.issubset(raw):
                raise self._snapshot_invalid("settlement")
            if frozenset(raw) not in (_SETTLEMENT_BASE_KEYS, _SETTLEMENT_KEYS):
                raise self._snapshot_invalid("settlement")
            settled_at = raw["settled_at"]
            raw_awards = raw["awards"]
            if not _is_int(settled_at) or settled_at < 0 or not isinstance(raw_awards, list):
                raise self._snapshot_invalid("settlement")
            awards = []
            award_players = set()
            for award in raw_awards:
                if not isinstance(award, (list, tuple)) or len(award) != 2:
                    raise self._snapshot_invalid("awards")
                player_id, amount = award
                if (
                    not _is_nonempty_str(player_id)
                    or (match_id, player_id) not in records
                    or not _is_int(amount)
                    or amount < 0
                    or amount > config["max_points"]
                    or player_id in award_players
                ):
                    raise self._snapshot_invalid("awards")
                award_players.add(player_id)
                awards.append((player_id, amount))
            rollback = {}
            raw_rollback = raw.get("rollback", {})
            if not isinstance(raw_rollback, dict):
                raise self._snapshot_invalid("rollback")
            for player_id, raw_delta in raw_rollback.items():
                if (
                    not _is_nonempty_str(player_id)
                    or (match_id, player_id) not in records
                    or not isinstance(raw_delta, dict)
                    or frozenset(raw_delta) != _ROLLBACK_KEYS
                ):
                    raise self._snapshot_invalid("rollback")
                delta = raw_delta["delta"]
                decayed = raw_delta["decayed"]
                if (
                    not _is_int(delta)
                    or not _is_int(decayed)
                    or decayed < 0
                    or decayed > config["max_points"]
                ):
                    raise self._snapshot_invalid("rollback")
                rollback[player_id] = (delta, decayed)
            if not rollback:
                rollback = {player_id: (amount, 0) for player_id, amount in awards}
            if set(rollback) != award_players:
                raise self._snapshot_invalid("rollback")
            settlements[match_id] = Settlement(
                match_id=match_id,
                settled_at=settled_at,
                awards=tuple(sorted(awards)),
                duplicate=False,
            )
            settlement_rollbacks[match_id] = rollback

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or frozenset(raw_stats) != frozenset(STAT_KEYS):
            raise self._snapshot_invalid("stats")
        stats: dict[str, int] = {}
        for key in STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                raise self._snapshot_invalid("stats")
            stats[key] = value
        if stats["leaves"] != len(records):
            raise self._snapshot_invalid("stats-leaves")
        if stats["settlements"] != len(settlements):
            raise self._snapshot_invalid("stats-settlements")
        if stats["reconnects"] > sum(
            record.reconnected_at is not None for record in records.values()
        ):
            raise self._snapshot_invalid("stats-reconnects")

        return (
            config,
            records,
            points,
            provisional,
            settlement_cooldowns,
            settlements,
            settlement_rollbacks,
            stats,
        )

    def restore(self, state: dict) -> None:
        with self._lock:
            (
                config,
                records,
                points,
                provisional,
                settlement_cooldowns,
                settlements,
                settlement_rollbacks,
                stats,
            ) = self._parse_snapshot_locked(state)

            self.grace_window = config["grace_window"]
            self.provisional_cooldown = config["provisional_cooldown"]
            self.max_points = config["max_points"]
            self.daily_decay = config["daily_decay"]
            self._records = records
            self._points = points
            self._provisional_cooldowns = provisional
            self._settlement_cooldowns = settlement_cooldowns
            self._settlements = settlements
            self._settlement_rollbacks = settlement_rollbacks
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in STAT_KEYS}
