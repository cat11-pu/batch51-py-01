"""阵营声望台账：递减收益、每日上限、阈值解锁与敌对惩罚下限。"""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass

FACTION_LEVELS = (0, 500, 1500, 3000, 6000)
DECAY_TABLE = (1.0, 0.75, 0.5, 0.25)
DEFAULT_DAY = 86400
SNAPSHOT_VERSION = 1

_STAT_KEYS = (
    "awards",
    "duplicates",
    "capped",
    "penalties",
    "transfers",
    "granted",
    "penalized",
    "moved",
    "converted",
    "unlocks",
)


class ReputationError(ValueError):
    """Raised when a reputation operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AwardResult:
    player: str
    faction: str
    requested: int
    granted: int
    multiplier: float
    points: int
    level: int
    duplicate: bool
    capped: bool


@dataclass(frozen=True)
class PenalizeResult:
    player: str
    faction: str
    requested: int
    applied: int
    points: int
    level: int
    floored: bool


@dataclass(frozen=True)
class TransferResult:
    player: str
    source: str
    target: str
    requested: int
    moved: int
    converted: int
    source_points: int
    target_points: int


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _request_text(value: object, detail: object = None) -> str:
    if not isinstance(value, str):
        raise ReputationError("REP_INVALID_REQUEST", detail)
    value = value.strip()
    if not value:
        raise ReputationError("REP_INVALID_REQUEST", detail)
    return value


def _positive_amount(value: object) -> int:
    if not _is_int(value) or value <= 0:
        raise ReputationError("REP_INVALID_AMOUNT", value)
    return value


def _normalize_levels(levels: object) -> tuple[int, ...]:
    if not isinstance(levels, (tuple, list)) or not levels:
        raise ReputationError("REP_INVALID_CONFIG", "levels")
    normalized = tuple(levels)
    if (
        any(not _is_int(value) for value in normalized)
        or normalized[0] != 0
        or any(left >= right for left, right in zip(normalized, normalized[1:]))
    ):
        raise ReputationError("REP_INVALID_CONFIG", "levels")
    return normalized


def _normalize_decay(decay: object) -> tuple[float, ...]:
    if not isinstance(decay, (tuple, list)) or not decay:
        raise ReputationError("REP_INVALID_CONFIG", "decay")
    normalized = tuple(float(value) if _is_number(value) else value for value in decay)
    if any(
        not _is_number(value)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
        for value in normalized
    ):
        raise ReputationError("REP_INVALID_CONFIG", "decay")
    return tuple(float(value) for value in normalized)


class FactionReputationLedger:
    """Track per-player reputation toward registered factions and its derived level."""

    def __init__(self, *, daily_cap: int = 1200,
                 levels: tuple[int, ...] = FACTION_LEVELS,
                 decay: tuple[float, ...] = DECAY_TABLE,
                 day: int = DEFAULT_DAY) -> None:
        if not _is_int(daily_cap) or daily_cap < 0:
            raise ReputationError("REP_INVALID_CONFIG", "daily_cap")
        if not _is_int(day) or day <= 0:
            raise ReputationError("REP_INVALID_CONFIG", "day")
        self.daily_cap = daily_cap
        self.levels = _normalize_levels(levels)
        self.decay = _normalize_decay(decay)
        self.day = day
        self._lock = threading.RLock()
        self._factions: set[str] = set()
        self._hostiles: dict[str, set[str]] = {}
        self._points: dict[str, dict[str, int]] = {}
        self._daily: dict[str, dict[str, dict]] = {}
        self._awards: dict[str, dict] = {}
        self._unlocks: dict[str, dict[str, set[int]]] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _at(value: object) -> int:
        if not _is_int(value):
            raise ReputationError("REP_INVALID_REQUEST", value)
        return value

    @staticmethod
    def _faction_name(value: object) -> str:
        return _request_text(value, value)

    def _require_faction(self, faction: str) -> None:
        if faction not in self._factions:
            raise ReputationError("REP_UNKNOWN_FACTION", faction)

    def _level_for_points(self, points: int) -> int:
        level = 0
        for index, threshold in enumerate(self.levels):
            if points >= threshold:
                level = index
            else:
                break
        return level

    def _ensure_entry(self, player: str, faction: str) -> None:
        self._points.setdefault(player, {}).setdefault(faction, 0)
        self._unlocks.setdefault(player, {}).setdefault(faction, set())

    def _day_entry(self, player: str, day_index: int) -> dict:
        days = self._daily.setdefault(player, {})
        return days.setdefault(str(day_index), {"used": 0, "sources": {}})

    def _maybe_day_entry(self, player: str, day_index: int) -> dict | None:
        return self._daily.get(player, {}).get(str(day_index))

    def register_faction(self, faction: str, *, hostiles=()) -> None:
        """Register a faction and the factions it is hostile toward."""
        faction = self._faction_name(faction)
        if hostiles is None:
            raise ReputationError("REP_INVALID_REQUEST", hostiles)
        if isinstance(hostiles, str):
            hostile_values = (self._faction_name(hostiles),)
        else:
            try:
                hostile_values = tuple(self._faction_name(value) for value in hostiles)
            except TypeError as exc:
                raise ReputationError("REP_INVALID_REQUEST", hostiles) from exc

        with self._lock:
            self._factions.add(faction)
            current = self._hostiles.setdefault(faction, set())
            current.update(hostile_values)

    def award(self, player: str, faction: str, amount: int, *, source: str,
              at: int, event_id: str) -> AwardResult:
        """Award reputation from one source, applying decay and the daily cap."""
        player = _request_text(player, player)
        faction = self._faction_name(faction)
        amount = _positive_amount(amount)
        source = _request_text(source, source)
        at = self._at(at)
        event_id = _request_text(event_id, event_id)

        with self._lock:
            self._require_faction(faction)
            previous = self._awards.get(event_id)
            if previous is not None:
                self._stats["duplicates"] += 1
                return AwardResult(
                    player=previous["player"],
                    faction=previous["faction"],
                    requested=previous["requested"],
                    granted=previous["granted"],
                    multiplier=previous["multiplier"],
                    points=previous["points"],
                    level=previous["level"],
                    duplicate=True,
                    capped=previous["capped"],
                )

            day_index = at // self.day
            day_entry = self._day_entry(player, day_index)
            source_counts = day_entry["sources"].setdefault(faction, {})
            used_count = source_counts.get(source, 0)
            multiplier = self.decay[min(used_count, len(self.decay) - 1)]
            calculated = int(math.floor(amount * multiplier))
            remaining = max(0, self.daily_cap - day_entry["used"])
            granted = min(calculated, remaining)
            capped = calculated > remaining

            source_counts[source] = used_count + 1
            day_entry["used"] += granted
            self._ensure_entry(player, faction)
            points = self._points[player][faction] + granted
            self._points[player][faction] = points
            level = self._level_for_points(points)

            record = {
                "player": player,
                "faction": faction,
                "requested": amount,
                "granted": granted,
                "multiplier": multiplier,
                "points": points,
                "level": level,
                "duplicate": False,
                "capped": capped,
            }
            self._awards[event_id] = record
            self._stats["awards"] += 1
            self._stats["granted"] += granted
            if capped:
                self._stats["capped"] += 1
            return AwardResult(**record)

    def penalize(self, player: str, faction: str, amount: int, *, at: int) -> PenalizeResult:
        """Remove reputation without dropping under the current level floor."""
        player = _request_text(player, player)
        faction = self._faction_name(faction)
        amount = _positive_amount(amount)
        self._at(at)

        with self._lock:
            self._require_faction(faction)
            self._ensure_entry(player, faction)
            points = self._points[player][faction]
            level = self._level_for_points(points)
            floor = self.levels[level]
            updated = max(floor, points - amount)
            applied = points - updated
            self._points[player][faction] = updated
            self._stats["penalties"] += 1
            self._stats["penalized"] += applied
            return PenalizeResult(
                player=player,
                faction=faction,
                requested=amount,
                applied=applied,
                points=updated,
                level=level,
                floored=applied < amount,
            )

    def points_of(self, player: str, faction: str) -> int:
        """Stored reputation points of one player toward one faction."""
        player = _request_text(player, player)
        faction = self._faction_name(faction)
        with self._lock:
            self._require_faction(faction)
            return self._points.get(player, {}).get(faction, 0)

    def level_of(self, player: str, faction: str) -> int:
        """Level index derived from the stored points and the threshold table."""
        player = _request_text(player, player)
        faction = self._faction_name(faction)
        with self._lock:
            self._require_faction(faction)
            points = self._points.get(player, {}).get(faction, 0)
            return self._level_for_points(points)

    def daily_used(self, player: str, *, at: int) -> int:
        """Reputation already granted to the player inside the server day of ``at``."""
        player = _request_text(player, player)
        at = self._at(at)
        day_index = at // self.day
        with self._lock:
            entry = self._maybe_day_entry(player, day_index)
            return 0 if entry is None else entry["used"]

    def unlock_check(self, player: str, faction: str) -> tuple[int, ...]:
        """Levels unlocked since the previous check, claiming them for this call."""
        player = _request_text(player, player)
        faction = self._faction_name(faction)
        with self._lock:
            self._require_faction(faction)
            self._ensure_entry(player, faction)
            points = self._points[player][faction]
            level = self._level_for_points(points)
            claimed = self._unlocks[player][faction]
            newly_claimed = tuple(
                candidate
                for candidate in range(1, level + 1)
                if candidate not in claimed
            )
            claimed.update(newly_claimed)
            self._stats["unlocks"] += len(newly_claimed)
            return newly_claimed

    def transfer(self, player: str, source: str, target: str, amount: int, *,
                 at: int) -> TransferResult:
        """Move reputation between factions, subject to the target level ceiling."""
        player = _request_text(player, player)
        source = self._faction_name(source)
        target = self._faction_name(target)
        amount = _positive_amount(amount)
        self._at(at)

        with self._lock:
            self._require_faction(source)
            self._require_faction(target)
            if source == target:
                raise ReputationError("REP_INVALID_REQUEST", "source equals target")

            source_points = self._points.get(player, {}).get(source, 0)
            if source_points < amount:
                raise ReputationError(
                    "REP_INSUFFICIENT",
                    {"available": source_points, "requested": amount},
                )

            target_points = self._points.get(player, {}).get(target, 0)
            target_level = self._level_for_points(target_points)
            if target_level + 1 < len(self.levels):
                ceiling = self.levels[target_level + 1]
                capacity = max(0, ceiling - target_points)
            else:
                capacity = amount

            # The requested points leave the source.  If the target cannot
            # accept all of them, scale the conversion down proportionally so
            # that the target lands exactly on its current level ceiling.
            moved = amount
            converted = min(moved, capacity)
            self._ensure_entry(player, source)
            self._ensure_entry(player, target)
            source_points -= moved
            target_points += converted
            self._points[player][source] = source_points
            self._points[player][target] = target_points
            self._stats["transfers"] += 1
            self._stats["moved"] += moved
            self._stats["converted"] += converted
            return TransferResult(
                player=player,
                source=source,
                target=target,
                requested=amount,
                moved=moved,
                converted=converted,
                source_points=source_points,
                target_points=target_points,
            )

    def snapshot(self) -> dict:
        """Deep-copied ledger state for restart recovery."""
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "daily_cap": self.daily_cap,
                    "levels": list(self.levels),
                    "decay": list(self.decay),
                    "day": self.day,
                },
                "factions": sorted(self._factions),
                "hostiles": {
                    faction: sorted(self._hostiles.get(faction, ()))
                    for faction in sorted(self._factions)
                },
                "points": {
                    player: dict(by_faction)
                    for player, by_faction in self._points.items()
                },
                "daily": copy.deepcopy(self._daily),
                "awards": copy.deepcopy(self._awards),
                "unlocks": {
                    player: {
                        faction: sorted(levels)
                        for faction, levels in by_faction.items()
                    }
                    for player, by_faction in self._unlocks.items()
                },
                "stats": dict(self._stats),
            }
        return copy.deepcopy(state)

    @staticmethod
    def _snapshot_error(detail: object = None) -> ReputationError:
        return ReputationError("REP_SNAPSHOT_INVALID", detail)

    @classmethod
    def _parse_snapshot(cls, state: dict) -> tuple:
        try:
            return cls._parse_snapshot_unchecked(state)
        except ReputationError as exc:
            if exc.code == "REP_SNAPSHOT_INVALID":
                raise
            raise cls._snapshot_error(exc.code) from exc
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise cls._snapshot_error(str(exc)) from exc

    @classmethod
    def _parse_snapshot_unchecked(cls, state: dict) -> tuple:
        if not isinstance(state, dict):
            raise cls._snapshot_error("state")
        if set(state) != {
            "version", "config", "factions", "hostiles", "points", "daily",
            "awards", "unlocks", "stats",
        }:
            raise cls._snapshot_error("keys")
        if not _is_int(state["version"]) or state["version"] != SNAPSHOT_VERSION:
            raise cls._snapshot_error("version")

        try:
            config = state["config"]
            if not isinstance(config, dict) or set(config) != {
                "daily_cap", "levels", "decay", "day",
            }:
                raise cls._snapshot_error("config")
            daily_cap = config["daily_cap"]
            if not _is_int(daily_cap) or daily_cap < 0:
                raise cls._snapshot_error("daily_cap")
            levels = _normalize_levels(config["levels"])
            decay = _normalize_decay(config["decay"])
            day = config["day"]
            if not _is_int(day) or day <= 0:
                raise cls._snapshot_error("day")
        except ReputationError as exc:
            if exc.code == "REP_SNAPSHOT_INVALID":
                raise
            raise cls._snapshot_error("config") from exc

        factions_raw = state["factions"]
        if not isinstance(factions_raw, list):
            raise cls._snapshot_error("factions")
        factions: set[str] = set()
        for value in factions_raw:
            faction = _request_text(value, "factions")
            if faction in factions:
                raise cls._snapshot_error("factions")
            factions.add(faction)

        hostiles_raw = state["hostiles"]
        if not isinstance(hostiles_raw, dict):
            raise cls._snapshot_error("hostiles")
        hostiles: dict[str, set[str]] = {}
        for key, values in hostiles_raw.items():
            faction = _request_text(key, "hostiles")
            if faction not in factions or not isinstance(values, list):
                raise cls._snapshot_error("hostiles")
            hostile_set: set[str] = set()
            for value in values:
                hostile_set.add(_request_text(value, "hostiles"))
            hostiles[faction] = hostile_set

        points_raw = state["points"]
        if not isinstance(points_raw, dict):
            raise cls._snapshot_error("points")
        points: dict[str, dict[str, int]] = {}
        for player_raw, by_faction in points_raw.items():
            player = _request_text(player_raw, "points")
            if not isinstance(by_faction, dict) or player in points:
                raise cls._snapshot_error("points")
            player_points: dict[str, int] = {}
            for faction_raw, value in by_faction.items():
                faction = _request_text(faction_raw, "points")
                if (
                    faction not in factions
                    or not _is_int(value)
                    or value < 0
                    or faction in player_points
                ):
                    raise cls._snapshot_error("points")
                player_points[faction] = value
            points[player] = player_points

        daily_raw = state["daily"]
        if not isinstance(daily_raw, dict):
            raise cls._snapshot_error("daily")
        daily: dict[str, dict[str, dict]] = {}
        for player_raw, by_day in daily_raw.items():
            player = _request_text(player_raw, "daily")
            if not isinstance(by_day, dict) or player in daily:
                raise cls._snapshot_error("daily")
            player_days: dict[str, dict] = {}
            for day_raw, entry in by_day.items():
                day_key = cls._snapshot_day_key(day_raw)
                if day_key in player_days or not isinstance(entry, dict):
                    raise cls._snapshot_error("daily")
                if set(entry) != {"used", "sources"}:
                    raise cls._snapshot_error("daily")
                used = entry["used"]
                sources_raw = entry["sources"]
                if (
                    not _is_int(used)
                    or used < 0
                    or used > daily_cap
                    or not isinstance(sources_raw, dict)
                ):
                    raise cls._snapshot_error("daily")
                sources: dict[str, dict[str, int]] = {}
                for faction_raw, source_counts in sources_raw.items():
                    faction = _request_text(faction_raw, "daily")
                    if faction not in factions or not isinstance(source_counts, dict):
                        raise cls._snapshot_error("daily")
                    normalized_counts: dict[str, int] = {}
                    for source_raw, count in source_counts.items():
                        source = _request_text(source_raw, "daily")
                        if (
                            not _is_int(count)
                            or count <= 0
                            or source in normalized_counts
                        ):
                            raise cls._snapshot_error("daily")
                        normalized_counts[source] = count
                    sources[faction] = normalized_counts
                player_days[day_key] = {"used": used, "sources": sources}
            daily[player] = player_days

        awards_raw = state["awards"]
        if not isinstance(awards_raw, dict):
            raise cls._snapshot_error("awards")
        awards: dict[str, dict] = {}
        award_keys = {
            "player", "faction", "requested", "granted", "multiplier",
            "points", "level", "duplicate", "capped",
        }
        for event_raw, record in awards_raw.items():
            event_id = _request_text(event_raw, "awards")
            if event_id in awards or not isinstance(record, dict):
                raise cls._snapshot_error("awards")
            if set(record) != award_keys:
                raise cls._snapshot_error("awards")
            player = _request_text(record["player"], "awards")
            faction = _request_text(record["faction"], "awards")
            requested = record["requested"]
            granted = record["granted"]
            multiplier = record["multiplier"]
            saved_points = record["points"]
            level = record["level"]
            if (
                faction not in factions
                or not _is_int(requested)
                or requested <= 0
                or not _is_int(granted)
                or granted < 0
                or granted > requested
                or not _is_number(multiplier)
                or not math.isfinite(float(multiplier))
                or not 0.0 <= float(multiplier) <= 1.0
                or not _is_int(saved_points)
                or saved_points < 0
                or not _is_int(level)
                or level < 0
                or level >= len(levels)
                or not isinstance(record["duplicate"], bool)
                or not isinstance(record["capped"], bool)
            ):
                raise cls._snapshot_error("awards")
            awards[event_id] = {
                "player": player,
                "faction": faction,
                "requested": requested,
                "granted": granted,
                "multiplier": float(multiplier),
                "points": saved_points,
                "level": level,
                "duplicate": record["duplicate"],
                "capped": record["capped"],
            }

        unlocks_raw = state["unlocks"]
        if not isinstance(unlocks_raw, dict):
            raise cls._snapshot_error("unlocks")
        unlocks: dict[str, dict[str, set[int]]] = {}
        for player_raw, by_faction in unlocks_raw.items():
            player = _request_text(player_raw, "unlocks")
            if not isinstance(by_faction, dict) or player in unlocks:
                raise cls._snapshot_error("unlocks")
            player_unlocks: dict[str, set[int]] = {}
            for faction_raw, values in by_faction.items():
                faction = _request_text(faction_raw, "unlocks")
                if (
                    faction not in factions
                    or faction in player_unlocks
                    or not isinstance(values, list)
                ):
                    raise cls._snapshot_error("unlocks")
                claimed: set[int] = set()
                for value in values:
                    if (
                        not _is_int(value)
                        or value <= 0
                        or value >= len(levels)
                        or value in claimed
                    ):
                        raise cls._snapshot_error("unlocks")
                    claimed.add(value)
                player_unlocks[faction] = claimed
            unlocks[player] = player_unlocks

        point_pairs = {
            (player, faction)
            for player, by_faction in points.items()
            for faction in by_faction
        }
        unlock_pairs = {
            (player, faction)
            for player, by_faction in unlocks.items()
            for faction in by_faction
        }
        if point_pairs != unlock_pairs:
            raise cls._snapshot_error("unlocks")

        stats_raw = state["stats"]
        if not isinstance(stats_raw, dict) or set(stats_raw) != set(_STAT_KEYS):
            raise cls._snapshot_error("stats")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = stats_raw[key]
            if not _is_int(value) or value < 0:
                raise cls._snapshot_error("stats")
            stats[key] = value

        daily_pairs = {
            (player, faction)
            for player, by_day in daily.items()
            for entry in by_day.values()
            for faction in entry["sources"]
        }
        award_pairs = {
            (record["player"], record["faction"])
            for record in awards.values()
        }
        if not daily_pairs <= point_pairs or not award_pairs <= point_pairs:
            raise cls._snapshot_error("points")
        if not award_pairs <= daily_pairs:
            raise cls._snapshot_error("daily")
        if stats["awards"] != len(awards):
            raise cls._snapshot_error("stats")
        if stats["granted"] != sum(record["granted"] for record in awards.values()):
            raise cls._snapshot_error("stats")
        if stats["capped"] != sum(
            1 for record in awards.values() if record["capped"]
        ):
            raise cls._snapshot_error("stats")
        if stats["unlocks"] != sum(
            len(levels) for by_faction in unlocks.values()
            for levels in by_faction.values()
        ):
            raise cls._snapshot_error("stats")

        return (
            daily_cap,
            levels,
            decay,
            day,
            factions,
            hostiles,
            points,
            daily,
            awards,
            unlocks,
            stats,
        )

    @staticmethod
    def _snapshot_day_key(value: object) -> str:
        if _is_int(value):
            return str(value)
        if not isinstance(value, str):
            raise FactionReputationLedger._snapshot_error("daily")
        try:
            return str(int(value))
        except ValueError as exc:
            raise FactionReputationLedger._snapshot_error("daily") from exc

    def restore(self, state: dict) -> None:
        """Replace the ledger state from a snapshot, rejecting malformed payloads."""
        with self._lock:
            (
                daily_cap,
                levels,
                decay,
                day,
                factions,
                hostiles,
                points,
                daily,
                awards,
                unlocks,
                stats,
            ) = self._parse_snapshot(state)

            self.daily_cap = daily_cap
            self.levels = levels
            self.decay = decay
            self.day = day
            self._factions = factions
            self._hostiles = hostiles
            self._points = points
            self._daily = daily
            self._awards = awards
            self._unlocks = unlocks
            self._stats = stats

    def stats(self) -> dict:
        """Counters collected since the ledger was created."""
        with self._lock:
            return dict(self._stats)
