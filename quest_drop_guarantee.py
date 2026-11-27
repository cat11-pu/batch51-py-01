"""Quest item drop guarantee counters shared inside a party."""

from __future__ import annotations

import threading
from dataclasses import dataclass


DEFAULT_THRESHOLD = 3

PARTY_MAX_DISTANCE = 40
PARTY_MAX_LEVEL_GAP = 10

REASON_TOO_FAR = "DROP_PARTY_TOO_FAR"
REASON_LEVEL_GAP = "DROP_PARTY_LEVEL_GAP"

STAT_KEYS = ("kills", "duplicate_kills", "drops", "forced_drops", "resets")

SNAPSHOT_VERSION = 1


class QuestError(ValueError):
    """Refusal raised by the quest drop guarantee."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class KillReceipt:
    player_id: str
    quest_id: str
    kill_id: str
    accepted: bool
    duplicate: bool
    kills: int


@dataclass(frozen=True)
class DropOutcome:
    player_id: str
    quest_id: str
    dropped: bool
    forced: bool
    counter_after: int
    threshold: int
    item_count: int


@dataclass(frozen=True)
class QuestProgress:
    player_id: str
    quest_id: str
    registered: bool
    counter: int
    threshold: int
    remaining: int
    item_count: int
    kills: int


@dataclass(frozen=True)
class PartyMember:
    player_id: str
    distance: int
    level: int


@dataclass(frozen=True)
class PartyCredit:
    quest_id: str
    kill_id: str
    shared: tuple
    isolated: tuple


class QuestDropGuarantee:
    """Force a quest item drop after a run of misses and share party progress."""

    def __init__(self, *, threshold: int = 3) -> None:
        self._validate_threshold(threshold)
        self.threshold = threshold
        self._quest_thresholds = {}
        self._quests = {}
        self._stats = {key: 0 for key in STAT_KEYS}
        self._lock = threading.RLock()

    @staticmethod
    def _invalid(field: str, value: object) -> QuestError:
        return QuestError("DROP_INVALID_REQUEST",
                          {"field": field, "value": value})

    @classmethod
    def _validate_text(cls, field: str, value: object) -> str:
        if not isinstance(value, str) or not value:
            raise cls._invalid(field, value)
        return value

    @classmethod
    def _validate_at(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise cls._invalid("at", value)
        return value

    @classmethod
    def _validate_threshold(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise cls._invalid("threshold", value)
        return value

    def _effective_threshold(self, quest_id: str) -> int:
        return self._quest_thresholds.get(quest_id, self.threshold)

    def _record_for(self, player_id: str, quest_id: str, create: bool = False):
        player_map = self._quests.get(player_id)
        if player_map is None:
            if not create:
                return None
            player_map = self._quests[player_id] = {}
        record = player_map.get(quest_id)
        if record is None and create:
            record = player_map[quest_id] = {
                "counter": 0,
                "item_count": 0,
                "kills": 0,
                "kill_ids": set(),
            }
        return record

    def _register_kill_locked(self, player_id: str, quest_id: str,
                              kill_id: str) -> KillReceipt:
        record = self._record_for(player_id, quest_id, create=True)
        if kill_id in record["kill_ids"]:
            self._stats["duplicate_kills"] += 1
            return KillReceipt(player_id=player_id, quest_id=quest_id,
                               kill_id=kill_id, accepted=False,
                               duplicate=True, kills=record["kills"])
        record["kill_ids"].add(kill_id)
        record["kills"] += 1
        self._stats["kills"] += 1
        return KillReceipt(player_id=player_id, quest_id=quest_id,
                           kill_id=kill_id, accepted=True,
                           duplicate=False, kills=record["kills"])

    def register_kill(self, player_id: str, quest_id: str, *, kill_id: str,
                      monster_id: str, at: int) -> KillReceipt:
        self._validate_text("player_id", player_id)
        self._validate_text("quest_id", quest_id)
        self._validate_text("kill_id", kill_id)
        self._validate_text("monster_id", monster_id)
        self._validate_at(at)
        with self._lock:
            return self._register_kill_locked(player_id, quest_id, kill_id)

    def roll_drop(self, player_id: str, quest_id: str, *, kill_id: str,
                  base_drop: bool) -> DropOutcome:
        self._validate_text("player_id", player_id)
        self._validate_text("quest_id", quest_id)
        self._validate_text("kill_id", kill_id)
        if not isinstance(base_drop, bool):
            raise self._invalid("base_drop", base_drop)
        with self._lock:
            record = self._record_for(player_id, quest_id)
            if record is None or kill_id not in record["kill_ids"]:
                raise QuestError("DROP_UNKNOWN_KILL",
                                 {"player_id": player_id, "quest_id": quest_id,
                                  "kill_id": kill_id})
            threshold = self._effective_threshold(quest_id)
            if base_drop:
                record["counter"] = 0
                record["item_count"] += 1
                self._stats["drops"] += 1
                return DropOutcome(player_id=player_id, quest_id=quest_id,
                                   dropped=True, forced=False,
                                   counter_after=0, threshold=threshold,
                                   item_count=record["item_count"])
            record["counter"] += 1
            if record["counter"] >= threshold:
                record["counter"] = 0
                record["item_count"] += 1
                self._stats["drops"] += 1
                self._stats["forced_drops"] += 1
                return DropOutcome(player_id=player_id, quest_id=quest_id,
                                   dropped=True, forced=True,
                                   counter_after=0, threshold=threshold,
                                   item_count=record["item_count"])
            return DropOutcome(player_id=player_id, quest_id=quest_id,
                               dropped=False, forced=False,
                               counter_after=record["counter"],
                               threshold=threshold,
                               item_count=record["item_count"])

    def credit_party(self, quest_id: str, *, kill_id: str, monster_id: str,
                     participants: tuple, leader_id: str, at: int) -> PartyCredit:
        self._validate_text("quest_id", quest_id)
        self._validate_text("kill_id", kill_id)
        self._validate_text("monster_id", monster_id)
        self._validate_text("leader_id", leader_id)
        self._validate_at(at)
        if not isinstance(participants, (tuple, list)):
            raise self._invalid("participants", participants)
        members = []
        for member in participants:
            if not isinstance(member, PartyMember):
                raise self._invalid("participants", member)
            self._validate_text("member.player_id", member.player_id)
            if (isinstance(member.distance, bool)
                    or not isinstance(member.distance, int)):
                raise self._invalid("member.distance", member.distance)
            if (isinstance(member.level, bool)
                    or not isinstance(member.level, int)):
                raise self._invalid("member.level", member.level)
            members.append(member)
        leader = next((m for m in members if m.player_id == leader_id), None)
        if leader is None:
            raise QuestError("DROP_INVALID_REQUEST",
                             {"field": "leader_id", "value": leader_id})
        shared = []
        isolated = []
        with self._lock:
            for member in members:
                self._register_kill_locked(member.player_id, quest_id, kill_id)
                if member.distance > PARTY_MAX_DISTANCE:
                    isolated.append((member.player_id, REASON_TOO_FAR))
                elif abs(member.level - leader.level) > PARTY_MAX_LEVEL_GAP:
                    isolated.append((member.player_id, REASON_LEVEL_GAP))
                else:
                    shared.append(member.player_id)
        return PartyCredit(quest_id=quest_id, kill_id=kill_id,
                           shared=tuple(shared), isolated=tuple(isolated))

    def progress(self, player_id: str, quest_id: str) -> QuestProgress:
        self._validate_text("player_id", player_id)
        self._validate_text("quest_id", quest_id)
        with self._lock:
            threshold = self._effective_threshold(quest_id)
            record = self._record_for(player_id, quest_id)
            if record is None:
                return QuestProgress(player_id=player_id, quest_id=quest_id,
                                     registered=False, counter=0,
                                     threshold=threshold,
                                     remaining=threshold, item_count=0,
                                     kills=0)
            return QuestProgress(player_id=player_id, quest_id=quest_id,
                                 registered=True, counter=record["counter"],
                                 threshold=threshold,
                                 remaining=threshold - record["counter"],
                                 item_count=record["item_count"],
                                 kills=record["kills"])

    def configure_threshold(self, quest_id: str, threshold: int) -> int:
        self._validate_text("quest_id", quest_id)
        self._validate_threshold(threshold)
        with self._lock:
            self._quest_thresholds[quest_id] = threshold
            return threshold

    def reset_quest(self, player_id: str, quest_id: str, *, reason: str) -> int:
        self._validate_text("player_id", player_id)
        self._validate_text("quest_id", quest_id)
        self._validate_text("reason", reason)
        with self._lock:
            record = self._record_for(player_id, quest_id)
            previous = record["counter"] if record is not None else 0
            if record is not None:
                record["counter"] = 0
            self._stats["resets"] += 1
            return previous

    def kill_ids(self, player_id: str, quest_id: str) -> tuple:
        self._validate_text("player_id", player_id)
        self._validate_text("quest_id", quest_id)
        with self._lock:
            record = self._record_for(player_id, quest_id)
            if record is None:
                return ()
            return tuple(sorted(record["kill_ids"]))

    def snapshot(self) -> dict:
        with self._lock:
            config = {"threshold": self.threshold}
            if self._quest_thresholds:
                config["quests"] = dict(self._quest_thresholds)
            quests = {}
            for player_id, player_map in self._quests.items():
                quests[player_id] = {
                    quest_id: {
                        "counter": record["counter"],
                        "item_count": record["item_count"],
                        "kills": record["kills"],
                        "kill_ids": sorted(record["kill_ids"]),
                    }
                    for quest_id, record in player_map.items()
                }
            return {
                "version": SNAPSHOT_VERSION,
                "config": config,
                "quests": quests,
                "stats": dict(self._stats),
            }

    @staticmethod
    def _is_count(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    def _validate_snapshot(self, state: object) -> None:
        bad = QuestError("DROP_SNAPSHOT_INVALID", None)
        if not isinstance(state, dict):
            raise bad
        if set(state.keys()) != {"version", "config", "quests", "stats"}:
            raise QuestError("DROP_SNAPSHOT_INVALID",
                             {"field": "keys", "value": sorted(state.keys())})
        if state["version"] != SNAPSHOT_VERSION:
            raise QuestError("DROP_SNAPSHOT_INVALID",
                             {"field": "version", "value": state["version"]})
        config = state["config"]
        if not isinstance(config, dict):
            raise QuestError("DROP_SNAPSHOT_INVALID", {"field": "config"})
        threshold = config.get("threshold")
        if (isinstance(threshold, bool) or not isinstance(threshold, int)
                or threshold <= 0):
            raise QuestError("DROP_SNAPSHOT_INVALID",
                             {"field": "config.threshold", "value": threshold})
        overrides = config.get("quests", {})
        if not isinstance(overrides, dict):
            raise QuestError("DROP_SNAPSHOT_INVALID",
                             {"field": "config.quests"})
        for quest_id, value in overrides.items():
            if not isinstance(quest_id, str) or not quest_id:
                raise QuestError("DROP_SNAPSHOT_INVALID",
                                 {"field": "config.quests", "value": quest_id})
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise QuestError("DROP_SNAPSHOT_INVALID",
                                 {"field": "config.quests", "value": value})
        quests = state["quests"]
        if not isinstance(quests, dict):
            raise QuestError("DROP_SNAPSHOT_INVALID", {"field": "quests"})
        for player_id, player_map in quests.items():
            if not isinstance(player_id, str) or not player_id:
                raise QuestError("DROP_SNAPSHOT_INVALID",
                                 {"field": "quests", "value": player_id})
            if not isinstance(player_map, dict):
                raise QuestError("DROP_SNAPSHOT_INVALID",
                                 {"field": "quests", "value": player_id})
            for quest_id, entry in player_map.items():
                if not isinstance(quest_id, str) or not quest_id:
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "quests", "value": quest_id})
                if not isinstance(entry, dict) or set(entry.keys()) != {
                        "counter", "item_count", "kills", "kill_ids"}:
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "quest_entry",
                                      "value": quest_id})
                if not self._is_count(entry["counter"]):
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "counter"})
                if not self._is_count(entry["item_count"]):
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "item_count"})
                if not self._is_count(entry["kills"]):
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "kills"})
                kill_ids = entry["kill_ids"]
                if (not isinstance(kill_ids, (list, tuple))
                        or any(not isinstance(k, str) or not k
                               for k in kill_ids)
                        or len(set(kill_ids)) != len(kill_ids)):
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "kill_ids"})
                if entry["kills"] != len(kill_ids):
                    raise QuestError("DROP_SNAPSHOT_INVALID",
                                     {"field": "kills"})
        stats = state["stats"]
        if not isinstance(stats, dict) or set(stats.keys()) != set(STAT_KEYS):
            raise QuestError("DROP_SNAPSHOT_INVALID", {"field": "stats"})
        for key in STAT_KEYS:
            if not self._is_count(stats[key]):
                raise QuestError("DROP_SNAPSHOT_INVALID",
                                 {"field": "stats", "value": key})

    def restore(self, state: dict) -> None:
        self._validate_snapshot(state)
        with self._lock:
            config = state["config"]
            self.threshold = config["threshold"]
            self._quest_thresholds = dict(config.get("quests", {}))
            self._quests = {
                player_id: {
                    quest_id: {
                        "counter": entry["counter"],
                        "item_count": entry["item_count"],
                        "kills": entry["kills"],
                        "kill_ids": set(entry["kill_ids"]),
                    }
                    for quest_id, entry in player_map.items()
                }
                for player_id, player_map in state["quests"].items()
            }
            self._stats = {key: state["stats"][key] for key in STAT_KEYS}

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
