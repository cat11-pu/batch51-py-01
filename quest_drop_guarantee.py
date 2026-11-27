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
        self.threshold = threshold
        self._lock = threading.RLock()

    def register_kill(self, player_id: str, quest_id: str, *, kill_id: str,
                      monster_id: str, at: int) -> KillReceipt:
        raise NotImplementedError

    def roll_drop(self, player_id: str, quest_id: str, *, kill_id: str,
                  base_drop: bool) -> DropOutcome:
        raise NotImplementedError

    def credit_party(self, quest_id: str, *, kill_id: str, monster_id: str,
                     participants: tuple, leader_id: str, at: int) -> PartyCredit:
        raise NotImplementedError

    def progress(self, player_id: str, quest_id: str) -> QuestProgress:
        raise NotImplementedError

    def configure_threshold(self, quest_id: str, threshold: int) -> int:
        raise NotImplementedError

    def reset_quest(self, player_id: str, quest_id: str, *, reason: str) -> int:
        raise NotImplementedError

    def kill_ids(self, player_id: str, quest_id: str) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
