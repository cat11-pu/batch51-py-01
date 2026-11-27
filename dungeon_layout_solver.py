"""Deterministic dungeon layout generation with connectivity and key ordering."""

from __future__ import annotations

import threading
from dataclasses import dataclass


REASON_OK = "DUNGEON_OK"
REASON_MALFORMED = "DUNGEON_LAYOUT_MALFORMED"
REASON_KEY_ORDER = "DUNGEON_KEY_ORDER_UNSOLVABLE"
REASON_UNREACHABLE = "DUNGEON_UNREACHABLE_ROOMS"
REASON_BUDGET = "DUNGEON_BUDGET_EXCEEDED"
REASON_EXHAUSTED = "DUNGEON_REGENERATION_EXHAUSTED"

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


class LayoutSolver:
    """Generate seeded layouts and prove that every room stays reachable."""

    def __init__(
        self,
        *,
        monster_budget: int = 12,
        chest_budget: int = 4,
        max_attempts: int = 4,
    ) -> None:
        self.monster_budget = monster_budget
        self.chest_budget = chest_budget
        self.max_attempts = max_attempts
        self._lock = threading.RLock()

    def generate(self, seed: int, *, monster_budget: int | None = None,
                 chest_budget: int | None = None) -> Layout:
        raise NotImplementedError

    def validate(self, layout: Layout) -> ValidationReport:
        raise NotImplementedError

    def regenerate(self, seed: int, *, max_attempts: int | None = None,
                   monster_budget: int | None = None,
                   chest_budget: int | None = None) -> RegenerateResult:
        raise NotImplementedError

    def describe(self, layout: Layout) -> dict:
        raise NotImplementedError

    def path_to(self, layout: Layout, target: str) -> tuple | None:
        raise NotImplementedError

    def current(self) -> Layout | None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
