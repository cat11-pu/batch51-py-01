"""Device rule evaluation: ordered matching, node naming, and dangerous assignment gating."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class UdevError(ValueError):
    """Raised when a rule load or evaluation request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


MATCH_KEYS = ("SUBSYSTEM", "KERNEL", "DRIVER", "TAG")
ASSIGN_KEYS = ("NAME", "MODE", "OWNER", "GROUP", "SYMLINK", "TAG", "RUN")


@dataclass(frozen=True)
class RuleFile:
    source: str
    mode: int
    text: str


@dataclass(frozen=True)
class MatchClaim:
    key: str
    value: str


@dataclass(frozen=True)
class Assignment:
    key: str
    op: str
    value: str


@dataclass(frozen=True)
class Rule:
    index: int
    source: str
    line: int
    matches: tuple[MatchClaim, ...]
    assignments: tuple[Assignment, ...]


@dataclass(frozen=True)
class DeviceResult:
    device_id: str
    name: str | None
    mode: int | None
    owner: str | None
    group: str | None
    tags: tuple[str, ...]
    symlinks: tuple[str, ...]
    commands: tuple[str, ...]
    matched_rules: tuple[int, ...]


@dataclass(frozen=True)
class AuditEntry:
    device_id: str
    matched_rules: tuple[int, ...]
    applied_keys: tuple[str, ...]
    run_denied: int


@dataclass(frozen=True)
class Conflict:
    device_id: str
    key: str
    winner_rule: int
    loser_rule: int
    winner_value: str
    loser_value: str


class UdevRuleGuard:
    """Parse device rule files and evaluate them against device attributes."""

    def __init__(self, *, max_rules: int = 4096, allow_run: bool = False) -> None:
        self.max_rules = max_rules
        self._allow_run = allow_run
        self._lock = threading.RLock()

    def load_rules(self, files) -> tuple[Rule, ...]:
        raise NotImplementedError

    def rules(self) -> tuple[Rule, ...]:
        raise NotImplementedError

    def match_rule(self, rule: Rule, attrs: dict) -> bool:
        raise NotImplementedError

    def evaluate(self, device_id: str, attrs: dict) -> DeviceResult:
        raise NotImplementedError

    def simulate(self, devices) -> tuple[DeviceResult, ...]:
        raise NotImplementedError

    def audit(self) -> tuple[AuditEntry, ...]:
        raise NotImplementedError

    def conflicts(self) -> tuple[Conflict, ...]:
        raise NotImplementedError

    def set_allow_run(self, enabled: bool) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
