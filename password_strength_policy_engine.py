"""Layered password strength policy: baseline, tenant rules, scenario exceptions, scoring."""

from __future__ import annotations

import threading
from dataclasses import dataclass


RULE_ORDER = ("length", "classes", "repeat", "dictionary", "username")

DEFAULT_RULES = {
    "min_length": 12,
    "min_classes": 3,
    "max_repeats": 2,
    "min_score": 60,
}

PENALTIES = {
    "length": 25,
    "classes": 20,
    "repeat": 15,
    "dictionary": 30,
    "username": 40,
}


class PolicyError(ValueError):
    """Raised when policy composition or evaluation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CompositePolicy:
    tenant: str
    scenario: str | None
    version: int
    min_length: int
    min_classes: int
    max_repeats: int
    min_score: int
    exempted: tuple[str, ...]


@dataclass(frozen=True)
class Evaluation:
    passed: bool
    score: int
    failed: tuple[str, ...]
    exempted: tuple[str, ...]
    version: int


class StrengthPolicyEngine:
    """Compose strength rules from layers and evaluate passwords deterministically."""

    def __init__(self, *, dictionary=("password", "letmein", "qwerty")) -> None:
        self._dictionary = tuple(dictionary)
        self._lock = threading.RLock()

    def set_baseline(self, overrides: dict) -> int:
        raise NotImplementedError

    def set_tenant_policy(self, tenant: str, overrides: dict) -> int:
        raise NotImplementedError

    def register_exception(self, tenant: str, scenario: str, overrides: dict,
                           *, exempt=()) -> int:
        raise NotImplementedError

    def compose(self, tenant: str, *, scenario: str | None = None) -> CompositePolicy:
        raise NotImplementedError

    def explain(self, tenant: str, *, scenario: str | None = None) -> dict:
        raise NotImplementedError

    def evaluate(self, password, *, tenant: str, username: str | None = None,
                 scenario: str | None = None) -> Evaluation:
        raise NotImplementedError

    def reload(self, payload: dict) -> int:
        raise NotImplementedError

    def policy_version(self) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
