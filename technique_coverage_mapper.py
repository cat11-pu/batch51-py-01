"""Technique coverage mapping: many-to-many rule/technique attribution and weighted gaps."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping as TypingMapping


class MappingError(ValueError):
    """Raised when a coverage-mapping operation is refused."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    source: str
    retired: bool


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    weight: float
    parent: str | None
    retired: bool


@dataclass(frozen=True)
class Mapping:
    rule_id: str
    technique_id: str
    confidence: float
    source: str


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: str
    weight: float
    coverage: float
    mapping_count: int
    rules: tuple[str, ...]
    exempt: bool


@dataclass(frozen=True)
class CoverageGap:
    technique_id: str
    weight: float
    coverage: float
    reason: str


class TechniqueCoverageMapper:
    """Attribute detection rules to techniques and report weighted coverage gaps."""

    SNAPSHOT_KEYS = frozenset({"version", "rules", "techniques", "mappings", "stats"})

    def __init__(
        self,
        *,
        techniques: TypingMapping[str, TypingMapping[str, Any]] | None = None,
        exempt: tuple[str, ...] = (),
        max_rules: int = 500,
        max_mappings: int = 2000,
        max_techniques: int = 200,
    ) -> None:
        self._technique_spec = dict(techniques or {})
        self._exempt = tuple(exempt)
        self.max_rules = max_rules
        self.max_mappings = max_mappings
        self.max_techniques = max_techniques
        self._lock = threading.RLock()

    def register_rule(self, rule_id: str, *, name: str, source: str) -> Rule:
        raise NotImplementedError

    def map_technique(
        self, rule_id: str, technique_id: str, *, confidence: float, source: str
    ) -> Mapping:
        raise NotImplementedError

    def retire_technique(self, technique_id: str) -> Technique:
        raise NotImplementedError

    def retire_rule(self, rule_id: str) -> Rule:
        raise NotImplementedError

    def coverage_report(self) -> dict:
        raise NotImplementedError

    def gaps(self) -> tuple[CoverageGap, ...]:
        raise NotImplementedError

    def rules_for(self, technique_id: str) -> tuple[Rule, ...]:
        raise NotImplementedError

    def mappings_for(self, rule_id: str) -> tuple[Mapping, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
