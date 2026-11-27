"""Technique coverage mapping: many-to-many rule/technique attribution and weighted gaps."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass
from numbers import Real
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
    SNAPSHOT_VERSION = 1
    STATS_KEYS = frozenset(
        {"rules", "mappings", "techniques", "retired_rules", "retired_techniques"}
    )

    def __init__(
        self,
        *,
        techniques: TypingMapping[str, TypingMapping[str, Any]] | None = None,
        exempt: tuple[str, ...] = (),
        max_rules: int = 500,
        max_mappings: int = 2000,
        max_techniques: int = 200,
    ) -> None:
        self._lock = threading.RLock()
        self.max_rules = self._validate_cap("max_rules", max_rules)
        self.max_mappings = self._validate_cap("max_mappings", max_mappings)
        self.max_techniques = self._validate_cap("max_techniques", max_techniques)

        if techniques is None:
            techniques = {}
        if not isinstance(techniques, TypingMapping):
            raise MappingError("MAPPING_INVALID_REQUEST", "techniques must be a mapping")
        if len(techniques) > self.max_techniques:
            raise MappingError(
                "MAPPING_CAPACITY_EXCEEDED",
                f"technique count {len(techniques)} exceeds {self.max_techniques}",
            )

        self._rules: dict[str, Rule] = {}
        self._techniques: dict[str, Technique] = {}
        self._mappings: dict[tuple[str, str], Mapping] = {}
        self._technique_spec = copy.deepcopy(dict(techniques))
        self._techniques = self._parse_initial_techniques(techniques)
        self._exempt = self._parse_exempt(exempt)

    @staticmethod
    def _validate_cap(name: str, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MappingError(
                "MAPPING_INVALID_REQUEST", f"{name} must be a non-negative integer"
            )
        return value

    @staticmethod
    def _required_text(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise MappingError("MAPPING_INVALID_REQUEST", f"{field} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _validate_weight(value: Any) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise MappingError(
                "MAPPING_INVALID_REQUEST", "technique weight must be a positive number"
            )
        return float(value)

    @staticmethod
    def _validate_confidence(value: Any) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not math.isfinite(float(value))
            or not 0 < float(value) <= 1
        ):
            raise MappingError(
                "MAPPING_CONFIDENCE_INVALID",
                "confidence must be a number greater than 0 and at most 1",
            )
        return float(value)

    def _parse_initial_techniques(
        self, techniques: TypingMapping[str, TypingMapping[str, Any]]
    ) -> dict[str, Technique]:
        parsed: dict[str, Technique] = {}
        for raw_id, raw_spec in techniques.items():
            try:
                technique_id = self._required_text(raw_id, "technique_id")
            except MappingError as exc:
                raise MappingError("MAPPING_INVALID_REQUEST", exc.detail) from exc
            if technique_id in parsed:
                raise MappingError(
                    "MAPPING_INVALID_REQUEST", f"duplicate technique identifier {technique_id!r}"
                )
            if not isinstance(raw_spec, TypingMapping):
                raise MappingError(
                    "MAPPING_INVALID_REQUEST",
                    f"technique {technique_id!r} must be a mapping",
                )
            try:
                name = self._required_text(raw_spec.get("name"), "name")
            except MappingError as exc:
                raise MappingError(
                    "MAPPING_INVALID_REQUEST", f"technique {technique_id!r}: {exc.detail}"
                ) from exc
            try:
                weight = self._validate_weight(raw_spec.get("weight"))
            except MappingError as exc:
                raise MappingError(
                    "MAPPING_INVALID_REQUEST", f"technique {technique_id!r}: {exc.detail}"
                ) from exc

            parent = raw_spec.get("parent")
            if parent is not None:
                try:
                    parent = self._required_text(parent, "parent")
                except MappingError as exc:
                    raise MappingError(
                        "MAPPING_INVALID_REQUEST",
                        f"technique {technique_id!r}: {exc.detail}",
                    ) from exc

            parsed[technique_id] = Technique(
                technique_id=technique_id,
                name=name,
                weight=weight,
                parent=parent,
                retired=False,
            )

        for technique in parsed.values():
            parent = technique.parent
            if parent is None:
                continue
            if parent not in parsed:
                raise MappingError(
                    "MAPPING_TECHNIQUE_UNKNOWN",
                    f"parent technique {parent!r} is not in the catalog",
                )
            if parent == technique.technique_id:
                raise MappingError(
                    "MAPPING_INVALID_REQUEST",
                    f"technique {technique.technique_id!r} cannot be its own parent",
                )

        self._validate_technique_hierarchy(parsed)
        return parsed

    @staticmethod
    def _validate_technique_hierarchy(techniques: dict[str, Technique]) -> None:
        for technique_id in techniques:
            seen: set[str] = set()
            current = technique_id
            while current is not None:
                if current in seen:
                    raise MappingError(
                        "MAPPING_INVALID_REQUEST",
                        f"cycle in technique hierarchy at {current!r}",
                    )
                seen.add(current)
                technique = techniques.get(current)
                current = technique.parent if technique is not None else None

    def _parse_exempt(self, exempt: tuple[str, ...]) -> tuple[str, ...]:
        if isinstance(exempt, str):
            raise MappingError("MAPPING_INVALID_REQUEST", "exempt must be an iterable of ids")
        try:
            items = tuple(exempt)
        except TypeError as exc:
            raise MappingError(
                "MAPPING_INVALID_REQUEST", "exempt must be an iterable of ids"
            ) from exc

        result: set[str] = set()
        for raw_id in items:
            try:
                technique_id = self._required_text(raw_id, "exempt technique_id")
            except MappingError as exc:
                raise MappingError("MAPPING_INVALID_REQUEST", exc.detail) from exc
            if technique_id not in self._techniques:
                raise MappingError(
                    "MAPPING_TECHNIQUE_UNKNOWN",
                    f"exempt technique {technique_id!r} is not in the catalog",
                )
            result.add(technique_id)
        return tuple(sorted(result))

    @staticmethod
    def _mapping_record(mapping: Mapping) -> dict[str, Any]:
        return {
            "rule_id": mapping.rule_id,
            "technique_id": mapping.technique_id,
            "confidence": mapping.confidence,
            "source": mapping.source,
        }

    @staticmethod
    def _rule_record(rule: Rule) -> dict[str, Any]:
        return {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "source": rule.source,
            "retired": rule.retired,
        }

    @staticmethod
    def _technique_record(technique: Technique) -> dict[str, Any]:
        return {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "weight": technique.weight,
            "parent": technique.parent,
            "retired": technique.retired,
        }

    def _stats_locked(self) -> dict[str, int]:
        return {
            "rules": len(self._rules),
            "mappings": len(self._mappings),
            "techniques": len(self._techniques),
            "retired_rules": sum(rule.retired for rule in self._rules.values()),
            "retired_techniques": sum(
                technique.retired for technique in self._techniques.values()
            ),
        }

    def _coverage_report_locked(self) -> dict:
        by_technique: dict[str, list[Mapping]] = {
            technique_id: [] for technique_id in self._techniques
        }
        for mapping in self._mappings.values():
            if not self._rules[mapping.rule_id].retired:
                by_technique[mapping.technique_id].append(mapping)

        rows: list[TechniqueCoverage] = []
        weighted_covered = 0.0
        weighted_total = 0.0
        exempt = set(self._exempt)
        for technique_id in sorted(self._techniques):
            technique = self._techniques[technique_id]
            effective = [] if technique.retired else by_technique[technique_id]
            coverage = max((mapping.confidence for mapping in effective), default=0.0)
            rows.append(
                TechniqueCoverage(
                    technique_id=technique_id,
                    weight=technique.weight,
                    coverage=coverage,
                    mapping_count=len(effective),
                    rules=tuple(sorted({mapping.rule_id for mapping in effective})),
                    exempt=technique_id in exempt,
                )
            )
            if not technique.retired and technique_id not in exempt:
                weighted_total += technique.weight
                weighted_covered += technique.weight * coverage

        if weighted_total:
            weighted_coverage = round(weighted_covered / weighted_total, 4)
        else:
            weighted_coverage = 0.0

        return {
            "weighted_coverage": weighted_coverage,
            "techniques": rows,
            "exempt": self._exempt,
            "retired": tuple(
                technique_id
                for technique_id in sorted(self._techniques)
                if self._techniques[technique_id].retired
            ),
            "counts": {
                "rules": len(self._rules),
                "mappings": len(self._mappings),
                "techniques": len(self._techniques),
            },
        }

    def register_rule(self, rule_id: str, *, name: str, source: str) -> Rule:
        rule_id = self._required_text(rule_id, "rule_id")
        name = self._required_text(name, "name")
        source = self._required_text(source, "source")
        with self._lock:
            if rule_id in self._rules:
                raise MappingError(
                    "MAPPING_RULE_DUPLICATE", f"rule {rule_id!r} is already registered"
                )
            if len(self._rules) >= self.max_rules:
                raise MappingError(
                    "MAPPING_CAPACITY_EXCEEDED",
                    f"rule count would exceed {self.max_rules}",
                )
            rule = Rule(rule_id=rule_id, name=name, source=source, retired=False)
            self._rules[rule_id] = rule
            return rule

    def map_technique(
        self, rule_id: str, technique_id: str, *, confidence: float, source: str
    ) -> Mapping:
        rule_id = self._required_text(rule_id, "rule_id")
        technique_id = self._required_text(technique_id, "technique_id")
        source = self._required_text(source, "source")
        confidence = self._validate_confidence(confidence)

        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                raise MappingError(
                    "MAPPING_RULE_UNKNOWN", f"rule {rule_id!r} is not registered"
                )
            if rule.retired:
                raise MappingError(
                    "MAPPING_RULE_RETIRED", f"rule {rule_id!r} has been retired"
                )
            if technique_id not in self._techniques:
                raise MappingError(
                    "MAPPING_TECHNIQUE_UNKNOWN",
                    f"technique {technique_id!r} is not in the catalog",
                )

            key = (rule_id, technique_id)
            existing = self._mappings.get(key)
            if existing is not None:
                if confidence <= existing.confidence:
                    return existing
                mapping = Mapping(
                    rule_id=rule_id,
                    technique_id=technique_id,
                    confidence=confidence,
                    source=source,
                )
                self._mappings[key] = mapping
                return mapping

            if len(self._mappings) >= self.max_mappings:
                raise MappingError(
                    "MAPPING_CAPACITY_EXCEEDED",
                    f"mapping count would exceed {self.max_mappings}",
                )

            mapping = Mapping(
                rule_id=rule_id,
                technique_id=technique_id,
                confidence=confidence,
                source=source,
            )
            self._mappings[key] = mapping
            return mapping

    def retire_technique(self, technique_id: str) -> Technique:
        technique_id = self._required_text(technique_id, "technique_id")
        with self._lock:
            technique = self._techniques.get(technique_id)
            if technique is None:
                raise MappingError(
                    "MAPPING_TECHNIQUE_UNKNOWN",
                    f"technique {technique_id!r} is not in the catalog",
                )
            if technique.retired:
                return technique
            retired = Technique(
                technique_id=technique.technique_id,
                name=technique.name,
                weight=technique.weight,
                parent=technique.parent,
                retired=True,
            )
            self._techniques[technique_id] = retired
            return retired

    def retire_rule(self, rule_id: str) -> Rule:
        rule_id = self._required_text(rule_id, "rule_id")
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                raise MappingError(
                    "MAPPING_RULE_UNKNOWN", f"rule {rule_id!r} is not registered"
                )
            if rule.retired:
                return rule
            retired = Rule(
                rule_id=rule.rule_id,
                name=rule.name,
                source=rule.source,
                retired=True,
            )
            self._rules[rule_id] = retired
            return retired

    def coverage_report(self) -> dict:
        with self._lock:
            return self._coverage_report_locked()

    def gaps(self) -> tuple[CoverageGap, ...]:
        with self._lock:
            report = self._coverage_report_locked()
            exempt = set(report["exempt"])
            retired = set(report["retired"])
            gaps = [
                CoverageGap(
                    technique_id=row.technique_id,
                    weight=row.weight,
                    coverage=row.coverage,
                    reason="no_coverage" if row.coverage == 0 else "partial_coverage",
                )
                for row in report["techniques"]
                if row.technique_id not in exempt
                and row.technique_id not in retired
                and row.coverage < 1.0
            ]
            gaps.sort(key=lambda gap: (-gap.weight, gap.technique_id))
            return tuple(gaps)

    def rules_for(self, technique_id: str) -> tuple[Rule, ...]:
        technique_id = self._required_text(technique_id, "technique_id")
        with self._lock:
            if technique_id not in self._techniques:
                raise MappingError(
                    "MAPPING_TECHNIQUE_UNKNOWN",
                    f"technique {technique_id!r} is not in the catalog",
                )
            rule_ids = sorted(
                mapping.rule_id
                for mapping in self._mappings.values()
                if mapping.technique_id == technique_id
            )
            return tuple(self._rules[rule_id] for rule_id in rule_ids)

    def mappings_for(self, rule_id: str) -> tuple[Mapping, ...]:
        rule_id = self._required_text(rule_id, "rule_id")
        with self._lock:
            if rule_id not in self._rules:
                raise MappingError(
                    "MAPPING_RULE_UNKNOWN", f"rule {rule_id!r} is not registered"
                )
            mappings = [
                mapping
                for (mapped_rule, _), mapping in self._mappings.items()
                if mapped_rule == rule_id
            ]
            mappings.sort(key=lambda mapping: mapping.technique_id)
            return tuple(mappings)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": self.SNAPSHOT_VERSION,
                "rules": {
                    rule_id: self._rule_record(self._rules[rule_id])
                    for rule_id in sorted(self._rules)
                },
                "techniques": {
                    technique_id: self._technique_record(self._techniques[technique_id])
                    for technique_id in sorted(self._techniques)
                },
                "mappings": [
                    self._mapping_record(self._mappings[key])
                    for key in sorted(self._mappings)
                ],
                "stats": self._stats_locked(),
            }
            return copy.deepcopy(state)

    @staticmethod
    def _snapshot_invalid(detail: Any) -> None:
        raise MappingError("MAPPING_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(
        self, state: Any
    ) -> tuple[dict[str, Rule], dict[str, Technique], dict[tuple[str, str], Mapping]]:
        if not isinstance(state, dict) or set(state) != self.SNAPSHOT_KEYS:
            self._snapshot_invalid("snapshot must contain exactly the five required keys")
        version = state.get("version")
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version != self.SNAPSHOT_VERSION
        ):
            self._snapshot_invalid("unsupported snapshot version")

        raw_rules = state.get("rules")
        if not isinstance(raw_rules, dict):
            self._snapshot_invalid("rules must be a mapping")
        if len(raw_rules) > self.max_rules:
            self._snapshot_invalid("rule count exceeds the configured capacity")

        rules: dict[str, Rule] = {}
        for raw_id, payload in raw_rules.items():
            if not isinstance(payload, dict) or set(payload) != {
                "rule_id",
                "name",
                "source",
                "retired",
            }:
                self._snapshot_invalid(f"invalid rule record for {raw_id!r}")
            rule_id = payload.get("rule_id")
            name = payload.get("name")
            source = payload.get("source")
            retired = payload.get("retired")
            if (
                not isinstance(raw_id, str)
                or not isinstance(rule_id, str)
                or rule_id != raw_id
                or not rule_id.strip()
                or not isinstance(name, str)
                or not name.strip()
                or not isinstance(source, str)
                or not source.strip()
                or not isinstance(retired, bool)
            ):
                self._snapshot_invalid(f"invalid rule record for {raw_id!r}")
            if rule_id in rules:
                self._snapshot_invalid(f"duplicate rule record for {rule_id!r}")
            rules[rule_id] = Rule(
                rule_id=rule_id,
                name=name,
                source=source,
                retired=retired,
            )

        raw_techniques = state.get("techniques")
        if not isinstance(raw_techniques, dict):
            self._snapshot_invalid("techniques must be a mapping")
        if len(raw_techniques) > self.max_techniques:
            self._snapshot_invalid("technique count exceeds the configured capacity")

        techniques: dict[str, Technique] = {}
        for raw_id, payload in raw_techniques.items():
            if not isinstance(payload, dict) or set(payload) != {
                "technique_id",
                "name",
                "weight",
                "parent",
                "retired",
            }:
                self._snapshot_invalid(f"invalid technique record for {raw_id!r}")
            technique_id = payload.get("technique_id")
            name = payload.get("name")
            weight = payload.get("weight")
            parent = payload.get("parent")
            retired = payload.get("retired")
            if (
                not isinstance(raw_id, str)
                or not isinstance(technique_id, str)
                or technique_id != raw_id
                or not technique_id.strip()
                or not isinstance(name, str)
                or not name.strip()
                or isinstance(weight, bool)
                or not isinstance(weight, Real)
                or not math.isfinite(float(weight))
                or float(weight) <= 0
                or (parent is not None and (not isinstance(parent, str) or not parent.strip()))
                or not isinstance(retired, bool)
            ):
                self._snapshot_invalid(f"invalid technique record for {raw_id!r}")
            if technique_id in techniques:
                self._snapshot_invalid(f"duplicate technique record for {technique_id!r}")
            techniques[technique_id] = Technique(
                technique_id=technique_id,
                name=name,
                weight=float(weight),
                parent=parent,
                retired=retired,
            )

        for technique in techniques.values():
            if technique.parent is not None and technique.parent not in techniques:
                self._snapshot_invalid(
                    f"unknown parent {technique.parent!r} for {technique.technique_id!r}"
                )
            if technique.parent == technique.technique_id:
                self._snapshot_invalid(
                    f"technique {technique.technique_id!r} cannot be its own parent"
                )
        try:
            self._validate_technique_hierarchy(techniques)
        except MappingError as exc:
            self._snapshot_invalid(exc.detail)

        raw_mappings = state.get("mappings")
        if not isinstance(raw_mappings, list):
            self._snapshot_invalid("mappings must be a list")
        if len(raw_mappings) > self.max_mappings:
            self._snapshot_invalid("mapping count exceeds the configured capacity")

        mappings: dict[tuple[str, str], Mapping] = {}
        for payload in raw_mappings:
            if not isinstance(payload, dict) or set(payload) != {
                "rule_id",
                "technique_id",
                "confidence",
                "source",
            }:
                self._snapshot_invalid("invalid mapping record")
            rule_id = payload.get("rule_id")
            technique_id = payload.get("technique_id")
            confidence = payload.get("confidence")
            source = payload.get("source")
            if (
                not isinstance(rule_id, str)
                or not isinstance(technique_id, str)
                or not isinstance(source, str)
                or not source.strip()
                or isinstance(confidence, bool)
                or not isinstance(confidence, Real)
                or not math.isfinite(float(confidence))
                or not 0 < float(confidence) <= 1
                or rule_id not in rules
                or technique_id not in techniques
            ):
                self._snapshot_invalid("invalid mapping record")
            key = (rule_id, technique_id)
            if key in mappings:
                self._snapshot_invalid(
                    f"duplicate mapping for {rule_id!r}/{technique_id!r}"
                )
            mappings[key] = Mapping(
                rule_id=rule_id,
                technique_id=technique_id,
                confidence=float(confidence),
                source=source,
            )

        raw_stats = state.get("stats")
        if not isinstance(raw_stats, dict) or set(raw_stats) != self.STATS_KEYS:
            self._snapshot_invalid("stats must contain exactly the five required keys")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in raw_stats.values()
        ):
            self._snapshot_invalid("stats values must be non-negative integers")

        actual_stats = {
            "rules": len(rules),
            "mappings": len(mappings),
            "techniques": len(techniques),
            "retired_rules": sum(rule.retired for rule in rules.values()),
            "retired_techniques": sum(
                technique.retired for technique in techniques.values()
            ),
        }
        if raw_stats != actual_stats:
            self._snapshot_invalid("stats do not match snapshot contents")

        return rules, techniques, mappings

    def restore(self, state: dict) -> None:
        with self._lock:
            rules, techniques, mappings = self._parse_snapshot(state)
            self._rules = rules
            self._techniques = techniques
            self._mappings = mappings
            self._technique_spec = {
                technique_id: {
                    "name": technique.name,
                    "weight": technique.weight,
                    "parent": technique.parent,
                }
                for technique_id, technique in techniques.items()
            }
            self._exempt = tuple(
                technique_id
                for technique_id in self._exempt
                if technique_id in self._techniques
            )

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()
