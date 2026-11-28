"""Device rule evaluation: ordered matching, node naming, and dangerous assignment gating."""

from __future__ import annotations

import copy
import fnmatch
import re
import threading
from dataclasses import dataclass
from collections.abc import Mapping


class UdevError(ValueError):
    """Raised when a rule load or evaluation request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


MATCH_KEYS = ("SUBSYSTEM", "KERNEL", "DRIVER", "TAG")
ASSIGN_KEYS = ("NAME", "MODE", "OWNER", "GROUP", "SYMLINK", "TAG", "RUN")

_COUNTER_KEYS = ("reloads", "evaluations", "matches", "run_denied")
_SNAPSHOT_KEYS = {
    "version",
    "rules",
    "allow_run",
    "counters",
    "audit",
    "conflicts",
}
_ATTR_KEY = re.compile(r"^ATTR\{([^{}]+)\}$")
_CLAUSE = re.compile(
    r"^(?P<key>[A-Za-z_][A-Za-z0-9_]*(?:\{[^{}]*\})?)"
    r"\s*(?P<op>==|!=|\+=|=|-=|:=)\s*(?P<value>.*)$"
)
_OCTAL = re.compile(r"^(?:0[oO])?[0-7]+$")


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
        if type(max_rules) is not int or max_rules < 0:
            raise UdevError(
                "UDEV_CAPACITY_EXCEEDED",
                {"max_rules": max_rules},
            )
        if type(allow_run) is not bool:
            raise UdevError(
                "UDEV_RULE_SYNTAX",
                {"allow_run": "must be a boolean"},
            )
        self.max_rules = max_rules
        self._allow_run = allow_run
        self._rules: tuple[Rule, ...] = ()
        self._counters = {key: 0 for key in _COUNTER_KEYS}
        self._audit: list[AuditEntry] = []
        self._conflicts: list[Conflict] = []
        self._lock = threading.RLock()

    def load_rules(self, files) -> tuple[Rule, ...]:
        parsed = self._parse_files(files)
        with self._lock:
            self._rules = parsed
            self._counters["reloads"] += 1
        return parsed

    def rules(self) -> tuple[Rule, ...]:
        with self._lock:
            return self._rules

    def match_rule(self, rule: Rule, attrs: dict) -> bool:
        if not isinstance(rule, Rule) or not isinstance(attrs, Mapping):
            raise UdevError("UDEV_RULE_SYNTAX", {"match": "invalid rule or attrs"})
        return all(self._claims_match(claim, attrs) for claim in rule.matches)

    def evaluate(self, device_id: str, attrs: dict) -> DeviceResult:
        if not isinstance(device_id, str) or not isinstance(attrs, Mapping):
            raise UdevError("UDEV_RULE_SYNTAX", {"evaluate": "invalid request"})
        with self._lock:
            if len(self._audit) >= self.max_rules:
                raise UdevError(
                    "UDEV_CAPACITY_EXCEEDED",
                    {"audit": len(self._audit), "max_rules": self.max_rules},
                )
            result, conflicts, applied_keys, denied, match_count = (
                self._evaluate_locked(device_id, attrs, self._allow_run)
            )
            self._counters["evaluations"] += 1
            self._counters["matches"] += match_count
            self._counters["run_denied"] += denied
            self._audit.append(
                AuditEntry(
                    device_id=device_id,
                    matched_rules=result.matched_rules,
                    applied_keys=applied_keys,
                    run_denied=denied,
                )
            )
            if conflicts:
                self._conflicts.extend(conflicts)
            return result

    def simulate(self, devices) -> tuple[DeviceResult, ...]:
        if isinstance(devices, (str, bytes, bytearray)):
            raise UdevError("UDEV_RULE_SYNTAX", {"simulate": "invalid devices"})
        try:
            pending = list(devices)
        except TypeError as exc:
            raise UdevError(
                "UDEV_RULE_SYNTAX",
                {"simulate": "devices must be iterable"},
            ) from exc

        results: list[DeviceResult] = []
        with self._lock:
            allow_run = self._allow_run
            for item in pending:
                try:
                    device_id, attrs = item
                except (TypeError, ValueError) as exc:
                    raise UdevError(
                        "UDEV_RULE_SYNTAX",
                        {"simulate": "each device must be (device_id, attrs)"},
                    ) from exc
                if not isinstance(device_id, str) or not isinstance(attrs, Mapping):
                    raise UdevError(
                        "UDEV_RULE_SYNTAX",
                        {"simulate": "invalid device request"},
                    )
                result, _, _, _, _ = self._evaluate_locked(
                    device_id,
                    attrs,
                    allow_run,
                )
                results.append(result)
        return tuple(results)

    def audit(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._audit)

    def conflicts(self) -> tuple[Conflict, ...]:
        with self._lock:
            return tuple(self._conflicts)

    def set_allow_run(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise UdevError(
                "UDEV_RULE_SYNTAX",
                {"allow_run": "must be a boolean"},
            )
        with self._lock:
            self._allow_run = enabled

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "rules": copy.deepcopy(list(self._rules)),
                "allow_run": self._allow_run,
                "counters": copy.deepcopy(self._counters),
                "audit": copy.deepcopy(list(self._audit)),
                "conflicts": copy.deepcopy(list(self._conflicts)),
            }

    def restore(self, state: dict) -> None:
        try:
            candidate = copy.deepcopy(state)
        except Exception as exc:
            raise UdevError(
                "UDEV_SNAPSHOT_INVALID",
                {"state": "not copyable"},
            ) from exc

        rules, allow_run, counters, audits, conflicts = self._validate_snapshot(
            candidate
        )
        with self._lock:
            self._rules = rules
            self._allow_run = allow_run
            self._counters = counters
            self._audit = audits
            self._conflicts = conflicts

    def stats(self) -> dict:
        with self._lock:
            return {
                "rules": len(self._rules),
                "reloads": self._counters["reloads"],
                "evaluations": self._counters["evaluations"],
                "matches": self._counters["matches"],
                "run_denied": self._counters["run_denied"],
                "conflicts": len(self._conflicts),
            }

    def _parse_files(self, files) -> tuple[Rule, ...]:
        if isinstance(files, (str, bytes, bytearray)):
            raise UdevError("UDEV_RULE_SYNTAX", {"files": "must be a sequence"})
        try:
            rule_files = list(files)
        except TypeError as exc:
            raise UdevError(
                "UDEV_RULE_SYNTAX",
                {"files": "must be iterable"},
            ) from exc

        parsed: list[Rule] = []
        for rule_file in rule_files:
            if not isinstance(rule_file, RuleFile):
                raise UdevError(
                    "UDEV_RULE_SYNTAX",
                    {"files": "entries must be RuleFile"},
                )
            source = rule_file.source
            mode = rule_file.mode
            text = rule_file.text
            if not isinstance(source, str) or type(mode) is not int or mode < 0:
                raise UdevError(
                    "UDEV_RULE_SYNTAX",
                    {"source": source, "mode": mode},
                )
            if not isinstance(text, str):
                raise UdevError(
                    "UDEV_RULE_SYNTAX",
                    {"source": source, "text": "must be a string"},
                )
            if mode & 0o020:
                raise UdevError(
                    "UDEV_FILE_INSECURE",
                    {"source": source, "mode": mode},
                )

            for line_number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                matches, assignments = self._parse_line(
                    line,
                    source,
                    line_number,
                )
                if len(parsed) >= self.max_rules:
                    raise UdevError(
                        "UDEV_CAPACITY_EXCEEDED",
                        {
                            "source": source,
                            "line": line_number,
                            "max_rules": self.max_rules,
                        },
                    )
                parsed.append(
                    Rule(
                        index=len(parsed),
                        source=source,
                        line=line_number,
                        matches=matches,
                        assignments=assignments,
                    )
                )
        return tuple(parsed)

    def _parse_line(
        self,
        line: str,
        source: str,
        line_number: int,
    ) -> tuple[tuple[MatchClaim, ...], tuple[Assignment, ...]]:
        content = self._strip_comment(line).strip()
        if not content:
            return (), ()

        clauses = self._split_clauses(content, source, line_number)
        matches: list[MatchClaim] = []
        assignments: list[Assignment] = []
        for clause in clauses:
            match = _CLAUSE.fullmatch(clause.strip())
            if match is None:
                self._syntax(source, line_number, clause)
            key = match.group("key")
            op = match.group("op")
            value = self._parse_quoted(
                match.group("value"),
                source,
                line_number,
            )

            attr_match = _ATTR_KEY.fullmatch(key)
            is_match = (
                key in ("SUBSYSTEM", "KERNEL", "DRIVER")
                or attr_match is not None
                or (key == "TAG" and op == "==")
            )
            if is_match:
                if op != "==":
                    self._syntax(source, line_number, clause)
                matches.append(MatchClaim(key=key, value=value))
                continue
            if key in ASSIGN_KEYS:
                if op not in ("=", "+="):
                    self._syntax(source, line_number, clause)
                if key == "MODE":
                    self._parse_mode(value, source, line_number)
                assignments.append(Assignment(key=key, op=op, value=value))
                continue
            self._syntax(source, line_number, clause)

        return tuple(matches), tuple(assignments)

    @staticmethod
    def _strip_comment(line: str) -> str:
        quoted = False
        escaped = False
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if quoted and char == "\\":
                escaped = True
                continue
            if char == '"':
                quoted = not quoted
                continue
            if char == "#" and not quoted:
                return line[:index]
        return line

    @staticmethod
    def _split_clauses(
        content: str,
        source: str,
        line_number: int,
    ) -> list[str]:
        clauses: list[str] = []
        start = 0
        quoted = False
        escaped = False
        for index, char in enumerate(content):
            if escaped:
                escaped = False
                continue
            if quoted and char == "\\":
                escaped = True
                continue
            if char == '"':
                quoted = not quoted
                continue
            if char == "," and not quoted:
                clause = content[start:index].strip()
                if not clause:
                    UdevRuleGuard._syntax(source, line_number, content)
                clauses.append(clause)
                start = index + 1
        if quoted:
            UdevRuleGuard._syntax(source, line_number, content)
        clause = content[start:].strip()
        if not clause:
            UdevRuleGuard._syntax(source, line_number, content)
        clauses.append(clause)
        return clauses

    @staticmethod
    def _parse_quoted(value: str, source: str, line_number: int) -> str:
        value = value.strip()
        if not value.startswith('"'):
            UdevRuleGuard._syntax(source, line_number, value)
        result: list[str] = []
        index = 1
        while index < len(value):
            char = value[index]
            if char == "\\":
                index += 1
                if index >= len(value):
                    UdevRuleGuard._syntax(source, line_number, value)
                result.append(value[index])
                index += 1
                continue
            if char == '"':
                if value[index + 1 :].strip():
                    UdevRuleGuard._syntax(source, line_number, value)
                return "".join(result)
            result.append(char)
            index += 1
        UdevRuleGuard._syntax(source, line_number, value)

    @staticmethod
    def _parse_mode(value: str, source: str, line_number: int) -> int:
        if _OCTAL.fullmatch(value) is None:
            UdevRuleGuard._syntax(source, line_number, value)
        try:
            return int(value, 8)
        except ValueError:
            UdevRuleGuard._syntax(source, line_number, value)

    @staticmethod
    def _syntax(source: str, line: int, clause: str) -> None:
        raise UdevError(
            "UDEV_RULE_SYNTAX",
            {"source": source, "line": line, "clause": clause},
        )

    @staticmethod
    def _claims_match(claim: MatchClaim, attrs: Mapping) -> bool:
        if claim.key in attrs:
            actual = attrs[claim.key]
        else:
            attr_match = _ATTR_KEY.fullmatch(claim.key)
            if attr_match is None:
                actual = None
            else:
                attr_name = attr_match.group(1)
                actual = attrs.get(attr_name)
                if actual is None:
                    nested = attrs.get("ATTR")
                    if isinstance(nested, Mapping):
                        actual = nested.get(attr_name)

        if isinstance(actual, (list, tuple, set, frozenset)):
            return claim.value in actual
        if claim.key == "TAG" and isinstance(actual, str):
            return claim.value == actual or claim.value in actual.split()
        if isinstance(actual, str):
            return actual == claim.value or fnmatch.fnmatchcase(actual, claim.value)
        return actual == claim.value

    def _evaluate_locked(
        self,
        device_id: str,
        attrs: Mapping,
        allow_run: bool,
    ) -> tuple[
        DeviceResult,
        list[Conflict],
        tuple[str, ...],
        int,
        int,
    ]:
        name: str | None = None
        name_rule: int | None = None
        mode: int | None = None
        owner: str | None = None
        group: str | None = None
        tags: list[str] = []
        symlinks: list[str] = []
        commands: list[str] = []
        applied_keys: list[str] = []
        applied_seen: set[str] = set()
        matched_rules: list[int] = []
        conflicts: list[Conflict] = []
        denied = 0

        def mark_applied(key: str) -> None:
            if key not in applied_seen:
                applied_seen.add(key)
                applied_keys.append(key)

        for rule in self._rules:
            if not all(self._claims_match(claim, attrs) for claim in rule.matches):
                continue
            matched_rules.append(rule.index)
            for assignment in rule.assignments:
                key = assignment.key
                value = assignment.value
                if key == "NAME":
                    if name_rule is not None:
                        conflicts.append(
                            Conflict(
                                device_id=device_id,
                                key="NAME",
                                winner_rule=rule.index,
                                loser_rule=name_rule,
                                winner_value=value,
                                loser_value=name or "",
                            )
                        )
                    name = value
                    name_rule = rule.index
                    mark_applied(key)
                elif key == "MODE":
                    mode = int(value, 8)
                    mark_applied(key)
                elif key == "OWNER":
                    owner = value
                    mark_applied(key)
                elif key == "GROUP":
                    group = value
                    mark_applied(key)
                elif key == "TAG":
                    if assignment.op == "=":
                        tags.clear()
                    if value not in tags:
                        tags.append(value)
                    mark_applied(key)
                elif key == "SYMLINK":
                    if assignment.op == "=":
                        symlinks.clear()
                    if value not in symlinks:
                        symlinks.append(value)
                    mark_applied(key)
                elif key == "RUN":
                    if allow_run:
                        commands.append(value)
                        mark_applied(key)
                    else:
                        denied += 1

        result = DeviceResult(
            device_id=device_id,
            name=name,
            mode=mode,
            owner=owner,
            group=group,
            tags=tuple(tags),
            symlinks=tuple(symlinks),
            commands=tuple(commands),
            matched_rules=tuple(matched_rules),
        )
        return result, conflicts, tuple(applied_keys), denied, len(matched_rules)

    def _validate_snapshot(
        self,
        state: object,
    ) -> tuple[
        tuple[Rule, ...],
        bool,
        dict[str, int],
        list[AuditEntry],
        list[Conflict],
    ]:
        invalid = self._snapshot_invalid
        if not isinstance(state, dict):
            invalid("state must be a dict")
        if set(state) != _SNAPSHOT_KEYS:
            invalid("state fields do not match the snapshot schema")
        if type(state["version"]) is not int or state["version"] != 1:
            invalid("unsupported snapshot version")
        if type(state["allow_run"]) is not bool:
            invalid("allow_run must be a boolean")

        counters = state["counters"]
        if not isinstance(counters, dict) or set(counters) != set(_COUNTER_KEYS):
            invalid("counters must contain exactly the counter fields")
        copied_counters: dict[str, int] = {}
        for key in _COUNTER_KEYS:
            value = counters[key]
            if type(value) is not int or value < 0:
                invalid(f"counter {key} must be a non-negative integer")
            copied_counters[key] = value

        raw_rules = state["rules"]
        if not isinstance(raw_rules, list):
            invalid("rules must be a list")
        if len(raw_rules) > self.max_rules:
            invalid("rule count exceeds capacity")
        rules: list[Rule] = []
        for index, rule in enumerate(raw_rules):
            if not isinstance(rule, Rule):
                invalid("rules entries must be Rule objects")
            if (
                type(rule.index) is not int
                or rule.index != index
                or not isinstance(rule.source, str)
                or type(rule.line) is not int
                or rule.line < 1
                or not isinstance(rule.matches, tuple)
                or not isinstance(rule.assignments, tuple)
            ):
                invalid("invalid rule metadata")
            for claim in rule.matches:
                if (
                    not isinstance(claim, MatchClaim)
                    or not isinstance(claim.key, str)
                    or not isinstance(claim.value, str)
                    or (
                        claim.key not in MATCH_KEYS
                        and _ATTR_KEY.fullmatch(claim.key) is None
                    )
                ):
                    invalid("invalid match claim")
            for assignment in rule.assignments:
                if (
                    not isinstance(assignment, Assignment)
                    or assignment.key not in ASSIGN_KEYS
                    or assignment.op not in ("=", "+=")
                    or not isinstance(assignment.value, str)
                ):
                    invalid("invalid assignment")
                if assignment.key == "MODE":
                    try:
                        self._parse_mode(assignment.value, rule.source, rule.line)
                    except UdevError as exc:
                        raise UdevError("UDEV_SNAPSHOT_INVALID", exc.detail) from exc
            rules.append(rule)

        raw_audit = state["audit"]
        if not isinstance(raw_audit, list):
            invalid("audit must be a list")
        if len(raw_audit) > self.max_rules:
            invalid("audit count exceeds capacity")
        audits: list[AuditEntry] = []
        for entry in raw_audit:
            if (
                not isinstance(entry, AuditEntry)
                or not isinstance(entry.device_id, str)
                or not isinstance(entry.matched_rules, tuple)
                or not isinstance(entry.applied_keys, tuple)
                or type(entry.run_denied) is not int
                or entry.run_denied < 0
                or any(
                    type(rule_index) is not int or rule_index < 0
                    for rule_index in entry.matched_rules
                )
                or any(
                    not isinstance(key, str) for key in entry.applied_keys
                )
            ):
                invalid("invalid audit entry")
            audits.append(entry)

        raw_conflicts = state["conflicts"]
        if not isinstance(raw_conflicts, list):
            invalid("conflicts must be a list")
        conflicts: list[Conflict] = []
        for conflict in raw_conflicts:
            if (
                not isinstance(conflict, Conflict)
                or not isinstance(conflict.device_id, str)
                or conflict.key != "NAME"
                or type(conflict.winner_rule) is not int
                or conflict.winner_rule < 0
                or type(conflict.loser_rule) is not int
                or conflict.loser_rule < 0
                or not isinstance(conflict.winner_value, str)
                or not isinstance(conflict.loser_value, str)
            ):
                invalid("invalid conflict entry")
            conflicts.append(conflict)

        return (
            tuple(rules),
            state["allow_run"],
            copied_counters,
            audits,
            conflicts,
        )

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise UdevError("UDEV_SNAPSHOT_INVALID", detail)
