"""Credential scanning: entropy threshold, placeholder exclusion, hit merging."""

from __future__ import annotations

import copy
import hashlib
import math
import re
import string
import threading
from collections import Counter
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace
from typing import Mapping


class ScanError(ValueError):
    """Raised when a scan request or a snapshot is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Rule:
    name: str
    prefix: str | None
    min_length: int
    max_length: int
    min_entropy: float
    severity: str


@dataclass(frozen=True)
class Token:
    value: str
    line: int
    column: int


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    preview: str
    fingerprint: str
    path: str
    line: int
    column: int
    also_in: tuple[str, ...] = ()


DEFAULT_RULES = (
    Rule("aws_access_key", "AKIA", 20, 20, 3.0, "high"),
    Rule("slack_bot_token", "xoxb-", 20, 80, 2.5, "high"),
    Rule("generic_api_key", None, 24, 64, 3.5, "medium"),
)

PLACEHOLDERS = frozenset({
    "changeme", "change_me", "placeholder", "example", "sample", "dummy",
    "secret", "password", "passw0rd", "token", "apikey", "api_key",
    "your_key_here", "your_token_here", "redacted", "fixme", "todo", "xxxx",
})

_TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "_-+/")
_COUNTER_KEYS = frozenset({
    "scans", "tokens", "suppressed", "duplicates", "findings", "restored",
})
_SNAPSHOT_KEYS = frozenset({"version", "rules", "findings", "seen", "counters"})
_SNAPSHOT_VERSION = 1
_ENTROPY_EPSILON = 1e-9
_SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_HASH_CONTEXT = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:sha[-_]?(?:1|224|256|384|512)|md5|"
    r"blake2[bs]?|crc32|adler32|hash|digest|checksum|hmac|commit)"
    r"(?![A-Za-z0-9])"
)
_TEST_CONTEXT = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:test(?:s|ing)?|fixtures?|mocks?|fake|dummy|"
    r"example|sample|vectors?|golden|test[_-]?data|test[_-]?vectors?)"
    r"(?![A-Za-z0-9])"
)
_TEST_PATH = re.compile(
    r"(?i)(?:^|/)(?:fixtures?|testdata|test[_-]?vectors?|golden)(?:/|[^/]*$)"
)
_OBVIOUS_TEST_TOKEN = re.compile(
    r"(?i)(?:example|placeholder|changeme|dummy|sample|test[_-]?vector)"
)


class SecretEntropyScanner:
    """Find high-entropy credentials in text and merge repeats per secret."""

    def __init__(self, *, rules=None, min_length: int = 8,
                 max_token_length: int = 512) -> None:
        self._lock = threading.RLock()
        self._min_length = self._require_int(
            "min_length", min_length, minimum=1
        )
        self._max_token_length = self._require_int(
            "max_token_length", max_token_length, minimum=1
        )
        if self._max_token_length < self._min_length:
            raise ScanError(
                "SCAN_INVALID_ARGUMENT",
                "max_token_length must be at least min_length",
            )
        source_rules = DEFAULT_RULES if rules is None else rules
        self._rules = self._coerce_rules(source_rules)
        self._findings: list[Finding] = []
        self._seen: dict[tuple[str, str], int] = {}
        self._counters = {name: 0 for name in _COUNTER_KEYS}

    def entropy(self, text: str) -> float:
        if not isinstance(text, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "text must be a string")
        return self._entropy(text)

    def tokenize(self, text: str) -> list[Token]:
        if not isinstance(text, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "text must be a string")
        with self._lock:
            return self._tokenize(text)

    def is_placeholder(self, token: str) -> bool:
        if not isinstance(token, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "token must be a string")
        folded = token.lower()
        return folded in PLACEHOLDERS or len(set(token)) < 3

    def match_rule(self, token: str) -> Rule | None:
        if not isinstance(token, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "token must be a string")
        with self._lock:
            return self._match_rule(token)

    def scan_text(self, text: str, *, path: str, commit: str | None = None) -> list[Finding]:
        self._validate_scan_args(text, path, commit)
        with self._lock:
            self._counters["scans"] += 1
            return self._scan_text(text, path)

    def scan_files(self, files: dict, *, commit: str | None = None) -> list[Finding]:
        if not isinstance(files, Mapping):
            raise ScanError("SCAN_INVALID_ARGUMENT", "files must be a mapping")
        if commit is not None and not isinstance(commit, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "commit must be a string or None")
        items = list(files.items())
        for path, text in items:
            self._validate_scan_args(text, path, commit)

        results: list[Finding] = []
        with self._lock:
            for path, text in items:
                self._counters["scans"] += 1
                results.extend(self._scan_text(text, path))
        return results

    def findings(self) -> tuple[Finding, ...]:
        with self._lock:
            return tuple(self._findings)

    def findings_for(self, rule: str) -> tuple[Finding, ...]:
        if not isinstance(rule, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "rule name must be a string")
        with self._lock:
            return tuple(finding for finding in self._findings
                         if finding.rule == rule)

    def report(self) -> tuple[Finding, ...]:
        with self._lock:
            return tuple(sorted(self._findings, key=self._report_key))

    def add_rule(self, name: str, *, prefix: str | None = None,
                 min_length: int = 8, max_length: int | None = None,
                 min_entropy: float = 3.5, severity: str = "medium") -> None:
        with self._lock:
            if max_length is None:
                if (isinstance(min_length, bool)
                        or not isinstance(min_length, int)
                        or min_length < 1):
                    raise ScanError(
                        "SCAN_INVALID_RULE",
                        "min_length must be a positive integer",
                    )
                checked_min = min_length
                max_length = max(self._max_token_length, checked_min)
            rule = self._build_rule(
                name, prefix, min_length, max_length, min_entropy, severity
            )
            self._rules = self._rules + (rule,)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "rules": [self._rule_to_dict(rule) for rule in self._rules],
                "findings": [self._finding_to_dict(finding)
                             for finding in self._findings],
                "seen": copy.deepcopy(self._seen),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                rules, findings, seen, counters = self._decode_snapshot(state)
            except ScanError as exc:
                if exc.code == "SCAN_SNAPSHOT_INVALID":
                    raise
                raise ScanError("SCAN_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:
                raise ScanError("SCAN_SNAPSHOT_INVALID", str(exc)) from exc

            counters["restored"] += 1
            self._rules = rules
            self._findings = findings
            self._seen = seen
            self._counters = counters

    def _entropy(self, text: str) -> float:
        size = len(text)
        if size == 0:
            return 0.0
        value = -sum(
            (count / size) * math.log2(count / size)
            for count in Counter(text).values()
        )
        rounded = round(value, 6)
        return 0.0 if rounded == 0 else rounded

    def _tokenize(self, text: str) -> list[Token]:
        tokens: list[Token] = []
        line = 1
        column = 1
        index = 0
        size = len(text)

        while index < size:
            char = text[index]
            if char in _TOKEN_CHARS:
                start_line = line
                start_column = column
                start = index
                while index < size and text[index] in _TOKEN_CHARS:
                    index += 1
                    column += 1
                value = text[start:index]
                if len(value) >= self._min_length:
                    tokens.append(Token(
                        value[:self._max_token_length],
                        start_line,
                        start_column,
                    ))
                continue

            index += 1
            if char == "\n":
                line += 1
                column = 1
            else:
                column += 1

        return tokens

    def _match_rule(self, token: str) -> Rule | None:
        token = token[:self._max_token_length]
        entropy = self._entropy(token)
        for rule in self._rules:
            if rule.prefix is not None and not token.startswith(rule.prefix):
                continue
            if not (rule.min_length <= len(token) <= rule.max_length):
                continue
            if entropy + _ENTROPY_EPSILON < rule.min_entropy:
                continue
            return rule
        return None

    def _scan_text(self, text: str, path: str) -> list[Finding]:
        tokens = self._tokenize(text)
        self._counters["tokens"] += len(tokens)
        lines = text.split("\n")
        added: list[int] = []

        for token in tokens:
            if self.is_placeholder(token.value):
                self._counters["suppressed"] += 1
                continue

            line_text = ""
            if 1 <= token.line <= len(lines):
                line_text = lines[token.line - 1]
            if self._context_excluded(token.value, line_text, path):
                self._counters["suppressed"] += 1
                continue

            rule = self._match_rule(token.value)
            if rule is None:
                continue

            fingerprint = self._fingerprint(token.value)
            key = (rule.name, fingerprint)
            existing_index = self._seen.get(key)
            if existing_index is None:
                finding = Finding(
                    rule=rule.name,
                    severity=rule.severity,
                    preview=token.value[:4] + "***",
                    fingerprint=fingerprint,
                    path=path,
                    line=token.line,
                    column=token.column,
                )
                existing_index = len(self._findings)
                self._findings.append(finding)
                self._seen[key] = existing_index
                self._counters["findings"] += 1
                added.append(existing_index)
                continue

            self._counters["duplicates"] += 1
            existing = self._findings[existing_index]
            if path not in existing.also_in:
                self._findings[existing_index] = dataclass_replace(
                    existing, also_in=existing.also_in + (path,)
                )

        return [self._findings[index] for index in added]

    def _context_excluded(self, token: str, line_text: str, path: str) -> bool:
        if _OBVIOUS_TEST_TOKEN.search(token):
            return True
        if _TEST_CONTEXT.search(line_text) or _TEST_PATH.search(path):
            return True
        if len(token) >= 32 and _HASH_CONTEXT.search(line_text):
            return True
        return False

    @staticmethod
    def _fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _report_key(finding: Finding) -> tuple:
        rank = _SEVERITY_ORDER.get(finding.severity.lower(), -1)
        return (
            -rank,
            finding.path,
            finding.line,
            finding.column,
            finding.rule,
            finding.fingerprint,
        )

    @staticmethod
    def _require_int(name: str, value: object, *, minimum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ScanError("SCAN_INVALID_ARGUMENT", f"{name} must be an integer")
        if value < minimum:
            raise ScanError(
                "SCAN_INVALID_ARGUMENT", f"{name} must be at least {minimum}"
            )
        return value

    def _build_rule(self, name: str, prefix: str | None, min_length: int,
                    max_length: int, min_entropy: float,
                    severity: str) -> Rule:
        if not isinstance(name, str) or not name:
            raise ScanError("SCAN_INVALID_RULE", "rule name must be a non-empty string")
        if prefix is not None and not isinstance(prefix, str):
            raise ScanError("SCAN_INVALID_RULE", "rule prefix must be a string or None")
        try:
            min_length = self._require_int("min_length", min_length, minimum=1)
            max_length = self._require_int("max_length", max_length, minimum=1)
        except ScanError as exc:
            raise ScanError("SCAN_INVALID_RULE", exc.detail) from exc
        if max_length < min_length:
            raise ScanError(
                "SCAN_INVALID_RULE", "max_length must be at least min_length"
            )
        if (isinstance(min_entropy, bool)
                or not isinstance(min_entropy, (int, float))
                or not math.isfinite(min_entropy)
                or min_entropy < 0):
            raise ScanError(
                "SCAN_INVALID_RULE", "min_entropy must be a finite non-negative number"
            )
        if not isinstance(severity, str) or not severity:
            raise ScanError("SCAN_INVALID_RULE", "severity must be a non-empty string")
        return Rule(
            name=name,
            prefix=prefix,
            min_length=min_length,
            max_length=max_length,
            min_entropy=float(min_entropy),
            severity=severity,
        )

    def _coerce_rules(self, rules: object) -> tuple[Rule, ...]:
        if isinstance(rules, (str, bytes, Mapping)):
            raise ScanError("SCAN_INVALID_RULE", "rules must be a sequence of rules")
        try:
            values = tuple(rules)
        except TypeError as exc:
            raise ScanError(
                "SCAN_INVALID_RULE", "rules must be a sequence of rules"
            ) from exc

        coerced: list[Rule] = []
        for value in values:
            if isinstance(value, Rule):
                rule = self._build_rule(
                    value.name, value.prefix, value.min_length,
                    value.max_length, value.min_entropy, value.severity,
                )
            elif isinstance(value, Mapping):
                try:
                    name = value["name"]
                    prefix = value.get("prefix")
                    min_length = value["min_length"]
                    max_length = value["max_length"]
                    min_entropy = value["min_entropy"]
                    severity = value["severity"]
                except KeyError as exc:
                    raise ScanError(
                        "SCAN_INVALID_RULE", f"missing rule field {exc.args[0]}"
                    ) from exc
                rule = self._build_rule(
                    name, prefix, min_length, max_length,
                    min_entropy, severity,
                )
            else:
                raise ScanError("SCAN_INVALID_RULE", "unsupported rule value")
            coerced.append(rule)
        return tuple(coerced)

    @staticmethod
    def _validate_scan_args(text: object, path: object,
                            commit: object) -> None:
        if not isinstance(text, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "text must be a string")
        if not isinstance(path, str) or not path:
            raise ScanError("SCAN_INVALID_ARGUMENT", "path must be a non-empty string")
        if commit is not None and not isinstance(commit, str):
            raise ScanError("SCAN_INVALID_ARGUMENT", "commit must be a string or None")

    @staticmethod
    def _rule_to_dict(rule: Rule) -> dict:
        return {
            "name": rule.name,
            "prefix": rule.prefix,
            "min_length": rule.min_length,
            "max_length": rule.max_length,
            "min_entropy": rule.min_entropy,
            "severity": rule.severity,
        }

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict:
        return {
            "rule": finding.rule,
            "severity": finding.severity,
            "preview": finding.preview,
            "fingerprint": finding.fingerprint,
            "path": finding.path,
            "line": finding.line,
            "column": finding.column,
            "also_in": tuple(finding.also_in),
        }

    def _decode_snapshot(
        self, state: object
    ) -> tuple[tuple[Rule, ...], list[Finding],
               dict[tuple[str, str], int], dict]:
        if not isinstance(state, Mapping):
            raise ScanError("SCAN_SNAPSHOT_INVALID", "snapshot must be a mapping")
        if set(state) != _SNAPSHOT_KEYS:
            raise ScanError("SCAN_SNAPSHOT_INVALID", "snapshot keys are invalid")
        version = state["version"]
        if (isinstance(version, bool) or not isinstance(version, int)
                or version != _SNAPSHOT_VERSION):
            raise ScanError("SCAN_SNAPSHOT_INVALID", "unsupported snapshot version")

        rules = self._decode_snapshot_rules(state["rules"])
        findings = self._decode_snapshot_findings(state["findings"])
        seen = self._decode_snapshot_seen(state["seen"])
        counters = self._decode_snapshot_counters(state["counters"])

        if counters["findings"] != len(findings):
            raise ScanError(
                "SCAN_SNAPSHOT_INVALID", "finding counter does not match findings"
            )
        if len(seen) != len(findings):
            raise ScanError(
                "SCAN_SNAPSHOT_INVALID", "dedup index does not match findings"
            )

        rule_severities: dict[str, set[str]] = {}
        for rule in rules:
            rule_severities.setdefault(rule.name, set()).add(rule.severity)
        rule_names = set(rule_severities)
        indexes: set[int] = set()
        for key, index in seen.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid dedup key")
            rule_name, fingerprint = key
            if not isinstance(rule_name, str) or not isinstance(fingerprint, str):
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid dedup key")
            if rule_name not in rule_names:
                raise ScanError("SCAN_SNAPSHOT_INVALID", "dedup rule is unknown")
            if (isinstance(index, bool) or not isinstance(index, int)
                    or not 0 <= index < len(findings)):
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid dedup index")
            if index in indexes:
                raise ScanError("SCAN_SNAPSHOT_INVALID", "duplicate dedup index")
            finding = findings[index]
            if (finding.rule != rule_name
                    or finding.fingerprint != fingerprint):
                raise ScanError(
                    "SCAN_SNAPSHOT_INVALID", "dedup index does not match finding"
                )
            if finding.rule not in rule_names:
                raise ScanError("SCAN_SNAPSHOT_INVALID", "finding rule is unknown")
            if finding.severity not in rule_severities[finding.rule]:
                raise ScanError(
                    "SCAN_SNAPSHOT_INVALID", "finding severity is inconsistent"
                )
            indexes.add(index)

        if indexes != set(range(len(findings))):
            raise ScanError(
                "SCAN_SNAPSHOT_INVALID", "dedup index is incomplete"
            )

        return rules, findings, seen, counters

    def _decode_snapshot_rules(self, value: object) -> tuple[Rule, ...]:
        if not isinstance(value, (list, tuple)):
            raise ScanError("SCAN_SNAPSHOT_INVALID", "rules must be a sequence")
        rules = self._coerce_rules(value)
        return rules

    def _decode_snapshot_findings(self, value: object) -> list[Finding]:
        if not isinstance(value, (list, tuple)):
            raise ScanError("SCAN_SNAPSHOT_INVALID", "findings must be a sequence")
        findings: list[Finding] = []
        for item in value:
            if isinstance(item, Finding):
                finding = item
            elif isinstance(item, Mapping):
                try:
                    finding = Finding(
                        rule=item["rule"],
                        severity=item["severity"],
                        preview=item["preview"],
                        fingerprint=item["fingerprint"],
                        path=item["path"],
                        line=item["line"],
                        column=item["column"],
                        also_in=tuple(item.get("also_in", ())),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ScanError(
                        "SCAN_SNAPSHOT_INVALID", "invalid finding"
                    ) from exc
            else:
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid finding")

            if (not isinstance(finding.rule, str) or not finding.rule
                    or not isinstance(finding.severity, str)
                    or not isinstance(finding.preview, str)
                    or not finding.preview.endswith("***")
                    or len(finding.preview) > 7
                    or not isinstance(finding.fingerprint, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", finding.fingerprint)
                    or not isinstance(finding.path, str) or not finding.path
                    or isinstance(finding.line, bool)
                    or not isinstance(finding.line, int) or finding.line < 1
                    or isinstance(finding.column, bool)
                    or not isinstance(finding.column, int) or finding.column < 1
                    or not isinstance(finding.also_in, tuple)
                    or any(not isinstance(path, str) or not path
                           for path in finding.also_in)):
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid finding fields")
            findings.append(finding)
        return findings

    def _decode_snapshot_seen(
        self, value: object
    ) -> dict[tuple[str, str], int]:
        if not isinstance(value, Mapping):
            raise ScanError("SCAN_SNAPSHOT_INVALID", "seen index must be a mapping")
        seen: dict[tuple[str, str], int] = {}
        for key, index in value.items():
            if not isinstance(key, tuple) or len(key) != 2:
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid dedup key")
            if not isinstance(key[0], str) or not isinstance(key[1], str):
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid dedup key")
            if isinstance(index, bool) or not isinstance(index, int):
                raise ScanError("SCAN_SNAPSHOT_INVALID", "invalid dedup index")
            seen[key] = index
        return seen

    def _decode_snapshot_counters(self, value: object) -> dict:
        if not isinstance(value, Mapping):
            raise ScanError("SCAN_SNAPSHOT_INVALID", "counters must be a mapping")
        if set(value) != _COUNTER_KEYS:
            raise ScanError("SCAN_SNAPSHOT_INVALID", "counter keys are invalid")
        counters = {}
        for key in _COUNTER_KEYS:
            count = value[key]
            if (isinstance(count, bool) or not isinstance(count, int)
                    or count < 0):
                raise ScanError(
                    "SCAN_SNAPSHOT_INVALID", f"invalid counter {key}"
                )
            counters[key] = count
        return counters
