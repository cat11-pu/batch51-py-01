"""Credential scanning: entropy threshold, placeholder exclusion, hit merging."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class SecretEntropyScanner:
    """Find high-entropy credentials in text and merge repeats per secret."""

    def __init__(self, *, rules=None, min_length: int = 8,
                 max_token_length: int = 512) -> None:
        self._lock = threading.RLock()
        self._rules = tuple(rules) if rules is not None else DEFAULT_RULES
        self._min_length = min_length
        self._max_token_length = max_token_length

    def entropy(self, text: str) -> float:
        raise NotImplementedError

    def tokenize(self, text: str) -> list[Token]:
        raise NotImplementedError

    def is_placeholder(self, token: str) -> bool:
        raise NotImplementedError

    def match_rule(self, token: str) -> Rule | None:
        raise NotImplementedError

    def scan_text(self, text: str, *, path: str, commit: str | None = None) -> list[Finding]:
        raise NotImplementedError

    def scan_files(self, files: dict, *, commit: str | None = None) -> list[Finding]:
        raise NotImplementedError

    def findings(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def findings_for(self, rule: str) -> tuple[Finding, ...]:
        raise NotImplementedError

    def report(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def add_rule(self, name: str, *, prefix: str | None = None,
                 min_length: int = 8, max_length: int | None = None,
                 min_entropy: float = 3.5, severity: str = "medium") -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
