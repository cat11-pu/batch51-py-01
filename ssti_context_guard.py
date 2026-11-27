"""Template sandbox: adjudicate expressions, filters and includes before rendering."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SstiError(ValueError):
    """Raised when an expression, filter, include or template is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    offset: int


@dataclass(frozen=True)
class Analysis:
    root: str
    attributes: tuple[str, ...]
    filters: tuple[str, ...]
    depth: int
    tokens: int


@dataclass(frozen=True)
class Verdict:
    status: str
    code: str | None
    detail: dict


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    action: str
    subject: str
    verdict: str
    code: str | None


DEFAULT_POLICY = {
    "roots": {"user": ("name", "email"), "site": ("title",)},
    "filters": ("upper", "lower", "escape"),
    "template_root": "templates",
    "max_depth": 8,
    "max_tokens": 64,
    "max_include_depth": 4,
}


class SstiContextGuard:
    """Decide whether a template expression may reach the renderer."""

    def __init__(self, *, policy: dict | None = None) -> None:
        self._lock = threading.RLock()
        self._policy = dict(policy) if policy is not None else dict(DEFAULT_POLICY)

    def tokenize(self, expression: str) -> list[Token]:
        raise NotImplementedError

    def analyze_expression(self, expression: str) -> Analysis:
        raise NotImplementedError

    def check_attribute_chain(self, chain: str) -> tuple[str, ...]:
        raise NotImplementedError

    def check_filter(self, name: str, args: tuple[str, ...] = ()) -> None:
        raise NotImplementedError

    def adjudicate(self, expression: str, *, subject: str = "") -> Verdict:
        raise NotImplementedError

    def resolve_include(self, path: str, *, from_template: str = "") -> str:
        raise NotImplementedError

    def register_template(self, name: str, source: str) -> None:
        raise NotImplementedError

    def adjudicate_template(self, name: str) -> Verdict:
        raise NotImplementedError

    def templates(self) -> tuple[str, ...]:
        raise NotImplementedError

    def render(self, template: str, expression: str, context) -> str:
        raise NotImplementedError

    def set_policy(self, policy: dict) -> None:
        raise NotImplementedError

    def policy(self) -> dict:
        raise NotImplementedError

    def audit_log(self) -> tuple[AuditEntry, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
