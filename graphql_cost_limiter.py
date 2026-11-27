"""GraphQL admission control: depth, field cost, alias amplification, fragment cycles."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GraphqlError(ValueError):
    """Raised when a query cannot be parsed or its fragments cannot be resolved."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Field:
    name: str
    alias: str | None
    directives: tuple[str, ...]
    selection: tuple


@dataclass(frozen=True)
class Spread:
    name: str
    directives: tuple[str, ...]


@dataclass(frozen=True)
class InlineFragment:
    type_name: str | None
    directives: tuple[str, ...]
    selection: tuple


@dataclass(frozen=True)
class Fragment:
    name: str
    type_name: str
    selection: tuple


@dataclass(frozen=True)
class Document:
    operation: str
    name: str | None
    selections: tuple
    fragments: dict


@dataclass(frozen=True)
class Expanded:
    operation: str
    name: str | None
    selections: tuple


@dataclass(frozen=True)
class CostReport:
    fields: int
    cost: int
    depth: int
    aliases: int
    introspection: int


@dataclass(frozen=True)
class Admission:
    allowed: bool
    reason: str | None
    report: CostReport
    limits: dict


class GraphqlCostLimiter:
    """Decide whether a query is cheap enough to reach the executor."""

    def __init__(self, *, max_cost: int = 1000, max_depth: int = 10,
                 max_aliases: int = 25, introspection_budget: int = 50) -> None:
        self._lock = threading.RLock()
        self._limits = {
            "max_cost": max_cost,
            "max_depth": max_depth,
            "max_aliases": max_aliases,
            "introspection_budget": introspection_budget,
        }

    def parse(self, query: str) -> Document:
        raise NotImplementedError

    def resolve_fragments(self, document: Document) -> Expanded:
        raise NotImplementedError

    def compute_depth(self, document: Document) -> int:
        raise NotImplementedError

    def compute_cost(self, document: Document) -> CostReport:
        raise NotImplementedError

    def check_limits(self, document: Document, *, client: str | None = None) -> Admission:
        raise NotImplementedError

    def admit(self, query: str, *, client: str | None = None) -> Admission:
        raise NotImplementedError

    def set_client_limits(self, client: str, *, max_cost: int | None = None,
                          max_depth: int | None = None,
                          max_aliases: int | None = None,
                          introspection_budget: int | None = None) -> None:
        raise NotImplementedError

    def client_limits(self, client: str) -> dict:
        raise NotImplementedError

    def clear_client_limits(self, client: str) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
