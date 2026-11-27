"""Entity expansion budget guard for untrusted XML documents."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class XxeError(ValueError):
    """Raised when the guard refuses a document or a policy change."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DtdInspection:
    """Result of scanning the declaration section of a document."""

    declarations: int
    internal: tuple
    external: tuple
    parameter: tuple
    external_subset: str | None


class XxeEntityGuard:
    """Inspect declared entities before parsing and enforce expansion budgets."""

    def __init__(self, *, max_depth: int = 6, max_bytes: int = 2048) -> None:
        self.max_depth = max_depth
        self.max_bytes = max_bytes
        self._lock = threading.RLock()

    def declare_namespace(self, namespace: str, *, prefix: str) -> None:
        raise NotImplementedError

    def revoke_namespace(self, namespace: str) -> bool:
        raise NotImplementedError

    def block_external(self, namespace: str, *, allow: bool = False) -> bool:
        raise NotImplementedError

    def inspect_dtd(self, document: str) -> DtdInspection:
        raise NotImplementedError

    def expand_budget(self, document: str) -> dict:
        raise NotImplementedError

    def parse_report(self, document: str) -> dict:
        raise NotImplementedError

    def describe_entity(self, name: str) -> dict:
        raise NotImplementedError

    def entity_names(self) -> tuple:
        raise NotImplementedError

    def reference_count(self, name: str) -> int:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
