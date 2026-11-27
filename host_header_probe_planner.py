"""Host header probe planning with reflection and cache key classification."""

from __future__ import annotations

import threading
from dataclasses import dataclass


VARIANTS = (
    "plain",
    "case",
    "trailing-dot",
    "port",
    "absolute",
    "duplicate",
    "prefixed",
)

CACHE_MARKER_HEADERS = ("vary", "x-cache-key")


class HostError(ValueError):
    """Raised when a target definition or a probe list is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Probe:
    target_id: str
    variant: str
    host_header: str
    port: int


class HostHeaderProbePlanner:
    """Generate host header variants per target and grade observed reflections."""

    def __init__(self, *, per_target_limit: int = 10) -> None:
        self.per_target_limit = per_target_limit
        self._lock = threading.RLock()

    def add_target(self, target_id: str, *, host: str, scheme: str = "https",
                   ports=(443,)) -> int:
        raise NotImplementedError

    def remove_target(self, target_id: str) -> bool:
        raise NotImplementedError

    def plan_probes(self, target_id: str) -> tuple:
        raise NotImplementedError

    def variants_for(self, target_id: str) -> tuple:
        raise NotImplementedError

    def dedupe(self, target_id: str, probes) -> tuple:
        raise NotImplementedError

    def classify_reflection(self, observation: dict) -> dict:
        raise NotImplementedError

    def detect_cache_key(self, headers: dict) -> bool:
        raise NotImplementedError

    def describe_target(self, target_id: str) -> dict:
        raise NotImplementedError

    def list_targets(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
