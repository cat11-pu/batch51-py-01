"""CORS policy evaluator: origin matching, credential rules, preflight cache keys."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CorsError(ValueError):
    """Raised when a policy or cache operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CorsPolicy:
    route: str
    origins: tuple[str, ...]
    methods: tuple[str, ...]
    headers: tuple[str, ...]
    allow_credentials: bool
    max_age: int


@dataclass(frozen=True)
class CorsDecision:
    allowed: bool
    allow_origin: str | None
    allow_methods: tuple[str, ...]
    allow_headers: tuple[str, ...]
    max_age: int
    cacheable: bool
    cache_key: str | None
    reason: str


class CorsPolicyEvaluator:
    """Evaluate per-route CORS policy and keep a bounded preflight cache."""

    def __init__(self, *, max_cache_entries: int = 64,
                 default_max_age: int = 600) -> None:
        self.max_cache_entries = max_cache_entries
        self.default_max_age = default_max_age
        self._lock = threading.RLock()
        self._policies: dict[str, CorsPolicy] = {}
        self._cache: dict[str, dict] = {}
        self._stats = {
            "policies": 0,
            "evaluations": 0,
            "preflights": 0,
            "denied": 0,
            "cache_hits": 0,
            "cache_evictions": 0,
        }

    def register_policy(self, route: str, *, origins, methods=("GET", "HEAD"),
                        headers=(), allow_credentials: bool = False,
                        max_age: int | None = None) -> CorsPolicy:
        raise NotImplementedError

    def policy_for(self, route: str) -> CorsPolicy | None:
        raise NotImplementedError

    def evaluate(self, route: str, origin: str, *, method: str = "GET",
                 credentials: bool = False, now: float | None = None) -> CorsDecision:
        raise NotImplementedError

    def preflight(self, route: str, origin: str, *, method: str, headers=(),
                  credentials: bool = False, now: float | None = None) -> CorsDecision:
        raise NotImplementedError

    def cache_key(self, route: str, origin: str, *, method: str, headers=()) -> str:
        raise NotImplementedError

    def remember(self, decision: CorsDecision, *, now: float | None = None) -> str:
        raise NotImplementedError

    def lookup_cache(self, key: str, *, now: float | None = None) -> CorsDecision | None:
        raise NotImplementedError

    def invalidate(self, route: str) -> int:
        raise NotImplementedError

    def cache_size(self) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
