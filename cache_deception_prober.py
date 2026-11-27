"""Web cache deception prober: variant planning, cache-key normalisation, hit verification."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit


class CacheError(ValueError):
    """Raised when a cache-deception probe is refused or malformed."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: str


@dataclass(frozen=True)
class ProbeVariant:
    variant_id: str
    kind: str
    path: str
    suffix: str
    auth_required: bool


@dataclass(frozen=True)
class ProbeRecord:
    probe_id: str
    path: str
    variant: ProbeVariant
    cache_key: str
    first_status: int
    first_headers: tuple[tuple[str, str], ...]
    second_status: int | None
    second_headers: tuple[tuple[str, str], ...]
    marker_seen: bool
    requests: int


@dataclass(frozen=True)
class ProbeVerdict:
    probe_id: str
    status: str
    reason: str
    evidence: Mapping[str, Any]


class CacheDeceptionProber:
    """Plan suffix-confusion variants against a private path and verify cache hits."""

    VARIANT_ORDER = ("css", "js", "jpg", "semicolon", "null_byte", "uppercase", "extra_slash")
    SUFFIXES = {
        "css": ".css",
        "js": ".js",
        "jpg": ".jpg",
        "semicolon": ";.css",
        "null_byte": "%00.css",
        "uppercase": ".Css",
        "extra_slash": "/.css",
    }
    CACHE_KEY_POLICIES = ("query_ignored", "query_included")
    SNAPSHOT_KEYS = frozenset({"version", "origin", "probes", "verdicts", "stats"})

    def __init__(
        self,
        *,
        origin: str,
        private_prefixes: tuple[str, ...] = ("/account",),
        max_probes_per_path: int = 6,
        max_total_requests: int = 40,
        cache_key_policy: str = "query_ignored",
        fetcher: Callable[..., Any] | None = None,
    ) -> None:
        if cache_key_policy not in self.CACHE_KEY_POLICIES:
            raise CacheError("CACHE_INVALID_REQUEST", {"field": "cache_key_policy"})
        self.origin = origin.rstrip("/")
        self.private_prefixes = tuple(private_prefixes)
        self.max_probes_per_path = max_probes_per_path
        self.max_total_requests = max_total_requests
        self.cache_key_policy = cache_key_policy
        self._fetcher = fetcher
        self._lock = threading.RLock()
        self._path_locks: dict[str, threading.RLock] = {}
        self._records: dict[str, ProbeRecord] = {}
        self._markers: dict[str, str] = {}
        self._verdicts: dict[str, ProbeVerdict] = {}
        self._stats = {
            "probes": 0,
            "verifications": 0,
            "requests": 0,
            "cached": 0,
            "not_cached": 0,
            "restores": 0,
        }

    def plan(self, path: str) -> tuple[ProbeVariant, ...]:
        raise NotImplementedError

    def probe(self, path: str, *, victim_marker: str) -> tuple[ProbeRecord, ...]:
        raise NotImplementedError

    def verify_cache(self, probe_id: str) -> ProbeVerdict:
        raise NotImplementedError

    def classify(self, probe_id: str) -> ProbeVerdict:
        raise NotImplementedError

    def cache_key_for(self, url: str) -> str:
        raise NotImplementedError

    def probes_for(self, path: str) -> tuple[ProbeRecord, ...]:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
