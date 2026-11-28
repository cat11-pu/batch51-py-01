"""Web cache deception prober: variant planning, cache-key normalisation, hit verification."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass, replace
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
        }

    _STAT_KEYS = ("probes", "verifications", "requests", "cached", "not_cached")

    @staticmethod
    def _header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
        lowered = name.lower()
        for key, value in headers:
            if key.lower() == lowered:
                return value
        return None

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return {token.strip().lower() for token in value.split(",")}

    def _normalize_path(self, path: Any) -> str:
        if not isinstance(path, str) or not path.startswith("/"):
            raise CacheError("CACHE_PATH_FORBIDDEN", {"path": path})
        base = path.rstrip("/")
        for prefix in self.private_prefixes:
            normalized = prefix.rstrip("/")
            if base == normalized or base.startswith(normalized + "/"):
                return base
        raise CacheError("CACHE_PATH_FORBIDDEN", {"path": path})

    def _path_lock_for(self, path: str) -> threading.RLock:
        with self._lock:
            lock = self._path_locks.get(path)
            if lock is None:
                lock = threading.RLock()
                self._path_locks[path] = lock
            return lock

    def _spend_request(self) -> None:
        with self._lock:
            if self._stats["requests"] >= self.max_total_requests:
                raise CacheError(
                    "CACHE_LIMIT_EXCEEDED",
                    {"max_total_requests": self.max_total_requests},
                )
            self._stats["requests"] += 1

    def _fetch(self, url: str, headers: dict[str, str]) -> Response:
        if self._fetcher is None:
            raise CacheError("CACHE_INVALID_REQUEST", {"field": "fetcher"})
        return self._fetcher("GET", url, headers)

    def plan(self, path: str) -> tuple[ProbeVariant, ...]:
        base = self._normalize_path(path)
        variants: list[ProbeVariant] = []
        seen: set[str] = set()
        for kind in self.VARIANT_ORDER:
            suffix = self.SUFFIXES[kind]
            variant_path = base + suffix
            if variant_path in seen:
                continue
            seen.add(variant_path)
            variants.append(
                ProbeVariant(
                    variant_id=f"{kind}:{variant_path}",
                    kind=kind,
                    path=variant_path,
                    suffix=suffix,
                    auth_required=True,
                )
            )
            if len(variants) >= self.max_probes_per_path:
                break
        return tuple(variants)

    def probe(self, path: str, *, victim_marker: str) -> tuple[ProbeRecord, ...]:
        if not isinstance(victim_marker, str) or not victim_marker.strip():
            raise CacheError("CACHE_INVALID_REQUEST", {"field": "victim_marker"})
        base = self._normalize_path(path)
        lock = self._path_lock_for(base)
        with lock:
            existing = self.probes_for(base)
            if existing:
                return existing
            records: list[ProbeRecord] = []
            for variant in self.plan(base):
                self._spend_request()
                response = self._fetch(
                    self.origin + variant.path,
                    {"Authorization": "Bearer cache-probe"},
                )
                records.append(
                    ProbeRecord(
                        probe_id=variant.variant_id,
                        path=base,
                        variant=variant,
                        cache_key=self.cache_key_for(self.origin + variant.path),
                        first_status=response.status,
                        first_headers=tuple(response.headers.items()),
                        second_status=None,
                        second_headers=(),
                        marker_seen=False,
                        requests=1,
                    )
                )
            with self._lock:
                for record in records:
                    self._records[record.probe_id] = record
                    self._markers[record.probe_id] = victim_marker
                self._stats["probes"] += len(records)
            return tuple(records)

    def verify_cache(self, probe_id: str) -> ProbeVerdict:
        with self._lock:
            record = self._records.get(probe_id)
            if record is None:
                raise CacheError("CACHE_PROBE_UNKNOWN", {"probe_id": probe_id})
            verdict = self._verdicts.get(probe_id)
            if verdict is not None:
                return verdict
            path = record.path
        lock = self._path_lock_for(path)
        with lock:
            with self._lock:
                verdict = self._verdicts.get(probe_id)
                if verdict is not None:
                    return verdict
                record = self._records[probe_id]
                marker = self._markers[probe_id]

            vary = self._header(record.first_headers, "vary")
            if vary is not None and self._tokens(vary) & {"cookie", "*"}:
                return self._store_verdict(
                    ProbeVerdict(probe_id, "not_cached", "vary_cookie", {"vary": vary})
                )
            cache_control = self._header(record.first_headers, "cache-control")
            if cache_control is not None and "no-store" in self._tokens(cache_control):
                return self._store_verdict(
                    ProbeVerdict(
                        probe_id,
                        "not_cached",
                        "no_store",
                        {"cache_control": cache_control},
                    )
                )

            self._spend_request()
            response = self._fetch(self.origin + record.variant.path, {})
            second_headers = tuple(response.headers.items())
            marker_seen = marker in response.body
            evidence: dict[str, Any] = {
                "second_status": response.status,
                "age": self._header(second_headers, "age"),
            }
            x_cache = self._header(second_headers, "x-cache")
            if x_cache is not None:
                evidence["x_cache"] = x_cache
            if marker_seen:
                verdict = ProbeVerdict(probe_id, "cached", "anonymous_marker_hit", evidence)
            else:
                verdict = ProbeVerdict(probe_id, "not_cached", "anonymous_miss", evidence)
            with self._lock:
                self._records[probe_id] = replace(
                    record,
                    second_status=response.status,
                    second_headers=second_headers,
                    marker_seen=marker_seen,
                    requests=record.requests + 1,
                )
            return self._store_verdict(verdict)

    def _store_verdict(self, verdict: ProbeVerdict) -> ProbeVerdict:
        with self._lock:
            self._verdicts[verdict.probe_id] = verdict
            self._stats["verifications"] += 1
            if verdict.status == "cached":
                self._stats["cached"] += 1
            elif verdict.status == "not_cached":
                self._stats["not_cached"] += 1
        return verdict

    def classify(self, probe_id: str) -> ProbeVerdict:
        with self._lock:
            if probe_id not in self._records:
                raise CacheError("CACHE_PROBE_UNKNOWN", {"probe_id": probe_id})
            verdict = self._verdicts.get(probe_id)
            if verdict is not None:
                return verdict
            return ProbeVerdict(probe_id, "inconclusive", "not_verified", {})

    def cache_key_for(self, url: str) -> str:
        split = urlsplit(url)
        host = split.netloc.lower()
        path = re.sub(r"/{2,}", "/", split.path).rstrip("/")
        key = host + path
        if self.cache_key_policy == "query_included" and split.query:
            key += "?" + split.query
        return key

    def probes_for(self, path: str) -> tuple[ProbeRecord, ...]:
        base = path.rstrip("/") if isinstance(path, str) else path
        with self._lock:
            return tuple(
                record for record in self._records.values() if record.path == base
            )

    def report(self) -> dict:
        with self._lock:
            verdict_counts = {"cached": 0, "not_cached": 0, "inconclusive": 0}
            cached_paths: set[str] = set()
            for record in self._records.values():
                verdict = self._verdicts.get(record.probe_id)
                if verdict is None:
                    verdict_counts["inconclusive"] += 1
                else:
                    verdict_counts[verdict.status] += 1
                    if verdict.status == "cached":
                        cached_paths.add(record.path)
            return {
                "origin": self.origin,
                "paths": tuple(sorted({record.path for record in self._records.values()})),
                "probes": len(self._records),
                "requests": self._stats["requests"],
                "verdicts": verdict_counts,
                "cached_paths": tuple(sorted(cached_paths)),
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": 1,
                "origin": self.origin,
                "probes": [
                    {
                        "probe_id": record.probe_id,
                        "path": record.path,
                        "victim_marker": self._markers[record.probe_id],
                        "variant": {
                            "variant_id": record.variant.variant_id,
                            "kind": record.variant.kind,
                            "path": record.variant.path,
                            "suffix": record.variant.suffix,
                            "auth_required": record.variant.auth_required,
                        },
                        "cache_key": record.cache_key,
                        "first_status": record.first_status,
                        "first_headers": [list(pair) for pair in record.first_headers],
                        "second_status": record.second_status,
                        "second_headers": [list(pair) for pair in record.second_headers],
                        "marker_seen": record.marker_seen,
                        "requests": record.requests,
                    }
                    for record in self._records.values()
                ],
                "verdicts": {
                    probe_id: {
                        "probe_id": verdict.probe_id,
                        "status": verdict.status,
                        "reason": verdict.reason,
                        "evidence": dict(verdict.evidence),
                    }
                    for probe_id, verdict in self._verdicts.items()
                },
                "stats": {key: self._stats[key] for key in self._STAT_KEYS},
            }
        return copy.deepcopy(state)

    @staticmethod
    def _invalid(detail: Any) -> CacheError:
        return CacheError("CACHE_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(
        self, state: Any
    ) -> tuple[str, dict[str, ProbeRecord], dict[str, str], dict[str, ProbeVerdict], dict[str, int]]:
        if not isinstance(state, Mapping):
            raise self._invalid({"reason": "not_a_mapping"})
        missing = self.SNAPSHOT_KEYS - set(state)
        if missing:
            raise self._invalid({"missing": sorted(missing)})
        if state["version"] != 1 or not isinstance(state["origin"], str):
            raise self._invalid({"reason": "bad_header"})
        probes = state["probes"]
        verdicts = state["verdicts"]
        stats = state["stats"]
        if not isinstance(probes, list) or not isinstance(verdicts, Mapping):
            raise self._invalid({"reason": "bad_sections"})
        if not isinstance(stats, Mapping) or any(
            not isinstance(stats.get(key), int)
            or isinstance(stats.get(key), bool)
            or stats.get(key) < 0
            for key in self._STAT_KEYS
        ):
            raise self._invalid({"reason": "bad_stats"})

        records: dict[str, ProbeRecord] = {}
        markers: dict[str, str] = {}
        for item in probes:
            if not isinstance(item, Mapping):
                raise self._invalid({"reason": "bad_probe"})
            variant_data = item["variant"]
            if not isinstance(variant_data, Mapping):
                raise self._invalid({"reason": "bad_variant"})
            variant = ProbeVariant(
                variant_id=str(variant_data["variant_id"]),
                kind=str(variant_data["kind"]),
                path=str(variant_data["path"]),
                suffix=str(variant_data["suffix"]),
                auth_required=bool(variant_data["auth_required"]),
            )
            marker = item["victim_marker"]
            if not isinstance(marker, str):
                raise self._invalid({"reason": "bad_marker"})
            second_status = item["second_status"]
            if second_status is not None and not isinstance(second_status, int):
                raise self._invalid({"reason": "bad_second_status"})
            record = ProbeRecord(
                probe_id=str(item["probe_id"]),
                path=str(item["path"]),
                variant=variant,
                cache_key=str(item["cache_key"]),
                first_status=int(item["first_status"]),
                first_headers=tuple(
                    (str(pair[0]), str(pair[1])) for pair in item["first_headers"]
                ),
                second_status=second_status,
                second_headers=tuple(
                    (str(pair[0]), str(pair[1])) for pair in item["second_headers"]
                ),
                marker_seen=bool(item["marker_seen"]),
                requests=int(item["requests"]),
            )
            records[record.probe_id] = record
            markers[record.probe_id] = marker

        parsed_verdicts: dict[str, ProbeVerdict] = {}
        for probe_id, verdict_data in verdicts.items():
            if not isinstance(verdict_data, Mapping):
                raise self._invalid({"reason": "bad_verdict"})
            evidence = verdict_data["evidence"]
            if not isinstance(evidence, Mapping):
                raise self._invalid({"reason": "bad_evidence"})
            verdict = ProbeVerdict(
                probe_id=str(verdict_data["probe_id"]),
                status=str(verdict_data["status"]),
                reason=str(verdict_data["reason"]),
                evidence=dict(evidence),
            )
            parsed_verdicts[str(probe_id)] = verdict

        parsed_stats = {key: int(stats[key]) for key in self._STAT_KEYS}
        return str(state["origin"]), records, markers, parsed_verdicts, parsed_stats

    def restore(self, state: dict) -> None:
        try:
            origin, records, markers, verdicts, stats = self._parse_snapshot(state)
        except CacheError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
            raise CacheError("CACHE_SNAPSHOT_INVALID", {"reason": repr(exc)}) from exc
        with self._lock:
            self.origin = origin
            self._records = records
            self._markers = markers
            self._verdicts = verdicts
            self._stats = dict(stats)

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in self._STAT_KEYS}

    def reset(self) -> None:
        with self._lock:
            self._records.clear()
            self._markers.clear()
            self._verdicts.clear()
            self._path_locks.clear()
            for key in self._STAT_KEYS:
                self._stats[key] = 0
