"""CORS policy evaluator: origin matching, credential rules, preflight cache keys."""

from __future__ import annotations

import copy
import json
import math
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit


_SNAPSHOT_VERSION = 1
_DEFAULT_PORTS = {"http": 80, "https": 443}
_STATS_KEYS = (
    "policies",
    "evaluations",
    "preflights",
    "denied",
    "cache_hits",
    "cache_evictions",
)
_POLICY_KEYS = {
    "route",
    "origins",
    "methods",
    "headers",
    "allow_credentials",
    "max_age",
}
_CACHE_KEYS = {"route", "version", "expires_at", "sequence", "decision"}
_DECISION_KEYS = {
    "allowed",
    "allow_origin",
    "allow_methods",
    "allow_headers",
    "max_age",
    "cacheable",
    "cache_key",
    "reason",
}


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
    _route: str | None = field(default=None, repr=False, compare=False)
    _route_version: int = field(default=0, repr=False, compare=False)


@dataclass(frozen=True)
class _PolicyRecord:
    policy: CorsPolicy
    normalized_origins: frozenset[str]
    wildcard: bool


@dataclass(frozen=True)
class _CacheEntry:
    decision: CorsDecision
    route: str
    version: int
    expires_at: float
    sequence: int


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _require_string(value: object, detail: str) -> str:
    if not isinstance(value, str) or value == "":
        raise CorsError("CORS_INVALID_POLICY", detail)
    return value


def _normalize_sequence(values: object, transform, detail: str) -> tuple[str, ...]:
    if values is None or isinstance(values, (str, bytes)):
        raise CorsError("CORS_INVALID_POLICY", detail)
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise CorsError("CORS_INVALID_POLICY", detail) from exc

    result: list[str] = []
    seen: set[str] = set()
    for value in iterator:
        if not isinstance(value, str) or value == "":
            raise CorsError("CORS_INVALID_POLICY", detail)
        normalized = transform(value)
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return tuple(result)


def _normalize_origins(origins: object) -> tuple[str, ...]:
    if origins is None or isinstance(origins, (str, bytes)):
        raise CorsError("CORS_INVALID_POLICY", "origins-must-be-a-sequence")
    try:
        iterator = iter(origins)
    except TypeError as exc:
        raise CorsError(
            "CORS_INVALID_POLICY", "origins-must-be-a-sequence"
        ) from exc

    result: list[str] = []
    for origin in iterator:
        if not isinstance(origin, str) or origin == "":
            raise CorsError("CORS_INVALID_POLICY", "invalid-origin")
        result.append(origin)
    if not result:
        raise CorsError("CORS_INVALID_POLICY", "origins-must-not-be-empty")
    return tuple(result)


def _canonical_origin(origin: object) -> str | None:
    if not isinstance(origin, str) or origin == "":
        return None
    if origin == "*":
        return "*"
    try:
        parsed = urlsplit(origin)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return origin.lower()
    if not scheme or host is None:
        return origin.lower()

    host = host.lower()
    if ":" in host:
        host = f"[{host}]"
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    if port is None:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _normalize_method(method: object) -> str:
    if not isinstance(method, str) or method == "":
        raise CorsError("CORS_INVALID_POLICY", "invalid-method")
    return method.upper()


def _normalize_request_headers(headers: object) -> tuple[str, ...]:
    return _normalize_sequence(
        headers, str.lower, "headers-must-be-non-empty-strings"
    )


def _now_or_monotonic(now: float | None) -> float:
    if now is None:
        return time.monotonic()
    if not _is_number(now):
        raise CorsError("CORS_INVALID_POLICY", "invalid-now")
    return float(now)


def _snapshot_invalid(detail: object) -> None:
    raise CorsError("CORS_SNAPSHOT_INVALID", detail)


class CorsPolicyEvaluator:
    """Evaluate per-route CORS policy and keep a bounded preflight cache."""

    def __init__(self, *, max_cache_entries: int = 64,
                 default_max_age: int = 600) -> None:
        if not _is_int(max_cache_entries) or max_cache_entries < 0:
            raise CorsError(
                "CORS_INVALID_POLICY", "max_cache_entries-must-be-non-negative"
            )
        if not _is_int(default_max_age) or default_max_age < 0:
            raise CorsError(
                "CORS_INVALID_POLICY", "default_max_age-must-be-non-negative"
            )

        self.max_cache_entries = max_cache_entries
        self.default_max_age = default_max_age
        self._lock = threading.RLock()
        self._policies: dict[str, CorsPolicy] = {}
        self._records: dict[str, _PolicyRecord] = {}
        self._versions: dict[str, int] = {}
        self._cache: dict[str, _CacheEntry] = {}
        self._sequence = 0
        self._stats = {key: 0 for key in _STATS_KEYS}

    def register_policy(self, route: str, origins, methods=("GET", "HEAD"),
                        headers=(), allow_credentials: bool = False,
                        max_age: int | None = None) -> CorsPolicy:
        route = _require_string(route, "route-must-be-a-non-empty-string")
        normalized_origins = _normalize_origins(origins)
        normalized_methods = _normalize_sequence(
            methods, str.upper, "methods-must-be-non-empty-strings"
        )
        normalized_headers = _normalize_sequence(
            headers, str.lower, "headers-must-be-non-empty-strings"
        )
        if not isinstance(allow_credentials, bool):
            raise CorsError(
                "CORS_INVALID_POLICY", "allow_credentials-must-be-a-boolean"
            )
        if max_age is None:
            normalized_max_age = self.default_max_age
        elif _is_int(max_age) and max_age >= 0:
            normalized_max_age = max_age
        else:
            raise CorsError(
                "CORS_INVALID_POLICY", "max_age-must-be-a-non-negative-integer"
            )

        policy = CorsPolicy(
            route=route,
            origins=normalized_origins,
            methods=normalized_methods,
            headers=normalized_headers,
            allow_credentials=allow_credentials,
            max_age=normalized_max_age,
        )
        canonical_origins = frozenset(
            canonical
            for origin in normalized_origins
            if origin != "*"
            for canonical in (_canonical_origin(origin),)
            if canonical is not None
        )
        record = _PolicyRecord(
            policy=policy,
            normalized_origins=canonical_origins,
            wildcard="*" in normalized_origins,
        )

        with self._lock:
            self._policies[route] = policy
            self._records[route] = record
            self._versions[route] = self._versions.get(route, 0) + 1
            self._remove_route_cache_locked(route)
            self._stats["policies"] = len(self._policies)
        return policy

    def policy_for(self, route: str) -> CorsPolicy | None:
        with self._lock:
            return self._policies.get(route)

    def evaluate(self, route: str, origin: str, method: str = "GET",
                 credentials: bool = False,
                 now: float | None = None) -> CorsDecision:
        with self._lock:
            self._stats["evaluations"] += 1
            record = self._records.get(route)
            if record is None:
                return self._denied_locked("no-policy")

            canonical_origin = _canonical_origin(origin)
            if not self._origin_matches(record, canonical_origin):
                return self._denied_locked("origin-not-allowed")

            policy = record.policy
            if credentials and not policy.allow_credentials:
                return self._denied_locked(
                    "credentials-not-allowed", allow_origin=origin
                )

            allow_origin = (
                origin
                if credentials or not record.wildcard
                else "*"
            )
            return CorsDecision(
                allowed=True,
                allow_origin=allow_origin,
                allow_methods=policy.methods,
                allow_headers=policy.headers,
                max_age=policy.max_age,
                cacheable=False,
                cache_key=None,
                reason="ok",
                _route=route,
                _route_version=self._versions.get(route, 0),
            )

    def preflight(self, route: str, origin: str, method: str, headers=(),
                  credentials: bool = False,
                  now: float | None = None) -> CorsDecision:
        with self._lock:
            self._stats["preflights"] += 1
            record = self._records.get(route)
            if record is None:
                return self._denied_locked("no-policy")

            canonical_origin = _canonical_origin(origin)
            if not self._origin_matches(record, canonical_origin):
                return self._denied_locked("origin-not-allowed")

            policy = record.policy
            if credentials and not policy.allow_credentials:
                return self._denied_locked(
                    "credentials-not-allowed", allow_origin=origin
                )

            try:
                normalized_method = _normalize_method(method)
            except CorsError:
                return self._denied_locked(
                    "method-not-allowed",
                    allow_origin=origin,
                    allow_methods=policy.methods,
                    allow_headers=policy.headers,
                )
            if normalized_method not in policy.methods:
                return self._denied_locked(
                    "method-not-allowed",
                    allow_origin=origin,
                    allow_methods=policy.methods,
                    allow_headers=policy.headers,
                )

            try:
                normalized_headers = _normalize_request_headers(headers)
            except CorsError:
                return self._denied_locked(
                    "header-not-allowed",
                    allow_origin=origin,
                    allow_methods=policy.methods,
                    allow_headers=policy.headers,
                )

            cache_key = self._cache_key_impl(
                route, origin, normalized_method, normalized_headers
            )
            if any(header not in policy.headers for header in normalized_headers):
                return self._denied_locked(
                    "header-not-allowed",
                    allow_origin=origin,
                    allow_methods=policy.methods,
                    allow_headers=policy.headers,
                    cache_key=cache_key,
                )

            return CorsDecision(
                allowed=True,
                allow_origin=(
                    origin
                    if credentials or not record.wildcard
                    else "*"
                ),
                allow_methods=policy.methods,
                allow_headers=policy.headers,
                max_age=policy.max_age,
                cacheable=True,
                cache_key=cache_key,
                reason="ok",
                _route=route,
                _route_version=self._versions.get(route, 0),
            )

    def cache_key(self, route: str, origin: str, method: str,
                  headers=()) -> str:
        route = _require_string(route, "route-must-be-a-non-empty-string")
        normalized_method = _normalize_method(method)
        normalized_headers = _normalize_request_headers(headers)
        return self._cache_key_impl(
            route, origin, normalized_method, normalized_headers
        )

    def remember(self, decision: CorsDecision,
                 now: float | None = None) -> str:
        if not isinstance(decision, CorsDecision) or not decision.cacheable:
            raise CorsError("CORS_INVALID_POLICY", "decision-is-not-cacheable")
        if not isinstance(decision.cache_key, str) or decision.cache_key == "":
            raise CorsError("CORS_INVALID_POLICY", "decision-has-no-cache-key")
        if decision._route is None:
            raise CorsError("CORS_INVALID_POLICY", "decision-has-no-route")

        timestamp = _now_or_monotonic(now)
        route = decision._route
        version = decision._route_version
        with self._lock:
            if self._records.get(route) is None:
                return decision.cache_key
            if self._versions.get(route, 0) != version:
                return decision.cache_key

            self._sequence += 1
            entry = _CacheEntry(
                decision=decision,
                route=route,
                version=version,
                expires_at=timestamp + decision.max_age,
                sequence=self._sequence,
            )
            self._cache.pop(decision.cache_key, None)
            if self.max_cache_entries == 0:
                return decision.cache_key

            self._cache[decision.cache_key] = entry
            while len(self._cache) > self.max_cache_entries:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
                self._stats["cache_evictions"] += 1
        return decision.cache_key

    def lookup_cache(self, key: str,
                     now: float | None = None) -> CorsDecision | None:
        timestamp = _now_or_monotonic(now)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if timestamp >= entry.expires_at:
                del self._cache[key]
                return None
            if (
                self._records.get(entry.route) is None
                or self._versions.get(entry.route, 0) != entry.version
            ):
                del self._cache[key]
                return None
            self._stats["cache_hits"] += 1
            return copy.deepcopy(entry.decision)

    def invalidate(self, route: str) -> int:
        with self._lock:
            removed = self._remove_route_cache_locked(route)
            self._versions[route] = self._versions.get(route, 0) + 1
            return removed

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def snapshot(self) -> dict:
        with self._lock:
            policies = {
                route: {
                    "route": policy.route,
                    "origins": list(policy.origins),
                    "methods": list(policy.methods),
                    "headers": list(policy.headers),
                    "allow_credentials": policy.allow_credentials,
                    "max_age": policy.max_age,
                }
                for route, policy in self._policies.items()
            }
            cache = {
                key: {
                    "route": entry.route,
                    "version": entry.version,
                    "expires_at": entry.expires_at,
                    "sequence": entry.sequence,
                    "decision": self._decision_to_dict(entry.decision),
                }
                for key, entry in self._cache.items()
            }
            return {
                "version": _SNAPSHOT_VERSION,
                "policies": policies,
                "cache": cache,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            snapshot = copy.deepcopy(state)
        except Exception as exc:
            raise CorsError(
                "CORS_SNAPSHOT_INVALID", "state-is-not-copyable"
            ) from exc

        if not isinstance(snapshot, dict):
            _snapshot_invalid("state-must-be-a-dict")
        if set(snapshot) != {"version", "policies", "cache", "stats"}:
            _snapshot_invalid("snapshot-keys-are-invalid")
        if (
            not _is_int(snapshot["version"])
            or snapshot["version"] != _SNAPSHOT_VERSION
        ):
            _snapshot_invalid("unsupported-snapshot-version")
        if not isinstance(snapshot["policies"], dict):
            _snapshot_invalid("policies-must-be-a-dict")
        if not isinstance(snapshot["cache"], dict):
            _snapshot_invalid("cache-must-be-a-dict")
        if not isinstance(snapshot["stats"], dict):
            _snapshot_invalid("stats-must-be-a-dict")

        policies: dict[str, CorsPolicy] = {}
        records: dict[str, _PolicyRecord] = {}
        for route, raw_policy in snapshot["policies"].items():
            if not isinstance(route, str) or route == "":
                _snapshot_invalid("policy-route-is-invalid")
            if not isinstance(raw_policy, dict):
                _snapshot_invalid("policy-entry-must-be-a-dict")
            if set(raw_policy) != _POLICY_KEYS:
                _snapshot_invalid("policy-fields-are-invalid")
            if raw_policy["route"] != route:
                _snapshot_invalid("policy-route-mismatch")
            try:
                origins = _normalize_origins(raw_policy["origins"])
                methods = _normalize_sequence(
                    raw_policy["methods"],
                    str.upper,
                    "methods-must-be-non-empty-strings",
                )
                headers = _normalize_sequence(
                    raw_policy["headers"],
                    str.lower,
                    "headers-must-be-non-empty-strings",
                )
            except CorsError as exc:
                _snapshot_invalid(exc.detail)
            if not isinstance(raw_policy["allow_credentials"], bool):
                _snapshot_invalid("allow_credentials-must-be-a-boolean")
            if (
                not _is_int(raw_policy["max_age"])
                or raw_policy["max_age"] < 0
            ):
                _snapshot_invalid("max_age-is-invalid")

            policy = CorsPolicy(
                route=route,
                origins=origins,
                methods=methods,
                headers=headers,
                allow_credentials=raw_policy["allow_credentials"],
                max_age=raw_policy["max_age"],
            )
            canonical_origins = frozenset(
                canonical
                for origin in origins
                if origin != "*"
                for canonical in (_canonical_origin(origin),)
                if canonical is not None
            )
            policies[route] = policy
            records[route] = _PolicyRecord(
                policy=policy,
                normalized_origins=canonical_origins,
                wildcard="*" in origins,
            )

        versions = {route: 0 for route in policies}
        cached_versions: dict[str, int] = {}
        cache: dict[str, _CacheEntry] = {}
        maximum_sequence = 0
        for key, raw_entry in snapshot["cache"].items():
            if not isinstance(key, str) or key == "":
                _snapshot_invalid("cache-key-is-invalid")
            if not isinstance(raw_entry, dict):
                _snapshot_invalid("cache-entry-must-be-a-dict")
            if set(raw_entry) != _CACHE_KEYS:
                _snapshot_invalid("cache-fields-are-invalid")

            route = raw_entry["route"]
            if not isinstance(route, str) or route not in policies:
                _snapshot_invalid("cache-route-is-invalid")
            version = raw_entry["version"]
            if not _is_int(version) or version < 0:
                _snapshot_invalid("cache-version-is-invalid")
            if (
                route in cached_versions
                and cached_versions[route] != version
            ):
                _snapshot_invalid("cache-versions-are-inconsistent")
            cached_versions[route] = version
            versions[route] = version

            expires_at = raw_entry["expires_at"]
            if not _is_number(expires_at):
                _snapshot_invalid("cache-expiry-is-invalid")
            sequence = raw_entry["sequence"]
            if not _is_int(sequence) or sequence < 0:
                _snapshot_invalid("cache-sequence-is-invalid")
            maximum_sequence = max(maximum_sequence, sequence)

            raw_decision = raw_entry["decision"]
            if not isinstance(raw_decision, dict):
                _snapshot_invalid("decision-must-be-a-dict")
            if set(raw_decision) != _DECISION_KEYS:
                _snapshot_invalid("decision-fields-are-invalid")
            if not isinstance(raw_decision["allowed"], bool):
                _snapshot_invalid("decision-allowed-is-invalid")
            if not isinstance(raw_decision["cacheable"], bool):
                _snapshot_invalid("decision-cacheable-is-invalid")
            if not raw_decision["allowed"] or not raw_decision["cacheable"]:
                _snapshot_invalid("cached-decision-is-not-allowed")
            allow_origin = raw_decision["allow_origin"]
            if allow_origin is not None and (
                not isinstance(allow_origin, str) or allow_origin == ""
            ):
                _snapshot_invalid("decision-allow-origin-is-invalid")
            try:
                allow_methods = _normalize_sequence(
                    raw_decision["allow_methods"],
                    str.upper,
                    "decision-methods-are-invalid",
                )
                allow_headers = _normalize_sequence(
                    raw_decision["allow_headers"],
                    str.lower,
                    "decision-headers-are-invalid",
                )
            except CorsError as exc:
                _snapshot_invalid(exc.detail)
            if (
                not _is_int(raw_decision["max_age"])
                or raw_decision["max_age"] < 0
            ):
                _snapshot_invalid("decision-max-age-is-invalid")
            cache_key = raw_decision["cache_key"]
            if not isinstance(cache_key, str) or cache_key != key:
                _snapshot_invalid("decision-cache-key-is-invalid")
            reason = raw_decision["reason"]
            if not isinstance(reason, str) or reason == "":
                _snapshot_invalid("decision-reason-is-invalid")

            decision = CorsDecision(
                allowed=raw_decision["allowed"],
                allow_origin=allow_origin,
                allow_methods=allow_methods,
                allow_headers=allow_headers,
                max_age=raw_decision["max_age"],
                cacheable=raw_decision["cacheable"],
                cache_key=cache_key,
                reason=reason,
                _route=route,
                _route_version=version,
            )
            cache[key] = _CacheEntry(
                decision=decision,
                route=route,
                version=version,
                expires_at=float(expires_at),
                sequence=sequence,
            )

        stats = snapshot["stats"]
        if set(stats) != set(_STATS_KEYS):
            _snapshot_invalid("stats-fields-are-invalid")
        for key in _STATS_KEYS:
            if not _is_int(stats[key]) or stats[key] < 0:
                _snapshot_invalid(f"stat-{key}-is-invalid")
        if stats["policies"] != len(policies):
            _snapshot_invalid("stats-policy-count-mismatch")

        while len(cache) > self.max_cache_entries:
            oldest_key = min(
                cache,
                key=lambda candidate: (
                    cache[candidate].sequence,
                    list(cache).index(candidate),
                ),
            )
            del cache[oldest_key]
            stats["cache_evictions"] += 1

        with self._lock:
            self._policies = policies
            self._records = records
            self._versions = versions
            self._cache = cache
            self._sequence = maximum_sequence
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _origin_matches(
        self, record: _PolicyRecord, canonical_origin: str | None
    ) -> bool:
        if record.wildcard:
            return canonical_origin is not None
        return (
            canonical_origin is not None
            and canonical_origin in record.normalized_origins
        )

    def _denied_locked(
        self,
        reason: str,
        *,
        allow_origin: str | None = None,
        allow_methods: tuple[str, ...] = (),
        allow_headers: tuple[str, ...] = (),
        cache_key: str | None = None,
    ) -> CorsDecision:
        self._stats["denied"] += 1
        return CorsDecision(
            allowed=False,
            allow_origin=allow_origin,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            max_age=0,
            cacheable=False,
            cache_key=cache_key,
            reason=reason,
        )

    def _cache_key_impl(
        self,
        route: str,
        origin: str,
        method: str,
        headers: tuple[str, ...],
    ) -> str:
        canonical_origin = _canonical_origin(origin)
        if canonical_origin is None:
            raise CorsError("CORS_INVALID_POLICY", "invalid-origin")
        payload = [
            route,
            canonical_origin,
            method.upper(),
            sorted(set(headers)),
        ]
        return json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        )

    def _remove_route_cache_locked(self, route: str) -> int:
        keys = [
            key for key, entry in self._cache.items() if entry.route == route
        ]
        for key in keys:
            del self._cache[key]
        return len(keys)

    @staticmethod
    def _decision_to_dict(decision: CorsDecision) -> dict:
        return {
            "allowed": decision.allowed,
            "allow_origin": decision.allow_origin,
            "allow_methods": list(decision.allow_methods),
            "allow_headers": list(decision.allow_headers),
            "max_age": decision.max_age,
            "cacheable": decision.cacheable,
            "cache_key": decision.cache_key,
            "reason": decision.reason,
        }
