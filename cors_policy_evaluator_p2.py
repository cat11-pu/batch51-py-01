"""Cross-origin policy evaluation with credential constraints and preflight TTL."""

from __future__ import annotations

import copy
import re
import threading


class CorsError(ValueError):
    """Raised when a route configuration or a request cannot be evaluated."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_AUTHORITY_FORBIDDEN_RE = re.compile(r"[\s/?#@]")


def _is_nonneg_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_pattern(pattern: object) -> None:
    """Raise CORS_INVALID_PATTERN unless *pattern* is a usable origin pattern."""
    if not isinstance(pattern, str) or not pattern:
        raise CorsError("CORS_INVALID_PATTERN", pattern)
    if pattern == "*":
        return
    if "://" not in pattern:
        raise CorsError("CORS_INVALID_PATTERN", pattern)
    scheme, authority = pattern.split("://", 1)
    if not _SCHEME_RE.match(scheme):
        raise CorsError("CORS_INVALID_PATTERN", pattern)
    if not authority or _AUTHORITY_FORBIDDEN_RE.search(authority):
        raise CorsError("CORS_INVALID_PATTERN", pattern)
    if ":" in authority:
        host, _, port = authority.rpartition(":")
        if not host or not port.isdigit():
            raise CorsError("CORS_INVALID_PATTERN", pattern)
    if "*" in authority:
        if authority.count("*") != 1 or not authority.startswith("*."):
            raise CorsError("CORS_INVALID_PATTERN", pattern)
        if len(authority) <= 2:
            raise CorsError("CORS_INVALID_PATTERN", pattern)


def _match_patterns(patterns, origin):
    """Return the configured pattern that wins for *origin*, or None."""
    if not isinstance(origin, str) or not origin:
        return None
    origin_lower = origin.lower()
    best_pattern = None
    best_key = None
    for index, pattern in enumerate(patterns):
        if pattern == "*":
            matched, exact = True, False
        elif "*" in pattern:
            prefix, suffix = pattern.lower().split("*", 1)
            matched = (
                origin_lower.startswith(prefix)
                and origin_lower.endswith(suffix)
                and len(origin_lower) > len(prefix) + len(suffix)
            )
            exact = False
        else:
            matched = origin_lower == pattern.lower()
            exact = True
        if not matched:
            continue
        key = (len(pattern), 1 if exact else 0, -index)
        if best_key is None or key > best_key:
            best_key = key
            best_pattern = pattern
    return best_pattern


def _priority_order(patterns):
    """Sort patterns by matching priority: longest first, exact beats wildcard."""
    indexed = list(enumerate(patterns))
    indexed.sort(key=lambda item: (-len(item[1]), 0 if "*" not in item[1] else 1, item[0]))
    return tuple(pattern for _, pattern in indexed)


class CorsPolicyEvaluatorP2:
    """Hold route level CORS policies and answer origin matching questions."""

    MAX_ORIGINS_PER_ROUTE = 256

    def __init__(self, *, max_age_cap: int = 600, default_max_age: int = 120) -> None:
        self.max_age_cap = max_age_cap
        self.default_max_age = default_max_age
        self._lock = threading.RLock()
        self._routes = {}
        self._evaluations = 0
        self._allowed = 0
        self._denied = 0
        self._preflights = 0

    def _route(self, route_id: str) -> dict:
        try:
            return self._routes[route_id]
        except KeyError:
            raise CorsError("CORS_UNKNOWN_ROUTE", route_id) from None

    def _ttl(self, route: dict, requested_max_age) -> int:
        base = route["max_age"] if route["max_age"] is not None else self.default_max_age
        ttl = min(base, self.max_age_cap)
        if requested_max_age is not None:
            ttl = min(ttl, requested_max_age)
        return ttl

    def add_route(self, route_id: str, *, allow_origins, allow_credentials: bool = False,
                  max_age: int | None = None) -> int:
        if not isinstance(route_id, str) or not route_id:
            raise CorsError("CORS_INVALID_REQUEST", route_id)
        if not isinstance(allow_origins, (list, tuple)):
            raise CorsError("CORS_INVALID_PATTERN", allow_origins)
        if max_age is not None and not _is_nonneg_int(max_age):
            raise CorsError("CORS_INVALID_REQUEST", max_age)
        deduped = []
        seen = set()
        for pattern in allow_origins:
            _validate_pattern(pattern)
            key = pattern.lower()
            if key not in seen:
                seen.add(key)
                deduped.append(pattern)
        if len(deduped) > self.MAX_ORIGINS_PER_ROUTE:
            raise CorsError("CORS_TOO_MANY_ORIGINS", route_id)
        with self._lock:
            if route_id in self._routes:
                raise CorsError("CORS_DUPLICATE_ROUTE", route_id)
            self._routes[route_id] = {
                "origins": deduped,
                "allow_credentials": bool(allow_credentials),
                "max_age": max_age,
            }
        return len(deduped)

    def remove_route(self, route_id: str) -> bool:
        with self._lock:
            return self._routes.pop(route_id, None) is not None

    def remove_origin(self, route_id: str, origin: str) -> bool:
        with self._lock:
            route = self._route(route_id)
            target = origin.lower() if isinstance(origin, str) else origin
            for index, pattern in enumerate(route["origins"]):
                if pattern.lower() == target:
                    del route["origins"][index]
                    return True
            return False

    def match_origin(self, route_id: str, origin: str) -> str | None:
        with self._lock:
            route = self._route(route_id)
            return _match_patterns(route["origins"], origin)

    def check_credentials(self, route_id: str, origin: str, *, credentials: bool) -> bool:
        with self._lock:
            route = self._route(route_id)
            pattern = _match_patterns(route["origins"], origin)
            if pattern is None:
                return False
            if not credentials:
                return True
            if not route["allow_credentials"]:
                return False
            return pattern != "*"

    def preflight_ttl(self, route_id: str, *, requested_max_age: int | None = None) -> int:
        with self._lock:
            route = self._route(route_id)
            if requested_max_age is not None and not _is_nonneg_int(requested_max_age):
                raise CorsError("CORS_INVALID_REQUEST", requested_max_age)
            return self._ttl(route, requested_max_age)

    def evaluate(self, route_id: str, *, origin: str, method: str = "GET",
                 credentials: bool = False) -> dict:
        with self._lock:
            route = self._route(route_id)
            pattern = _match_patterns(route["origins"], origin)
            max_age = self._ttl(route, None)
            self._evaluations += 1
            if isinstance(method, str) and method.upper() == "OPTIONS":
                self._preflights += 1
            if pattern is None:
                self._denied += 1
                return {"allowed": False, "echo_origin": None, "pattern": None,
                        "max_age": max_age, "reason": "no-match"}
            if credentials and not route["allow_credentials"]:
                self._denied += 1
                return {"allowed": False, "echo_origin": None, "pattern": pattern,
                        "max_age": max_age, "reason": "credentials-not-allowed"}
            if credentials and pattern == "*":
                self._denied += 1
                return {"allowed": False, "echo_origin": None, "pattern": pattern,
                        "max_age": max_age, "reason": "wildcard-credentials"}
            self._allowed += 1
            echo_origin = "*" if pattern == "*" else origin
            return {"allowed": True, "echo_origin": echo_origin, "pattern": pattern,
                    "max_age": max_age, "reason": "allowed"}

    def describe_route(self, route_id: str) -> dict:
        with self._lock:
            route = self._route(route_id)
            return {
                "route_id": route_id,
                "allow_origins": _priority_order(route["origins"]),
                "allow_credentials": route["allow_credentials"],
                "max_age": route["max_age"],
            }

    def list_routes(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._routes))

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": 1,
                "max_age_cap": self.max_age_cap,
                "default_max_age": self.default_max_age,
                "routes": [
                    {
                        "route_id": route_id,
                        "allow_origins": list(route["origins"]),
                        "allow_credentials": route["allow_credentials"],
                        "max_age": route["max_age"],
                    }
                    for route_id, route in sorted(self._routes.items())
                ],
                "stats": {
                    "evaluations": self._evaluations,
                    "allowed": self._allowed,
                    "denied": self._denied,
                    "preflights": self._preflights,
                },
            })

    def restore(self, state: dict) -> None:
        routes, max_age_cap, default_max_age, counters = self._parse_snapshot(state)
        with self._lock:
            self.max_age_cap = max_age_cap
            self.default_max_age = default_max_age
            self._routes = routes
            (self._evaluations, self._allowed,
             self._denied, self._preflights) = counters

    def _parse_snapshot(self, state):
        """Validate a snapshot without touching current state."""
        invalid = CorsError("CORS_SNAPSHOT_INVALID", state)
        if not isinstance(state, dict):
            raise invalid
        try:
            max_age_cap = state["max_age_cap"]
            default_max_age = state["default_max_age"]
            raw_routes = state["routes"]
            raw_stats = state["stats"]
        except KeyError:
            raise invalid from None
        if not _is_nonneg_int(max_age_cap) or not _is_nonneg_int(default_max_age):
            raise invalid
        if not isinstance(raw_routes, (list, tuple)):
            raise invalid
        routes = {}
        for entry in raw_routes:
            if not isinstance(entry, dict):
                raise invalid
            route_id = entry.get("route_id")
            origins = entry.get("allow_origins")
            allow_credentials = entry.get("allow_credentials")
            max_age = entry.get("max_age")
            if not isinstance(route_id, str) or not route_id or route_id in routes:
                raise invalid
            if (not isinstance(origins, (list, tuple))
                    or len(origins) > self.MAX_ORIGINS_PER_ROUTE):
                raise invalid
            validated = []
            seen = set()
            for pattern in origins:
                try:
                    _validate_pattern(pattern)
                except CorsError:
                    raise invalid from None
                key = pattern.lower()
                if key not in seen:
                    seen.add(key)
                    validated.append(pattern)
            if not isinstance(allow_credentials, bool):
                raise invalid
            if max_age is not None and not _is_nonneg_int(max_age):
                raise invalid
            routes[route_id] = {
                "origins": validated,
                "allow_credentials": allow_credentials,
                "max_age": max_age,
            }
        if not isinstance(raw_stats, dict):
            raise invalid
        counters = []
        for key in ("evaluations", "allowed", "denied", "preflights"):
            value = raw_stats.get(key)
            if not _is_nonneg_int(value):
                raise invalid
            counters.append(value)
        return routes, max_age_cap, default_max_age, tuple(counters)

    def stats(self) -> dict:
        with self._lock:
            return {
                "routes": len(self._routes),
                "evaluations": self._evaluations,
                "allowed": self._allowed,
                "denied": self._denied,
                "preflights": self._preflights,
            }

    def reset(self) -> None:
        with self._lock:
            self._evaluations = 0
            self._allowed = 0
            self._denied = 0
            self._preflights = 0
