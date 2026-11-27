"""Cross-origin policy evaluation with credential constraints and preflight TTL."""

from __future__ import annotations

import threading


class CorsError(ValueError):
    """Raised when a route configuration or a request cannot be evaluated."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class CorsPolicyEvaluatorP2:
    """Hold route level CORS policies and answer origin matching questions."""

    def __init__(self, *, max_age_cap: int = 600, default_max_age: int = 120) -> None:
        self.max_age_cap = max_age_cap
        self.default_max_age = default_max_age
        self._lock = threading.RLock()

    def add_route(self, route_id: str, *, allow_origins, allow_credentials: bool = False,
                  max_age: int | None = None) -> int:
        raise NotImplementedError

    def remove_route(self, route_id: str) -> bool:
        raise NotImplementedError

    def remove_origin(self, route_id: str, origin: str) -> bool:
        raise NotImplementedError

    def match_origin(self, route_id: str, origin: str) -> str | None:
        raise NotImplementedError

    def check_credentials(self, route_id: str, origin: str, *, credentials: bool) -> bool:
        raise NotImplementedError

    def preflight_ttl(self, route_id: str, *, requested_max_age: int | None = None) -> int:
        raise NotImplementedError

    def evaluate(self, route_id: str, *, origin: str, method: str = "GET",
                 credentials: bool = False) -> dict:
        raise NotImplementedError

    def describe_route(self, route_id: str) -> dict:
        raise NotImplementedError

    def list_routes(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
