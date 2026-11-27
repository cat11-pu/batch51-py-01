"""HTTP cookie scope guard: domain and path matching, prefix rules, replacement and cleanup."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CookieScopeError(ValueError):
    """Raised when a Set-Cookie header cannot be accepted."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class StoredCookie:
    name: str
    value: str
    domain: str
    path: str
    host_only: bool
    secure: bool
    http_only: bool
    same_site: str
    created_at: float
    prefix: str


@dataclass(frozen=True)
class DeliveryCookie:
    name: str
    value: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str


class CookieScopeGuard:
    """Keep a reverse proxy cookie jar and decide what may be sent back upstream."""

    def __init__(self, *, public_suffixes=("com", "net", "org"),
                 max_cookies: int = 200, max_per_domain: int = 50) -> None:
        self.public_suffixes = tuple(suffix.lower() for suffix in public_suffixes)
        self.max_cookies = max_cookies
        self.max_per_domain = max_per_domain
        self._lock = threading.RLock()
        self._cookies: dict[tuple[str, str, str], StoredCookie] = {}
        self._stats = {
            "stored": 0,
            "replaced": 0,
            "rejected": 0,
            "cleared": 0,
            "expired": 0,
        }

    def store(self, set_cookie: str, *, origin_host: str, secure: bool = True,
              now: float | None = None) -> StoredCookie | None:
        raise NotImplementedError

    def parse_set_cookie(self, set_cookie: str, *, origin_host: str,
                         secure: bool = True, now: float | None = None) -> StoredCookie | None:
        raise NotImplementedError

    def match(self, cookie: StoredCookie, host: str, path: str, *,
              secure: bool = True) -> bool:
        raise NotImplementedError

    def cookies_for(self, host: str, path: str, *, secure: bool = True) -> list[DeliveryCookie]:
        raise NotImplementedError

    def candidate_names(self, host: str, path: str, *, secure: bool = True) -> list[str]:
        raise NotImplementedError

    def parse_cookie_header(self, header: str, *, host: str, path: str,
                            secure: bool = True) -> list[tuple[str, str]]:
        raise NotImplementedError

    def get(self, name: str, *, domain: str, path: str) -> StoredCookie | None:
        raise NotImplementedError

    def clear(self, name: str, *, domain: str, path: str) -> int:
        raise NotImplementedError

    def clear_domain(self, domain: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
