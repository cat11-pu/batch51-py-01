"""HTTP cookie scope guard: domain and path matching, prefix rules, replacement and cleanup."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


class CookieScopeError(ValueError):
    """Raised when a Set-Cookie header cannot be accepted."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_STATS_KEYS = ("stored", "replaced", "rejected", "cleared", "expired")
_SNAPSHOT_VERSION = 1
_COOKIE_FIELDS = ("name", "value", "domain", "path", "host_only", "secure",
                  "http_only", "same_site", "created_at", "prefix")


def _normalize_host(host: object) -> str:
    if not isinstance(host, str):
        return ""
    return host.strip().lower().strip(".")


def _normalize_path(path: object) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        return "/"
    if len(path) > 1:
        stripped = path.rstrip("/")
        return stripped if stripped else "/"
    return path


def _path_match(cookie_path: str, request_path: str) -> bool:
    if request_path == cookie_path or cookie_path == "/":
        return True
    return request_path.startswith(cookie_path + "/")


def _domain_match(cookie_domain: str, host: str) -> bool:
    return host == cookie_domain or host.endswith("." + cookie_domain)


def _parse_expires(value: str) -> float | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        parsed = None
    if parsed is not None:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    for fmt in ("%a, %d-%b-%Y %H:%M:%S GMT",
                "%A, %d-%b-%y %H:%M:%S GMT",
                "%a %b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    return None


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

    def _parse(self, set_cookie: str, *, origin_host: str, secure: bool,
               now: float | None) -> tuple[StoredCookie, bool]:
        if now is None:
            now = time.time()
        if not isinstance(set_cookie, str) or not set_cookie.strip():
            raise CookieScopeError("COOKIE_PARSE_INVALID",
                                   "empty Set-Cookie header")
        origin = _normalize_host(origin_host)
        if not origin:
            raise CookieScopeError("COOKIE_DOMAIN_REJECTED",
                                   {"origin_host": origin_host})

        segments = set_cookie.split(";")
        name, sep, value = segments[0].partition("=")
        name = name.strip()
        value = value.strip()
        if not sep or not name:
            raise CookieScopeError("COOKIE_PARSE_INVALID",
                                   "Set-Cookie must start with name=value")
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        domain_attr = None
        path_attr = None
        max_age = None
        expires_ts = None
        secure_attr = False
        http_only = False
        same_site = ""
        for segment in segments[1:]:
            segment = segment.strip()
            if not segment:
                continue
            attr, _, attr_value = segment.partition("=")
            attr_key = attr.strip().lower()
            attr_value = attr_value.strip()
            if attr_key == "domain":
                domain_attr = attr_value
            elif attr_key == "path":
                path_attr = attr_value
            elif attr_key == "max-age":
                try:
                    max_age = int(attr_value)
                except ValueError:
                    max_age = None
            elif attr_key == "expires":
                parsed_ts = _parse_expires(attr_value)
                if parsed_ts is not None:
                    expires_ts = parsed_ts
            elif attr_key == "secure":
                secure_attr = True
            elif attr_key == "httponly":
                http_only = True
            elif attr_key == "samesite":
                same_site = attr_value

        if domain_attr:
            domain = _normalize_host(domain_attr)
            if (not domain or domain in self.public_suffixes
                    or not _domain_match(domain, origin)):
                raise CookieScopeError(
                    "COOKIE_DOMAIN_REJECTED",
                    {"domain": domain_attr, "origin_host": origin})
            host_only = False
        else:
            domain = origin
            host_only = True

        if path_attr and path_attr.startswith("/"):
            path = _normalize_path(path_attr)
        else:
            path = "/"

        if name.startswith("__Secure-"):
            prefix = "__Secure-"
        elif name.startswith("__Host-"):
            prefix = "__Host-"
        else:
            prefix = ""
        if prefix == "__Secure-" and not secure_attr:
            raise CookieScopeError(
                "COOKIE_PREFIX_VIOLATION",
                {"name": name, "reason": "__Secure- requires Secure attribute"})
        if prefix == "__Host-" and (not secure_attr or not host_only or path != "/"):
            raise CookieScopeError(
                "COOKIE_PREFIX_VIOLATION",
                {"name": name,
                 "reason": "__Host- requires Secure, no Domain and Path=/"})

        if max_age is not None:
            is_delete = max_age <= 0
        elif expires_ts is not None:
            is_delete = expires_ts <= now
        else:
            is_delete = False

        cookie = StoredCookie(
            name=name,
            value=value,
            domain=domain,
            path=path,
            host_only=host_only,
            secure=secure_attr,
            http_only=http_only,
            same_site=same_site,
            created_at=now,
            prefix=prefix,
        )
        return cookie, is_delete

    def _domain_count(self, domain: str) -> int:
        return sum(1 for key in self._cookies if key[1] == domain)

    def store(self, set_cookie: str, *, origin_host: str, secure: bool = True,
              now: float | None = None) -> StoredCookie | None:
        try:
            cookie, is_delete = self._parse(set_cookie, origin_host=origin_host,
                                            secure=secure, now=now)
        except CookieScopeError:
            with self._lock:
                self._stats["rejected"] += 1
            raise
        key = (cookie.name, cookie.domain, cookie.path)
        with self._lock:
            existing = self._cookies.get(key)
            if is_delete:
                if existing is not None:
                    del self._cookies[key]
                    self._stats["expired"] += 1
                return None
            if existing is not None:
                replacement = StoredCookie(
                    name=cookie.name,
                    value=cookie.value,
                    domain=cookie.domain,
                    path=cookie.path,
                    host_only=cookie.host_only,
                    secure=cookie.secure,
                    http_only=cookie.http_only,
                    same_site=cookie.same_site,
                    created_at=existing.created_at,
                    prefix=cookie.prefix,
                )
                self._cookies[key] = replacement
                self._stats["replaced"] += 1
                return replacement
            if (len(self._cookies) >= self.max_cookies
                    or self._domain_count(cookie.domain) >= self.max_per_domain):
                self._stats["rejected"] += 1
                raise CookieScopeError(
                    "COOKIE_STORE_FULL",
                    {"domain": cookie.domain,
                     "total": len(self._cookies),
                     "per_domain": self._domain_count(cookie.domain)})
            self._cookies[key] = cookie
            self._stats["stored"] += 1
            return cookie

    def parse_set_cookie(self, set_cookie: str, *, origin_host: str,
                         secure: bool = True, now: float | None = None) -> StoredCookie | None:
        cookie, is_delete = self._parse(set_cookie, origin_host=origin_host,
                                        secure=secure, now=now)
        return None if is_delete else cookie

    def match(self, cookie: StoredCookie, host: str, path: str, *,
              secure: bool = True) -> bool:
        host_norm = _normalize_host(host)
        path_norm = _normalize_path(path)
        if cookie.secure and not secure:
            return False
        if cookie.host_only:
            if host_norm != cookie.domain:
                return False
        elif not _domain_match(cookie.domain, host_norm):
            return False
        return _path_match(cookie.path, path_norm)

    def cookies_for(self, host: str, path: str, *, secure: bool = True) -> list[DeliveryCookie]:
        with self._lock:
            matched = [cookie for cookie in self._cookies.values()
                       if self.match(cookie, host, path, secure=secure)]
            matched.sort(key=lambda cookie: (-len(cookie.path), cookie.created_at))
            return [DeliveryCookie(
                name=cookie.name,
                value=cookie.value,
                domain=cookie.domain,
                path=cookie.path,
                secure=cookie.secure,
                http_only=cookie.http_only,
                same_site=cookie.same_site,
            ) for cookie in matched]

    def candidate_names(self, host: str, path: str, *, secure: bool = True) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for cookie in self.cookies_for(host, path, secure=secure):
            if cookie.name not in seen:
                seen.add(cookie.name)
                names.append(cookie.name)
        return names

    def parse_cookie_header(self, header: str, *, host: str, path: str,
                            secure: bool = True) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        seen: set[str] = set()
        if header:
            for part in header.split(";"):
                name, sep, value = part.partition("=")
                if not sep:
                    continue
                name = name.strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                pairs.append((name, value.strip()))
        rank = {name: index
                for index, name in enumerate(self.candidate_names(host, path, secure=secure))}
        pairs.sort(key=lambda pair: rank.get(pair[0], len(rank)))
        return pairs

    def get(self, name: str, *, domain: str, path: str) -> StoredCookie | None:
        key = (name, _normalize_host(domain), _normalize_path(path))
        with self._lock:
            return self._cookies.get(key)

    def clear(self, name: str, *, domain: str, path: str) -> int:
        key = (name, _normalize_host(domain), _normalize_path(path))
        with self._lock:
            if key not in self._cookies:
                return 0
            del self._cookies[key]
            self._stats["cleared"] += 1
            return 1

    def clear_domain(self, domain: str) -> int:
        target = _normalize_host(domain)
        with self._lock:
            doomed = [key for key in self._cookies
                      if _domain_match(target, key[1])]
            for key in doomed:
                del self._cookies[key]
            self._stats["cleared"] += len(doomed)
            return len(doomed)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "cookies": [
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "host_only": cookie.host_only,
                        "secure": cookie.secure,
                        "http_only": cookie.http_only,
                        "same_site": cookie.same_site,
                        "created_at": cookie.created_at,
                        "prefix": cookie.prefix,
                    }
                    for cookie in self._cookies.values()
                ],
                "stats": dict(self._stats),
            }

    def _validate_snapshot(self, state: object) -> tuple[dict, dict]:
        invalid = CookieScopeError("COOKIE_SNAPSHOT_INVALID",
                                   "snapshot must come from CookieScopeGuard.snapshot()")
        if not isinstance(state, dict):
            raise invalid
        if state.get("version") != _SNAPSHOT_VERSION:
            raise invalid
        raw_cookies = state.get("cookies")
        raw_stats = state.get("stats")
        if not isinstance(raw_cookies, list):
            raise invalid
        if (not isinstance(raw_stats, dict)
                or set(raw_stats.keys()) != set(_STATS_KEYS)
                or any(isinstance(v, bool) or not isinstance(v, (int, float))
                       for v in raw_stats.values())):
            raise invalid
        rebuilt: dict[tuple[str, str, str], StoredCookie] = {}
        for entry in raw_cookies:
            if not isinstance(entry, dict) or set(entry.keys()) != set(_COOKIE_FIELDS):
                raise invalid
            if not all(isinstance(entry[field], str)
                       for field in ("name", "value", "domain", "path",
                                     "same_site", "prefix")):
                raise invalid
            if not all(isinstance(entry[field], bool)
                       for field in ("host_only", "secure", "http_only")):
                raise invalid
            created_at = entry["created_at"]
            if isinstance(created_at, bool) or not isinstance(created_at, (int, float)):
                raise invalid
            cookie = StoredCookie(
                name=entry["name"],
                value=entry["value"],
                domain=entry["domain"],
                path=entry["path"],
                host_only=entry["host_only"],
                secure=entry["secure"],
                http_only=entry["http_only"],
                same_site=entry["same_site"],
                created_at=float(created_at),
                prefix=entry["prefix"],
            )
            rebuilt[(cookie.name, cookie.domain, cookie.path)] = cookie
        return rebuilt, {key: raw_stats[key] for key in _STATS_KEYS}

    def restore(self, state: dict) -> None:
        rebuilt, stats = self._validate_snapshot(state)
        with self._lock:
            self._cookies = rebuilt
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
