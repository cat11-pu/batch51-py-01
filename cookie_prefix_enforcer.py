"""Cookie 属性组合校验：安全前缀约束、域覆盖判定与同名取舍。"""

from __future__ import annotations

import copy
import threading

PREFIX_HOST = "__Host-"
PREFIX_SECURE = "__Secure-"

ACTION_SEND = "send"
ACTION_WITHHOLD = "withhold"
ACTION_REJECT = "reject"

MAX_NAME_LENGTH = 128
SNAPSHOT_VERSION = 1

_COOKIE_FIELDS = (
    "name",
    "value",
    "path",
    "domain",
    "secure",
    "httponly",
    "samesite",
    "max_age",
    "origin",
)

_STAT_FIELDS = ("applied", "replaced", "rejected", "delivered", "restores")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


class CookieError(ValueError):
    """Cookie 校验被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class CookiePrefixEnforcer:
    """校验下发 Cookie 的属性组合，并按域与路径维护一份可投递集合。"""

    def __init__(self, *, max_cookies=16, secure_transport=True):
        self.max_cookies = max_cookies
        self.secure_transport = bool(secure_transport)
        self._lock = threading.RLock()
        self._cookies = []
        self._stats = {
            "applied": 0,
            "replaced": 0,
            "rejected": 0,
            "delivered": 0,
            "restores": 0,
        }

    def parse_set_cookie(self, header):
        if not isinstance(header, str):
            raise CookieError("COOKIE_HEADER_INVALID", "header must be a string")
        if not header.strip():
            raise CookieError("COOKIE_HEADER_INVALID", "empty header")

        parts = header.split(";")
        first = parts[0]
        if "=" not in first:
            raise CookieError("COOKIE_HEADER_INVALID", "missing name/value pair")

        name, value = first.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise CookieError("COOKIE_HEADER_INVALID", "empty cookie name")
        if len(name) > MAX_NAME_LENGTH:
            raise CookieError("COOKIE_HEADER_INVALID", "cookie name too long")

        cookie = {
            "name": name,
            "value": value,
            "path": "/",
            "domain": None,
            "secure": False,
            "httponly": False,
            "samesite": None,
            "max_age": None,
        }

        for raw in parts[1:]:
            raw = raw.strip()
            if not raw:
                continue
            if "=" in raw:
                attr, attr_value = raw.split("=", 1)
                attr = attr.strip().lower()
                attr_value = attr_value.strip()
            else:
                attr = raw.strip().lower()
                attr_value = None

            if attr == "path":
                if attr_value is None:
                    raise CookieError("COOKIE_HEADER_INVALID", "Path requires a value")
                cookie["path"] = attr_value
            elif attr == "domain":
                if attr_value is None:
                    raise CookieError("COOKIE_HEADER_INVALID", "Domain requires a value")
                cookie["domain"] = attr_value.lstrip(".").lower()
            elif attr == "secure":
                cookie["secure"] = True
            elif attr == "httponly":
                cookie["httponly"] = True
            elif attr == "samesite":
                if attr_value is None:
                    raise CookieError("COOKIE_HEADER_INVALID", "SameSite requires a value")
                cookie["samesite"] = attr_value.lower()
            elif attr == "max-age":
                if attr_value is None:
                    raise CookieError("COOKIE_HEADER_INVALID", "Max-Age requires a value")
                try:
                    cookie["max_age"] = int(attr_value)
                except (TypeError, ValueError) as exc:
                    raise CookieError(
                        "COOKIE_HEADER_INVALID", "Max-Age must be an integer"
                    ) from exc

        return cookie

    def _as_cookie(self, cookie):
        if isinstance(cookie, str):
            return self.parse_set_cookie(cookie)
        if not isinstance(cookie, dict):
            raise CookieError("COOKIE_HEADER_INVALID", "cookie must be a mapping")
        return cookie

    def check_prefix(self, cookie):
        cookie = self._as_cookie(cookie)
        if not isinstance(cookie.get("name"), str):
            raise CookieError("COOKIE_HEADER_INVALID", "cookie name must be a string")
        name = cookie["name"]

        if name.startswith(PREFIX_HOST):
            if not bool(cookie.get("secure")):
                return {"ok": False, "reason": "COOKIE_PREFIX_SECURE_REQUIRED"}
            if cookie.get("path", "/") != "/":
                return {"ok": False, "reason": "COOKIE_PREFIX_PATH_REQUIRED"}
            if cookie.get("domain") is not None:
                return {"ok": False, "reason": "COOKIE_PREFIX_DOMAIN_FORBIDDEN"}
        elif name.startswith(PREFIX_SECURE):
            if not bool(cookie.get("secure")):
                return {"ok": False, "reason": "COOKIE_PREFIX_SECURE_REQUIRED"}

        return {"ok": True, "reason": None}

    @staticmethod
    def _normalize_host(host):
        if not isinstance(host, str):
            return None
        host = host.strip().lower()
        if host.endswith("."):
            host = host.rstrip(".")
        return host

    @staticmethod
    def _normalize_domain(domain):
        if not isinstance(domain, str):
            return None
        domain = domain.strip().lower().lstrip(".")
        if domain.endswith("."):
            domain = domain.rstrip(".")
        return domain

    def scope_cover(self, cookie, host):
        cookie = self._as_cookie(cookie)
        host = self._normalize_host(host)
        if not host:
            return False

        domain = cookie.get("domain")
        if domain is not None:
            domain = self._normalize_domain(domain)
            if not domain:
                return False
            return host == domain or host.endswith("." + domain)

        origin = self._normalize_host(cookie.get("origin"))
        return origin is not None and host == origin

    def _scope_domain(self, cookie):
        domain = cookie.get("domain")
        if domain is not None:
            return self._normalize_domain(domain) or ""
        return self._normalize_host(cookie.get("origin")) or ""

    def _scope_covers(self, outer, inner):
        outer_domain = self._scope_domain(outer)
        inner_domain = self._scope_domain(inner)
        if not outer_domain or not inner_domain:
            return False

        outer_is_domain = outer.get("domain") is not None
        inner_is_domain = inner.get("domain") is not None
        if inner_is_domain:
            if not outer_is_domain:
                return False
            return (
                inner_domain == outer_domain
                or inner_domain.endswith("." + outer_domain)
            )

        if not outer_is_domain:
            return inner_domain == outer_domain
        return (
            inner_domain == outer_domain
            or inner_domain.endswith("." + outer_domain)
        )

    def _scopes_overlap(self, left, right):
        return self._scope_covers(left, right) or self._scope_covers(right, left)

    def _specificity(self, cookie):
        domain = self._scope_domain(cookie)
        return (
            len(domain),
            0 if cookie.get("domain") is not None else 1,
        )

    def samesite_combo(self, cookie, *, cross_site=False):
        cookie = self._as_cookie(cookie)
        value = cookie.get("samesite")
        if value is None:
            value = "lax"
        elif isinstance(value, str):
            value = value.lower()

        if value not in ("strict", "lax", "none"):
            return {"action": ACTION_REJECT, "reason": "COOKIE_SAMESITE_INVALID"}

        if value == "none" and not bool(cookie.get("secure")):
            return {
                "action": ACTION_REJECT,
                "reason": "COOKIE_SAMESITE_NONE_INSECURE",
            }

        if cross_site and value in ("strict", "lax"):
            return {
                "action": ACTION_WITHHOLD,
                "reason": "COOKIE_SAMESITE_CROSS_SITE",
            }

        return {"action": ACTION_SEND, "reason": None}

    def apply(self, header, *, host, now=None):
        with self._lock:
            try:
                cookie = self.parse_set_cookie(header)
            except CookieError:
                self._stats["rejected"] += 1
                raise

            cookie["origin"] = self._normalize_host(host)
            if cookie["origin"] is None:
                cookie["origin"] = ""

            prefix = self.check_prefix(cookie)
            if not prefix["ok"]:
                self._stats["rejected"] += 1
                return self._result(False, prefix["reason"], False, cookie)

            samesite = self.samesite_combo(cookie)
            if samesite["action"] == ACTION_REJECT:
                self._stats["rejected"] += 1
                return self._result(False, samesite["reason"], False, cookie)

            if (
                not self.secure_transport
                and (
                    cookie["name"].startswith(PREFIX_HOST)
                    or cookie["name"].startswith(PREFIX_SECURE)
                )
            ):
                self._stats["rejected"] += 1
                return self._result(
                    False, "COOKIE_PREFIX_INSECURE_CHANNEL", False, cookie
                )

            same_name = [
                index
                for index, existing in enumerate(self._cookies)
                if existing["name"] == cookie["name"]
            ]
            new_path_length = len(cookie["path"])
            same_origin = [
                index
                for index in same_name
                if self._normalize_host(self._cookies[index].get("origin"))
                == cookie["origin"]
            ]

            if same_origin:
                longest = max(len(self._cookies[index]["path"]) for index in same_origin)
                if new_path_length < longest:
                    self._stats["rejected"] += 1
                    return self._result(False, "COOKIE_SHADOWED", False, cookie)

            remove = set(same_origin)
            for index in same_name:
                if index in remove:
                    continue
                existing = self._cookies[index]
                if not self._scopes_overlap(existing, cookie):
                    continue

                existing_specificity = self._specificity(existing)
                new_specificity = self._specificity(cookie)
                if existing_specificity > new_specificity:
                    self._stats["rejected"] += 1
                    return self._result(False, "COOKIE_SHADOWED", False, cookie)
                if (
                    existing_specificity == new_specificity
                    and new_path_length < len(existing["path"])
                ):
                    self._stats["rejected"] += 1
                    return self._result(False, "COOKIE_SHADOWED", False, cookie)
                remove.add(index)

            if len(self._cookies) - len(remove) + 1 > self.max_cookies:
                self._stats["rejected"] += 1
                raise CookieError("COOKIE_JAR_LIMIT", "cookie jar capacity exceeded")

            replaced = bool(remove)
            if remove:
                first = min(remove)
                updated = []
                for index, existing in enumerate(self._cookies):
                    if index == first:
                        updated.append(cookie)
                    elif index in remove:
                        continue
                    else:
                        updated.append(existing)
                self._cookies = updated
            else:
                self._cookies.append(cookie)

            self._stats["applied"] += 1
            if replaced:
                self._stats["replaced"] += 1
            return self._result(True, None, replaced, cookie)

    @staticmethod
    def _result(accepted, reason, replaced, cookie):
        return {
            "accepted": accepted,
            "reason": reason,
            "replaced": replaced,
            "cookie": copy.deepcopy(cookie),
        }

    @staticmethod
    def _path_matches(cookie_path, request_path):
        if request_path == cookie_path:
            return True
        if not request_path.startswith(cookie_path):
            return False
        if cookie_path.endswith("/"):
            return True
        return len(request_path) > len(cookie_path) and request_path[len(cookie_path)] == "/"

    def deliver(self, host, path, *, secure=True):
        with self._lock:
            selected = [
                cookie
                for cookie in self._cookies
                if self.scope_cover(cookie, host)
                and self._path_matches(cookie["path"], path)
                and not (not secure and cookie["secure"])
            ]
            selected.sort(key=lambda cookie: len(cookie["path"]), reverse=True)
            self._stats["delivered"] += len(selected)
            return copy.deepcopy(selected)

    def name_count(self, name):
        with self._lock:
            return sum(1 for cookie in self._cookies if cookie["name"] == name)

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "cookies": copy.deepcopy(self._cookies),
                "max_cookies": self.max_cookies,
                "secure_transport": self.secure_transport,
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state):
        with self._lock:
            cookies, max_cookies, secure_transport, stats = self._validated_snapshot(state)
            stats["restores"] += 1
            self._cookies = cookies
            self.max_cookies = max_cookies
            self.secure_transport = secure_transport
            self._stats = stats

    @staticmethod
    def _invalid_snapshot(detail):
        raise CookieError("COOKIE_SNAPSHOT_INVALID", detail)

    def _validated_snapshot(self, state):
        if not isinstance(state, dict):
            self._invalid_snapshot("snapshot must be a mapping")

        required = {"version", "cookies", "max_cookies", "secure_transport", "stats"}
        if not required.issubset(state):
            self._invalid_snapshot("snapshot is missing required fields")

        version = state["version"]
        if not _is_int(version) or version != SNAPSHOT_VERSION:
            self._invalid_snapshot("unsupported snapshot version")

        max_cookies = state["max_cookies"]
        if not _is_int(max_cookies) or max_cookies < 0:
            self._invalid_snapshot("max_cookies must be a non-negative integer")

        secure_transport = state["secure_transport"]
        if not isinstance(secure_transport, bool):
            self._invalid_snapshot("secure_transport must be a boolean")

        raw_cookies = state["cookies"]
        if not isinstance(raw_cookies, list):
            self._invalid_snapshot("cookies must be a list")
        if len(raw_cookies) > max_cookies:
            self._invalid_snapshot("cookies exceed max_cookies")

        cookies = []
        for raw in raw_cookies:
            if not isinstance(raw, dict):
                self._invalid_snapshot("cookie entries must be mappings")

            for field in ("name", "value", "path", "origin"):
                if field not in raw or not isinstance(raw[field], str):
                    self._invalid_snapshot("cookie %s must be a string" % field)

            if "domain" not in raw or not (
                raw["domain"] is None or isinstance(raw["domain"], str)
            ):
                self._invalid_snapshot("cookie domain must be a string or None")
            if "samesite" not in raw or not (
                raw["samesite"] is None or isinstance(raw["samesite"], str)
            ):
                self._invalid_snapshot("cookie samesite must be a string or None")
            if "secure" not in raw or not isinstance(raw["secure"], bool):
                self._invalid_snapshot("cookie secure must be a boolean")
            if "httponly" not in raw or not isinstance(raw["httponly"], bool):
                self._invalid_snapshot("cookie httponly must be a boolean")
            if "max_age" not in raw or not (
                raw["max_age"] is None or _is_int(raw["max_age"])
            ):
                self._invalid_snapshot("cookie max_age must be an integer or None")

            cookies.append({field: copy.deepcopy(raw[field]) for field in _COOKIE_FIELDS})

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict):
            self._invalid_snapshot("stats must be a mapping")
        stats = {}
        for field in _STAT_FIELDS:
            if field not in raw_stats or not _is_int(raw_stats[field]):
                self._invalid_snapshot("stat %s must be an integer" % field)
            stats[field] = raw_stats[field]

        return cookies, max_cookies, secure_transport, stats

    def stats(self):
        with self._lock:
            return dict(self._stats)
