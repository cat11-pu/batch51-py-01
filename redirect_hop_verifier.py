"""跳转参数校验：目标归一、协议相对变体判定与白名单逐跳比对。"""

from __future__ import annotations

import re
import threading
from urllib.parse import unquote, urljoin

DEFAULT_SCHEMES = ("https", "http")
DEFAULT_PORTS = {"http": 80, "https": 443}
HTTP_SCHEMES = frozenset(DEFAULT_PORTS)

_SNAPSHOT_VERSION = 1
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_STATS_KEYS = (
    "verifications",
    "hops_checked",
    "hop_denied",
    "chains_failed",
    "deduped",
    "restores",
)


class RedirectError(ValueError):
    """跳转目标被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class RedirectHopVerifier:
    """先归一目标，再按白名单逐跳比对整条跳转链。"""

    def __init__(self, *, allowed_hosts=(), allowed_schemes=DEFAULT_SCHEMES, max_hops=4):
        self._lock = threading.RLock()
        self._allowed_hosts = set()
        if isinstance(allowed_hosts, str):
            allowed_hosts = (allowed_hosts,)
        if isinstance(allowed_schemes, str):
            allowed_schemes = (allowed_schemes,)
        self._allowed_schemes = self._prepare_schemes(allowed_schemes)
        self._max_hops = self._validate_max_hops(max_hops)
        self._chain = []
        self._stats = {key: 0 for key in _STATS_KEYS}

        for host in allowed_hosts:
            self.allow_host(host)

    @staticmethod
    def _prepare_schemes(values):
        schemes = []
        for value in values:
            if not isinstance(value, str):
                raise TypeError("allowed_schemes must contain strings")
            scheme = value.lower()
            if scheme in HTTP_SCHEMES and scheme not in schemes:
                schemes.append(scheme)
        return tuple(schemes)

    @staticmethod
    def _validate_max_hops(value):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("max_hops must be a non-negative integer")
        return value

    @classmethod
    def _invalid(cls, detail):
        raise RedirectError("REDIRECT_TARGET_INVALID", detail)

    @classmethod
    def _split_authority(cls, authority):
        """Return (userinfo prefix, normalized host, port, port suffix)."""
        if not authority:
            cls._invalid("missing host")

        userinfo, marker, host_port = authority.rpartition("@")
        if not marker:
            userinfo = ""
        if not host_port:
            cls._invalid("missing host")

        port = None
        if host_port.startswith("["):
            end = host_port.find("]")
            if end < 0:
                cls._invalid("unterminated IPv6 host")
            raw_host = host_port[: end + 1]
            remainder = host_port[end + 1 :]
            if remainder:
                if not remainder.startswith(":"):
                    cls._invalid("invalid authority")
                port = remainder[1:]
        elif ":" in host_port:
            raw_host, port = host_port.rsplit(":", 1)
        else:
            raw_host = host_port

        if port == "":
            cls._invalid("empty port")
        if port is not None and not port.isdigit():
            cls._invalid("invalid port")

        host = unquote(raw_host).lower()
        if not host:
            cls._invalid("missing host")
        if any(char in host for char in "/?#@\\"):
            cls._invalid("invalid host")

        prefix = f"{userinfo}@" if marker else ""
        port_suffix = f":{port}" if port is not None else ""
        return prefix, host, port, port_suffix

    @classmethod
    def _normalize_authority(cls, authority, scheme):
        prefix, host, port, _ = cls._split_authority(authority)
        if port is not None and int(port) == DEFAULT_PORTS.get(scheme):
            port = None
        port_suffix = f":{port}" if port is not None else ""
        return f"{prefix}{host}{port_suffix}", host

    @staticmethod
    def _remove_dot_segments(path):
        if not path:
            return path

        absolute = path.startswith("/")
        trailing = path.endswith("/") or path.endswith("/.") or path.endswith("/..")
        parts = []
        for part in path.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)

        result = ("/" if absolute else "") + "/".join(parts)
        if absolute and not result:
            result = "/"
        if trailing and result and not result.endswith("/"):
            result += "/"
        return result

    @classmethod
    def _normalize_path_tail(cls, tail):
        indexes = [index for index in (tail.find("?"), tail.find("#")) if index >= 0]
        split_at = min(indexes) if indexes else len(tail)
        path, suffix = tail[:split_at], tail[split_at:]
        path = re.sub(r"/+", "/", path)
        path = cls._remove_dot_segments(path)
        return path + suffix

    @classmethod
    def _normalize_absolute(cls, scheme, tail):
        scheme = scheme.lower()
        if scheme not in HTTP_SCHEMES:
            return f"{scheme}:{tail}"

        body = tail.lstrip("/")
        if not body or body[0] in "?#":
            cls._invalid("missing host")

        indexes = [index for index in (body.find("/"), body.find("?"), body.find("#")) if index >= 0]
        split_at = min(indexes) if indexes else len(body)
        authority = body[:split_at]
        rest = body[split_at:]

        normalized_authority, _ = cls._normalize_authority(authority, scheme)
        return f"{scheme}://{normalized_authority}{cls._normalize_path_tail(rest)}"

    @classmethod
    def _normalize_whitelist_host(cls, host):
        if not isinstance(host, str) or not host.strip():
            cls._invalid("invalid whitelist host")

        value = host.strip().replace("\\", "/")
        if "://" in value:
            scheme = cls._scheme_from_target(value)
            if scheme is None:
                cls._invalid("invalid whitelist host")
            normalized = cls._normalize_absolute(scheme, value.split(":", 1)[1])
            return cls._host_from_normalized(normalized)
        if value.startswith("//") or any(char in value for char in "/?#"):
            cls._invalid("invalid whitelist host")

        prefix, normalized_host, _, _ = cls._split_authority(value)
        if prefix:
            cls._invalid("whitelist entries must be host names")
        return normalized_host

    @classmethod
    def _host_from_normalized(cls, target):
        match = _SCHEME_RE.match(target)
        if not match or match.group(1).lower() not in HTTP_SCHEMES:
            cls._invalid("not an HTTP target")
        remainder = target[match.end() :]
        if not remainder.startswith("//"):
            cls._invalid("missing host")
        remainder = remainder[2:]
        indexes = [
            index
            for index in (remainder.find("/"), remainder.find("?"), remainder.find("#"))
            if index >= 0
        ]
        split_at = min(indexes) if indexes else len(remainder)
        _, host, _, _ = cls._split_authority(remainder[:split_at])
        return host

    @staticmethod
    def _scheme_from_target(target):
        match = _SCHEME_RE.match(target)
        return match.group(1).lower() if match else None

    def allow_host(self, host):
        normalized = self._normalize_whitelist_host(host)
        with self._lock:
            self._allowed_hosts.add(normalized)

    def allowed_hosts(self):
        with self._lock:
            return sorted(self._allowed_hosts)

    def normalize_target(self, target, *, base=None):
        if not isinstance(target, str) or not target.strip():
            self._invalid("redirect target must be a non-empty string")

        value = target.replace("\\", "/").strip()
        match = _SCHEME_RE.match(value)
        if match:
            return self._normalize_absolute(match.group(1), value[match.end() :])

        if not base:
            self._invalid("redirect target is missing a scheme")

        try:
            normalized_base = self.normalize_target(base)
        except RedirectError:
            self._invalid("base redirect target is invalid")

        if value.startswith("//"):
            base_scheme = self._scheme_from_target(normalized_base)
            return self._normalize_absolute(base_scheme, value)

        return self.normalize_target(urljoin(normalized_base, value))

    def check_scheme(self, target):
        if isinstance(target, str):
            scheme = self._scheme_from_target(target.replace("\\", "/").strip())
        else:
            scheme = None
        with self._lock:
            allowed = self._allowed_schemes
        if scheme not in HTTP_SCHEMES or scheme not in allowed:
            raise RedirectError("REDIRECT_SCHEME_DENIED", scheme)
        return scheme

    def is_allowed(self, target):
        try:
            normalized = self.normalize_target(target)
            self.check_scheme(normalized)
            host = self._host_from_normalized(normalized)
        except RedirectError:
            return False
        with self._lock:
            return host in self._allowed_hosts

    def _failed_result(self, reason, denied, hops):
        self._stats["chains_failed"] += 1
        return {
            "ok": False,
            "reason": reason,
            "count": len(hops),
            "denied": denied,
            "hops": list(hops),
        }

    def verify_hops(self, targets):
        with self._lock:
            self._stats["verifications"] += 1
            hops = []
            seen = set()

            if isinstance(targets, str):
                targets = (targets,)
            try:
                iterator = iter(targets)
            except TypeError:
                return self._failed_result("REDIRECT_TARGET_INVALID", None, hops)

            for index, target in enumerate(iterator):
                if index >= self._max_hops:
                    return self._failed_result("REDIRECT_HOP_LIMIT", target, hops)

                self._stats["hops_checked"] += 1
                try:
                    normalized = self.normalize_target(target)
                    self.check_scheme(normalized)
                    host = self._host_from_normalized(normalized)
                except RedirectError as exc:
                    denied = target if isinstance(target, str) else None
                    return self._failed_result(exc.code, denied, hops)

                if normalized in seen:
                    return self._failed_result("REDIRECT_LOOP", normalized, hops)
                if host not in self._allowed_hosts:
                    self._stats["hop_denied"] += 1
                    return self._failed_result("REDIRECT_HOST_DENIED", normalized, hops)

                hops.append(normalized)
                seen.add(normalized)

            self._chain = list(hops)
            return {
                "ok": True,
                "reason": None,
                "count": len(hops),
                "denied": None,
                "hops": list(hops),
            }

    def hop_chain(self):
        with self._lock:
            return list(self._chain)

    def dedupe(self, targets):
        if isinstance(targets, str):
            targets = (targets,)
        result = []
        seen = set()
        removed = 0
        for target in targets:
            normalized = self.normalize_target(target)
            _, separator, remainder = normalized.partition("://")
            key = remainder if separator else normalized
            if key in seen:
                removed += 1
                continue
            seen.add(key)
            result.append(normalized)
        with self._lock:
            self._stats["deduped"] += removed
        return result

    def snapshot(self):
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "allowed_hosts": sorted(self._allowed_hosts),
                "allowed_schemes": list(self._allowed_schemes),
                "max_hops": self._max_hops,
                "chain": list(self._chain),
                "stats": dict(self._stats),
            }

    @classmethod
    def _snapshot_invalid(cls, detail):
        raise RedirectError("REDIRECT_SNAPSHOT_INVALID", detail)

    def restore(self, state):
        if not isinstance(state, dict):
            self._snapshot_invalid("snapshot must be a mapping")

        required = {"version", "allowed_hosts", "allowed_schemes", "max_hops", "chain", "stats"}
        if not required.issubset(state):
            self._snapshot_invalid("snapshot is missing required fields")

        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != _SNAPSHOT_VERSION:
            self._snapshot_invalid("unsupported snapshot version")

        raw_hosts = state["allowed_hosts"]
        raw_schemes = state["allowed_schemes"]
        raw_chain = state["chain"]
        raw_stats = state["stats"]
        max_hops = state["max_hops"]

        if not isinstance(raw_hosts, (list, tuple)) or not all(
            isinstance(host, str) for host in raw_hosts
        ):
            self._snapshot_invalid("allowed_hosts must be a sequence of strings")
        if not isinstance(raw_schemes, (list, tuple)) or not all(
            isinstance(scheme, str) for scheme in raw_schemes
        ):
            self._snapshot_invalid("allowed_schemes must be a sequence of strings")
        if not isinstance(raw_chain, (list, tuple)) or not all(
            isinstance(target, str) for target in raw_chain
        ):
            self._snapshot_invalid("chain must be a sequence of strings")
        if isinstance(max_hops, bool) or not isinstance(max_hops, int) or max_hops < 0:
            self._snapshot_invalid("max_hops must be a non-negative integer")
        if not isinstance(raw_stats, dict):
            self._snapshot_invalid("stats must be a mapping")

        normalized_hosts = set()
        try:
            for host in raw_hosts:
                normalized_hosts.add(self._normalize_whitelist_host(host))
        except RedirectError:
            self._snapshot_invalid("invalid allowed host")

        normalized_schemes = []
        for scheme in raw_schemes:
            lowered = scheme.lower()
            if lowered not in HTTP_SCHEMES:
                self._snapshot_invalid("invalid allowed scheme")
            if lowered not in normalized_schemes:
                normalized_schemes.append(lowered)

        restored_stats = {}
        for key in _STATS_KEYS:
            if key not in raw_stats:
                self._snapshot_invalid("stats is missing counters")
            value = raw_stats[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                self._snapshot_invalid("stats counters must be non-negative integers")
            restored_stats[key] = value

        with self._lock:
            self._allowed_hosts = normalized_hosts
            self._allowed_schemes = tuple(normalized_schemes)
            self._max_hops = max_hops
            self._chain = list(raw_chain)
            restored_stats["restores"] += 1
            self._stats = restored_stats

    def stats(self):
        with self._lock:
            return dict(self._stats)
