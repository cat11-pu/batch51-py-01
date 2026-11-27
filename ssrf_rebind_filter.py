"""出站 URL 的归一、地址范围判定、解析复核与跳转链审计。

判定结果统一折算成 EgressDecision：能给出原因码的一律返回 deny 决策，
只有形状层面无法归一（缺主机、端口越界、scheme 不在允许列表）才在
normalize() 里抛 SsrfError。
"""

from __future__ import annotations

import copy
import ipaddress
import threading
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

SCOPE_PUBLIC = "public"
SCOPE_PRIVATE = "private"
SCOPE_LOOPBACK = "loopback"
SCOPE_LINK_LOCAL = "link_local"
SCOPE_METADATA = "metadata"
SCOPE_INVALID = "invalid"

METADATA_ADDRESSES = frozenset({
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
})
_METADATA_IPS = frozenset(ipaddress.ip_address(item) for item in METADATA_ADDRESSES)

DEFAULT_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

STAT_KEYS = ("allowed", "denied", "hops", "redirects", "restores")
_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset({"version", "allow_hosts", "bindings", "audit", "stats"})
_AUDIT_KEYS = frozenset({"code", "host", "addresses", "hop", "reason"})


class SsrfError(ValueError):
    """归一失败或参数非法时抛出，code 为大写原因码。"""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str
    normalized: str


@dataclass(frozen=True)
class HopRecord:
    index: int
    url: str
    addresses: tuple[str, ...]
    verdict: str
    reason: str


@dataclass(frozen=True)
class EgressDecision:
    verdict: str
    target: Target | None
    hops: tuple[HopRecord, ...]
    failed_hop: int
    reason: str
    detail: Any = None


def _remove_last_segment(path: str) -> str:
    slash = path.rfind("/")
    if slash < 0:
        return ""
    return path[:slash]


def _remove_dot_segments(path: str) -> str:
    """按 RFC 3986 section 5.2.4 折叠点段，保留重复斜杠。"""

    output = ""
    remaining = path
    while remaining:
        if remaining.startswith("../"):
            remaining = remaining[3:]
        elif remaining.startswith("./"):
            remaining = remaining[2:]
        elif remaining.startswith("/./"):
            remaining = "/" + remaining[3:]
        elif remaining == "/.":
            remaining = "/"
        elif remaining.startswith("/../"):
            remaining = "/" + remaining[4:]
            output = _remove_last_segment(output)
        elif remaining == "/..":
            remaining = "/"
            output = _remove_last_segment(output)
        elif remaining in (".", ".."):
            remaining = ""
        else:
            if remaining.startswith("/"):
                next_slash = remaining.find("/", 1)
            else:
                next_slash = remaining.find("/")
            if next_slash < 0:
                output += remaining
                remaining = ""
            else:
                output += remaining[:next_slash]
                remaining = remaining[next_slash:]
    return output


def _strip_address_wrapper(address: str) -> str:
    text = address
    if text.startswith("["):
        closing = text.find("]")
        if closing >= 0:
            remainder = text[closing + 1:]
            if not remainder or remainder.startswith("%"):
                text = text[1:closing]
    if "%" in text:
        text = text.split("%", 1)[0]
    return text


def _parse_ip(address: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(address, str):
        return None
    text = _strip_address_wrapper(address)
    if not text:
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        numeric = _normalize_numeric_ipv4(text)
        if numeric is None:
            return None
        parsed = ipaddress.ip_address(numeric)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _parse_ipv4_component(component: str) -> int | None:
    if not component:
        return None
    lower = component.lower()
    try:
        if lower.startswith("0x"):
            digits = component[2:]
            if not digits or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
                return None
            return int(digits, 16)
        if len(component) > 1 and component.startswith("0"):
            if any(ch not in "01234567" for ch in component):
                return None
            return int(component, 8)
        if not component.isdigit():
            return None
        return int(component, 10)
    except ValueError:
        return None


def _normalize_numeric_ipv4(host: str) -> str | None:
    """把 inet_aton 风格的整数主机还原为点分十进制 IPv4。"""

    candidate = host.rstrip(".")
    if not candidate or ":" in candidate:
        return None
    parts = candidate.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = [_parse_ipv4_component(part) for part in parts]
    if any(value is None for value in values):
        return None

    numbers = [int(value) for value in values if value is not None]
    try:
        if len(numbers) == 1:
            if numbers[0] > 0xFFFFFFFF:
                return None
            value = numbers[0]
        elif len(numbers) == 2:
            if numbers[0] > 0xFF or numbers[1] > 0xFFFFFF:
                return None
            value = (numbers[0] << 24) | numbers[1]
        elif len(numbers) == 3:
            if numbers[0] > 0xFF or numbers[1] > 0xFF or numbers[2] > 0xFFFF:
                return None
            value = (numbers[0] << 24) | (numbers[1] << 16) | numbers[2]
        else:
            if any(number > 0xFF for number in numbers):
                return None
            value = (
                (numbers[0] << 24)
                | (numbers[1] << 16)
                | (numbers[2] << 8)
                | numbers[3]
            )
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        return None


def _canonical_host_key(host: str) -> str:
    if not isinstance(host, str):
        raise SsrfError("SSRF_URL_INVALID", "host must be a string")
    text = host.strip()
    if not text:
        raise SsrfError("SSRF_URL_INVALID", "host is empty")
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1]
    else:
        inner = text
    parsed = _parse_ip(inner)
    if parsed is not None:
        return str(parsed)
    numeric = _normalize_numeric_ipv4(inner)
    if numeric is not None:
        return numeric
    key = inner.lower().rstrip(".")
    if not key or any(ch.isspace() or ord(ch) < 0x20 for ch in key):
        raise SsrfError("SSRF_URL_INVALID", "invalid host")
    return key


def _bracket_host(host: str) -> str:
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def _explicit_port(netloc: str) -> tuple[bool, str | None]:
    host_port = netloc.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        closing = host_port.find("]")
        if closing < 0:
            raise SsrfError("SSRF_URL_INVALID", "unterminated IPv6 literal")
        remainder = host_port[closing + 1:]
        if not remainder:
            return False, None
        if not remainder.startswith(":"):
            raise SsrfError("SSRF_URL_INVALID", "invalid authority")
        return True, remainder[1:]
    if ":" in host_port:
        host_part, port_part = host_port.rsplit(":", 1)
        if ":" in host_part:
            raise SsrfError("SSRF_URL_INVALID", "IPv6 literal must be bracketed")
        return True, port_part
    return False, None


class SsrfRebindFilter:
    """维护主机白名单、解析绑定与跳转链，对每次出站给出可审计结论。"""

    def __init__(self, *, schemes=DEFAULT_SCHEMES, allow_hosts=(), allow_ports=(80, 443),
                 max_redirects: int = 5, max_hops: int = 8,
                 resolver: Callable[[str], tuple[str, ...]] | None = None,
                 allowed_cidrs=()) -> None:
        self.schemes = tuple(str(item).lower() for item in schemes)
        self.allow_ports = tuple(int(item) for item in allow_ports)
        self.max_redirects = max(0, int(max_redirects))
        self.max_hops = max(0, int(max_hops))
        self.resolver = resolver
        self._allowed_networks = tuple(
            ipaddress.ip_network(str(item), strict=False) for item in allowed_cidrs
        )
        self._lock = threading.RLock()
        self._allow_hosts: set[str] = set()
        for host in allow_hosts:
            self._allow_hosts.add(_canonical_host_key(host))
        self._bindings: dict[str, tuple[str, ...]] = {}
        self._audit: list[dict[str, Any]] = []
        self._stats = {name: 0 for name in STAT_KEYS}

    def normalize(self, raw: str) -> Target:
        if not isinstance(raw, str) or not raw:
            raise SsrfError("SSRF_URL_INVALID", "URL must be a non-empty string")
        if raw != raw.strip():
            raise SsrfError("SSRF_URL_INVALID", "URL contains surrounding whitespace")
        if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
            raise SsrfError("SSRF_URL_INVALID", "URL contains whitespace or control characters")
        if "\\" in raw:
            raise SsrfError("SSRF_URL_INVALID", "backslashes are not valid URL syntax")

        try:
            parsed = urlsplit(raw)
        except (TypeError, ValueError) as exc:
            raise SsrfError("SSRF_URL_INVALID", str(exc)) from exc

        scheme = parsed.scheme.lower()
        if not scheme or not parsed.netloc:
            raise SsrfError("SSRF_URL_INVALID", "URL must contain a scheme and host")
        if scheme not in self.schemes:
            raise SsrfError("SSRF_SCHEME_REJECTED", scheme)

        try:
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise SsrfError("SSRF_URL_INVALID", str(exc)) from exc
        if not host:
            raise SsrfError("SSRF_URL_INVALID", "URL is missing a host")

        try:
            has_explicit_port, port_text = _explicit_port(parsed.netloc)
        except SsrfError:
            raise
        if has_explicit_port:
            if port_text is None or not port_text.isdigit():
                raise SsrfError("SSRF_URL_INVALID", "invalid port")
            if port is None or not 1 <= port <= 65535:
                raise SsrfError("SSRF_URL_INVALID", "port must be in 1..65535")
        else:
            port = DEFAULT_PORTS.get(scheme)
            if port is None:
                raise SsrfError("SSRF_URL_INVALID", "scheme has no default port")

        if not 1 <= int(port) <= 65535:
            raise SsrfError("SSRF_URL_INVALID", "port must be in 1..65535")

        host_lower = host.lower()
        if ":" in host_lower:
            ip = _parse_ip(host_lower)
            if ip is None:
                raise SsrfError("SSRF_URL_INVALID", "invalid IPv6 literal")
            normalized_host = str(ip)
        else:
            numeric_host = _normalize_numeric_ipv4(host_lower)
            if numeric_host is not None:
                normalized_host = numeric_host
            else:
                if "%" in host_lower or any(
                    ch.isspace() or ord(ch) < 0x20 or ch in "/\\" for ch in host_lower
                ):
                    raise SsrfError("SSRF_URL_INVALID", "invalid host")
                normalized_host = host_lower
        if not normalized_host.rstrip("."):
            raise SsrfError("SSRF_URL_INVALID", "invalid host")

        path = _remove_dot_segments(parsed.path)
        if not path:
            path = "/"
        elif not path.startswith("/"):
            path = "/" + path

        netloc = _bracket_host(normalized_host)
        if has_explicit_port:
            netloc += f":{int(port)}"
        normalized = urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
        return Target(
            scheme=scheme,
            host=normalized_host,
            port=int(port),
            path=path,
            normalized=normalized,
        )

    def classify(self, address: str) -> str:
        parsed = _parse_ip(address)
        if parsed is None:
            return SCOPE_INVALID
        if parsed in _METADATA_IPS:
            return SCOPE_METADATA
        if parsed.is_loopback:
            return SCOPE_LOOPBACK
        if parsed.is_link_local:
            return SCOPE_LINK_LOCAL
        if (
            parsed.is_private
            or parsed.is_reserved
            or parsed.is_unspecified
            or parsed.is_multicast
            or not parsed.is_global
        ):
            return SCOPE_PRIVATE
        return SCOPE_PUBLIC

    def bind_resolution(self, host: str, addresses, *, now: int | None = None) -> tuple[str, ...]:
        del now
        with self._lock:
            key = _canonical_host_key(host)
            canonical = self._canonical_addresses(addresses)
            if canonical is None:
                raise SsrfError("SSRF_URL_INVALID", "resolution contains an invalid address")
            self._bindings[key] = canonical
            return canonical

    def decide(self, raw: str, *, now: int | None = None) -> EgressDecision:
        with self._lock:
            try:
                target = self.normalize(raw)
            except SsrfError as exc:
                return self._shape_denial(exc.code, exc.detail, count_verdict=True)
            except (TypeError, ValueError) as exc:
                return self._shape_denial("SSRF_URL_INVALID", str(exc), count_verdict=True)
            return self._evaluate_target_locked(target, now=now, count_verdict=True)

    def authorize(self, target: Target, *, now: int | None = None) -> EgressDecision:
        with self._lock:
            if not isinstance(target, Target):
                return self._shape_denial(
                    "SSRF_URL_INVALID", "authorize expects a Target", count_verdict=True
                )
            try:
                normalized = self.normalize(target.normalized)
            except SsrfError as exc:
                return self._shape_denial(exc.code, exc.detail, count_verdict=True)
            except (TypeError, ValueError) as exc:
                return self._shape_denial("SSRF_URL_INVALID", str(exc), count_verdict=True)
            return self._evaluate_target_locked(normalized, now=now, count_verdict=True)

    def follow_redirect(self, decision: EgressDecision, location: str, *,
                        now: int | None = None) -> EgressDecision:
        with self._lock:
            if not isinstance(decision, EgressDecision):
                return self._shape_denial(
                    "SSRF_URL_INVALID", "invalid decision", count_verdict=False
                )
            existing = tuple(decision.hops)
            if decision.verdict != "allow" or decision.target is None:
                return decision

            self._stats["redirects"] += 1
            if isinstance(location, str):
                try:
                    location = urljoin(decision.target.normalized, location)
                except ValueError:
                    pass
            try:
                target = self.normalize(location)
            except SsrfError as exc:
                if exc.code == "SSRF_SCHEME_REJECTED":
                    return self._redirect_scheme_denial_locked(
                        existing, location, exc.code, exc.detail
                    )
                return self._shape_denial(
                    exc.code,
                    exc.detail,
                    count_verdict=False,
                    hops=existing,
                    failed_hop=len(existing),
                )
            except (TypeError, ValueError) as exc:
                return self._shape_denial(
                    "SSRF_URL_INVALID",
                    str(exc),
                    count_verdict=False,
                    hops=existing,
                    failed_hop=len(existing),
                )

            redirects_used = max(0, len(existing) - 1)
            if redirects_used >= self.max_redirects or len(existing) >= self.max_hops:
                return self._redirect_limit_locked(existing, target)

            return self._evaluate_target_locked(
                target,
                now=now,
                count_verdict=False,
                prefix=existing,
            )

    def allow_host(self, host: str) -> None:
        key = _canonical_host_key(host)
        with self._lock:
            self._allow_hosts.add(key)

    def allowed_hosts(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._allow_hosts))

    def audit_log(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(copy.deepcopy(self._audit))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "allow_hosts": sorted(self._allow_hosts),
                "bindings": {
                    host: tuple(addresses)
                    for host, addresses in self._bindings.items()
                },
                "audit": copy.deepcopy(self._audit),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                allow_hosts, bindings, audit, stats = self._validate_snapshot(state)
            except SsrfError as exc:
                if exc.code == "SSRF_SNAPSHOT_INVALID":
                    raise
                raise SsrfError("SSRF_SNAPSHOT_INVALID", str(exc)) from exc
            except Exception as exc:
                raise SsrfError("SSRF_SNAPSHOT_INVALID", str(exc)) from exc
            self._allow_hosts = allow_hosts
            self._bindings = bindings
            self._audit = audit
            self._stats = stats
            self._stats["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _canonical_addresses(self, addresses) -> tuple[str, ...] | None:
        if addresses is None:
            return None
        if isinstance(addresses, str):
            items = (addresses,)
        else:
            try:
                items = tuple(addresses)
            except Exception:
                return None
        canonical = []
        for item in items:
            parsed = _parse_ip(item)
            if parsed is None:
                return None
            canonical.append(str(parsed))
        return tuple(canonical)

    def _display_addresses(self, addresses) -> tuple[str, ...]:
        if addresses is None:
            return ()
        if isinstance(addresses, str):
            items = (addresses,)
        else:
            try:
                items = tuple(addresses)
            except Exception:
                return ()
        return tuple(str(item) for item in items)

    def _literal_addresses(self, host: str) -> tuple[str, ...] | None:
        parsed = _parse_ip(host)
        if parsed is not None:
            return (str(parsed),)
        numeric = _normalize_numeric_ipv4(host)
        if numeric is not None:
            return (numeric,)
        return None

    def _resolve_target_locked(self, target: Target) -> tuple[tuple[str, ...], bool]:
        """返回 (地址, 是否解析失败)。调用方必须持有实例锁。"""

        literal = self._literal_addresses(target.host)
        if literal is not None:
            return literal, False

        key = _canonical_host_key(target.host)
        if self.resolver is None:
            return self._bindings.get(key, ()), False

        try:
            resolved = self.resolver(key)
        except Exception:
            return (), True
        if resolved is None:
            return (), True
        if isinstance(resolved, str):
            resolved = (resolved,)
        try:
            items = tuple(resolved)
        except Exception:
            return (), True
        if not items:
            return (), True

        canonical = self._canonical_addresses(items)
        if canonical is None:
            return self._display_addresses(items), False
        self._bindings[key] = canonical
        return canonical, False

    def _address_denial(self, addresses: tuple[str, ...]) -> str | None:
        metadata_hit = False
        private_hit = False
        invalid_hit = False
        for address in addresses:
            parsed = _parse_ip(address)
            if parsed is None:
                invalid_hit = True
                continue
            if any(
                parsed.version == network.version and parsed in network
                for network in self._allowed_networks
            ):
                continue
            scope = self.classify(address)
            if scope == SCOPE_METADATA:
                metadata_hit = True
            elif scope in (SCOPE_PRIVATE, SCOPE_LOOPBACK, SCOPE_LINK_LOCAL):
                private_hit = True
            elif scope == SCOPE_INVALID:
                invalid_hit = True

        if metadata_hit:
            return "SSRF_METADATA_DENIED"
        if private_hit or invalid_hit:
            return "SSRF_ADDRESS_DENIED"
        return None

    def _evaluate_target_locked(self, target: Target, *, now: int | None,
                                count_verdict: bool,
                                prefix: tuple[HopRecord, ...] = ()) -> EgressDecision:
        del now
        index = len(prefix)
        addresses: tuple[str, ...] = ()
        reason = "SSRF_OK"

        if self._allow_hosts:
            host_key = _canonical_host_key(target.host)
            if host_key not in self._allow_hosts:
                reason = "SSRF_HOST_NOT_ALLOWED"
        if reason == "SSRF_OK" and target.port not in self.allow_ports:
            reason = "SSRF_PORT_REJECTED"

        if reason == "SSRF_OK":
            addresses, unresolved = self._resolve_target_locked(target)
            if unresolved or not addresses:
                reason = "SSRF_UNRESOLVED"
            else:
                address_reason = self._address_denial(addresses)
                if address_reason is not None:
                    reason = address_reason

        verdict = "allow" if reason == "SSRF_OK" else "deny"
        hop = HopRecord(
            index=index,
            url=target.normalized,
            addresses=tuple(addresses),
            verdict=verdict,
            reason=reason,
        )
        hops = prefix + (hop,)
        self._append_hop_locked(hop, target.host)
        if count_verdict:
            self._stats["allowed" if verdict == "allow" else "denied"] += 1
        return EgressDecision(
            verdict=verdict,
            target=target,
            hops=hops,
            failed_hop=index if verdict == "deny" else -1,
            reason=reason,
        )

    def _append_hop_locked(self, hop: HopRecord, host: str) -> None:
        self._audit.append({
            "code": hop.reason,
            "host": host,
            "addresses": tuple(hop.addresses),
            "hop": hop.index,
            "reason": hop.reason,
        })
        self._stats["hops"] += 1

    def _shape_denial(self, code: str, detail: Any, *, count_verdict: bool,
                      hops: tuple[HopRecord, ...] = (),
                      failed_hop: int = -1) -> EgressDecision:
        if count_verdict:
            self._stats["denied"] += 1
        return EgressDecision(
            verdict="deny",
            target=None,
            hops=hops,
            failed_hop=failed_hop,
            reason=code,
            detail=detail,
        )

    def _redirect_limit_locked(self, existing: tuple[HopRecord, ...],
                               target: Target) -> EgressDecision:
        index = len(existing)
        hop = HopRecord(
            index=index,
            url=target.normalized,
            addresses=(),
            verdict="deny",
            reason="SSRF_REDIRECT_LIMIT",
        )
        self._append_hop_locked(hop, target.host)
        return EgressDecision(
            verdict="deny",
            target=target,
            hops=existing + (hop,),
            failed_hop=index,
            reason="SSRF_REDIRECT_LIMIT",
        )

    def _redirect_scheme_denial_locked(
        self, existing: tuple[HopRecord, ...], location: Any, code: str, detail: Any
    ) -> EgressDecision:
        index = len(existing)
        url = location if isinstance(location, str) else str(location)
        try:
            host = urlsplit(url).hostname or ""
        except (TypeError, ValueError):
            host = ""
        hop = HopRecord(
            index=index,
            url=url,
            addresses=(),
            verdict="deny",
            reason=code,
        )
        self._append_hop_locked(hop, host)
        return EgressDecision(
            verdict="deny",
            target=None,
            hops=existing + (hop,),
            failed_hop=index,
            reason=code,
            detail=detail,
        )

    def _validate_snapshot(
        self, state: dict
    ) -> tuple[set[str], dict[str, tuple[str, ...]], list[dict[str, Any]], dict[str, int]]:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise SsrfError("SSRF_SNAPSHOT_INVALID", "invalid snapshot keys")
        if type(state["version"]) is not int or state["version"] != _SNAPSHOT_VERSION:
            raise SsrfError("SSRF_SNAPSHOT_INVALID", "unsupported snapshot version")

        raw_hosts = state["allow_hosts"]
        if not isinstance(raw_hosts, (list, tuple)):
            raise SsrfError("SSRF_SNAPSHOT_INVALID", "allow_hosts must be a sequence")
        allow_hosts: set[str] = set()
        for host in raw_hosts:
            if not isinstance(host, str):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "allow_hosts entry is not a string")
            allow_hosts.add(_canonical_host_key(host))

        raw_bindings = state["bindings"]
        if not isinstance(raw_bindings, dict):
            raise SsrfError("SSRF_SNAPSHOT_INVALID", "bindings must be a mapping")
        bindings: dict[str, tuple[str, ...]] = {}
        for host, raw_addresses in raw_bindings.items():
            if not isinstance(host, str):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "binding host is not a string")
            if not isinstance(raw_addresses, (list, tuple)):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "binding addresses must be sequences")
            canonical = []
            for address in raw_addresses:
                if not isinstance(address, str):
                    raise SsrfError("SSRF_SNAPSHOT_INVALID", "binding address is not a string")
                parsed = _parse_ip(address)
                if parsed is None:
                    raise SsrfError("SSRF_SNAPSHOT_INVALID", "binding address is invalid")
                canonical.append(str(parsed))
            bindings[_canonical_host_key(host)] = tuple(canonical)

        raw_audit = state["audit"]
        if not isinstance(raw_audit, (list, tuple)):
            raise SsrfError("SSRF_SNAPSHOT_INVALID", "audit must be a sequence")
        audit: list[dict[str, Any]] = []
        for entry in raw_audit:
            if not isinstance(entry, dict) or set(entry) != _AUDIT_KEYS:
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "invalid audit entry")
            if not isinstance(entry["code"], str) or not isinstance(entry["reason"], str):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "audit code/reason is invalid")
            if not isinstance(entry["host"], str):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "audit host is invalid")
            if type(entry["hop"]) is not int or entry["hop"] < 0:
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "audit hop is invalid")
            raw_addresses = entry["addresses"]
            if not isinstance(raw_addresses, (list, tuple)):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "audit addresses is invalid")
            if any(not isinstance(address, str) for address in raw_addresses):
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "audit address is invalid")
            audit.append({
                "code": entry["code"],
                "host": entry["host"],
                "addresses": tuple(raw_addresses),
                "hop": entry["hop"],
                "reason": entry["reason"],
            })

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != frozenset(STAT_KEYS):
            raise SsrfError("SSRF_SNAPSHOT_INVALID", "invalid stats")
        stats: dict[str, int] = {}
        for key in STAT_KEYS:
            value = raw_stats[key]
            if type(value) is not int or value < 0:
                raise SsrfError("SSRF_SNAPSHOT_INVALID", "invalid stats value")
            stats[key] = value
        return allow_hosts, bindings, audit, stats
