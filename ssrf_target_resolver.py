"""SSRF 目标归一、范围判定与跳转逐跳复核。"""

from __future__ import annotations

import copy
import ipaddress
import re
import threading
import time
from urllib.parse import urljoin, urlsplit

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

DEFAULT_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}

_SCOPE_RANK = {
    SCOPE_PUBLIC: 0,
    SCOPE_INVALID: 1,
    SCOPE_PRIVATE: 2,
    SCOPE_LINK_LOCAL: 3,
    SCOPE_LOOPBACK: 4,
    SCOPE_METADATA: 5,
}

_PRIVATE_V4 = tuple(ipaddress.ip_network(item) for item in (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
))
_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
_PRIVATE_V6 = ipaddress.ip_network("fd00::/8")
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")
_LOOPBACK_V6 = ipaddress.ip_address("::1")

_SCHEME_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_HEX_PART = re.compile(r"^0[xX][0-9a-fA-F]+$")
_OCTAL_PART = re.compile(r"^0[0-7]+$")
_DECIMAL_PART = re.compile(r"^(?:0|[1-9][0-9]*)$")

_STAT_KEYS = (
    "normalized",
    "allowed",
    "denied",
    "bindings",
    "redirects",
    "redirect_limits",
    "hops_denied",
    "restores",
)


class SsrfError(ValueError):
    """目标归一或判定被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _parse_legacy_ipv4(value):
    """Parse the inet_aton numeric IPv4 forms used by browsers and curl."""
    if not isinstance(value, str) or not value or ":" in value:
        return None
    text = value.rstrip(".")
    if not text:
        return None
    parts = text.split(".")
    if len(parts) > 4:
        return None

    numbers = []
    for part in parts:
        if not part:
            return None
        if _HEX_PART.fullmatch(part):
            number = int(part, 16)
        elif _OCTAL_PART.fullmatch(part):
            number = int(part, 8)
        elif _DECIMAL_PART.fullmatch(part):
            number = int(part, 10)
        else:
            return None
        numbers.append(number)

    if len(numbers) == 1:
        widths = (32,)
    elif len(numbers) == 2:
        widths = (8, 24)
    elif len(numbers) == 3:
        widths = (8, 8, 16)
    else:
        widths = (8, 8, 8, 8)

    packed = 0
    for number, width in zip(numbers, widths):
        if number < 0 or number >= (1 << width):
            return None
        packed = (packed << width) | number
    return str(ipaddress.IPv4Address(packed))


def _parse_address_literal(value):
    if not isinstance(value, str) or not value:
        return None
    if value != value.strip() or "%" in value:
        return None
    if ":" in value:
        try:
            return ipaddress.IPv6Address(value)
        except ValueError:
            return None
    legacy = _parse_legacy_ipv4(value)
    if legacy is not None:
        return ipaddress.IPv4Address(legacy)
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None


def _canonical_address(value):
    parsed = _parse_address_literal(value)
    if parsed is None:
        raise SsrfError("SSRF_INVALID_TARGET", {"address": value})
    return str(parsed)


def _address_sort_key(value):
    parsed = ipaddress.ip_address(value)
    return parsed.version, int(parsed)


def _worst_scope(scopes):
    if not scopes:
        return SCOPE_PUBLIC
    return max(scopes, key=lambda scope: _SCOPE_RANK.get(scope, 0))


def _embedded_ipv4(address):
    if isinstance(address, ipaddress.IPv6Address):
        return address.ipv4_mapped
    return None


class SsrfTargetResolver:
    """把用户提交的地址归一成可判定目标，并在判定时点绑定解析结果。"""

    def __init__(self, *, schemes=DEFAULT_SCHEMES, allow_hosts=(), deny_cidrs=(),
                 max_redirects=3, max_targets=64):
        self.schemes = tuple(str(item).strip().lower() for item in schemes)
        self.max_redirects = max(0, int(max_redirects))
        self.max_targets = max(0, int(max_targets))
        self._lock = threading.RLock()
        self._stats = {
            "normalized": 0,
            "allowed": 0,
            "denied": 0,
            "bindings": 0,
            "redirects": 0,
            "redirect_limits": 0,
            "hops_denied": 0,
            "restores": 0,
        }
        self._allow_hosts = set()
        for host in allow_hosts:
            self._allow_hosts.add(self._normalize_host(host))

        self._deny_cidrs = []
        self._deny_networks = []
        for cidr in deny_cidrs:
            try:
                network = ipaddress.ip_network(str(cidr).strip(), strict=False)
            except ValueError as exc:
                raise SsrfError("SSRF_INVALID_TARGET", {"cidr": cidr}) from exc
            text = str(network)
            if text not in self._deny_cidrs:
                self._deny_cidrs.append(text)
                self._deny_networks.append(network)

        self._targets = []
        self._chains = {}
        self._host_bindings = {}
        self._decisions = {}

    @staticmethod
    def _normalize_host(host):
        if not isinstance(host, str):
            raise SsrfError("SSRF_INVALID_TARGET", {"host": host})
        text = host.strip()
        if not text:
            raise SsrfError("SSRF_INVALID_TARGET", {"host": host})
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        elif "[" in text or "]" in text:
            raise SsrfError("SSRF_INVALID_TARGET", {"host": host})

        text = text.rstrip(".")
        if not text:
            raise SsrfError("SSRF_INVALID_TARGET", {"host": host})
        if any(character.isspace() or ord(character) < 32 for character in text):
            raise SsrfError("SSRF_INVALID_TARGET", {"host": host})
        if any(character in "/?#@\\" for character in text):
            raise SsrfError("SSRF_INVALID_TARGET", {"host": host})

        if ":" in text:
            if "%" in text:
                raise SsrfError("SSRF_INVALID_TARGET", {"host": host})
            try:
                return str(ipaddress.IPv6Address(text))
            except ValueError as exc:
                raise SsrfError("SSRF_INVALID_TARGET", {"host": host}) from exc

        legacy = _parse_legacy_ipv4(text)
        if legacy is not None:
            return legacy
        return text.lower()

    @staticmethod
    def _url_host(host):
        if ":" in host:
            return "[{}]".format(host)
        return host

    def _normalize_target(self, raw, *, count):
        if not isinstance(raw, str):
            raise SsrfError("SSRF_INVALID_TARGET", {"target": raw})
        text = raw.strip()
        if not text:
            raise SsrfError("SSRF_INVALID_TARGET", {"target": raw})

        match = _SCHEME_PREFIX.match(text)
        if match is None:
            raise SsrfError("SSRF_INVALID_TARGET", {"target": raw})
        scheme = match.group(1).lower()
        if scheme not in self.schemes:
            raise SsrfError("SSRF_SCHEME_DENIED", {"scheme": scheme})

        try:
            parsed = urlsplit(text)
            if parsed.scheme.lower() != scheme or not parsed.netloc:
                raise SsrfError("SSRF_INVALID_TARGET", {"target": raw})
            if parsed.username is not None or parsed.password is not None:
                raise SsrfError("SSRF_INVALID_TARGET", {"target": raw})
            host = parsed.hostname
            port = parsed.port
        except SsrfError:
            raise
        except ValueError as exc:
            raise SsrfError("SSRF_INVALID_TARGET", {"target": raw}) from exc

        if not host:
            raise SsrfError("SSRF_INVALID_TARGET", {"target": raw})
        host = self._normalize_host(host)
        default_port = DEFAULT_PORTS.get(scheme)
        effective_port = port if port is not None else default_port

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if parsed.fragment:
            path += "#" + parsed.fragment

        canonical = "{}://{}".format(scheme, self._url_host(host))
        if port is not None and port != default_port:
            canonical += ":{}".format(port)
        canonical += path

        if count:
            with self._lock:
                self._stats["normalized"] += 1
        return {
            "scheme": scheme,
            "host": host,
            "port": effective_port,
            "path": path,
            "canonical": canonical,
        }

    def normalize(self, raw):
        return self._normalize_target(raw, count=True)

    def classify_scope(self, address):
        parsed = _parse_address_literal(address)
        if parsed is None:
            return SCOPE_INVALID

        embedded = _embedded_ipv4(parsed)
        if embedded is not None:
            parsed = embedded

        if str(parsed) in METADATA_ADDRESSES:
            return SCOPE_METADATA
        if isinstance(parsed, ipaddress.IPv4Address):
            if parsed in _LOOPBACK_V4:
                return SCOPE_LOOPBACK
            if parsed in _LINK_LOCAL_V4:
                return SCOPE_LINK_LOCAL
            if any(parsed in network for network in _PRIVATE_V4):
                return SCOPE_PRIVATE
        else:
            if parsed == _LOOPBACK_V6:
                return SCOPE_LOOPBACK
            if parsed in _LINK_LOCAL_V6:
                return SCOPE_LINK_LOCAL
            if parsed in _PRIVATE_V6:
                return SCOPE_PRIVATE
        return SCOPE_PUBLIC

    def _prepare_addresses(self, addresses):
        if addresses is None:
            return []
        if isinstance(addresses, str):
            addresses = (addresses,)
        canonical = set()
        try:
            iterator = iter(addresses)
        except TypeError as exc:
            raise SsrfError("SSRF_INVALID_TARGET", {"addresses": addresses}) from exc
        for address in iterator:
            canonical.add(_canonical_address(address))
        return sorted(canonical, key=_address_sort_key)

    def _binding_locked(self, host, addresses, now, *, increment):
        normalized_host = self._normalize_host(host)
        normalized_addresses = self._prepare_addresses(addresses)
        if not normalized_addresses:
            raise SsrfError("SSRF_RESOLUTION_EMPTY", {"host": normalized_host})
        binding = {
            "host": normalized_host,
            "addresses": normalized_addresses,
            "bound_at": time.time() if now is None else now,
        }
        self._host_bindings[normalized_host] = copy.deepcopy(binding)
        if increment:
            self._stats["bindings"] += 1
        return binding

    def bind_resolution(self, host, addresses, *, now=None):
        with self._lock:
            return self._binding_locked(host, addresses, now, increment=True)

    def _deny_hit(self, host, addresses):
        targets = []
        parsed_host = _parse_address_literal(host)
        if parsed_host is not None:
            targets.append(parsed_host)
        for address in addresses:
            parsed = _parse_address_literal(address)
            if parsed is not None:
                targets.append(parsed)

        for parsed in targets:
            candidates = [parsed]
            embedded = _embedded_ipv4(parsed)
            if embedded is not None:
                candidates.append(embedded)
            for candidate in candidates:
                for network in self._deny_networks:
                    if candidate.version == network.version and candidate in network:
                        return True
        return False

    def _decision_record(self, target, *, addresses, bound_at, verdict,
                         reason, scope):
        return {
            "target": target["canonical"],
            "host": target["host"],
            "verdict": verdict,
            "reason": reason,
            "scope": scope,
            "addresses": copy.deepcopy(addresses),
            "bound_at": bound_at,
        }

    def _evaluate_locked(self, target, *, addresses, now, count_stats):
        binding = None
        if addresses is not None:
            binding = self._binding_locked(
                target["host"], addresses, now, increment=True
            )
        else:
            existing = self._host_bindings.get(target["host"])
            if existing is not None:
                binding = copy.deepcopy(existing)

        bound_addresses = binding["addresses"] if binding is not None else []
        bound_at = binding["bound_at"] if binding is not None else None
        address_scopes = [
            self.classify_scope(address) for address in bound_addresses
        ]
        host_scope = self.classify_scope(target["host"])
        scope_inputs = list(address_scopes)
        if host_scope != SCOPE_INVALID:
            scope_inputs.append(host_scope)
        scope = _worst_scope(scope_inputs) if scope_inputs else host_scope

        if self._deny_hit(target["host"], bound_addresses):
            verdict = "deny"
            reason = "SSRF_HOST_DENIED"
        elif target["host"] in self._allow_hosts:
            verdict = "allow"
            reason = "allowlisted"
            scope = host_scope
        elif binding is not None:
            non_public = [
                item for item in address_scopes if item != SCOPE_PUBLIC
            ]
            if non_public:
                verdict = "deny"
                reason = "SSRF_RESOLVED_PRIVATE"
                scope = _worst_scope(non_public)
            elif host_scope not in (SCOPE_PUBLIC, SCOPE_INVALID):
                verdict = "deny"
                reason = "SSRF_SCOPE_DENIED"
                scope = host_scope
            else:
                verdict = "allow"
                reason = "public"
                scope = SCOPE_PUBLIC
        elif host_scope == SCOPE_PUBLIC:
            verdict = "allow"
            reason = "public"
        else:
            verdict = "deny"
            reason = "SSRF_SCOPE_DENIED"

        record = self._decision_record(
            target,
            addresses=bound_addresses if binding is not None else None,
            bound_at=bound_at,
            verdict=verdict,
            reason=reason,
            scope=scope,
        )
        self._decisions[target["canonical"]] = copy.deepcopy(record)
        if count_stats:
            if verdict == "allow":
                self._stats["allowed"] += 1
            else:
                self._stats["denied"] += 1
        return record

    @staticmethod
    def _public_decision(record):
        return {
            "target": record["target"],
            "verdict": record["verdict"],
            "reason": record["reason"],
            "scope": record["scope"],
        }

    def decide(self, raw, *, addresses=None, now=None):
        with self._lock:
            target = self.normalize(raw)
            record = self._evaluate_locked(
                target, addresses=addresses, now=now, count_stats=True
            )
            return self._public_decision(record)

    def _raise_denied(self, record):
        raise SsrfError(
            record["reason"],
            {
                "target": record["target"],
                "scope": record["scope"],
            },
        )

    def authorize_request(self, target, *, addresses=None, now=None):
        with self._lock:
            normalized = self.normalize(target)
            record = self._decisions.get(normalized["canonical"])

            if record is not None and record["verdict"] != "allow":
                self._raise_denied(record)

            if record is not None and record["reason"] == "allowlisted":
                if addresses is not None:
                    current_addresses = self._prepare_addresses(addresses)
                    if self._deny_hit(normalized["host"], current_addresses):
                        raise SsrfError(
                            "SSRF_HOST_DENIED",
                            {"target": normalized["canonical"]},
                        )
                return normalized["canonical"]

            if record is not None:
                if self.classify_scope(normalized["host"]) == SCOPE_PUBLIC:
                    return normalized["canonical"]
                bound_addresses = record["addresses"] or []
                if addresses is not None:
                    current_addresses = self._prepare_addresses(addresses)
                    if current_addresses != bound_addresses:
                        scopes = [
                            self.classify_scope(address)
                            for address in current_addresses
                        ]
                        non_public = [
                            scope for scope in scopes
                            if scope != SCOPE_PUBLIC
                        ]
                        if non_public:
                            raise SsrfError(
                                "SSRF_RESOLVED_PRIVATE",
                                {
                                    "target": normalized["canonical"],
                                    "scope": _worst_scope(non_public),
                                },
                            )
                        raise SsrfError(
                            "SSRF_HOST_DENIED",
                            {"target": normalized["canonical"]},
                        )
                non_public = []
                for address in bound_addresses:
                    scope = self.classify_scope(address)
                    if scope != SCOPE_PUBLIC:
                        non_public.append(scope)
                if non_public:
                    raise SsrfError(
                        "SSRF_RESOLVED_PRIVATE",
                        {
                            "target": normalized["canonical"],
                            "scope": _worst_scope(non_public),
                        },
                    )
                host_scope = self.classify_scope(normalized["host"])
                if host_scope not in (SCOPE_PUBLIC, SCOPE_INVALID):
                    raise SsrfError(
                        "SSRF_SCOPE_DENIED",
                        {
                            "target": normalized["canonical"],
                            "scope": host_scope,
                        },
                    )
                return normalized["canonical"]

            existing_binding = self._host_bindings.get(normalized["host"])
            if existing_binding is not None and addresses is not None:
                bound_addresses = existing_binding["addresses"]
                current_addresses = self._prepare_addresses(addresses)
                if current_addresses != bound_addresses:
                    scopes = [
                        self.classify_scope(address)
                        for address in current_addresses + bound_addresses
                    ]
                    non_public = [
                        scope for scope in scopes if scope != SCOPE_PUBLIC
                    ]
                    if non_public:
                        raise SsrfError(
                            "SSRF_RESOLVED_PRIVATE",
                            {
                                "target": normalized["canonical"],
                                "scope": _worst_scope(non_public),
                            },
                        )
                    raise SsrfError(
                        "SSRF_HOST_DENIED",
                        {"target": normalized["canonical"]},
                    )

            record = self._evaluate_locked(
                normalized,
                addresses=None if existing_binding is not None else addresses,
                now=now,
                count_stats=False,
            )
            if record["verdict"] != "allow":
                self._raise_denied(record)
            return normalized["canonical"]

    def follow_redirect(self, target, location, *, now=None):
        with self._lock:
            original = self.normalize(target)
            origin = original["canonical"]
            chain = self._chains.get(origin)

            if chain is None:
                if len(self._targets) >= self.max_targets:
                    raise SsrfError(
                        "SSRF_TARGET_LIMIT",
                        {"max_targets": self.max_targets},
                    )
                first = self._evaluate_locked(
                    original, addresses=None, now=now, count_stats=False
                )
                if first["verdict"] != "allow":
                    self._stats["hops_denied"] += 1
                    raise SsrfError(
                        "SSRF_HOP_DENIED",
                        {"hop": 1, "target": origin},
                    )
                self._targets.append(origin)
                chain = [copy.deepcopy(first)]
                self._chains[origin] = chain

            if not isinstance(location, str):
                self.normalize(location)
            base = chain[-1]["target"]
            joined = urljoin(base, location)
            candidate = self.normalize(joined)
            next_target = candidate["canonical"]
            next_hop = len(chain) + 1

            if any(hop["target"] == next_target for hop in chain):
                raise SsrfError(
                    "SSRF_REDIRECT_LOOP",
                    {"hop": next_hop, "target": next_target},
                )
            if len(chain) > self.max_redirects:
                self._stats["redirect_limits"] += 1
                raise SsrfError(
                    "SSRF_REDIRECT_LIMIT",
                    {"hop": next_hop, "target": next_target},
                )

            decision = self._evaluate_locked(
                candidate, addresses=None, now=now, count_stats=False
            )
            if decision["verdict"] != "allow":
                self._stats["hops_denied"] += 1
                raise SsrfError(
                    "SSRF_HOP_DENIED",
                    {"hop": next_hop, "target": next_target},
                )

            chain.append(copy.deepcopy(decision))
            self._stats["redirects"] += 1
            return next_target

    def hops_for(self, target):
        if not isinstance(target, str):
            return []
        try:
            normalized = self._normalize_target(target, count=False)
        except SsrfError:
            return []
        with self._lock:
            chain = self._chains.get(normalized["canonical"])
            if chain is None:
                return []
            return [hop["target"] for hop in chain]

    def allow_host(self, host):
        normalized = self._normalize_host(host)
        with self._lock:
            self._allow_hosts.add(normalized)
        return normalized

    def allowed_hosts(self):
        with self._lock:
            return sorted(self._allow_hosts)

    def targets(self):
        with self._lock:
            return list(self._targets)

    def snapshot(self):
        with self._lock:
            return copy.deepcopy({
                "version": 1,
                "schemes": list(self.schemes),
                "allow_hosts": sorted(self._allow_hosts),
                "deny_cidrs": list(self._deny_cidrs),
                "max_redirects": self.max_redirects,
                "targets": list(self._targets),
                "chains": self._chains,
                "bindings": {
                    "hosts": self._host_bindings,
                    "targets": self._decisions,
                },
                "stats": self._stats,
            })

    @staticmethod
    def _snapshot_error(detail=None):
        raise SsrfError("SSRF_SNAPSHOT_INVALID", detail)

    @classmethod
    def _restore_record(cls, value):
        if not isinstance(value, dict):
            cls._snapshot_error({"record": value})
        required = {
            "target", "host", "verdict", "reason", "scope",
            "addresses", "bound_at",
        }
        if not required.issubset(value):
            cls._snapshot_error({"record": value})
        if not isinstance(value["target"], str):
            cls._snapshot_error({"target": value["target"]})
        if not isinstance(value["host"], str):
            cls._snapshot_error({"host": value["host"]})
        if value["verdict"] not in ("allow", "deny"):
            cls._snapshot_error({"verdict": value["verdict"]})
        if not isinstance(value["reason"], str) or not value["reason"]:
            cls._snapshot_error({"reason": value["reason"]})
        if value["scope"] not in _SCOPE_RANK:
            cls._snapshot_error({"scope": value["scope"]})
        addresses = value["addresses"]
        if addresses is not None:
            if not isinstance(addresses, (list, tuple)):
                cls._snapshot_error({"addresses": addresses})
            addresses = [cls._checked_address(item) for item in addresses]
        bound_at = value["bound_at"]
        if bound_at is not None and (
            isinstance(bound_at, bool)
            or not isinstance(bound_at, (int, float))
        ):
            cls._snapshot_error({"bound_at": bound_at})
        return {
            "target": value["target"],
            "host": value["host"],
            "verdict": value["verdict"],
            "reason": value["reason"],
            "scope": value["scope"],
            "addresses": copy.deepcopy(addresses),
            "bound_at": bound_at,
        }

    @staticmethod
    def _checked_address(value):
        if not isinstance(value, str):
            raise SsrfError("SSRF_SNAPSHOT_INVALID", {"address": value})
        try:
            return _canonical_address(value)
        except SsrfError as exc:
            raise SsrfError("SSRF_SNAPSHOT_INVALID", exc.detail) from None

    def restore(self, state):
        try:
            if not isinstance(state, dict):
                self._snapshot_error()
            required = {
                "version", "schemes", "allow_hosts", "deny_cidrs",
                "max_redirects", "targets", "chains", "bindings", "stats",
            }
            if not required.issubset(state):
                self._snapshot_error()
            if (
                isinstance(state["version"], bool)
                or not isinstance(state["version"], int)
                or state["version"] != 1
            ):
                self._snapshot_error({"version": state["version"]})

            schemes_value = state["schemes"]
            if not isinstance(schemes_value, (list, tuple)):
                self._snapshot_error({"schemes": schemes_value})
            if any(not isinstance(item, str) for item in schemes_value):
                self._snapshot_error({"schemes": schemes_value})
            schemes = tuple(item.strip().lower() for item in schemes_value)
            if any(not item for item in schemes):
                self._snapshot_error({"schemes": schemes_value})

            allow_value = state["allow_hosts"]
            if not isinstance(allow_value, (list, tuple)):
                self._snapshot_error({"allow_hosts": allow_value})
            allow_hosts = set()
            for host in allow_value:
                allow_hosts.add(self._normalize_host(host))

            deny_value = state["deny_cidrs"]
            if not isinstance(deny_value, (list, tuple)):
                self._snapshot_error({"deny_cidrs": deny_value})
            deny_cidrs = []
            deny_networks = []
            for cidr in deny_value:
                if not isinstance(cidr, str):
                    self._snapshot_error({"deny_cidr": cidr})
                network = ipaddress.ip_network(cidr, strict=False)
                text = str(network)
                if text not in deny_cidrs:
                    deny_cidrs.append(text)
                    deny_networks.append(network)

            max_redirects = state["max_redirects"]
            if (
                isinstance(max_redirects, bool)
                or not isinstance(max_redirects, int)
                or max_redirects < 0
            ):
                self._snapshot_error({"max_redirects": max_redirects})

            targets_value = state["targets"]
            if not isinstance(targets_value, (list, tuple)):
                self._snapshot_error({"targets": targets_value})
            targets = []
            for target in targets_value:
                if not isinstance(target, str):
                    self._snapshot_error({"target": target})
                targets.append(target)
            if len(targets) != len(set(targets)):
                self._snapshot_error({"targets": targets_value})

            chains_value = state["chains"]
            if not isinstance(chains_value, dict):
                self._snapshot_error({"chains": chains_value})
            chains = {}
            for origin, hops in chains_value.items():
                if not isinstance(origin, str) or not isinstance(hops, (list, tuple)):
                    self._snapshot_error({"chains": chains_value})
                if not hops:
                    self._snapshot_error({"chain": origin})
                restored_hops = [self._restore_record(hop) for hop in hops]
                if restored_hops[0]["target"] != origin:
                    self._snapshot_error({"chain": origin})
                targets_in_chain = [hop["target"] for hop in restored_hops]
                if len(targets_in_chain) != len(set(targets_in_chain)):
                    self._snapshot_error({"chain": origin})
                chains[origin] = restored_hops
            if set(chains) != set(targets):
                self._snapshot_error({"targets": targets_value})

            bindings_value = state["bindings"]
            if not isinstance(bindings_value, dict):
                self._snapshot_error({"bindings": bindings_value})
            hosts_value = bindings_value.get("hosts")
            decisions_value = bindings_value.get("targets")
            if not isinstance(hosts_value, dict) or not isinstance(
                decisions_value, dict
            ):
                self._snapshot_error({"bindings": bindings_value})

            host_bindings = {}
            for host, binding in hosts_value.items():
                if not isinstance(host, str) or not isinstance(binding, dict):
                    self._snapshot_error({"binding": binding})
                if not {"host", "addresses", "bound_at"}.issubset(binding):
                    self._snapshot_error({"binding": binding})
                normalized_host = self._normalize_host(host)
                if binding["host"] != normalized_host:
                    self._snapshot_error({"binding": binding})
                addresses = binding["addresses"]
                if not isinstance(addresses, (list, tuple)) or not addresses:
                    self._snapshot_error({"binding": binding})
                checked_addresses = [
                    self._checked_address(item) for item in addresses
                ]
                bound_at = binding["bound_at"]
                if bound_at is not None and (
                    isinstance(bound_at, bool)
                    or not isinstance(bound_at, (int, float))
                ):
                    self._snapshot_error({"bound_at": bound_at})
                host_bindings[normalized_host] = {
                    "host": normalized_host,
                    "addresses": checked_addresses,
                    "bound_at": bound_at,
                }

            decisions = {}
            for target, record in decisions_value.items():
                if not isinstance(target, str):
                    self._snapshot_error({"decision": target})
                decisions[target] = self._restore_record(record)

            stats_value = state["stats"]
            if not isinstance(stats_value, dict):
                self._snapshot_error({"stats": stats_value})
            if not set(_STAT_KEYS).issubset(stats_value):
                self._snapshot_error({"stats": stats_value})
            stats = {}
            for key in _STAT_KEYS:
                value = stats_value[key]
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    self._snapshot_error({"stats": stats_value})
                stats[key] = value
        except Exception as exc:
            if isinstance(exc, SsrfError) and exc.code == "SSRF_SNAPSHOT_INVALID":
                raise
            raise SsrfError("SSRF_SNAPSHOT_INVALID") from exc

        with self._lock:
            self.schemes = schemes
            self.max_redirects = max_redirects
            self._allow_hosts = allow_hosts
            self._deny_cidrs = deny_cidrs
            self._deny_networks = deny_networks
            self._targets = targets
            self._chains = chains
            self._host_bindings = host_bindings
            self._decisions = decisions
            stats["restores"] += 1
            self._stats = stats

    def stats(self):
        with self._lock:
            return dict(self._stats)
