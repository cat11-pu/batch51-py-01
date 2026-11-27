"""IPv6 extension header chain validation for an edge forwarder."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
HEADER_KINDS = ("hop", "dest", "routing", "fragment", "ah", "esp")
DEFAULT_POLICY = {
    "allow_hop_by_hop": True,
    "hop_options": ("pad1", "router-alert"),
    "dest_options": ("pad1", "padn"),
    "routing_types": (1, 2, 3),
    "strip_hop_by_hop": False,
}


class ExtHeaderError(ValueError):
    """Raised when a packet or policy cannot be processed at all."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ExtHeader:
    index: int
    kind: str
    length: int
    options: tuple[str, ...]
    routing_type: int | None


@dataclass(frozen=True)
class Verdict:
    packet_id: str
    action: str
    reason: str
    header_index: int | None
    chain_length: int


class ExtHeaderFilter:
    """Parse an IPv6 extension header chain and decide forward, strip or drop."""

    def __init__(self, *, max_chain_length: int = 256, max_headers: int = 8,
                 audit_limit: int = 64) -> None:
        self.max_chain_length = max_chain_length
        self.max_headers = max_headers
        self.audit_limit = audit_limit
        self._lock = threading.RLock()
        self._policies: dict[str, dict] = {}
        self._audit: list[Verdict] = []
        self._verdicts: dict[str, Verdict] = {}
        self._stats = {
            "forwarded": 0,
            "stripped": 0,
            "dropped": 0,
            "headers_removed": 0,
            "policy_updates": 0,
        }

    def register_interface(self, iface: str, policy=None) -> dict:
        normalized = self._normalize_policy(policy)
        with self._lock:
            self._policies[iface] = copy.deepcopy(normalized)
            self._stats["policy_updates"] += 1
        return copy.deepcopy(normalized)

    def remove_interface(self, iface: str) -> bool:
        with self._lock:
            if iface not in self._policies:
                return False
            del self._policies[iface]
            return True

    def policy_for(self, iface: str | None) -> dict:
        with self._lock:
            policy = self._policies.get(iface, DEFAULT_POLICY)
            return copy.deepcopy(policy)

    def parse_chain(self, raw) -> tuple[ExtHeader, ...]:
        if not isinstance(raw, list):
            raise ExtHeaderError("EXT_INVALID_PACKET",
                                 {"detail": "headers must be a list"})
        chain = []
        for index, header in enumerate(raw):
            if not isinstance(header, dict) or "kind" not in header \
                    or "length" not in header:
                raise ExtHeaderError("EXT_INVALID_PACKET",
                                     {"detail": f"header {index} missing kind/length"})
            options = header.get("options", ())
            if options is None:
                options = ()
            chain.append(ExtHeader(
                index=index,
                kind=header["kind"],
                length=header["length"],
                options=tuple(options),
                routing_type=header.get("routing_type"),
            ))
        return tuple(chain)

    def evaluate(self, packet, iface: str | None = None) -> Verdict:
        headers = self.parse_chain(self._packet_headers(packet))
        packet_id = packet.get("packet_id") if isinstance(packet, dict) else None
        chain_length = sum(header.length for header in headers)

        if len(headers) > self.max_headers:
            return self._record(packet_id, "drop", "too_many_headers",
                                None, chain_length)
        if chain_length > self.max_chain_length:
            return self._record(packet_id, "drop", "chain_too_long",
                                None, chain_length)

        policy = self.policy_for(iface)
        seen_dest = False
        fragment_seen = False
        esp_index: int | None = None

        for header in headers:
            if esp_index is not None:
                return self._record(packet_id, "drop", "esp_not_last",
                                    esp_index, chain_length)
            kind = header.kind

            if kind == "hop":
                if fragment_seen:
                    return self._record(packet_id, "drop", "hop_after_fragment",
                                        header.index, chain_length)
                if not policy["allow_hop_by_hop"]:
                    if policy["strip_hop_by_hop"]:
                        removed = sum(1 for item in headers if item.kind == "hop")
                        return self._record(packet_id, "strip", "hop_stripped",
                                            header.index, chain_length,
                                            headers_removed=removed)
                    return self._record(packet_id, "drop", "hop_not_allowed",
                                        header.index, chain_length)
                denied = [option for option in header.options
                          if option not in policy["hop_options"]]
                if denied:
                    return self._record(packet_id, "drop", "hop_option_denied",
                                        header.index, chain_length)

            elif kind == "dest":
                if seen_dest:
                    return self._record(packet_id, "drop", "duplicate_dest",
                                        header.index, chain_length)
                seen_dest = True
                denied = [option for option in header.options
                          if option not in policy["dest_options"]]
                if denied:
                    return self._record(packet_id, "drop", "dest_option_denied",
                                        header.index, chain_length)

            elif kind == "routing":
                routing_type = header.routing_type
                if routing_type in (0, 4):
                    return self._record(packet_id, "drop",
                                        "routing_type_reserved",
                                        header.index, chain_length)
                if routing_type not in policy["routing_types"]:
                    return self._record(packet_id, "drop",
                                        "routing_type_denied",
                                        header.index, chain_length)

            elif kind == "fragment":
                fragment_seen = True

            elif kind == "esp":
                esp_index = header.index

        if esp_index is not None and headers[-1].kind != "esp":
            return self._record(packet_id, "drop", "esp_not_last",
                                esp_index, chain_length)

        return self._record(packet_id, "forward", "ok", None, chain_length)

    def strip(self, packet, iface: str | None = None) -> tuple[ExtHeader, ...]:
        headers = self.parse_chain(self._packet_headers(packet))
        policy = self.policy_for(iface)
        if not policy["allow_hop_by_hop"] and policy["strip_hop_by_hop"]:
            return tuple(header for header in headers if header.kind != "hop")
        return tuple(headers)

    def verdict_for(self, packet_id: str) -> Verdict | None:
        with self._lock:
            return self._verdicts.get(packet_id)

    def audit_trail(self, limit: int | None = None) -> tuple[Verdict, ...]:
        with self._lock:
            trail = tuple(self._audit)
        if limit is not None:
            trail = trail[-limit:] if limit > 0 else ()
        return trail

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "policies": copy.deepcopy(self._policies),
                "audit": copy.deepcopy(self._audit),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state) -> None:
        self._validate_snapshot(state)
        with self._lock:
            policies = copy.deepcopy(state["policies"])
            audit = copy.deepcopy(state["audit"])
            stats = copy.deepcopy(state["stats"])
            self._policies = policies
            self._audit = audit[-self.audit_limit:]
            self._verdicts = {
                verdict.packet_id: verdict for verdict in self._audit
            }
            self._stats = stats

    @staticmethod
    def _normalize_policy(policy) -> dict:
        source = policy if isinstance(policy, dict) else {}
        merged = dict(DEFAULT_POLICY)
        for key, default in DEFAULT_POLICY.items():
            if key in source:
                merged[key] = source[key]
        hop_options = tuple(sorted(set(merged["hop_options"])))
        dest_options = tuple(sorted(set(merged["dest_options"])))
        routing_types = tuple(sorted(set(merged["routing_types"])))
        return {
            "allow_hop_by_hop": bool(merged["allow_hop_by_hop"]),
            "hop_options": hop_options,
            "dest_options": dest_options,
            "routing_types": routing_types,
            "strip_hop_by_hop": bool(merged["strip_hop_by_hop"]),
        }

    @staticmethod
    def _packet_headers(packet):
        if not isinstance(packet, dict) or not isinstance(packet.get("headers"), list):
            raise ExtHeaderError("EXT_INVALID_PACKET",
                                 {"detail": "packet headers missing"})
        return packet["headers"]

    def _record(self, packet_id, action, reason, header_index, chain_length,
                headers_removed=0) -> Verdict:
        verdict = Verdict(packet_id=packet_id, action=action, reason=reason,
                          header_index=header_index, chain_length=chain_length)
        with self._lock:
            self._audit.append(verdict)
            if len(self._audit) > self.audit_limit:
                overflow = len(self._audit) - self.audit_limit
                evicted = self._audit[:overflow]
                del self._audit[:overflow]
                for old in evicted:
                    if self._verdicts.get(old.packet_id) is old:
                        del self._verdicts[old.packet_id]
            self._verdicts[packet_id] = verdict
            self._stats[self._STAT_KEYS[action]] += 1
            if headers_removed:
                self._stats["headers_removed"] += headers_removed
        return verdict

    _STAT_KEYS = {
        "forward": "forwarded",
        "strip": "stripped",
        "drop": "dropped",
    }

    @staticmethod
    def _validate_snapshot(state) -> None:
        required = ("version", "policies", "audit", "stats")
        if not isinstance(state, dict) or set(state) != set(required):
            raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                 {"detail": "snapshot keys mismatch"})
        if state["version"] != SNAPSHOT_VERSION:
            raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                 {"detail": "unsupported snapshot version"})
        if not isinstance(state["policies"], dict):
            raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                 {"detail": "policies must be a dict"})
        for iface, policy in state["policies"].items():
            if not isinstance(policy, dict) or set(policy) != set(DEFAULT_POLICY):
                raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                     {"detail": f"bad policy for {iface}"})
        if not isinstance(state["audit"], list):
            raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                 {"detail": "audit must be a list"})
        for verdict in state["audit"]:
            if not isinstance(verdict, Verdict):
                raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                     {"detail": "bad audit entry"})
        stats = state["stats"]
        expected_stats = ("forwarded", "stripped", "dropped",
                          "headers_removed", "policy_updates")
        if not isinstance(stats, dict) or set(stats) != set(expected_stats) \
                or not all(isinstance(value, int) for value in stats.values()):
            raise ExtHeaderError("EXT_SNAPSHOT_INVALID",
                                 {"detail": "bad stats block"})
