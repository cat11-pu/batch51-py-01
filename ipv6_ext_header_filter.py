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
        raise NotImplementedError

    def remove_interface(self, iface: str) -> bool:
        raise NotImplementedError

    def policy_for(self, iface: str | None) -> dict:
        raise NotImplementedError

    def parse_chain(self, raw) -> tuple[ExtHeader, ...]:
        raise NotImplementedError

    def evaluate(self, packet, iface: str | None = None) -> Verdict:
        raise NotImplementedError

    def strip(self, packet, iface: str | None = None) -> tuple[ExtHeader, ...]:
        raise NotImplementedError

    def verdict_for(self, packet_id: str) -> Verdict | None:
        raise NotImplementedError

    def audit_trail(self, limit: int | None = None) -> tuple[Verdict, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError
