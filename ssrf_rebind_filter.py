"""出站 URL 的归一、地址范围判定、解析复核与跳转链审计。

判定结果统一折算成 EgressDecision：能给出原因码的一律返回 deny 决策，
只有形状层面无法归一（缺主机、端口越界、scheme 不在允许列表）才在
normalize() 里抛 SsrfError。
"""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass
from typing import Any, Callable

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

STAT_KEYS = ("allowed", "denied", "hops", "redirects", "restores")


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


class SsrfRebindFilter:
    """维护主机白名单、解析绑定与跳转链，对每次出站给出可审计结论。"""

    def __init__(self, *, schemes=DEFAULT_SCHEMES, allow_hosts=(), allow_ports=(80, 443),
                 max_redirects: int = 5, max_hops: int = 8,
                 resolver: Callable[[str], tuple[str, ...]] | None = None,
                 allowed_cidrs=()) -> None:
        self.schemes = tuple(str(item).lower() for item in schemes)
        self.allow_ports = tuple(int(item) for item in allow_ports)
        self.max_redirects = max_redirects
        self.max_hops = max_hops
        self.resolver = resolver
        self.allowed_cidrs = tuple(str(item) for item in allowed_cidrs)
        self._lock = threading.RLock()
        self._allow_hosts: list[str] = [str(item) for item in allow_hosts]
        self._bindings: dict[str, tuple[str, ...]] = {}
        self._audit: list[dict] = []
        self._stats = {name: 0 for name in STAT_KEYS}

    def normalize(self, raw: str) -> Target:
        raise NotImplementedError

    def classify(self, address: str) -> str:
        raise NotImplementedError

    def bind_resolution(self, host: str, addresses, *, now: int | None = None) -> tuple[str, ...]:
        raise NotImplementedError

    def decide(self, raw: str, *, now: int | None = None) -> EgressDecision:
        raise NotImplementedError

    def authorize(self, target: Target, *, now: int | None = None) -> EgressDecision:
        raise NotImplementedError

    def follow_redirect(self, decision: EgressDecision, location: str, *,
                        now: int | None = None) -> EgressDecision:
        raise NotImplementedError

    def allow_host(self, host: str) -> None:
        raise NotImplementedError

    def allowed_hosts(self) -> tuple[str, ...]:
        raise NotImplementedError

    def audit_log(self) -> tuple[dict, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
