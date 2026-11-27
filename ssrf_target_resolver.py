"""SSRF 目标归一、范围判定与跳转逐跳复核。"""

from __future__ import annotations

import ipaddress
import threading

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


class SsrfError(ValueError):
    """目标归一或判定被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SsrfTargetResolver:
    """把用户提交的地址归一成可判定目标，并在判定时点绑定解析结果。"""

    def __init__(self, *, schemes=DEFAULT_SCHEMES, allow_hosts=(), deny_cidrs=(),
                 max_redirects=3, max_targets=64):
        self.schemes = tuple(str(item).lower() for item in schemes)
        self.max_redirects = max_redirects
        self.max_targets = max_targets
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

    def normalize(self, raw):
        raise NotImplementedError

    def classify_scope(self, address):
        raise NotImplementedError

    def bind_resolution(self, host, addresses, *, now=None):
        raise NotImplementedError

    def decide(self, raw, *, addresses=None, now=None):
        raise NotImplementedError

    def authorize_request(self, target, *, addresses=None, now=None):
        raise NotImplementedError

    def follow_redirect(self, target, location, *, now=None):
        raise NotImplementedError

    def hops_for(self, target):
        raise NotImplementedError

    def allow_host(self, host):
        raise NotImplementedError

    def allowed_hosts(self):
        raise NotImplementedError

    def targets(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
