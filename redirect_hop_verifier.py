"""跳转参数校验：目标归一、协议相对变体判定与白名单逐跳比对。"""

from __future__ import annotations

import threading

DEFAULT_SCHEMES = ("https", "http")
DEFAULT_PORTS = {"http": 80, "https": 443}


class RedirectError(ValueError):
    """跳转目标被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class RedirectHopVerifier:
    """先归一目标，再按白名单逐跳比对整条跳转链。"""

    def __init__(self, *, allowed_hosts=(), allowed_schemes=DEFAULT_SCHEMES, max_hops=4):
        self.allowed_schemes = tuple(str(item).lower() for item in allowed_schemes)
        self.max_hops = max_hops
        self._lock = threading.RLock()
        self._stats = {
            "verifications": 0,
            "hops_checked": 0,
            "hop_denied": 0,
            "chains_failed": 0,
            "deduped": 0,
            "restores": 0,
        }

    def allow_host(self, host):
        raise NotImplementedError

    def allowed_hosts(self):
        raise NotImplementedError

    def normalize_target(self, target, *, base=None):
        raise NotImplementedError

    def check_scheme(self, target):
        raise NotImplementedError

    def is_allowed(self, target):
        raise NotImplementedError

    def verify_hops(self, targets):
        raise NotImplementedError

    def hop_chain(self):
        raise NotImplementedError

    def dedupe(self, targets):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
