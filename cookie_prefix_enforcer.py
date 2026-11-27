"""Cookie 属性组合校验：安全前缀约束、域覆盖判定与同名取舍。"""

from __future__ import annotations

import threading

PREFIX_HOST = "__Host-"
PREFIX_SECURE = "__Secure-"

ACTION_SEND = "send"
ACTION_WITHHOLD = "withhold"
ACTION_REJECT = "reject"

MAX_NAME_LENGTH = 128


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
        self.secure_transport = secure_transport
        self._lock = threading.RLock()
        self._stats = {
            "applied": 0,
            "replaced": 0,
            "rejected": 0,
            "delivered": 0,
            "restores": 0,
        }

    def parse_set_cookie(self, header):
        raise NotImplementedError

    def check_prefix(self, cookie):
        raise NotImplementedError

    def scope_cover(self, cookie, host):
        raise NotImplementedError

    def samesite_combo(self, cookie, *, cross_site=False):
        raise NotImplementedError

    def apply(self, header, *, host, now=None):
        raise NotImplementedError

    def deliver(self, host, path, *, secure=True):
        raise NotImplementedError

    def name_count(self, name):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
