"""依赖名称相似度索引：同形字归并、阈值分级与增量维护。"""

from __future__ import annotations

import threading

HOMOGLYPHS = {
    "\u0430": "a",  # а cyrillic
    "\u0435": "e",  # е cyrillic
    "\u043e": "o",  # о cyrillic
    "\u0440": "p",  # р cyrillic
    "\u0441": "c",  # с cyrillic
    "\u0445": "x",  # х cyrillic
    "\u0456": "i",  # і cyrillic
    "\u03bf": "o",  # ο greek
    "\u03b1": "a",  # α greek
    "\u0261": "g",  # ɡ latin script g
}

KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

LEVEL_EXACT = "exact"
LEVEL_CRITICAL = "critical"
LEVEL_HIGH = "high"
LEVEL_NEAR = "near"
LEVEL_FAR = "far"

MAX_NAME_LENGTH = 64


class TyposquatError(ValueError):
    """索引操作被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PackageTyposquatIndex:
    """为受关注包名建立相似度索引，按阈值给候选分级。"""

    def __init__(self, *, max_watches=64, high=0.90, near=0.80):
        self.max_watches = max_watches
        self.high = high
        self.near = near
        self._lock = threading.RLock()
        self._stats = {
            "watches": 0,
            "watch_adds": 0,
            "queries": 0,
            "observed": 0,
            "removed": 0,
            "restores": 0,
        }

    def add_watch(self, name, *, ecosystem="pypi", now=None):
        raise NotImplementedError

    def remove_watch(self, name):
        raise NotImplementedError

    def watches(self):
        raise NotImplementedError

    def similarity(self, left, right):
        raise NotImplementedError

    def classify(self, incoming):
        raise NotImplementedError

    def candidate(self, incoming, *, limit=3):
        raise NotImplementedError

    def observe(self, incoming, *, now=None):
        raise NotImplementedError

    def history_for(self, watched):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
