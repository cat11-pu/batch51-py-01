"""路径穿越探测：编码阶梯、客户端与服务端归一化差异及基线对照判据。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

MAX_REQUESTS = 64
MAX_VARIANTS = 128
MAX_DEPTH = 4
LENGTH_THRESHOLD = 16
DEFAULT_TARGET_FILE = "etc/passwd"
SIGNATURE = "root:x:0:0"

LAYERS = ("plain", "backslash", "url-encoded", "double-encoded", "overlong-utf8",
          "semicolon", "dot-truncation", "unicode-normalized", "absolute")

LAYER_TEMPLATES = {
    "plain": "../",
    "backslash": "..\\",
    "url-encoded": "..%2f",
    "double-encoded": "%252e%252e%252f",
    "overlong-utf8": "%c0%ae%c0%ae%2f",
    "semicolon": "..;/",
    "dot-truncation": ".../",
    "unicode-normalized": "%ef%bc%8e%ef%bc%8e%2f",
}

WAF_MARKERS = ("access denied", "blocked by waf")


class ProbeError(ValueError):
    """变体生成、发送或判定被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Variant:
    layer: str
    raw: str
    key: str


@dataclass(frozen=True)
class Response:
    status: int
    body: str


@dataclass(frozen=True)
class ProbeRecord:
    layer: str
    raw: str
    key: str
    baseline_status: int
    baseline_length: int
    baseline_body: str
    variant_status: int
    variant_body: str


@dataclass(frozen=True)
class Verdict:
    key: str
    layer: str
    hit: bool
    reason: str


def variant_key(raw, *, platform="posix"):
    """变体的去重键：posix 下就是原串，windows 下按段剥离尾随点与空格。"""
    raise NotImplementedError


def baseline_path(target, length):
    """构造与变体等长的正常路径，用于基线对照。"""
    raise NotImplementedError


class PathTraversalProber:
    """生成穿越变体、对照基线并给出命中判定。"""

    def __init__(self, *, transport=None, max_requests=MAX_REQUESTS,
                 max_depth=MAX_DEPTH, signature=SIGNATURE,
                 threshold=LENGTH_THRESHOLD):
        self.transport = transport
        self.max_requests = max_requests
        self.max_depth = max_depth
        self.signature = signature
        self.threshold = threshold
        self._baselines = {}
        self._probed = []
        self._counters = {"generated": 0, "sent": 0, "requests": 0, "hits": 0}
        self._lock = threading.RLock()

    def generate_variants(self, depth=2, *, target_file=DEFAULT_TARGET_FILE):
        raise NotImplementedError

    def dedupe(self, variants, *, platform="posix"):
        raise NotImplementedError

    def send(self, target, variants):
        raise NotImplementedError

    def judge(self, records):
        raise NotImplementedError

    def report(self, verdicts):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
