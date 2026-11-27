"""CSP 策略求值：指令回退链、nonce 与 hash 覆盖以及多份策略的交集判定。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

MAX_POLICY_CHARS = 4096
MAX_DIRECTIVES = 32
MAX_POLICIES = 8

MODES = ("enforce", "report-only")

KIND_CHAINS = {
    "script": ("script-src-elem", "script-src", "default-src"),
    "style": ("style-src-elem", "style-src", "default-src"),
    "img": ("img-src", "default-src"),
    "connect": ("connect-src", "default-src"),
    "font": ("font-src", "default-src"),
    "media": ("media-src", "default-src"),
}

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


class CspError(ValueError):
    """策略解析、求值或快照操作被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Policy:
    name: str
    mode: str
    directives: dict


@dataclass(frozen=True)
class PolicySet:
    enforce: tuple
    report_only: tuple
    digest: str


@dataclass(frozen=True)
class Violation:
    policy: str
    directive: str
    blocked_uri: str
    reason: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    directive: object
    matched: object
    violations: tuple
    blocked_by: tuple


def effective_directive(directives, kind):
    """按 kind 的回退链返回第一个存在的指令名，全部缺失返回 None。"""
    raise NotImplementedError


def source_matches(expression, url, *, origin=""):
    """判定单条来源表达式是否匹配目标 URL。"""
    raise NotImplementedError


class CspPolicyEvaluator:
    """解析并求值 enforce 与 report-only 策略。"""

    def __init__(self, *, origin="", max_policies=MAX_POLICIES):
        self.origin = origin
        self.max_policies = max_policies
        self.revision = 0
        self._policies = {}
        self._counters = {"evaluated": 0, "allowed": 0, "blocked": 0, "violations": 0}
        self._lock = threading.RLock()

    def parse_policy(self, text, *, mode="enforce", name="policy"):
        raise NotImplementedError

    def register_policy(self, policy):
        raise NotImplementedError

    def evaluate(self, policy, *, url, kind="script", nonce=None, hashes=()):
        raise NotImplementedError

    def merge_policies(self, policies):
        raise NotImplementedError

    def check_nonce(self, policy, *, directive, nonce):
        raise NotImplementedError

    def report(self, decisions):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
