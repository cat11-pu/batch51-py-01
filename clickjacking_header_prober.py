"""Clickjacking header prober: XFO / CSP frame-ancestors evaluation with ancestor chains."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping


class FrameError(ValueError):
    """Raised when a framing probe is refused or malformed."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class HeaderSet:
    url: str
    status: int
    pairs: tuple[tuple[str, str], ...]
    hops: tuple[str, ...]


@dataclass(frozen=True)
class XfoPolicy:
    mode: str
    raw: str
    supported: bool


@dataclass(frozen=True)
class FrameAncestors:
    present: bool
    sources: tuple[str, ...]
    raw: str


@dataclass(frozen=True)
class AncestorChain:
    origins: tuple[str, ...]


@dataclass(frozen=True)
class FrameVerdict:
    status: str
    reason: str
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class Probe:
    url: str
    target: str
    ancestors: AncestorChain
    verdict: FrameVerdict


class ClickjackingHeaderProber:
    """Decide whether a target page can be framed by a chain of ancestor origins."""

    SNAPSHOT_KEYS = frozenset({"version", "probes", "verdicts", "stats"})

    def __init__(
        self,
        *,
        fetcher: Callable[[str], Any],
        max_probes_per_target: int = 4,
        max_redirects: int = 3,
    ) -> None:
        self._fetcher = fetcher
        self.max_probes_per_target = max_probes_per_target
        self.max_redirects = max_redirects
        self._lock = threading.RLock()
        self._target_locks: dict[str, threading.RLock] = {}

    def fetch_headers(self, url: str) -> HeaderSet:
        raise NotImplementedError

    def parse_xfo(self, headers: HeaderSet) -> XfoPolicy:
        raise NotImplementedError

    def parse_frame_ancestors(self, headers: HeaderSet) -> FrameAncestors:
        raise NotImplementedError

    def evaluate(self, url: str, *, ancestors: tuple[str, ...]) -> FrameVerdict:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def probe_count(self, target: str) -> int:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
