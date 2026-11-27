"""Throttle bypass prober: path variants, counter bucket verdicts, probe budget."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ThrottleError(ValueError):
    """Raised when a prober operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Variant:
    variant_id: str
    endpoint_id: str
    kind: str
    raw_path: str
    query: str
    normalized: str


@dataclass(frozen=True)
class CounterVerdict:
    variant_id: str
    counter_key: str
    verdict: str


@dataclass(frozen=True)
class WindowReport:
    endpoint_id: str
    window_index: int
    counts: dict
    exhausted: tuple[str, ...]
    total: int


@dataclass(frozen=True)
class ReserveResult:
    allowed: bool
    reason: str
    total_left: int
    window_left: int
    window_index: int


class ThrottleBypassProber:
    """Plan endpoint variants and judge whether they share a rate-limit counter."""

    def __init__(self, *, total_budget: int = 24, window_rate: int = 4,
                 window_seconds: int = 10) -> None:
        self.total_budget = total_budget
        self.window_rate = window_rate
        self.window_seconds = window_seconds
        self._lock = threading.RLock()

    def add_endpoint(self, endpoint_id: str, *, path: str,
                     params: tuple = ()) -> None:
        raise NotImplementedError

    def remove_endpoint(self, endpoint_id: str) -> bool:
        raise NotImplementedError

    def plan_variants(self, endpoint_id: str) -> tuple[Variant, ...]:
        raise NotImplementedError

    def dedupe(self, variants) -> tuple[Variant, ...]:
        raise NotImplementedError

    def classify_counter(self, endpoint_id: str, observations, *,
                         decode_before_route: bool = False) -> tuple[CounterVerdict, ...]:
        raise NotImplementedError

    def measure_window(self, endpoint_id: str, window_index: int,
                       responses) -> WindowReport:
        raise NotImplementedError

    def compare_windows(self, first: WindowReport,
                        second: WindowReport) -> tuple[str, ...]:
        raise NotImplementedError

    def conclude(self, endpoint_id: str, reports) -> dict:
        raise NotImplementedError

    def reserve_probe(self, endpoint_id: str, *, at: int = 0) -> ReserveResult:
        raise NotImplementedError

    def describe_endpoint(self, endpoint_id: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
