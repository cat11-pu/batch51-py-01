"""Render target load/store operation planning and bandwidth accounting."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class LoadOpError(ValueError):
    """Raised when a load/store plan is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TargetState:
    """Declared render target."""

    name: str
    bytes_per_frame: int
    samples: int
    persistent: bool
    external_read: bool


@dataclass(frozen=True)
class UsePlan:
    """One decided use of a render target inside the frame."""

    target: str
    pass_index: int
    kind: str
    load_op: str
    store_op: str
    resolve: bool
    sampled: bool


class LoadOpOptimizer:
    """Pick clear/load/discard per render target use and account the saved bandwidth."""

    def __init__(self, *, max_targets: int = 64,
                 max_uses_per_target: int = 64) -> None:
        self._lock = threading.RLock()
        self._config = {"max_targets": max_targets,
                        "max_uses_per_target": max_uses_per_target}
        self._targets: dict = {}
        self._uses: dict = {}
        self._counters: dict = {
            "targets": 0,
            "uses": 0,
            "plans": 0,
            "rejected": 0,
        }

    def declare_target(self, name: str, *, bytes_per_frame: int,
                       samples: int = 1, persistent: bool = False,
                       external_read: bool = False) -> TargetState:
        raise NotImplementedError

    def declare_external_read(self, name: str) -> TargetState:
        raise NotImplementedError

    def declare_use(self, target: str, pass_index: int, kind: str, *,
                    resolve: bool = False, sampled: bool = False) -> None:
        raise NotImplementedError

    def plan(self) -> tuple:
        raise NotImplementedError

    def load_op_of(self, target: str, pass_index: int) -> str:
        raise NotImplementedError

    def store_op_of(self, target: str, pass_index: int) -> str:
        raise NotImplementedError

    def bandwidth_saved(self) -> dict:
        raise NotImplementedError

    def target_state(self, name: str) -> TargetState:
        raise NotImplementedError

    def uses_of(self, target: str) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
