"""Red team action scheduler: per-asset exclusion, maintenance windows, cancellation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SchedulerError(ValueError):
    """Raised when a scheduler operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Action:
    action_id: str
    asset_id: str
    mode: str
    window_start: int
    window_end: int
    steps: tuple[str, ...]
    state: str
    enqueue_seq: int


@dataclass(frozen=True)
class Grant:
    action_id: str
    asset_id: str
    mode: str
    granted: bool
    reason: str
    started_at: int | None


@dataclass(frozen=True)
class CancelResult:
    action_id: str
    released: bool
    dropped_steps: tuple[str, ...]
    state: str


@dataclass(frozen=True)
class TimelineRow:
    action_id: str
    asset_id: str
    mode: str
    started_at: int
    state: str


class RedteamActionScheduler:
    """Sequence red team actions against shared assets inside maintenance windows."""

    def __init__(self, *, max_actions: int = 32, max_steps: int = 8) -> None:
        self.max_actions = max_actions
        self.max_steps = max_steps
        self._lock = threading.RLock()

    def enqueue(self, action_id: str, asset_id: str, *, mode: str = "destructive",
                window_start: int = 0, window_end: int = 10,
                steps: tuple[str, ...] = ()) -> Action:
        raise NotImplementedError

    def acquire_asset(self, action_id: str, *, at: int = 0) -> Grant:
        raise NotImplementedError

    def release_asset(self, action_id: str) -> bool:
        raise NotImplementedError

    def cancel(self, action_id: str, *, at: int = 0) -> CancelResult:
        raise NotImplementedError

    def dispatch_step(self, action_id: str, step: str) -> tuple[str, ...]:
        raise NotImplementedError

    def steps_for(self, action_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def active_for(self, asset_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def timeline(self) -> tuple[TimelineRow, ...]:
        raise NotImplementedError

    def state_of(self, action_id: str) -> str | None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
