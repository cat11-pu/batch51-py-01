"""Cost based motion matching over indexed animation clips."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class MotionError(ValueError):
    """Raised when a clip, an index request or a query is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Frame:
    time_ms: int
    pose: tuple
    trajectory: tuple


@dataclass(frozen=True)
class Candidate:
    clip_id: str
    frame_index: int
    cost: float


@dataclass(frozen=True)
class QueryResult:
    candidates: tuple
    index_version: int


@dataclass(frozen=True)
class IndexReport:
    clips: int
    frames: int
    version: int
    rebuilt: bool


class MotionMatchingIndex:
    """Index clip poses and future trajectories for cheapest frame lookup."""

    def __init__(self, *, pose_weight: float = 1.0,
                 trajectory_weight: float = 1.0,
                 exclusion_window: int = 2) -> None:
        self._lock = threading.RLock()
        self._pose_weight = pose_weight
        self._trajectory_weight = trajectory_weight
        self._exclusion_window = exclusion_window
        self._clips: dict = {}
        self._pose_dim = None
        self._traj_dim = None
        self._traj_len = None
        self._version = 0
        self._built_version = 0
        self._current = None
        self._stats = {"clips": 0, "frames": 0, "builds": 0, "reused": 0,
                       "queries": 0, "commits": 0, "removals": 0,
                       "rejections": 0}

    def add_clip(self, clip_id: str, frames) -> int:
        raise NotImplementedError

    def remove_clip(self, clip_id: str) -> int:
        raise NotImplementedError

    def build_index(self) -> IndexReport:
        raise NotImplementedError

    def query(self, state: dict, *, limit: int = 8) -> QueryResult:
        raise NotImplementedError

    def set_weights(self, pose_weight: float, trajectory_weight: float) -> tuple:
        raise NotImplementedError

    def commit_choice(self, clip_id: str, frame_index: int) -> Candidate:
        raise NotImplementedError

    def current_choice(self) -> tuple | None:
        raise NotImplementedError

    def index_version(self) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
