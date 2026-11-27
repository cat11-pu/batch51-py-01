"""Late-latch reprojection for a stereo compositor: prediction, depth reprojection, drop compensation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1
EYES = ("left", "right")


class ReprojectError(ValueError):
    """Raised when a reprojection request cannot be served."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Pose:
    frame: int
    eye: str
    position: tuple[float, float, float]
    orientation: tuple[float, float, float, float]
    timestamp_ms: float


@dataclass(frozen=True)
class HorizonPlan:
    requested_ms: float
    used_ms: float
    clipped: bool


@dataclass(frozen=True)
class ReprojectionPlan:
    frame: int
    eye: str
    predicted_at_ms: float
    used_horizon_ms: float
    total_samples: int
    low_confidence: int
    reprojected: bool


class LateLatchReprojector:
    """Reproject rendered frames onto the latest pose at composite time."""

    def __init__(self, *, min_horizon_ms: float = 0.0,
                 max_horizon_ms: float = 40.0, focal: float = 900.0,
                 depth_epsilon: float = 1e-3) -> None:
        self.min_horizon_ms = min_horizon_ms
        self.max_horizon_ms = max_horizon_ms
        self.focal = focal
        self.depth_epsilon = depth_epsilon
        self._lock = threading.RLock()

    def submit_pose(self, frame, *, eye, position, orientation, timestamp_ms):
        raise NotImplementedError

    def pose_for(self, frame, *, eye):
        raise NotImplementedError

    def prediction_horizon(self, *, render_time_ms, compose_time_ms):
        raise NotImplementedError

    def reproject(self, frame, *, eye, depths, rotation_only=False):
        raise NotImplementedError

    def late_latch(self, frame, *, compose_time_ms, depths):
        raise NotImplementedError

    def mark_low_confidence(self, frame, *, eye, count):
        raise NotImplementedError

    def frame_state(self, frame, *, eye=None):
        raise NotImplementedError

    def drop_frame(self, frame):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
