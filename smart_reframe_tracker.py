"""Vertical reframe: subject tracking, crop-window keyframes and render planning."""

from __future__ import annotations

import threading
from dataclasses import dataclass


REFRAME_SNAPSHOT_VERSION = 1


class ReframeError(ValueError):
    """Raised when a reframe operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SourceInfo:
    """Source frame geometry and the derived crop width."""

    width: int
    height: int
    window_width: int


@dataclass(frozen=True)
class TrackSample:
    """One observation of the tracked subjects."""

    timestamp_ms: int
    subject_id: str | None
    x: int
    y: int
    confidence: float


@dataclass(frozen=True)
class Keyframe:
    """One crop-window keyframe."""

    timestamp_ms: int
    center_x: int


@dataclass(frozen=True)
class Window:
    """Crop window at one timestamp."""

    timestamp_ms: int
    x: int
    width: int
    center: float


class SmartReframeTracker:
    """Track subjects in the source frame and drive the crop window over time."""

    def __init__(self, *, aspect_num: int = 9, aspect_den: int = 16,
                 max_keyframes: int = 64, max_track: int = 1024,
                 max_step_px: int = 64, max_accel_px: int = 32) -> None:
        for name, value in (("aspect_num", aspect_num),
                            ("aspect_den", aspect_den),
                            ("max_keyframes", max_keyframes),
                            ("max_track", max_track),
                            ("max_step_px", max_step_px),
                            ("max_accel_px", max_accel_px)):
            if not isinstance(value, int) or value <= 0:
                raise ReframeError("RF_INVALID_SETTING", name)
        self.aspect_num = aspect_num
        self.aspect_den = aspect_den
        self.max_keyframes = max_keyframes
        self.max_track = max_track
        self.max_step_px = max_step_px
        self.max_accel_px = max_accel_px
        self._lock = threading.RLock()
        self._source: SourceInfo | None = None
        self._samples: list = []
        self._keyframes: dict = {}
        self._subjects: set = set()
        self._confidence = 1.0
        self._counters = {
            "lost": 0,
            "dropped": 0,
            "plans": 0,
            "rejected": 0,
        }

    def set_source(self, width: int, height: int) -> SourceInfo:
        """Fix the source geometry and derive the crop width."""
        raise NotImplementedError("set_source")

    def observe(self, timestamp_ms: int, subjects) -> TrackSample:
        """Record one observation of the tracked subjects."""
        raise NotImplementedError("observe")

    def primary_at(self, timestamp_ms: int):
        """Primary subject at or before the timestamp, or None."""
        raise NotImplementedError("primary_at")

    def confidence_at(self, timestamp_ms: int) -> float:
        """Tracking confidence at or before the timestamp."""
        raise NotImplementedError("confidence_at")

    def add_keyframe(self, timestamp_ms: int, center_x: int) -> Keyframe:
        """Insert a crop-window keyframe."""
        raise NotImplementedError("add_keyframe")

    def remove_keyframe(self, timestamp_ms: int) -> Keyframe:
        """Delete a crop-window keyframe and return it."""
        raise NotImplementedError("remove_keyframe")

    def keyframes(self) -> tuple:
        """Keyframes in ascending time order."""
        raise NotImplementedError("keyframes")

    def window_at(self, timestamp_ms: int) -> Window:
        """Crop window at the timestamp."""
        raise NotImplementedError("window_at")

    def render_plan(self, *, start_ms: int = 0, end_ms: int | None = None,
                    step_ms: int = 40) -> tuple:
        """Crop window for every render step in the range."""
        raise NotImplementedError("render_plan")

    def snapshot(self) -> dict:
        """Deep copy of tracker state."""
        raise NotImplementedError("snapshot")

    def restore(self, state: dict) -> None:
        """Replace tracker state with a snapshot."""
        raise NotImplementedError("restore")

    def stats(self) -> dict:
        """Current counters."""
        raise NotImplementedError("stats")
