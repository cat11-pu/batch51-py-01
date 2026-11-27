"""Speed ramp planning: keyframed playback rates, source mapping and stretch plans."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SpeedRampError(ValueError):
    """Raised when a speed ramp request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SpeedKeyframe:
    """One authored speed control point on the output timeline."""

    output_frame: int
    speed: float


@dataclass(frozen=True)
class AudioStretchSegment:
    """One pitch preserving stretch window aligned with a video segment."""

    index: int
    output_start: int
    output_frames: int
    source_start: int
    source_frames: int
    ratio: float
    fade_frames: int


@dataclass(frozen=True)
class RampIssue:
    """One advisory or blocking problem found on the authored curve."""

    code: str
    at_frame: int


class SpeedRampPlanner:
    """Map full length output frames back to source frames for a ramp plan."""

    def __init__(self, *, frame_rate: int = 30, max_speed: float = 8.0,
                 max_keyframes: int = 32, max_accel: float = 0.5,
                 max_output_frames: int = 100000) -> None:
        self.frame_rate = frame_rate
        self.max_speed = max_speed
        self.max_keyframes = max_keyframes
        self.max_accel = max_accel
        self.max_output_frames = max_output_frames
        self._lock = threading.RLock()
        self._keyframes: tuple[SpeedKeyframe, ...] = ()
        self._source_frames: int | None = None
        self._plans = 0

    def set_source_duration(self, frames: int) -> int:
        raise NotImplementedError

    def set_keyframes(self, keyframes) -> int:
        raise NotImplementedError

    def keyframes(self) -> tuple[SpeedKeyframe, ...]:
        raise NotImplementedError

    def speed_at(self, output_frame: int) -> float:
        raise NotImplementedError

    def map_time(self, output_frame: int) -> int:
        raise NotImplementedError

    def unmap_time(self, source_frame: int) -> int:
        raise NotImplementedError

    def output_frames(self) -> int:
        raise NotImplementedError

    def frame_budget(self) -> dict:
        raise NotImplementedError

    def audio_segments(self) -> tuple[AudioStretchSegment, ...]:
        raise NotImplementedError

    def validate(self) -> tuple[RampIssue, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
