"""GPU frame capture scheduler: pre-roll ring buffer, async export, privacy masks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CaptureError(ValueError):
    """Raised when a capture operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FrameMeta:
    """One frame accepted by the ring buffer."""

    frame_no: int
    payload_size: int
    captured: tuple
    added_at: str | None


@dataclass(frozen=True)
class CaptureTicket:
    """Handle for one capture request."""

    capture_id: str
    reason: str
    status: str
    trigger_frame: int
    first_frame: int
    last_frame: int


@dataclass(frozen=True)
class CaptureRecord:
    """Export result of one finalized capture."""

    capture_id: str
    reason: str
    trigger_frame: int
    first_frame: int
    last_frame: int
    frame_count: int
    bytes_total: int
    masked_regions: tuple
    masks_applied: int
    finalized_at: str | None


class FrameCaptureScheduler:
    """Keep a short pre-roll of frames and export the window around a trigger."""

    def __init__(self, *, ring_size: int = 64, pre_frames: int = 30,
                 post_frames: int = 10, max_active: int = 2,
                 min_interval_frames: int = 0,
                 max_bytes: int = 8_000_000) -> None:
        self._lock = threading.RLock()
        self._config = {
            "ring_size": ring_size,
            "pre_frames": pre_frames,
            "post_frames": post_frames,
            "max_active": max_active,
            "min_interval_frames": min_interval_frames,
            "max_bytes": max_bytes,
        }
        self._ring: dict = {}
        self._order: list = []
        self._captures: dict = {}
        self._claimed: set = set()
        self._masks: list = []
        self._counters: dict = {
            "frames": 0,
            "captures": 0,
            "finalized": 0,
            "rejected": 0,
            "dropped_frames": 0,
            "merged": 0,
            "masks": 0,
        }

    def arm(self, *, pre_frames: int | None = None,
            post_frames: int | None = None,
            ring_size: int | None = None) -> dict:
        raise NotImplementedError

    def on_frame(self, frame_no: int, *, payload_size: int = 1024,
                 now: str | None = None) -> FrameMeta:
        raise NotImplementedError

    def trigger(self, reason: str, *, frame_no: int | None = None,
                now: str | None = None) -> CaptureTicket:
        raise NotImplementedError

    def finalize(self, capture_id: str, *,
                 now: str | None = None) -> CaptureRecord:
        raise NotImplementedError

    def mask_region(self, *, x: int, y: int, width: int, height: int) -> int:
        raise NotImplementedError

    def capture_of(self, capture_id: str) -> CaptureTicket:
        raise NotImplementedError

    def captures(self) -> tuple:
        raise NotImplementedError

    def active_captures(self) -> tuple:
        raise NotImplementedError

    def ring_frames(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
