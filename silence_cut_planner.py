"""Silence cut planning: energy and zero-crossing detection, gap merging, fades."""

from __future__ import annotations

import threading
from typing import NamedTuple


SILENCE_SNAPSHOT_VERSION = 1


class SilenceError(ValueError):
    """Raised when a silence-planning operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class FrameRange(NamedTuple):
    """Half-open millisecond range."""

    start_ms: int
    end_ms: int


class Segment(NamedTuple):
    """One kept piece of audio with its fades."""

    start_ms: int
    end_ms: int
    fade_in_ms: int
    fade_out_ms: int


class CutPlan(NamedTuple):
    """Result of one planning pass."""

    kept: tuple
    cuts: tuple
    removed_ms: int


class SilenceCutPlanner:
    """Detect silence from per-frame energy and zero-crossing rate, then plan cuts."""

    def __init__(self, *, sample_rate: int = 48000, frame_ms: int = 20,
                 silence_db: float = -45.0, zcr_max: float = 0.35,
                 min_silence_ms: int = 300, min_keep_ms: int = 200,
                 fade_ms: int = 10, max_ranges: int = 1024,
                 max_frames: int = 100000) -> None:
        for name, value in (("sample_rate", sample_rate), ("frame_ms", frame_ms),
                            ("min_silence_ms", min_silence_ms),
                            ("min_keep_ms", min_keep_ms), ("fade_ms", fade_ms),
                            ("max_ranges", max_ranges), ("max_frames", max_frames)):
            if not isinstance(value, int) or value <= 0:
                raise SilenceError("SIL_INVALID_ARG", name)
        if not isinstance(silence_db, (int, float)):
            raise SilenceError("SIL_INVALID_ARG", "silence_db")
        if not isinstance(zcr_max, (int, float)) or not 0.0 <= zcr_max <= 1.0:
            raise SilenceError("SIL_INVALID_ARG", "zcr_max")
        self.sample_rate = sample_rate
        self.frame_ms = frame_ms
        self.silence_db = float(silence_db)
        self.zcr_max = float(zcr_max)
        self.min_silence_ms = min_silence_ms
        self.min_keep_ms = min_keep_ms
        self.fade_ms = fade_ms
        self.max_ranges = max_ranges
        self.max_frames = max_frames
        self._lock = threading.RLock()
        self._frames: list = []
        self._ranges: list = []
        self._cuts: tuple = ()
        self._merged = 0
        self._counters = {
            "plans": 0,
            "rejected": 0,
        }

    def analyze(self, frames, *, sample_rate: int | None = None) -> int:
        """Append (rms_db, zcr) frames and return the cumulative frame count."""
        raise NotImplementedError("analyze")

    def silence_ranges(self) -> tuple:
        """Detected silence ranges, ascending and non-overlapping."""
        raise NotImplementedError("silence_ranges")

    def voiced_ranges(self) -> tuple:
        """Complement of the silence ranges over the analysed window."""
        raise NotImplementedError("voiced_ranges")

    def merge_gaps(self, min_keep_ms: int | None = None) -> int:
        """Merge silence ranges separated by a shorter voiced gap."""
        raise NotImplementedError("merge_gaps")

    def plan_cuts(self, *, pad_lead_ms: int = 0,
                  pad_tail_ms: int = 0) -> CutPlan:
        """Build the keep list and the cut list for the current analysis."""
        raise NotImplementedError("plan_cuts")

    def apply_padding(self, pad_lead_ms: int, pad_tail_ms: int) -> tuple:
        """Grow every cut by the given padding, clamped and disjoint."""
        raise NotImplementedError("apply_padding")

    def cuts(self) -> tuple:
        """Cut ranges used by the last planning pass."""
        raise NotImplementedError("cuts")

    def preview(self) -> dict:
        """Source duration, output duration, kept and cut ranges."""
        raise NotImplementedError("preview")

    def snapshot(self) -> dict:
        """Deep copy of planner state."""
        raise NotImplementedError("snapshot")

    def restore(self, state: dict) -> None:
        """Replace planner state with a snapshot."""
        raise NotImplementedError("restore")

    def stats(self) -> dict:
        """Current counters."""
        raise NotImplementedError("stats")
