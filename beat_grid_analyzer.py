"""Beat grid analysis: onset detection, tempo estimate, tap overrides, grid segments."""

from __future__ import annotations

import threading
from dataclasses import dataclass


BEAT_SNAPSHOT_VERSION = 1


class BeatError(ValueError):
    """Raised when a beat-grid operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BeatPoint:
    """One point of the automatic beat grid."""

    index: int
    time: float
    bpm: float


@dataclass(frozen=True)
class TapSegment:
    """One manual tap span that overrides the automatic grid."""

    start: float
    end: float
    bpm: float
    anchor: float


@dataclass(frozen=True)
class GridSegment:
    """One constant-tempo piece of the final grid."""

    start: float
    end: float
    bpm: float
    source: str


class BeatGridAnalyzer:
    """Incremental onset analysis and grid assembly for one audio stream."""

    def __init__(self, *, frame_hz: float = 100.0, onset_threshold: float = 0.5,
                 rise_ratio: float = 2.0, max_frames: int = 200000,
                 max_onsets: int = 8192) -> None:
        if not isinstance(frame_hz, (int, float)) or frame_hz <= 0:
            raise BeatError("BEAT_INVALID", "frame_hz")
        if not isinstance(onset_threshold, (int, float)) or onset_threshold < 0:
            raise BeatError("BEAT_INVALID", "onset_threshold")
        if not isinstance(rise_ratio, (int, float)) or rise_ratio < 1:
            raise BeatError("BEAT_INVALID", "rise_ratio")
        if not isinstance(max_frames, int) or max_frames <= 0:
            raise BeatError("BEAT_INVALID", "max_frames")
        if not isinstance(max_onsets, int) or max_onsets <= 0:
            raise BeatError("BEAT_INVALID", "max_onsets")
        self.frame_hz = float(frame_hz)
        self.onset_threshold = float(onset_threshold)
        self.rise_ratio = float(rise_ratio)
        self.max_frames = max_frames
        self.max_onsets = max_onsets
        self._lock = threading.RLock()
        self._frames: list = []
        self._onsets: list = []
        self._taps: list = []
        self._counters = {
            "rejected": 0,
        }

    def feed(self, frames, *, frame_hz: float | None = None) -> int:
        """Append envelope frames and return the cumulative frame count."""
        raise NotImplementedError("feed")

    def onsets(self) -> tuple:
        """Detected onset times in seconds, ascending."""
        raise NotImplementedError("onsets")

    def estimate_tempo(self, *, min_bpm: float = 40.0,
                       max_bpm: float = 240.0) -> float:
        """Return the median-interval tempo in beats per minute."""
        raise NotImplementedError("estimate_tempo")

    def beat_times(self) -> tuple:
        """Automatic grid beat times covering the analysed window."""
        raise NotImplementedError("beat_times")

    def beat_at(self, index: int) -> BeatPoint:
        """Return the grid beat with the given index."""
        raise NotImplementedError("beat_at")

    def snap(self, timestamp: float, *, tolerance: float = 0.03):
        """Return the nearest beat inside the tolerance, or None."""
        raise NotImplementedError("snap")

    def tap_correct(self, start: float, end: float, *, bpm: float,
                    anchor: float | None = None) -> TapSegment:
        """Register a manual tap span that overrides the automatic grid."""
        raise NotImplementedError("tap_correct")

    def grid_segments(self) -> tuple:
        """Final constant-tempo segments, ascending and contiguous."""
        raise NotImplementedError("grid_segments")

    def tempo_at(self, timestamp: float) -> float:
        """Tempo of the grid segment covering the timestamp."""
        raise NotImplementedError("tempo_at")

    def clear_taps(self) -> int:
        """Drop every manual tap span and report how many were removed."""
        raise NotImplementedError("clear_taps")

    def snapshot(self) -> dict:
        """Deep copy of the analyser state."""
        raise NotImplementedError("snapshot")

    def restore(self, state: dict) -> None:
        """Replace the analyser state with a snapshot."""
        raise NotImplementedError("restore")

    def stats(self) -> dict:
        """Current counters."""
        raise NotImplementedError("stats")
