"""Per-segment encode quality gate: metrics, re-encode budget and parallel evaluation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


GATE_SNAPSHOT_VERSION = 1


class GateError(ValueError):
    """Raised when a quality-gate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SegmentInfo:
    """State of one submitted segment."""

    segment_id: str
    frames: int
    score: float | None
    decision: str
    evaluated: bool


class EncodeQualityGate:
    """Score encoded segments against their source and spend a re-encode budget."""

    def __init__(self, *, threshold: float = 0.95, budget: int = 8,
                 max_segments: int = 512, max_frames_per_segment: int = 4096,
                 workers: int = 4) -> None:
        if not isinstance(threshold, (int, float)) or not 0.0 <= threshold <= 1.0:
            raise GateError("QG_INVALID_THRESHOLD", threshold)
        if not isinstance(budget, int) or budget < 0:
            raise GateError("QG_INVALID_BUDGET", budget)
        if not isinstance(max_segments, int) or max_segments <= 0:
            raise GateError("QG_INVALID_SEGMENT", max_segments)
        if not isinstance(max_frames_per_segment, int) or max_frames_per_segment <= 0:
            raise GateError("QG_INVALID_SEGMENT", max_frames_per_segment)
        if not isinstance(workers, int) or workers <= 0:
            raise GateError("QG_INVALID_SEGMENT", workers)
        self.threshold = float(threshold)
        self.budget = budget
        self.max_segments = max_segments
        self.max_frames_per_segment = max_frames_per_segment
        self.workers = workers
        self._lock = threading.RLock()
        self._segments: dict = {}
        self._order: list = []
        self._counters = {
            "submitted": 0,
            "accepted": 0,
            "reencode": 0,
            "unevaluated": 0,
            "budget_spent": 0,
            "rejected": 0,
        }

    def set_threshold(self, value: float) -> float:
        """Set the acceptance threshold and return the previous one."""
        raise NotImplementedError("set_threshold")

    def set_budget(self, value: int) -> int:
        """Set the re-encode budget and return the previous one."""
        raise NotImplementedError("set_budget")

    def budget_left(self) -> int:
        """Re-encode budget still available."""
        raise NotImplementedError("budget_left")

    def submit_segment(self, segment_id: str, *, decoded, source) -> SegmentInfo:
        """Register one encoded segment together with its source frames."""
        raise NotImplementedError("submit_segment")

    def score(self, segment_id: str) -> float:
        """Quality metric in the zero-to-one range."""
        raise NotImplementedError("score")

    def decide(self, segment_id: str) -> str:
        """Accept or re-encode the segment, spending budget at most once."""
        raise NotImplementedError("decide")

    def evaluate_all(self, *, workers: int | None = None) -> dict:
        """Decide every submitted segment in a thread pool."""
        raise NotImplementedError("evaluate_all")

    def report(self) -> dict:
        """Aggregated report over all segments."""
        raise NotImplementedError("report")

    def segments(self) -> tuple:
        """Segment identifiers in submission order."""
        raise NotImplementedError("segments")

    def segment_info(self, segment_id: str) -> SegmentInfo:
        """Current state of one segment."""
        raise NotImplementedError("segment_info")

    def snapshot(self) -> dict:
        """Deep copy of gate state."""
        raise NotImplementedError("snapshot")

    def restore(self, state: dict) -> None:
        """Replace gate state with a snapshot."""
        raise NotImplementedError("restore")
