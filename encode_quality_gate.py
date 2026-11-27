"""Per-segment encode quality gate: metrics, re-encode budget and parallel evaluation."""

from __future__ import annotations

import copy
import threading
from concurrent.futures import ThreadPoolExecutor
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


@dataclass
class _Record:
    segment_id: str
    frames: int
    decoded: tuple | None
    source: tuple | None
    metric: float | None
    score: float | None
    decision: str
    evaluated: bool
    decided: bool


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_threshold(value: object) -> bool:
    return (isinstance(value, (int, float))
            and not isinstance(value, bool)
            and 0.0 <= value <= 1.0)


class EncodeQualityGate:
    """Score encoded segments against their source and spend a re-encode budget."""

    def __init__(self, *, threshold: float = 0.95, budget: int = 8,
                 max_segments: int = 512, max_frames_per_segment: int = 4096,
                 workers: int = 4) -> None:
        if not _valid_threshold(threshold):
            raise GateError("QG_INVALID_THRESHOLD", threshold)
        if not _is_int(budget) or budget < 0:
            raise GateError("QG_INVALID_BUDGET", budget)
        if not _is_int(max_segments) or max_segments <= 0:
            raise GateError("QG_INVALID_SEGMENT", max_segments)
        if not _is_int(max_frames_per_segment) or max_frames_per_segment <= 0:
            raise GateError("QG_INVALID_SEGMENT", max_frames_per_segment)
        if not _is_int(workers) or workers <= 0:
            raise GateError("QG_INVALID_SEGMENT", workers)
        self.threshold = float(threshold)
        self.budget = budget
        self.max_segments = max_segments
        self.max_frames_per_segment = max_frames_per_segment
        self.workers = workers
        self._lock = threading.RLock()
        self._segments: dict[str, _Record] = {}
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
        if not _valid_threshold(value):
            raise GateError("QG_INVALID_THRESHOLD", value)
        with self._lock:
            previous = self.threshold
            self.threshold = float(value)
            return previous

    def set_budget(self, value: int) -> int:
        """Set the re-encode budget and return the previous one."""
        if not _is_int(value) or value < 0:
            raise GateError("QG_INVALID_BUDGET", value)
        with self._lock:
            previous = self.budget
            self.budget = value
            return previous

    def budget_left(self) -> int:
        """Re-encode budget still available."""
        with self._lock:
            return max(0, self.budget - self._counters["budget_spent"])

    def submit_segment(self, segment_id: str, *, decoded, source) -> SegmentInfo:
        """Register one encoded segment together with its source frames."""
        normalized = self._normalize_segment_id(segment_id)
        with self._lock:
            self._check_submit_slot_locked(normalized)

        try:
            decoded_frames, source_frames, frames = self._prepare_frames(
                decoded, source)
        except GateError:
            with self._lock:
                self._counters["rejected"] += 1
            raise

        with self._lock:
            self._check_submit_slot_locked(normalized)
            record = _Record(
                segment_id=normalized,
                frames=frames,
                decoded=decoded_frames,
                source=source_frames,
                metric=None,
                score=None,
                decision="pending",
                evaluated=False,
                decided=False,
            )
            self._segments[normalized] = record
            self._order.append(normalized)
            self._counters["submitted"] += 1
            return self._info_locked(record)

    def score(self, segment_id: str) -> float:
        """Quality metric in the zero-to-one range."""
        record = self._record(segment_id)
        return self._metric_for(record)

    def decide(self, segment_id: str) -> str:
        """Accept or re-encode the segment, spending budget at most once."""
        record = self._record(segment_id)
        metric = self._metric_for(record)
        with self._lock:
            return self._decide_locked(record, metric)

    def evaluate_all(self, *, workers: int | None = None) -> dict:
        """Decide every submitted segment in a thread pool."""
        if workers is None:
            worker_count = self.workers
        elif not _is_int(workers) or workers <= 0:
            raise GateError("QG_INVALID_SEGMENT", workers)
        else:
            worker_count = workers

        with self._lock:
            ordered = tuple(self._order)

        if not ordered:
            return {}

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            metrics = list(executor.map(self.score, ordered))

        result = {}
        with self._lock:
            for segment_id, metric in zip(ordered, metrics):
                record = self._segments[segment_id]
                result[segment_id] = self._decide_locked(record, metric)
        return result

    def report(self) -> dict:
        """Aggregated report over all segments."""
        with self._lock:
            return {
                "segments": len(self._order),
                "accepted": self._counters["accepted"],
                "reencode": self._counters["reencode"],
                "unevaluated": self._counters["unevaluated"],
                "budget_spent": self._counters["budget_spent"],
                "budget_left": max(
                    0, self.budget - self._counters["budget_spent"]),
                "threshold": self.threshold,
            }

    def segments(self) -> tuple:
        """Segment identifiers in submission order."""
        with self._lock:
            return tuple(self._order)

    def segment_info(self, segment_id: str) -> SegmentInfo:
        """Current state of one segment."""
        with self._lock:
            return self._info_locked(self._record_locked(segment_id))

    def snapshot(self) -> dict:
        """Deep copy of gate state."""
        with self._lock:
            segments = []
            for segment_id in self._order:
                record = self._segments[segment_id]
                segments.append({
                    "segment_id": record.segment_id,
                    "frames": record.frames,
                    "score": record.score,
                    "decision": record.decision,
                    "evaluated": record.evaluated,
                    "metric": self._metric_for(record),
                })
            state = {
                "version": GATE_SNAPSHOT_VERSION,
                "threshold": self.threshold,
                "budget_left": max(
                    0, self.budget - self._counters["budget_spent"]),
                "segments": segments,
                "counters": dict(self._counters),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace gate state with a snapshot."""
        try:
            restored = self._parse_snapshot(state)
        except (KeyError, TypeError, ValueError, OverflowError):
            raise GateError("QG_SNAPSHOT_INVALID", state) from None
        with self._lock:
            segments, order, counters, budget_left, threshold = restored
            self._segments = segments
            self._order = order
            self._counters = counters
            self.budget = budget_left + counters["budget_spent"]
            self.threshold = threshold

    def _normalize_segment_id(self, segment_id: object) -> str:
        if not isinstance(segment_id, str):
            with self._lock:
                self._counters["rejected"] += 1
            raise GateError("QG_INVALID_SEGMENT", segment_id)
        normalized = segment_id.strip()
        if not normalized:
            with self._lock:
                self._counters["rejected"] += 1
            raise GateError("QG_INVALID_SEGMENT", segment_id)
        return normalized

    def _check_submit_slot_locked(self, segment_id: str) -> None:
        if segment_id in self._segments:
            self._counters["rejected"] += 1
            raise GateError("QG_SEGMENT_EXISTS", segment_id)
        if len(self._order) >= self.max_segments:
            self._counters["rejected"] += 1
            raise GateError("QG_CAPACITY", len(self._order))

    def _prepare_frames(self, decoded, source):
        try:
            decoded_list = list(decoded)
            source_list = list(source)
        except TypeError:
            raise GateError("QG_FRAME_COUNT", None) from None

        count = len(decoded_list)
        if count == 0 or count != len(source_list):
            raise GateError("QG_FRAME_COUNT", count)
        if count > self.max_frames_per_segment:
            raise GateError("QG_CAPACITY", count)

        decoded_frames = self._normalize_frames(decoded_list)
        source_frames = self._normalize_frames(source_list)

        pixel_count = len(decoded_frames[0][1])
        for frames in (decoded_frames, source_frames):
            for _, pixels in frames:
                if len(pixels) != pixel_count:
                    raise GateError("QG_INVALID_FRAME", len(pixels))

        return (
            tuple(sorted(decoded_frames, key=lambda item: item[0])),
            tuple(sorted(source_frames, key=lambda item: item[0])),
            count,
        )

    def _normalize_frames(self, frames):
        normalized = []
        seen_pts = set()
        for frame in frames:
            if not isinstance(frame, (tuple, list)) or len(frame) != 2:
                raise GateError("QG_INVALID_FRAME", frame)
            pts, pixels = frame
            if not _is_int(pts) or pts < 0:
                raise GateError("QG_INVALID_FRAME", pts)
            if pts in seen_pts:
                raise GateError("QG_DUPLICATE_PTS", pts)
            seen_pts.add(pts)

            if isinstance(pixels, (str, bytes, bytearray, dict, set,
                                   frozenset)):
                raise GateError("QG_INVALID_FRAME", pixels)
            try:
                pixel_tuple = tuple(pixels)
            except TypeError:
                raise GateError("QG_INVALID_FRAME", pixels) from None
            if not pixel_tuple:
                raise GateError("QG_INVALID_FRAME", pixels)
            for pixel in pixel_tuple:
                if not _is_int(pixel) or not 0 <= pixel <= 255:
                    raise GateError("QG_INVALID_FRAME", pixel)
            normalized.append((pts, pixel_tuple))
        return normalized

    def _compute_metric(self, decoded, source) -> float:
        total_error = 0
        pixel_count = 0
        for (_, decoded_pixels), (_, source_pixels) in zip(decoded, source):
            total_error += sum(
                abs(left - right)
                for left, right in zip(decoded_pixels, source_pixels)
            )
            pixel_count += len(decoded_pixels)
        mean_error = total_error / pixel_count
        return round(1.0 - (mean_error / 255.0), 6)

    def _metric_for(self, record: _Record) -> float:
        if record.metric is not None:
            return record.metric
        return self._compute_metric(record.decoded, record.source)

    def _record(self, segment_id: object) -> _Record:
        with self._lock:
            return self._record_locked(segment_id)

    def _record_locked(self, segment_id: object) -> _Record:
        normalized = segment_id.strip() if isinstance(segment_id, str) else None
        if normalized is None or normalized not in self._segments:
            raise GateError("QG_UNKNOWN_SEGMENT", segment_id)
        return self._segments[normalized]

    def _decide_locked(self, record: _Record, metric: float) -> str:
        if record.decided:
            return record.decision

        if record.metric is None:
            record.metric = metric
        record.score = metric
        record.decided = True

        if metric >= self.threshold:
            record.decision = "accept"
            record.evaluated = True
            self._counters["accepted"] += 1
        elif self.budget_left() > 0:
            record.decision = "reencode"
            record.evaluated = True
            self._counters["reencode"] += 1
            self._counters["budget_spent"] += 1
        else:
            record.decision = "accept"
            record.evaluated = False
            self._counters["unevaluated"] += 1
        return record.decision

    def _info_locked(self, record: _Record) -> SegmentInfo:
        return SegmentInfo(
            segment_id=record.segment_id,
            frames=record.frames,
            score=record.score,
            decision=record.decision,
            evaluated=record.evaluated,
        )

    def _parse_snapshot(self, state):
        if not isinstance(state, dict):
            raise ValueError("snapshot")
        for key in ("version", "threshold", "budget_left", "segments",
                    "counters"):
            if key not in state:
                raise ValueError(key)

        if (not _is_int(state["version"])
                or state["version"] != GATE_SNAPSHOT_VERSION):
            raise ValueError("version")
        if not _valid_threshold(state["threshold"]):
            raise ValueError("threshold")
        budget_left = state["budget_left"]
        if not _is_int(budget_left) or budget_left < 0:
            raise ValueError("budget_left")

        raw_segments = state["segments"]
        if isinstance(raw_segments, dict):
            raw_segments = list(raw_segments.values())
        if not isinstance(raw_segments, list):
            raise ValueError("segments")
        if len(raw_segments) > self.max_segments:
            raise ValueError("capacity")

        counters_raw = state["counters"]
        if not isinstance(counters_raw, dict):
            raise ValueError("counters")
        counter_names = ("submitted", "accepted", "reencode", "unevaluated",
                         "budget_spent", "rejected")
        counters = {}
        for name in counter_names:
            value = counters_raw[name]
            if not _is_int(value) or value < 0:
                raise ValueError(name)
            counters[name] = value

        segments = {}
        order = []
        accepted = 0
        reencode = 0
        unevaluated = 0
        for raw in raw_segments:
            if not isinstance(raw, dict):
                raise ValueError("segment")
            for key in ("segment_id", "frames", "score", "decision",
                        "evaluated"):
                if key not in raw:
                    raise ValueError(key)

            segment_id = raw["segment_id"]
            if not isinstance(segment_id, str) or not segment_id.strip():
                raise ValueError("segment_id")
            segment_id = segment_id.strip()
            if segment_id in segments:
                raise ValueError("duplicate segment_id")

            frames = raw["frames"]
            if not _is_int(frames) or frames <= 0:
                raise ValueError("frames")
            if frames > self.max_frames_per_segment:
                raise ValueError("frames capacity")

            decision = raw["decision"]
            if decision not in ("pending", "accept", "reencode"):
                raise ValueError("decision")
            evaluated = raw["evaluated"]
            if not isinstance(evaluated, bool):
                raise ValueError("evaluated")
            if decision == "pending" and evaluated:
                raise ValueError("pending evaluated")

            score = raw["score"]
            if score is not None and not _valid_threshold(score):
                raise ValueError("score")

            decoded_frames = None
            source_frames = None
            metric = raw.get("metric")
            if metric is not None:
                if not _valid_threshold(metric):
                    raise ValueError("metric")
                metric = float(metric)
            elif "decoded" in raw or "source" in raw:
                if "decoded" not in raw or "source" not in raw:
                    raise ValueError("frames")
                decoded_frames, source_frames, prepared_frames = (
                    self._prepare_frames(raw["decoded"], raw["source"]))
                if prepared_frames != frames:
                    raise ValueError("frames")
                metric = self._compute_metric(decoded_frames, source_frames)
            elif score is not None:
                metric = float(score)
            else:
                raise ValueError("metric")

            if score is not None and abs(float(score) - metric) > 1e-9:
                raise ValueError("score metric")
            if decision != "pending" and score is None and evaluated:
                raise ValueError("score")

            if decision == "pending":
                if score is not None:
                    raise ValueError("pending score")
                decided = False
            else:
                decided = True
                if decision == "reencode":
                    if not evaluated or score is None:
                        raise ValueError("reencode state")
                    reencode += 1
                elif evaluated:
                    if score is None:
                        raise ValueError("accepted state")
                    accepted += 1
                else:
                    unevaluated += 1

            record = _Record(
                segment_id=segment_id,
                frames=frames,
                decoded=decoded_frames,
                source=source_frames,
                metric=metric,
                score=None if score is None else float(score),
                decision=decision,
                evaluated=evaluated,
                decided=decided,
            )
            segments[segment_id] = record
            order.append(segment_id)

        if counters["submitted"] != len(order):
            raise ValueError("submitted")
        if counters["accepted"] != accepted:
            raise ValueError("accepted")
        if counters["reencode"] != reencode:
            raise ValueError("reencode")
        if counters["unevaluated"] != unevaluated:
            raise ValueError("unevaluated")
        if counters["budget_spent"] != reencode:
            raise ValueError("budget_spent")

        return (segments, order, counters, budget_left,
                float(state["threshold"]))
