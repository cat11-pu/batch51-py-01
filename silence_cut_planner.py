"""Silence cut planning: energy and zero-crossing detection, gap merging, fades."""

from __future__ import annotations

import copy
import math
import numbers
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
            if not self._is_positive_int(value):
                raise SilenceError("SIL_INVALID_ARG", name)
        if not self._is_number(silence_db):
            raise SilenceError("SIL_INVALID_ARG", "silence_db")
        if not self._is_number(zcr_max) or not 0.0 <= zcr_max <= 1.0:
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
        self._frames: list[tuple[float, float]] = []
        self._ranges: tuple[FrameRange, ...] = ()
        self._cuts: tuple = ()
        self._kept: tuple = ()
        self._plan_valid = False
        self._stats = {
            "frames": 0,
            "duration_ms": 0,
            "silences": 0,
            "cuts": 0,
            "kept": 0,
            "merged": 0,
            "plans": 0,
            "rejected": 0,
        }

    @staticmethod
    def _is_positive_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    @staticmethod
    def _is_number(value) -> bool:
        if isinstance(value, bool) or not isinstance(value, numbers.Number):
            return False
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return False
        return math.isfinite(number)

    @classmethod
    def _normalise_frame(cls, frame, index: int) -> tuple[float, float]:
        try:
            values = tuple(frame)
        except (TypeError, ValueError):
            raise SilenceError("SIL_INVALID_FRAME", index) from None
        if len(values) != 2:
            raise SilenceError("SIL_INVALID_FRAME", index)
        db, zcr = values
        if not cls._is_number(db):
            raise SilenceError("SIL_INVALID_FRAME", index)
        if not cls._is_number(zcr) or not 0.0 <= zcr <= 1.0:
            raise SilenceError("SIL_INVALID_FRAME", index)
        return float(db), float(zcr)

    def _reject(self, code: str, detail=None) -> None:
        self._stats["rejected"] += 1
        raise SilenceError(code, detail)

    def _detect_ranges(self, frames) -> tuple[FrameRange, ...]:
        ranges: list[FrameRange] = []
        run_start: int | None = None
        for index, (db, zcr) in enumerate(frames):
            silent = db <= self.silence_db and zcr <= self.zcr_max
            if silent:
                if run_start is None:
                    run_start = index
            elif run_start is not None:
                start_ms = run_start * self.frame_ms
                end_ms = index * self.frame_ms
                if end_ms - start_ms >= self.min_silence_ms:
                    ranges.append(FrameRange(start_ms, end_ms))
                run_start = None
        if run_start is not None:
            start_ms = run_start * self.frame_ms
            end_ms = len(frames) * self.frame_ms
            if end_ms - start_ms >= self.min_silence_ms:
                ranges.append(FrameRange(start_ms, end_ms))
        return tuple(ranges)

    def _duration_ms(self) -> int:
        return len(self._frames) * self.frame_ms

    def _invalidate_plan(self) -> None:
        self._cuts = ()
        self._kept = ()
        self._plan_valid = False
        self._stats["cuts"] = 0
        self._stats["kept"] = 0

    @staticmethod
    def _complement(ranges, duration_ms: int) -> tuple[FrameRange, ...]:
        result: list[FrameRange] = []
        cursor = 0
        for item in ranges:
            if item.start_ms > cursor:
                result.append(FrameRange(cursor, item.start_ms))
            cursor = max(cursor, item.end_ms)
        if cursor < duration_ms:
            result.append(FrameRange(cursor, duration_ms))
        return tuple(result)

    def _validate_padding(self, pad_lead_ms, pad_tail_ms) -> tuple[int, int]:
        values = []
        for name, value in (("pad_lead_ms", pad_lead_ms),
                            ("pad_tail_ms", pad_tail_ms)):
            if (not self._is_number(value) or value < 0
                    or int(value) != value):
                raise SilenceError("SIL_INVALID_PAD", name)
            values.append(int(value))
        return values[0], values[1]

    def _padded_cuts(self, pad_lead_ms: int,
                     pad_tail_ms: int) -> tuple[FrameRange, ...]:
        duration_ms = self._duration_ms()
        candidates = [
            FrameRange(max(0, item.start_ms - pad_lead_ms),
                       min(duration_ms, item.end_ms + pad_tail_ms))
            for item in self._ranges
        ]
        for index in range(len(candidates) - 1):
            left = candidates[index]
            right = candidates[index + 1]
            if left.end_ms > right.start_ms:
                boundary = (self._ranges[index].end_ms
                            + self._ranges[index + 1].start_ms) // 2
                candidates[index] = FrameRange(left.start_ms, boundary)
                candidates[index + 1] = FrameRange(boundary, right.end_ms)
        return tuple(item for item in candidates if item.end_ms > item.start_ms)

    def _padding_overlaps(self, pad_lead_ms: int, pad_tail_ms: int) -> bool:
        duration_ms = self._duration_ms()
        previous_end = None
        for item in self._ranges:
            start = max(0, item.start_ms - pad_lead_ms)
            end = min(duration_ms, item.end_ms + pad_tail_ms)
            if previous_end is not None and start < previous_end:
                return True
            previous_end = end
        return False

    def _segments_for(self, cuts, duration_ms: int) -> tuple[Segment, ...]:
        segments: list[Segment] = []
        for piece in self._complement(cuts, duration_ms):
            length = piece.end_ms - piece.start_ms
            fade_in = self.fade_ms if piece.start_ms > 0 else 0
            fade_out = self.fade_ms if piece.end_ms < duration_ms else 0
            fade_in = min(fade_in, length)
            fade_out = min(fade_out, length)
            segments.append(Segment(piece.start_ms, piece.end_ms,
                                    fade_in, fade_out))
        return tuple(segments)

    def _segments_after_overlap(self, cuts,
                                duration_ms: int) -> tuple[Segment, ...]:
        """Resolve the tail of a padded overlap at the voiced-gap midpoint."""
        if sum(item.end_ms - item.start_ms for item in cuts) >= duration_ms:
            return ()
        pieces: list[FrameRange] = []
        if cuts[0].start_ms > 0:
            pieces.append(FrameRange(0, cuts[0].start_ms))
        cursor = cuts[0].end_ms
        for item in cuts[1:]:
            if item.start_ms > cursor:
                pieces.append(FrameRange(cursor, item.start_ms))
            cursor = item.start_ms
        if cursor < duration_ms:
            pieces.append(FrameRange(cursor, duration_ms))

        segments: list[Segment] = []
        for piece in pieces:
            length = piece.end_ms - piece.start_ms
            fade_in = self.fade_ms if piece.start_ms > 0 else 0
            fade_out = self.fade_ms if piece.end_ms < duration_ms else 0
            segments.append(Segment(piece.start_ms, piece.end_ms,
                                    min(fade_in, length),
                                    min(fade_out, length)))
        return tuple(segments)

    def analyze(self, frames, *, sample_rate: int | None = None) -> int:
        """Append (rms_db, zcr) frames and return the cumulative frame count."""
        with self._lock:
            if sample_rate is not None and sample_rate != self.sample_rate:
                self._reject("SIL_SAMPLE_RATE", sample_rate)

            if frames is None:
                self._reject("SIL_INVALID_FRAME", "frames")

            remaining = self.max_frames - len(self._frames)
            try:
                input_len = len(frames)
            except TypeError:
                input_len = None
            if input_len is not None and input_len == 0:
                self._reject("SIL_EMPTY_BUFFER", None)
            if input_len is not None and input_len > remaining:
                self._reject("SIL_CAPACITY", "frames")

            normalised: list[tuple[float, float]] = []
            try:
                iterator = iter(frames)
            except TypeError:
                self._reject("SIL_INVALID_FRAME", "frames")
            for index, frame in enumerate(iterator):
                if len(normalised) >= remaining:
                    self._reject("SIL_CAPACITY", "frames")
                normalised.append(self._normalise_frame(frame, index))

            if not normalised:
                self._reject("SIL_EMPTY_BUFFER", None)

            candidate = self._frames + normalised
            ranges = self._detect_ranges(candidate)
            if len(ranges) > self.max_ranges:
                self._reject("SIL_CAPACITY", "ranges")

            self._frames = candidate
            self._ranges = ranges
            self._stats["frames"] = len(candidate)
            self._stats["duration_ms"] = self._duration_ms()
            self._stats["silences"] = len(ranges)
            self._invalidate_plan()
            return len(candidate)

    def silence_ranges(self) -> tuple:
        """Detected silence ranges, ascending and non-overlapping."""
        with self._lock:
            return self._ranges

    def voiced_ranges(self) -> tuple:
        """Complement of the silence ranges over the analysed window."""
        with self._lock:
            return self._complement(self._ranges, self._duration_ms())

    def merge_gaps(self, min_keep_ms: int | None = None) -> int:
        """Merge silence ranges separated by a shorter voiced gap."""
        with self._lock:
            if min_keep_ms is None:
                threshold = self.min_keep_ms
            else:
                if not self._is_number(min_keep_ms) or min_keep_ms < 0:
                    raise SilenceError("SIL_INVALID_ARG", "min_keep_ms")
                threshold = min_keep_ms

            merged_ranges: list[FrameRange] = []
            merged_count = 0
            for item in self._ranges:
                if (merged_ranges
                        and item.start_ms - merged_ranges[-1].end_ms
                        < threshold):
                    previous = merged_ranges[-1]
                    merged_ranges[-1] = FrameRange(
                        previous.start_ms, max(previous.end_ms, item.end_ms))
                    merged_count += 1
                else:
                    merged_ranges.append(item)

            if merged_count:
                self._ranges = tuple(merged_ranges)
                self._stats["silences"] = len(self._ranges)
                self._stats["merged"] += merged_count
                self._invalidate_plan()
            return merged_count

    def plan_cuts(self, *, pad_lead_ms: int = 0,
                  pad_tail_ms: int = 0) -> CutPlan:
        """Build the keep list and the cut list for the current analysis."""
        with self._lock:
            lead, tail = self._validate_padding(pad_lead_ms, pad_tail_ms)
            duration_ms = self._duration_ms()
            cuts = self._padded_cuts(lead, tail)
            if cuts and self._padding_overlaps(lead, tail):
                kept = self._segments_after_overlap(cuts, duration_ms)
            else:
                kept = self._segments_for(cuts, duration_ms)
            removed_ms = sum(item.end_ms - item.start_ms
                             for item in cuts)

            self._cuts = cuts
            self._kept = kept
            self._plan_valid = True
            self._stats["cuts"] = len(cuts)
            self._stats["kept"] = len(kept)
            self._stats["plans"] += 1
            return CutPlan(kept, cuts, removed_ms)

    def apply_padding(self, pad_lead_ms: int, pad_tail_ms: int) -> tuple:
        """Grow every cut by the given padding, clamped and disjoint."""
        with self._lock:
            lead, tail = self._validate_padding(pad_lead_ms, pad_tail_ms)
            duration_ms = self._duration_ms()
            cuts = self._padded_cuts(lead, tail)
            self._cuts = cuts
            self._kept = self._segments_for(cuts, duration_ms)
            self._plan_valid = True
            self._stats["cuts"] = len(cuts)
            self._stats["kept"] = len(self._kept)
            return cuts

    def cuts(self) -> tuple:
        """Cut ranges used by the last planning pass."""
        with self._lock:
            return self._cuts

    def preview(self) -> dict:
        """Source duration, output duration, kept and cut ranges."""
        with self._lock:
            duration_ms = self._duration_ms()
            if self._plan_valid:
                kept = self._kept
                cuts = self._cuts
            else:
                cuts = self._padded_cuts(0, 0)
                kept = self._segments_for(cuts, duration_ms)
            output_ms = sum(item.end_ms - item.start_ms for item in kept)
            return {
                "source_duration_ms": duration_ms,
                "output_duration_ms": output_ms,
                "kept": kept,
                "cuts": cuts,
            }

    def snapshot(self) -> dict:
        """Deep copy of planner state."""
        with self._lock:
            return {
                "version": SILENCE_SNAPSHOT_VERSION,
                "sample_rate": self.sample_rate,
                "frame_ms": self.frame_ms,
                "frames": copy.deepcopy(self._frames),
                "ranges": copy.deepcopy(list(self._ranges)),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        """Replace planner state with a snapshot."""
        with self._lock:
            parsed = self._parse_snapshot(state)
            self.sample_rate = parsed["sample_rate"]
            self.frame_ms = parsed["frame_ms"]
            self._frames = parsed["frames"]
            self._ranges = parsed["ranges"]
            self._cuts = ()
            self._kept = ()
            self._plan_valid = False
            self._stats = parsed["stats"]

    def _parse_snapshot(self, state) -> dict:
        try:
            if not isinstance(state, dict):
                raise ValueError
            if set(state) != {"version", "sample_rate", "frame_ms",
                              "frames", "ranges", "stats"}:
                raise ValueError
            version = state["version"]
            if (isinstance(version, bool)
                    or not isinstance(version, int)
                    or version != SILENCE_SNAPSHOT_VERSION):
                raise ValueError
            sample_rate = state["sample_rate"]
            frame_ms = state["frame_ms"]
            if (not self._is_positive_int(sample_rate)
                    or not self._is_positive_int(frame_ms)):
                raise ValueError

            raw_frames = state["frames"]
            if not isinstance(raw_frames, (list, tuple)):
                raise ValueError
            frames = [self._normalise_frame(frame, index)
                      for index, frame in enumerate(raw_frames)]

            raw_ranges = state["ranges"]
            if not isinstance(raw_ranges, (list, tuple)):
                raise ValueError
            ranges: list[FrameRange] = []
            previous_end = -1
            for item in raw_ranges:
                try:
                    start_ms, end_ms = item
                except (TypeError, ValueError):
                    raise ValueError from None
                if (isinstance(start_ms, bool)
                        or isinstance(end_ms, bool)
                        or not isinstance(start_ms, int)
                        or not isinstance(end_ms, int)
                        or start_ms < 0
                        or end_ms <= start_ms
                        or start_ms < previous_end):
                    raise ValueError
                ranges.append(FrameRange(start_ms, end_ms))
                previous_end = end_ms

            raw_stats = state["stats"]
            if not isinstance(raw_stats, dict):
                raise ValueError
            stat_keys = ("frames", "duration_ms", "silences", "cuts",
                         "kept", "merged", "plans", "rejected")
            if set(raw_stats) != set(stat_keys):
                raise ValueError
            stats = {}
            for key in stat_keys:
                value = raw_stats[key]
                if (not isinstance(value, int) or isinstance(value, bool)
                        or value < 0):
                    raise ValueError
                stats[key] = value

            duration_ms = len(frames) * frame_ms
            if (stats["frames"] != len(frames)
                    or stats["duration_ms"] != duration_ms
                    or stats["silences"] != len(ranges)
                    or any(item.end_ms > duration_ms for item in ranges)):
                raise ValueError
        except SilenceError:
            raise SilenceError("SIL_SNAPSHOT_INVALID", state) from None
        except (TypeError, ValueError, KeyError):
            raise SilenceError("SIL_SNAPSHOT_INVALID", state) from None

        if len(frames) > self.max_frames or len(ranges) > self.max_ranges:
            raise SilenceError("SIL_CAPACITY", "snapshot")

        return {
            "sample_rate": sample_rate,
            "frame_ms": frame_ms,
            "frames": frames,
            "ranges": tuple(ranges),
            "stats": stats,
        }

    def stats(self) -> dict:
        """Current counters."""
        with self._lock:
            return dict(self._stats)
