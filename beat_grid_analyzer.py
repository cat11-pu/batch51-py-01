"""Beat grid analysis: onset detection, tempo estimate, tap overrides, grid segments."""

from __future__ import annotations

import bisect
import math
import threading
from dataclasses import dataclass


BEAT_SNAPSHOT_VERSION = 1


def _is_number(value) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        return False


def _median(values):
    ordered = sorted(values)
    size = len(ordered)
    middle = size // 2
    if size % 2:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2.0


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
        if not _is_number(frame_hz) or float(frame_hz) <= 0.0:
            raise BeatError("BEAT_INVALID", "frame_hz")
        if not _is_number(onset_threshold) or float(onset_threshold) < 0.0:
            raise BeatError("BEAT_INVALID", "onset_threshold")
        if not _is_number(rise_ratio) or float(rise_ratio) < 1.0:
            raise BeatError("BEAT_INVALID", "rise_ratio")
        if (not isinstance(max_frames, int) or isinstance(max_frames, bool)
                or max_frames <= 0):
            raise BeatError("BEAT_INVALID", "max_frames")
        if (not isinstance(max_onsets, int) or isinstance(max_onsets, bool)
                or max_onsets <= 0):
            raise BeatError("BEAT_INVALID", "max_onsets")
        self.frame_hz = float(frame_hz)
        self.onset_threshold = float(onset_threshold)
        self.rise_ratio = float(rise_ratio)
        self.max_frames = max_frames
        self.max_onsets = max_onsets
        self._lock = threading.RLock()
        self._frames = 0
        self._onsets: list = []
        self._taps: list = []
        self._last_energy = 0.0
        self._counters = {
            "rejected": 0,
        }

    def feed(self, frames, *, frame_hz: float | None = None) -> int:
        """Append envelope frames and return the cumulative frame count."""
        with self._lock:
            if frame_hz is not None:
                if not _is_number(frame_hz) or float(frame_hz) != self.frame_hz:
                    self._reject("BEAT_FRAME_RATE", "frame_hz")

            if frames is None or isinstance(frames, (str, bytes, bytearray)):
                self._reject("BEAT_INVALID", "frames")
            try:
                iterator = iter(frames)
            except TypeError:
                self._reject("BEAT_INVALID", "frames")

            remaining = self.max_frames - self._frames
            batch = []
            for value in iterator:
                if not _is_number(value) or float(value) < 0.0:
                    self._reject("BEAT_INVALID", "frame")
                if len(batch) >= remaining:
                    self._reject("BEAT_CAPACITY", "frames")
                batch.append(float(value))

            if not batch:
                self._reject("BEAT_EMPTY_BUFFER", "frames")

            previous = self._last_energy
            new_onsets = []
            for offset, energy in enumerate(batch):
                if (energy >= self.onset_threshold
                        and energy >= previous * self.rise_ratio):
                    if len(self._onsets) + len(new_onsets) >= self.max_onsets:
                        self._reject("BEAT_CAPACITY", "onsets")
                    new_onsets.append((self._frames + offset) / self.frame_hz)
                previous = energy

            self._frames += len(batch)
            self._onsets.extend(new_onsets)
            self._last_energy = batch[-1]
            return self._frames

    def onsets(self) -> tuple:
        """Detected onset times in seconds, ascending."""
        with self._lock:
            return tuple(self._onsets)

    def estimate_tempo(self, *, min_bpm: float = 40.0,
                       max_bpm: float = 240.0) -> float:
        """Return the median-interval tempo in beats per minute."""
        with self._lock:
            if (not _is_number(min_bpm) or not _is_number(max_bpm)
                    or float(min_bpm) <= 0.0
                    or float(max_bpm) <= float(min_bpm)):
                raise BeatError("BEAT_INVALID", "bpm range")
            if len(self._onsets) < 2:
                raise BeatError("BEAT_EMPTY_GRID", "onsets")

            intervals = [
                self._onsets[index + 1] - self._onsets[index]
                for index in range(len(self._onsets) - 1)
            ]
            bpm = round(60.0 / _median(intervals), 2)
            if bpm < float(min_bpm) or bpm > float(max_bpm):
                raise BeatError("BEAT_TEMPO_RANGE", bpm)
            return float(bpm)

    def beat_times(self) -> tuple:
        """Automatic grid beat times covering the analysed window."""
        with self._lock:
            return self._beat_times_locked()

    def beat_at(self, index: int) -> BeatPoint:
        """Return the grid beat with the given index."""
        with self._lock:
            if (not isinstance(index, int) or isinstance(index, bool)
                    or index < 0):
                raise BeatError("BEAT_INDEX", index)
            times = self._beat_times_locked()
            if index >= len(times):
                raise BeatError("BEAT_INDEX", index)
            timestamp = times[index]
            return BeatPoint(index, timestamp, self._tempo_at_locked(timestamp))

    def snap(self, timestamp: float, *, tolerance: float = 0.03):
        """Return the nearest beat inside the tolerance, or None."""
        with self._lock:
            if not _is_number(timestamp) or float(timestamp) < 0.0:
                raise BeatError("BEAT_INVALID", "timestamp")
            if not _is_number(tolerance) or float(tolerance) < 0.0:
                raise BeatError("BEAT_INVALID", "tolerance")

            times = self._beat_times_locked()
            if not times:
                return None

            target = float(timestamp)
            position = bisect.bisect_left(times, target)
            candidates = []
            if position > 0:
                candidates.append(position - 1)
            if position < len(times):
                candidates.append(position)
            if not candidates:
                return None

            best = candidates[0]
            best_distance = abs(times[best] - target)
            for candidate in candidates[1:]:
                distance = abs(times[candidate] - target)
                if distance < best_distance:
                    best = candidate
                    best_distance = distance
            if best_distance > float(tolerance) + 1e-12:
                return None
            return BeatPoint(
                best, times[best], self._tempo_at_locked(times[best])
            )

    def tap_correct(self, start: float, end: float, *, bpm: float,
                    anchor: float | None = None) -> TapSegment:
        """Register a manual tap span that overrides the automatic grid."""
        with self._lock:
            if (not _is_number(start) or not _is_number(end)
                    or not _is_number(bpm)):
                raise BeatError("BEAT_INVALID", "tap")
            start_value = float(start)
            end_value = float(end)
            bpm_value = float(bpm)
            if (start_value < 0.0 or start_value >= end_value
                    or bpm_value < 20.0 or bpm_value > 300.0):
                raise BeatError("BEAT_INVALID", "tap")

            if anchor is None:
                anchor_value = start_value
            else:
                if not _is_number(anchor):
                    raise BeatError("BEAT_INVALID", "anchor")
                anchor_value = float(anchor)
                if anchor_value < start_value or anchor_value > end_value:
                    raise BeatError("BEAT_INVALID", "anchor")

            replacement = TapSegment(
                start_value, end_value, bpm_value, anchor_value
            )
            updated = []
            for old in self._taps:
                if old.end <= start_value or old.start >= end_value:
                    updated.append(old)
                    continue
                if old.start < start_value:
                    updated.append(self._clip_tap(old, old.start, start_value))
                if old.end > end_value:
                    updated.append(self._clip_tap(old, end_value, old.end))
            updated.append(replacement)
            updated.sort(key=lambda tap: (tap.start, tap.end))
            self._taps = updated
            return replacement

    def grid_segments(self) -> tuple:
        """Final constant-tempo segments, ascending and contiguous."""
        with self._lock:
            return tuple(
                GridSegment(
                    piece["start"], piece["end"], piece["bpm"],
                    piece["source"],
                )
                for piece in self._pieces_locked()
            )

    def tempo_at(self, timestamp: float) -> float:
        """Tempo of the grid segment covering the timestamp."""
        with self._lock:
            if not _is_number(timestamp) or float(timestamp) < 0.0:
                raise BeatError("BEAT_INVALID", "timestamp")
            return self._tempo_at_locked(float(timestamp))

    def clear_taps(self) -> int:
        """Drop every manual tap span and report how many were removed."""
        with self._lock:
            removed = len(self._taps)
            self._taps = []
            return removed

    def snapshot(self) -> dict:
        """Deep copy of the analyser state."""
        with self._lock:
            return {
                "version": BEAT_SNAPSHOT_VERSION,
                "frame_hz": self.frame_hz,
                "onset_threshold": self.onset_threshold,
                "rise_ratio": self.rise_ratio,
                "frames": self._frames,
                "onsets": list(self._onsets),
                "taps": [
                    {
                        "start": tap.start,
                        "end": tap.end,
                        "bpm": tap.bpm,
                        "anchor": tap.anchor,
                    }
                    for tap in self._taps
                ],
                "stats": self._stats_locked(),
            }

    def restore(self, state: dict) -> None:
        """Replace the analyser state with a snapshot."""
        with self._lock:
            if not isinstance(state, dict):
                self._snapshot_invalid("state")

            required = (
                "version", "frame_hz", "onset_threshold", "rise_ratio",
                "frames", "onsets", "taps", "stats",
            )
            if any(key not in state for key in required):
                self._snapshot_invalid("missing")

            version = state["version"]
            if (not isinstance(version, int) or isinstance(version, bool)
                    or version != BEAT_SNAPSHOT_VERSION):
                self._snapshot_invalid("version")

            frame_hz = state["frame_hz"]
            threshold = state["onset_threshold"]
            rise_ratio = state["rise_ratio"]
            if not _is_number(frame_hz) or float(frame_hz) <= 0.0:
                self._snapshot_invalid("frame_hz")
            if not _is_number(threshold) or float(threshold) < 0.0:
                self._snapshot_invalid("onset_threshold")
            if not _is_number(rise_ratio) or float(rise_ratio) < 1.0:
                self._snapshot_invalid("rise_ratio")

            frames = state["frames"]
            if (not isinstance(frames, int) or isinstance(frames, bool)
                    or frames < 0 or frames > self.max_frames):
                self._snapshot_invalid("frames")

            raw_onsets = state["onsets"]
            if not isinstance(raw_onsets, list):
                self._snapshot_invalid("onsets")
            if len(raw_onsets) > self.max_onsets:
                self._snapshot_invalid("onsets")
            onsets = []
            previous_onset = -1.0
            duration = frames / float(frame_hz)
            for value in raw_onsets:
                if not _is_number(value) or float(value) < 0.0:
                    self._snapshot_invalid("onset")
                onset = float(value)
                if onset <= previous_onset or onset > duration + 1e-9:
                    self._snapshot_invalid("onset")
                onsets.append(onset)
                previous_onset = onset

            raw_taps = state["taps"]
            if not isinstance(raw_taps, list):
                self._snapshot_invalid("taps")
            taps = []
            previous_end = -1.0
            for item in raw_taps:
                if not isinstance(item, dict):
                    self._snapshot_invalid("tap")
                if any(key not in item for key in ("start", "end", "bpm", "anchor")):
                    self._snapshot_invalid("tap")
                start = item["start"]
                end = item["end"]
                bpm = item["bpm"]
                anchor = item["anchor"]
                if (not _is_number(start) or not _is_number(end)
                        or not _is_number(bpm) or not _is_number(anchor)):
                    self._snapshot_invalid("tap")
                start_value = float(start)
                end_value = float(end)
                bpm_value = float(bpm)
                anchor_value = float(anchor)
                if (start_value < 0.0 or start_value >= end_value
                        or bpm_value < 20.0 or bpm_value > 300.0
                        or anchor_value < start_value
                        or anchor_value > end_value
                        or start_value < previous_end - 1e-9):
                    self._snapshot_invalid("tap")
                taps.append(TapSegment(
                    start_value, end_value, bpm_value, anchor_value
                ))
                previous_end = end_value

            raw_stats = state["stats"]
            if not isinstance(raw_stats, dict):
                self._snapshot_invalid("stats")
            stat_keys = (
                "frames", "onsets", "taps", "beats", "segments", "rejected"
            )
            if any(key not in raw_stats for key in stat_keys):
                self._snapshot_invalid("stats")
            counters = {}
            for key in stat_keys:
                value = raw_stats[key]
                if (not isinstance(value, int) or isinstance(value, bool)
                        or value < 0):
                    self._snapshot_invalid("stats")
                counters[key] = value
            if (counters["frames"] != frames
                    or counters["onsets"] != len(onsets)
                    or counters["taps"] != len(taps)):
                self._snapshot_invalid("stats")

            self.frame_hz = float(frame_hz)
            self.onset_threshold = float(threshold)
            self.rise_ratio = float(rise_ratio)
            self._frames = frames
            self._onsets = onsets
            self._taps = taps
            self._last_energy = 0.0
            self._counters["rejected"] = counters["rejected"]

    def stats(self) -> dict:
        """Current counters."""
        with self._lock:
            return self._stats_locked()

    def _reject(self, code: str, detail: object = None) -> None:
        self._counters["rejected"] += 1
        raise BeatError(code, detail)

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> None:
        raise BeatError("BEAT_SNAPSHOT_INVALID", detail)

    @staticmethod
    def _clip_tap(tap: TapSegment, start: float, end: float) -> TapSegment:
        interval = 60.0 / tap.bpm
        anchor = tap.anchor
        if not (start <= anchor <= end):
            first = anchor + math.ceil((start - anchor) / interval - 1e-12) * interval
            if first <= end + 1e-12:
                anchor = min(max(first, start), end)
            else:
                anchor = start
        return TapSegment(start, end, tap.bpm, anchor)

    def _duration_locked(self) -> float:
        return self._frames / self.frame_hz

    def _auto_tempo_spans_locked(self, duration: float):
        onsets = self._onsets
        if len(onsets) < 2 or duration <= 0.0:
            return []

        intervals = [
            onsets[index + 1] - onsets[index]
            for index in range(len(onsets) - 1)
        ]
        spans = []
        segment_start = 0
        reference = intervals[0]
        group = [intervals[0]]

        def append_span(start_index, end_time):
            bpm = round(60.0 / _median(group), 2)
            spans.append({
                "start": onsets[start_index],
                "end": end_time,
                "bpm": bpm,
                "anchor": onsets[start_index],
            })

        for index in range(1, len(intervals)):
            interval = intervals[index]
            if abs(interval - reference) / reference > 0.05:
                append_span(segment_start, onsets[index])
                segment_start = index
                reference = interval
                group = [interval]
            else:
                group.append(interval)
        append_span(segment_start, onsets[-1])

        spans[0]["start"] = 0.0
        spans[-1]["end"] = duration
        cleaned = []
        for span in spans:
            if span["end"] <= span["start"]:
                continue
            if (cleaned
                    and cleaned[-1]["bpm"] == span["bpm"]
                    and abs(cleaned[-1]["end"] - span["start"]) <= 1e-12):
                cleaned[-1]["end"] = span["end"]
            else:
                cleaned.append(span)
        return cleaned

    def _tap_for_time_locked(self, timestamp: float, taps=None):
        if taps is None:
            taps = self._taps
        for index, item in enumerate(taps):
            if isinstance(item, tuple):
                start, end, tap = item
            else:
                tap = item
                start, end = tap.start, tap.end
            if start <= timestamp < end:
                return index, tap
        return None, None

    def _pieces_locked(self):
        duration = self._duration_locked()
        if duration <= 0.0:
            return []

        spans = self._auto_tempo_spans_locked(duration)
        cuts = {0.0, duration}
        for span in spans:
            cuts.add(min(max(span["start"], 0.0), duration))
            cuts.add(min(max(span["end"], 0.0), duration))
        clipped_taps = []
        for tap in self._taps:
            start = min(max(tap.start, 0.0), duration)
            end = min(max(tap.end, 0.0), duration)
            if end > start:
                cuts.add(start)
                cuts.add(end)
                clipped_taps.append((start, end, tap))

        ordered_cuts = sorted(cuts)
        pieces = []
        for index in range(len(ordered_cuts) - 1):
            start = ordered_cuts[index]
            end = ordered_cuts[index + 1]
            if end <= start:
                continue
            middle = (start + end) / 2.0
            tap_index, tap = self._tap_for_time_locked(middle, clipped_taps)
            if tap is not None:
                source = "manual"
                bpm = tap.bpm
                anchor = tap.anchor
                key = ("manual", tap_index, bpm, anchor)
            else:
                span = None
                for candidate in spans:
                    if candidate["start"] <= middle < candidate["end"]:
                        span = candidate
                        break
                if span is None:
                    continue
                source = "auto"
                bpm = span["bpm"]
                anchor = None
                key = ("auto", bpm)

            if (pieces and pieces[-1]["key"] == key
                    and abs(pieces[-1]["end"] - start) <= 1e-12):
                pieces[-1]["end"] = end
            else:
                pieces.append({
                    "start": start,
                    "end": end,
                    "bpm": bpm,
                    "source": source,
                    "anchor": anchor,
                    "key": key,
                })
        return pieces

    def _auto_anchor_locked(self, start: float, end: float) -> float:
        onsets = self._onsets
        if not onsets:
            return start
        index = bisect.bisect_left(onsets, start - 1e-12)
        if index < len(onsets) and onsets[index] <= end + 1e-12:
            return onsets[index]
        before = bisect.bisect_right(onsets, end + 1e-12) - 1
        if before >= 0:
            return onsets[before]
        return onsets[0]

    def _beat_times_locked(self) -> tuple:
        pieces = self._pieces_locked()
        if not pieces:
            return ()

        duration = self._duration_locked()
        beats = []
        for piece in pieces:
            interval = 60.0 / piece["bpm"]
            if interval <= 0.0:
                continue
            if piece["source"] == "manual":
                anchor = piece["anchor"]
            else:
                anchor = self._auto_anchor_locked(
                    piece["start"], piece["end"]
                )
            first_index = math.ceil(
                (piece["start"] - anchor) / interval - 1e-12
            )
            last_index = math.floor(
                (piece["end"] - anchor) / interval + 1e-12
            )
            for index in range(first_index, last_index + 1):
                timestamp = anchor + index * interval
                if timestamp < -1e-12 or timestamp > duration + 1e-12:
                    continue
                if timestamp < piece["start"] - 1e-12:
                    continue
                if timestamp > piece["end"] + 1e-12:
                    continue
                beats.append(0.0 if abs(timestamp) <= 1e-12 else timestamp)

        beats.sort()
        unique = []
        for timestamp in beats:
            if not unique or timestamp - unique[-1] > 1e-9:
                unique.append(timestamp)
        return tuple(unique)

    def _tempo_at_locked(self, timestamp: float) -> float:
        pieces = self._pieces_locked()
        if not pieces:
            raise BeatError("BEAT_EMPTY_GRID", "tempo")
        starts = [piece["start"] for piece in pieces]
        index = bisect.bisect_right(starts, timestamp) - 1
        if index < 0:
            index = 0
        return float(pieces[index]["bpm"])

    def _stats_locked(self) -> dict:
        return {
            "frames": self._frames,
            "onsets": len(self._onsets),
            "taps": len(self._taps),
            "beats": len(self._beat_times_locked()),
            "segments": len(self._pieces_locked()),
            "rejected": self._counters["rejected"],
        }
