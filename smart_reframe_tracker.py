"""Vertical reframe: subject tracking, crop-window keyframes and render planning."""

from __future__ import annotations

import bisect
import copy
import math
import threading
from dataclasses import dataclass
from numbers import Real
from typing import Mapping


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

    MIN_PRIMARY_DWELL_MS = 500

    def __init__(self, *, aspect_num: int = 9, aspect_den: int = 16,
                 max_keyframes: int = 64, max_track: int = 1024,
                 max_step_px: int = 64, max_accel_px: int = 32) -> None:
        for name, value in (("aspect_num", aspect_num),
                            ("aspect_den", aspect_den),
                            ("max_keyframes", max_keyframes),
                            ("max_track", max_track),
                            ("max_step_px", max_step_px),
                            ("max_accel_px", max_accel_px)):
            if not self._is_int(value) or value <= 0:
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
        self._subject_count = 0
        self._confidence = 1.0
        self._last_observe_ms: int | None = None
        self._last_subject_id: str | None = None
        self._primary_subject_id: str | None = None
        self._primary_since_ms: int | None = None
        self._last_x: int | None = None
        self._last_y: int | None = None
        self._window_version = 0
        self._window_cache: dict[int, Window] = {}
        self._counters = {
            "lost": 0,
            "dropped": 0,
            "plans": 0,
            "rejected": 0,
        }

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _round_half_up(value: float) -> int:
        return int(math.floor(value + 0.5))

    def _window_width_for(self, height: int) -> int:
        numerator = height * self.aspect_num
        quotient, remainder = divmod(numerator, self.aspect_den)
        if remainder * 2 >= self.aspect_den:
            quotient += 1
        return quotient

    def _check_time(self, timestamp_ms: object) -> int:
        if not self._is_int(timestamp_ms) or timestamp_ms < 0:
            raise ReframeError("RF_INVALID_TIME", timestamp_ms)
        return timestamp_ms

    def _reject(self, code: str, detail: object = None):
        self._counters["rejected"] += 1
        raise ReframeError(code, detail)

    def _require_source(self) -> SourceInfo:
        if self._source is None:
            raise ReframeError("RF_INVALID_SOURCE", "source not set")
        return self._source

    def _invalidate_window_cache_locked(self) -> None:
        self._window_version += 1
        self._window_cache.clear()

    def _validated_subjects(self, subjects) -> list[tuple[str, int, int, float]]:
        source = self._source
        if source is None:
            raise ReframeError("RF_INVALID_SOURCE", "source not set")
        try:
            items = list(subjects)
        except Exception as exc:
            raise ReframeError("RF_INVALID_SUBJECT", str(exc)) from exc

        validated: list[tuple[str, int, int, float]] = []
        for item in items:
            try:
                subject_id, x, y, weight = item
            except Exception as exc:
                raise ReframeError("RF_INVALID_SUBJECT", item) from exc

            if not isinstance(subject_id, str):
                raise ReframeError("RF_INVALID_SUBJECT", item)
            subject_id = subject_id.strip()
            if not subject_id:
                raise ReframeError("RF_INVALID_SUBJECT", item)
            if (not self._is_int(x) or not self._is_int(y)
                    or not 0 <= x < source.width
                    or not 0 <= y < source.height):
                raise ReframeError("RF_INVALID_SUBJECT", item)
            if not isinstance(weight, Real) or isinstance(weight, bool):
                raise ReframeError("RF_INVALID_SUBJECT", item)
            try:
                numeric_weight = float(weight)
            except (OverflowError, TypeError, ValueError) as exc:
                raise ReframeError("RF_INVALID_SUBJECT", item) from exc
            if not math.isfinite(numeric_weight) or numeric_weight <= 0:
                raise ReframeError("RF_INVALID_SUBJECT", item)
            validated.append((subject_id, x, y, numeric_weight))
        return validated

    def _append_sample_locked(self, sample: TrackSample) -> None:
        if self.max_track == 1:
            if self._samples:
                self._counters["dropped"] += 1
            self._samples = [sample]
            return

        if len(self._samples) < self.max_track:
            self._samples.append(sample)
            return

        combined = self._samples + [sample]
        if self.max_track == 2:
            selected = [combined[0], combined[-1]]
        else:
            first_time = combined[0].timestamp_ms
            last_time = combined[-1].timestamp_ms
            span = last_time - first_time
            targets = [
                first_time + span * position / (self.max_track - 1)
                for position in range(self.max_track)
            ]

            prefix = [0.0]
            for index in range(self.max_track):
                error = combined[index].timestamp_ms - targets[index]
                prefix.append(prefix[-1] + error * error)

            suffix = [0.0] * (self.max_track + 1)
            for index in range(self.max_track - 1, -1, -1):
                error = combined[index + 1].timestamp_ms - targets[index]
                suffix[index] = suffix[index + 1] + error * error

            drop_at = min(
                range(1, self.max_track),
                key=lambda index: (prefix[index] + suffix[index], index),
            )
            selected = combined[:drop_at] + combined[drop_at + 1:]
        self._samples = selected
        self._counters["dropped"] += 1

    def _choose_primary_locked(
        self,
        validated: list[tuple[str, int, int, float]],
        timestamp_ms: int,
    ) -> tuple[str, int, int, float]:
        highest = validated[0]
        for candidate in validated[1:]:
            if candidate[3] > highest[3]:
                highest = candidate

        current = None
        if self._primary_subject_id is not None:
            for candidate in validated:
                if candidate[0] == self._primary_subject_id:
                    current = candidate
                    break

        if current is None:
            chosen = highest
        elif highest[0] == current[0]:
            chosen = current
        elif abs(highest[1] - current[1]) <= self._source.window_width:
            chosen = highest
        elif (self._primary_since_ms is None
              or timestamp_ms - self._primary_since_ms
              >= self.MIN_PRIMARY_DWELL_MS):
            chosen = highest
        else:
            chosen = current

        if chosen[0] != self._primary_subject_id:
            self._primary_subject_id = chosen[0]
            self._primary_since_ms = timestamp_ms
        elif self._primary_since_ms is None:
            self._primary_since_ms = timestamp_ms
        return chosen

    def _sample_index_at(self, timestamp_ms: int) -> int | None:
        if not self._samples:
            return None
        index = bisect.bisect_right(
            [sample.timestamp_ms for sample in self._samples], timestamp_ms
        ) - 1
        return index if index >= 0 else None

    def _clamped_center(self, source: SourceInfo, center: float) -> float:
        if source.window_width >= source.width:
            return source.width / 2.0
        minimum = source.window_width / 2.0
        maximum = source.width - source.window_width / 2.0
        return min(max(float(center), minimum), maximum)

    def _make_window(self, timestamp_ms: int, center: float) -> Window:
        source = self._require_source()
        clamped = self._clamped_center(source, center)
        x = self._round_half_up(clamped - source.window_width / 2.0)
        maximum_x = max(0, source.width - source.window_width)
        x = min(max(x, 0), maximum_x)
        return Window(timestamp_ms, x, source.window_width, float(clamped))

    def _raw_window_at(self, timestamp_ms: int) -> Window:
        source = self._require_source()
        ordered = self.keyframes()
        if not ordered:
            return self._make_window(timestamp_ms, source.width / 2.0)
        if timestamp_ms <= ordered[0].timestamp_ms:
            return self._make_window(timestamp_ms, ordered[0].center_x)
        if timestamp_ms >= ordered[-1].timestamp_ms:
            return self._make_window(timestamp_ms, ordered[-1].center_x)

        timestamps = [keyframe.timestamp_ms for keyframe in ordered]
        index = bisect.bisect_right(timestamps, timestamp_ms) - 1
        left = ordered[index]
        right = ordered[index + 1]
        elapsed = timestamp_ms - left.timestamp_ms
        duration = right.timestamp_ms - left.timestamp_ms
        progress = elapsed / duration
        eased = progress * progress * (3.0 - 2.0 * progress)
        center = left.center_x + (right.center_x - left.center_x) * eased
        return self._make_window(timestamp_ms, center)

    def _segment_profile(
        self, start: float, end: float, step_count: int
    ) -> list[float]:
        if step_count <= 0:
            return [start]
        distance = end - start
        if abs(distance) <= 1e-12:
            return [start] * (step_count + 1)

        direction = 1.0 if distance > 0 else -1.0
        amount = abs(distance)
        maximum_speed = max(1e-9, self.max_step_px - 1.0)
        maximum_accel = max(1e-9, (self.max_accel_px - 2.0) / 2.0)
        upper_ramp = (step_count + 1) // 2

        selected = None
        for ramp in range(upper_ramp, 0, -1):
            denominator = ramp * (step_count - ramp + 1)
            accel = amount / denominator
            peak = amount / (step_count - ramp + 1)
            if accel <= maximum_accel + 1e-12 and peak <= maximum_speed + 1e-12:
                selected = accel, peak, ramp
                break

        if selected is None:
            best = None
            for ramp in range(1, upper_ramp + 1):
                accel = min(maximum_accel, maximum_speed / ramp)
                reach = accel * ramp * (step_count - ramp + 1)
                if best is None or reach > best[0]:
                    best = (reach, accel, ramp)
            _, accel, ramp = best
        else:
            accel, _, ramp = selected

        peak = ramp * accel
        cruise_count = step_count - (2 * ramp - 1)
        velocities = [
            direction * accel * index for index in range(1, ramp + 1)
        ]
        velocities.extend([direction * peak] * cruise_count)
        velocities.extend([
            direction * accel * index for index in range(ramp - 1, 0, -1)
        ])

        profile = [start]
        for velocity in velocities:
            profile.append(profile[-1] + velocity)
        if selected is not None:
            profile[-1] = end
        return profile

    def _constrain_centers(
        self, centers: list[float], timestamps: list[int]
    ) -> list[float]:
        if len(centers) < 2:
            return centers

        def within_limits(path) -> bool:
            previous_step = 0.0
            for previous, current in zip(path, path[1:]):
                step = current - previous
                if abs(step) > self.max_step_px + 1e-9:
                    return False
                if abs(step - previous_step) > self.max_accel_px + 1e-9:
                    return False
                previous_step = step
            return True

        if within_limits(centers):
            x_path = [
                self._make_window(timestamp, center).x
                for timestamp, center in zip(timestamps, centers)
            ]
            if within_limits(x_path):
                return centers

        index_by_time = {
            timestamp: index for index, timestamp in enumerate(timestamps)
        }
        anchors = {0, len(centers) - 1}
        for timestamp in self._keyframes:
            index = index_by_time.get(timestamp)
            if index is not None and 0 < index < len(centers) - 1:
                anchors.add(index)
        ordered_anchors = sorted(anchors)

        result = [centers[0]]
        for left, right in zip(ordered_anchors, ordered_anchors[1:]):
            segment = self._segment_profile(
                result[-1], centers[right], right - left
            )
            result.extend(segment[1:])
        return result

    def set_source(self, width: int, height: int) -> SourceInfo:
        """Fix the source geometry and derive the crop width."""
        with self._lock:
            if not self._is_int(width) or not self._is_int(height):
                raise ReframeError("RF_INVALID_SOURCE", (width, height))
            if width <= 0 or height <= 0:
                raise ReframeError("RF_INVALID_SOURCE", (width, height))

            if self._source is not None:
                if (width, height) == (self._source.width, self._source.height):
                    return self._source
                raise ReframeError("RF_INVALID_SOURCE", (width, height))

            source = SourceInfo(width, height, self._window_width_for(height))
            self._source = source
            self._invalidate_window_cache_locked()
            return source

    def observe(self, timestamp_ms: int, subjects) -> TrackSample:
        """Record one observation of the tracked subjects."""
        with self._lock:
            if not self._is_int(timestamp_ms) or timestamp_ms < 0:
                self._reject("RF_INVALID_TIME", timestamp_ms)
            if self._source is None:
                self._reject("RF_INVALID_SOURCE", "source not set")
            if self._last_observe_ms is not None:
                if timestamp_ms == self._last_observe_ms:
                    self._reject("RF_DUPLICATE_TIME", timestamp_ms)
                if timestamp_ms < self._last_observe_ms:
                    self._reject("RF_OUT_OF_ORDER", timestamp_ms)

            try:
                validated = self._validated_subjects(subjects)
            except ReframeError as exc:
                if exc.code == "RF_INVALID_SUBJECT":
                    self._reject(exc.code, exc.detail)
                raise

            if validated:
                primary = self._choose_primary_locked(validated, timestamp_ms)
                subject_id, x, y, _ = primary
                confidence = 1.0
                self._last_subject_id = subject_id
                self._last_x = x
                self._last_y = y
                self._confidence = confidence
                for candidate_id, _, _, _ in validated:
                    if candidate_id not in self._subjects:
                        self._subjects.add(candidate_id)
                        self._subject_count += 1
            else:
                source = self._source
                if self._last_x is None:
                    self._last_x = source.width // 2
                if self._last_y is None:
                    self._last_y = source.height // 2
                subject_id = None
                x = self._last_x
                y = self._last_y
                confidence = max(0.0, self._confidence - 0.25)
                self._confidence = confidence
                self._counters["lost"] += 1

            sample = TrackSample(timestamp_ms, subject_id, x, y, confidence)
            self._append_sample_locked(sample)
            self._last_observe_ms = timestamp_ms
            return sample

    def primary_at(self, timestamp_ms: int):
        """Primary subject at or before the timestamp, or None."""
        with self._lock:
            timestamp_ms = self._check_time(timestamp_ms)
            index = self._sample_index_at(timestamp_ms)
            if index is None:
                return None
            return self._samples[index].subject_id

    def confidence_at(self, timestamp_ms: int) -> float:
        """Tracking confidence at or before the timestamp."""
        with self._lock:
            timestamp_ms = self._check_time(timestamp_ms)
            index = self._sample_index_at(timestamp_ms)
            if index is None:
                return 1.0
            return self._samples[index].confidence

    def add_keyframe(self, timestamp_ms: int, center_x: int) -> Keyframe:
        """Insert a crop-window keyframe."""
        with self._lock:
            if not self._is_int(timestamp_ms) or timestamp_ms < 0:
                self._reject("RF_INVALID_TIME", timestamp_ms)
            if self._source is None:
                self._reject("RF_INVALID_SOURCE", "source not set")
            if timestamp_ms in self._keyframes:
                self._reject("RF_DUPLICATE_TIME", timestamp_ms)
            if (not self._is_int(center_x)
                    or not 0 <= center_x <= self._source.width):
                self._reject("RF_WINDOW_OUT_OF_BOUNDS", center_x)
            if len(self._keyframes) >= self.max_keyframes:
                self._reject("RF_KEYFRAME_LIMIT", timestamp_ms)

            keyframe = Keyframe(timestamp_ms, center_x)
            self._keyframes[timestamp_ms] = keyframe
            self._invalidate_window_cache_locked()
            return keyframe

    def remove_keyframe(self, timestamp_ms: int) -> Keyframe:
        """Delete a crop-window keyframe and return it."""
        with self._lock:
            if not self._is_int(timestamp_ms) or timestamp_ms < 0:
                self._reject("RF_INVALID_TIME", timestamp_ms)
            keyframe = self._keyframes.get(timestamp_ms)
            if keyframe is None:
                self._reject("RF_UNKNOWN_KEYFRAME", timestamp_ms)
            del self._keyframes[timestamp_ms]
            self._invalidate_window_cache_locked()
            return keyframe

    def keyframes(self) -> tuple:
        """Keyframes in ascending time order."""
        with self._lock:
            return tuple(self._keyframes[key] for key in sorted(self._keyframes))

    def window_at(self, timestamp_ms: int) -> Window:
        """Crop window at the timestamp."""
        with self._lock:
            timestamp_ms = self._check_time(timestamp_ms)
            self._require_source()
            cached = self._window_cache.get(timestamp_ms)
            if cached is not None:
                return cached
            return self._raw_window_at(timestamp_ms)

    def render_plan(self, *, start_ms: int = 0, end_ms: int | None = None,
                    step_ms: int = 40) -> tuple:
        """Crop window for every render step in the range."""
        with self._lock:
            if (not self._is_int(start_ms) or start_ms < 0
                    or not self._is_int(step_ms) or step_ms <= 0):
                self._reject("RF_INVALID_RANGE",
                             (start_ms, end_ms, step_ms))
            if end_ms is not None and (
                    not self._is_int(end_ms) or end_ms <= start_ms):
                self._reject("RF_INVALID_RANGE",
                             (start_ms, end_ms, step_ms))
            if self._source is None:
                self._reject("RF_INVALID_SOURCE", "source not set")

            if end_ms is None:
                if self._keyframes:
                    final_ms = max(self._keyframes)
                elif self._samples:
                    final_ms = self._samples[-1].timestamp_ms
                else:
                    final_ms = start_ms
                final_ms = max(start_ms, final_ms)
            else:
                final_ms = end_ms

            timestamps = list(range(start_ms, final_ms + 1, step_ms))
            desired = [self._raw_window_at(ts).center for ts in timestamps]
            centers = self._constrain_centers(desired, timestamps)
            plan = tuple(
                self._make_window(timestamp_ms, center)
                for timestamp_ms, center in zip(timestamps, centers)
            )
            self._window_cache = {
                window.timestamp_ms: window for window in plan
            }
            self._counters["plans"] += 1
            return plan

    def snapshot(self) -> dict:
        """Deep copy of tracker state."""
        with self._lock:
            state = {
                "version": REFRAME_SNAPSHOT_VERSION,
                "source": (
                    None if self._source is None else {
                        "width": self._source.width,
                        "height": self._source.height,
                        "window_width": self._source.window_width,
                    }
                ),
                "samples": [
                    {
                        "timestamp_ms": sample.timestamp_ms,
                        "subject_id": sample.subject_id,
                        "x": sample.x,
                        "y": sample.y,
                        "confidence": sample.confidence,
                    }
                    for sample in self._samples
                ],
                "keyframes": [
                    {
                        "timestamp_ms": keyframe.timestamp_ms,
                        "center_x": keyframe.center_x,
                    }
                    for keyframe in self.keyframes()
                ],
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def _snapshot_error(self, detail: object = None):
        raise ReframeError("RF_SNAPSHOT_INVALID", detail)

    @staticmethod
    def _mapping_or_object(value: object, fields: tuple[str, ...]):
        if isinstance(value, Mapping):
            for field in fields:
                if field not in value:
                    raise ReframeError("RF_SNAPSHOT_INVALID", field)
            return {field: value[field] for field in fields}
        if all(hasattr(value, field) for field in fields):
            return {field: getattr(value, field) for field in fields}
        raise ReframeError("RF_SNAPSHOT_INVALID", value)

    def _parse_snapshot(self, state: object):
        if not isinstance(state, Mapping):
            self._snapshot_error(state)
        required = ("version", "source", "samples", "keyframes", "stats")
        if any(field not in state for field in required):
            self._snapshot_error("missing field")
        if (not self._is_int(state["version"])
                or state["version"] != REFRAME_SNAPSHOT_VERSION):
            self._snapshot_error("version")

        raw_source = state["source"]
        source = None
        if raw_source is not None:
            source_fields = self._mapping_or_object(
                raw_source, ("width", "height", "window_width")
            )
            width = source_fields["width"]
            height = source_fields["height"]
            window_width = source_fields["window_width"]
            if (not self._is_int(width) or not self._is_int(height)
                    or not self._is_int(window_width)
                    or width <= 0 or height <= 0 or window_width <= 0):
                self._snapshot_error("source")
            if window_width != self._window_width_for(height):
                self._snapshot_error("window_width")
            source = SourceInfo(width, height, window_width)

        raw_samples = state["samples"]
        if not isinstance(raw_samples, (list, tuple)):
            self._snapshot_error("samples")
        if len(raw_samples) > self.max_track:
            self._snapshot_error("samples limit")
        samples: list[TrackSample] = []
        previous_time = -1
        sample_subjects = set()
        for raw_sample in raw_samples:
            fields = self._mapping_or_object(
                raw_sample,
                ("timestamp_ms", "subject_id", "x", "y", "confidence"),
            )
            timestamp_ms = fields["timestamp_ms"]
            subject_id = fields["subject_id"]
            x = fields["x"]
            y = fields["y"]
            confidence = fields["confidence"]
            if (not self._is_int(timestamp_ms) or timestamp_ms < 0
                    or timestamp_ms <= previous_time):
                self._snapshot_error("sample time")
            if subject_id is not None:
                if not isinstance(subject_id, str) or not subject_id.strip():
                    self._snapshot_error("sample subject")
                subject_id = subject_id.strip()
                sample_subjects.add(subject_id)
            if source is None:
                self._snapshot_error("sample without source")
            if (not self._is_int(x) or not self._is_int(y)
                    or not 0 <= x < source.width
                    or not 0 <= y < source.height):
                self._snapshot_error("sample position")
            if (not isinstance(confidence, Real)
                    or isinstance(confidence, bool)
                    or not math.isfinite(float(confidence))
                    or not 0.0 <= float(confidence) <= 1.0):
                self._snapshot_error("sample confidence")
            samples.append(TrackSample(
                timestamp_ms, subject_id, x, y, float(confidence)
            ))
            previous_time = timestamp_ms

        raw_keyframes = state["keyframes"]
        if not isinstance(raw_keyframes, (list, tuple)):
            self._snapshot_error("keyframes")
        if len(raw_keyframes) > self.max_keyframes:
            self._snapshot_error("keyframes limit")
        keyframes: dict[int, Keyframe] = {}
        for raw_keyframe in raw_keyframes:
            fields = self._mapping_or_object(
                raw_keyframe, ("timestamp_ms", "center_x")
            )
            timestamp_ms = fields["timestamp_ms"]
            center_x = fields["center_x"]
            if (not self._is_int(timestamp_ms) or timestamp_ms < 0
                    or timestamp_ms in keyframes):
                self._snapshot_error("keyframe time")
            if source is None:
                self._snapshot_error("keyframe without source")
            if (not self._is_int(center_x)
                    or not 0 <= center_x <= source.width):
                self._snapshot_error("keyframe center")
            keyframes[timestamp_ms] = Keyframe(timestamp_ms, center_x)

        raw_stats = state["stats"]
        stat_fields = ("samples", "subjects", "keyframes", "lost",
                       "dropped", "plans", "rejected")
        if not isinstance(raw_stats, Mapping):
            self._snapshot_error("stats")
        stats = {}
        for field in stat_fields:
            if field not in raw_stats:
                self._snapshot_error(field)
            value = raw_stats[field]
            if not self._is_int(value) or value < 0:
                self._snapshot_error(field)
            stats[field] = value
        if stats["samples"] != len(samples):
            self._snapshot_error("stats samples")
        if stats["keyframes"] != len(keyframes):
            self._snapshot_error("stats keyframes")
        if stats["subjects"] < len(sample_subjects):
            self._snapshot_error("stats subjects")

        return source, samples, keyframes, stats, sample_subjects

    def restore(self, state: dict) -> None:
        """Replace tracker state with a snapshot."""
        with self._lock:
            try:
                (source, samples, keyframes, stats,
                 sample_subjects) = self._parse_snapshot(state)
            except ReframeError as exc:
                if exc.code == "RF_SNAPSHOT_INVALID":
                    raise
                raise ReframeError("RF_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:
                raise ReframeError("RF_SNAPSHOT_INVALID", exc) from exc

            self._source = source
            self._samples = samples
            self._keyframes = dict(keyframes)
            self._subjects = set(sample_subjects)
            self._subject_count = stats["subjects"]
            self._counters = {
                "lost": stats["lost"],
                "dropped": stats["dropped"],
                "plans": stats["plans"],
                "rejected": stats["rejected"],
            }
            self._last_observe_ms = (
                samples[-1].timestamp_ms if samples else None
            )
            if samples:
                self._confidence = samples[-1].confidence
                self._last_x = samples[-1].x
                self._last_y = samples[-1].y
                self._last_subject_id = None
                last_index = None
                for index in range(len(samples) - 1, -1, -1):
                    sample = samples[index]
                    if sample.subject_id is not None:
                        self._last_subject_id = sample.subject_id
                        last_index = index
                        break
                self._primary_subject_id = self._last_subject_id
                self._primary_since_ms = None
                if last_index is not None:
                    for index in range(last_index, -1, -1):
                        sample = samples[index]
                        if sample.subject_id == self._last_subject_id:
                            self._primary_since_ms = sample.timestamp_ms
                        else:
                            break
            else:
                self._confidence = 1.0
                self._last_x = None
                self._last_y = None
                self._last_subject_id = None
                self._primary_subject_id = None
                self._primary_since_ms = None
            self._invalidate_window_cache_locked()

    def stats(self) -> dict:
        """Current counters."""
        with self._lock:
            return {
                "samples": len(self._samples),
                "subjects": self._subject_count,
                "keyframes": len(self._keyframes),
                "lost": self._counters["lost"],
                "dropped": self._counters["dropped"],
                "plans": self._counters["plans"],
                "rejected": self._counters["rejected"],
            }
