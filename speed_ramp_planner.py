"""Speed ramp planning: keyframed playback rates, source mapping and stretch plans."""

from __future__ import annotations

import math
import operator
import threading
from bisect import bisect_right
from dataclasses import dataclass
from fractions import Fraction


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


def _as_int(value: object) -> int:
    if isinstance(value, bool):
        raise TypeError("boolean is not a frame count")
    return operator.index(value)


def _as_finite_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("speed must be a real number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("speed must be finite")
    return result


def _exact(value: float) -> Fraction:
    return Fraction(str(value))


class SpeedRampPlanner:
    """Map full length output frames back to source frames for a ramp plan."""

    def __init__(self, *, frame_rate: int = 30, max_speed: float = 8.0,
                 max_keyframes: int = 32, max_accel: float = 0.5,
                 max_output_frames: int = 100000) -> None:
        frame_rate = self._positive_int(frame_rate, "frame_rate")
        max_speed = self._speed(max_speed, "max_speed")
        max_keyframes = self._positive_int(max_keyframes, "max_keyframes")
        max_accel = self._nonnegative_float(max_accel, "max_accel")
        max_output_frames = self._nonnegative_int(max_output_frames,
                                                  "max_output_frames")

        self.frame_rate = frame_rate
        self.max_speed = max_speed
        self.max_keyframes = max_keyframes
        self.max_accel = max_accel
        self.max_output_frames = max_output_frames
        self._lock = threading.RLock()
        self._keyframes: tuple[SpeedKeyframe, ...] = ()
        self._source_frames: int | None = None
        self._plans = 0

    @staticmethod
    def _invalid(detail: object = None) -> SpeedRampError:
        return SpeedRampError("SPEED_RAMP_INVALID", detail)

    @classmethod
    def _positive_int(cls, value: object, name: str) -> int:
        try:
            result = _as_int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise cls._invalid(name) from exc
        if result <= 0:
            raise cls._invalid(name)
        return result

    @classmethod
    def _nonnegative_int(cls, value: object, name: str) -> int:
        try:
            result = _as_int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise cls._invalid(name) from exc
        if result < 0:
            raise cls._invalid(name)
        return result

    @classmethod
    def _speed(cls, value: object, name: str) -> float:
        try:
            result = _as_finite_float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise cls._invalid(name) from exc
        if result < 0:
            raise cls._invalid(name)
        return result

    @classmethod
    def _nonnegative_float(cls, value: object, name: str) -> float:
        return cls._speed(value, name)

    @classmethod
    def _parse_keyframes(cls, keyframes, max_speed: float
                         ) -> tuple[SpeedKeyframe, ...]:
        try:
            raw = tuple(keyframes)
        except TypeError as exc:
            raise cls._invalid("keyframes") from exc
        if not raw:
            raise cls._invalid("keyframes must not be empty")

        parsed: list[SpeedKeyframe] = []
        previous = -1
        for item in raw:
            if isinstance(item, (str, bytes)):
                raise cls._invalid("keyframe must be a pair")
            try:
                frame_value, speed_value = item
            except (TypeError, ValueError) as exc:
                raise cls._invalid("keyframe must be a pair") from exc

            try:
                frame = _as_int(frame_value)
                speed = _as_finite_float(speed_value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise cls._invalid("keyframe values") from exc

            if frame < 0 or frame <= previous:
                raise cls._invalid("keyframe frames must be strictly increasing")
            if speed < 0 or speed > max_speed:
                raise cls._invalid("keyframe speed out of range")

            parsed.append(SpeedKeyframe(frame, speed))
            previous = frame

        if not parsed or parsed[0].output_frame != 0:
            raise cls._invalid("first keyframe must be at frame 0")
        return tuple(parsed)

    def _require_keyframes_locked(self) -> tuple[SpeedKeyframe, ...]:
        keyframes = self._keyframes
        if not keyframes:
            raise SpeedRampError("SPEED_RAMP_STATE", "keyframes")
        return keyframes

    def _require_plan_locked(self) -> tuple[int, tuple[SpeedKeyframe, ...]]:
        keyframes = self._require_keyframes_locked()
        source_frames = self._source_frames
        if source_frames is None:
            raise SpeedRampError("SPEED_RAMP_STATE", "source_frames")
        return source_frames, keyframes

    @staticmethod
    def _geometry(keyframes: tuple[SpeedKeyframe, ...]
                  ) -> tuple[tuple[int, ...], tuple[Fraction, ...],
                             tuple[Fraction, ...]]:
        frames = tuple(keyframe.output_frame for keyframe in keyframes)
        speeds = tuple(_exact(keyframe.speed) for keyframe in keyframes)
        prefixes = [Fraction(0)]
        for index in range(len(keyframes) - 1):
            delta = frames[index + 1] - frames[index]
            prefixes.append(prefixes[-1] + delta * speeds[index])
        return frames, speeds, tuple(prefixes)

    def _accel_issues_locked(self) -> tuple[RampIssue, ...]:
        keyframes = self._keyframes
        limit = _exact(self.max_accel)
        issues: list[RampIssue] = []
        for previous, current in zip(keyframes, keyframes[1:]):
            previous_speed = _exact(previous.speed)
            current_speed = _exact(current.speed)
            delta = abs(current_speed - previous_speed)
            scale = max(previous_speed, current_speed)
            if delta > limit * scale:
                issues.append(RampIssue("ACCEL_LIMIT", current.output_frame))
        return tuple(issues)

    def _output_frame_locked(self, source_frames: int,
                             keyframes: tuple[SpeedKeyframe, ...]) -> int:
        frames, speeds, prefixes = self._geometry(keyframes)
        target = Fraction(source_frames)

        for index, speed in enumerate(speeds):
            start = frames[index]
            end = frames[index + 1] if index + 1 < len(frames) else None
            base = prefixes[index]

            if base >= target:
                return start
            if speed == 0:
                continue

            steps = math.ceil((target - base) / speed)
            output_frame = start + steps
            if end is None or output_frame <= end:
                return output_frame

        raise SpeedRampError("SPEED_RAMP_UNREACHABLE", source_frames)

    def _freeze_frames_locked(self, output_end: int,
                              keyframes: tuple[SpeedKeyframe, ...]) -> int:
        frames, speeds, _ = self._geometry(keyframes)
        frozen = 0
        for index, speed in enumerate(speeds):
            start = frames[index]
            if start >= output_end:
                break
            if speed != 0:
                continue
            end = frames[index + 1] if index + 1 < len(frames) else output_end
            frozen += max(0, min(end, output_end) - start)
        return frozen

    def set_source_duration(self, frames: int) -> int:
        source_frames = self._positive_int(frames, "source_frames")
        with self._lock:
            self._source_frames = source_frames
        return source_frames

    def set_keyframes(self, keyframes) -> int:
        try:
            count = len(keyframes)
        except (TypeError, AttributeError):
            try:
                keyframes = tuple(keyframes)
            except TypeError as exc:
                raise self._invalid("keyframes") from exc
            count = len(keyframes)

        with self._lock:
            if count > self.max_keyframes:
                raise SpeedRampError("SPEED_RAMP_LIMIT",
                                     {"count": count,
                                      "limit": self.max_keyframes})
            parsed = self._parse_keyframes(keyframes, self.max_speed)
            self._keyframes = parsed
        return len(parsed)

    def keyframes(self) -> tuple[SpeedKeyframe, ...]:
        with self._lock:
            return self._keyframes

    def speed_at(self, output_frame: int) -> float:
        try:
            frame = _as_int(output_frame)
        except (TypeError, ValueError, OverflowError) as exc:
            raise self._invalid("output_frame") from exc
        if frame < 0:
            raise self._invalid("output_frame")

        with self._lock:
            keyframes = self._require_keyframes_locked()
        frames = tuple(keyframe.output_frame for keyframe in keyframes)
        index = bisect_right(frames, frame) - 1
        return keyframes[index].speed

    def map_time(self, output_frame: int) -> int:
        try:
            frame = _as_int(output_frame)
        except (TypeError, ValueError, OverflowError) as exc:
            raise self._invalid("output_frame") from exc
        if frame < 0:
            raise self._invalid("output_frame")

        with self._lock:
            keyframes = self._require_keyframes_locked()
            frames, speeds, prefixes = self._geometry(keyframes)

        index = bisect_right(frames, frame) - 1
        position = prefixes[index] + (frame - frames[index]) * speeds[index]
        return position.numerator // position.denominator

    def unmap_time(self, source_frame: int) -> int:
        try:
            target_value = _as_int(source_frame)
        except (TypeError, ValueError, OverflowError) as exc:
            raise self._invalid("source_frame") from exc
        if target_value < 0:
            raise self._invalid("source_frame")

        with self._lock:
            keyframes = self._require_keyframes_locked()
            frames, speeds, prefixes = self._geometry(keyframes)

        target = Fraction(target_value)
        for index, speed in enumerate(speeds):
            start = frames[index]
            end = frames[index + 1] if index + 1 < len(frames) else None
            base = prefixes[index]

            if base >= target:
                return start
            if speed == 0:
                continue

            steps = math.ceil((target - base) / speed)
            output_frame = start + steps
            if end is None or output_frame <= end:
                return output_frame

        raise SpeedRampError("SPEED_RAMP_UNREACHABLE", source_frame)

    def output_frames(self) -> int:
        with self._lock:
            source_frames, keyframes = self._require_plan_locked()
            return self._output_frame_locked(source_frames, keyframes)

    def frame_budget(self) -> dict:
        with self._lock:
            source_frames, keyframes = self._require_plan_locked()
            issues = self._accel_issues_locked()
            if issues:
                raise SpeedRampError("SPEED_RAMP_ACCEL_LIMIT",
                                     issues[0].at_frame)

            output_frames = self._output_frame_locked(source_frames, keyframes)
            if output_frames > self.max_output_frames:
                raise SpeedRampError(
                    "SPEED_RAMP_BUDGET_EXCEEDED",
                    {"output_frames": output_frames,
                     "budget": self.max_output_frames},
                )

            freeze_frames = self._freeze_frames_locked(output_frames, keyframes)
            self._plans += 1
            return {
                "output_frames": output_frames,
                "source_frames": source_frames,
                "freeze_frames": freeze_frames,
                "budget": self.max_output_frames,
            }

    def audio_segments(self) -> tuple[AudioStretchSegment, ...]:
        with self._lock:
            source_frames, keyframes = self._require_plan_locked()
            output_end = self._output_frame_locked(source_frames, keyframes)
            if output_end > self.max_output_frames:
                raise SpeedRampError(
                    "SPEED_RAMP_BUDGET_EXCEEDED",
                    {"output_frames": output_end,
                     "budget": self.max_output_frames},
                )
            frames, speeds, prefixes = self._geometry(keyframes)
            frame_rate = self.frame_rate

        windows: list[tuple[int, int, int, int, int]] = []
        for index in range(len(frames)):
            output_start = frames[index]
            if output_start >= output_end:
                break
            output_stop = (frames[index + 1]
                           if index + 1 < len(frames) else output_end)
            output_stop = min(output_stop, output_end)
            output_count = output_stop - output_start
            if output_count <= 0:
                continue

            source_begin = prefixes[index]
            source_stop = source_begin + output_count * speeds[index]
            source_start = (source_begin.numerator //
                            source_begin.denominator)
            source_end = source_stop.numerator // source_stop.denominator
            source_count = source_end - source_start
            windows.append((output_start, output_count, source_start,
                            source_count, index))

        fade_unit = max(1, round(frame_rate / 30))
        boundary_fades = [
            min(fade_unit, windows[index][1], windows[index + 1][1])
            for index in range(len(windows) - 1)
        ]

        segments: list[AudioStretchSegment] = []
        for position, (output_start, output_count, source_start,
                       source_count, source_index) in enumerate(windows):
            fades = []
            if position > 0:
                fades.append(boundary_fades[position - 1])
            if position < len(boundary_fades):
                fades.append(boundary_fades[position])
            fade_frames = max(fades, default=0)
            ratio = output_count / source_count if source_count else 0.0
            segments.append(AudioStretchSegment(
                index=len(segments),
                output_start=output_start,
                output_frames=output_count,
                source_start=source_start,
                source_frames=source_count,
                ratio=ratio,
                fade_frames=fade_frames,
            ))
        return tuple(segments)

    def validate(self) -> tuple[RampIssue, ...]:
        with self._lock:
            return self._accel_issues_locked()

    def stats(self) -> dict:
        with self._lock:
            keyframes = self._keyframes
        if not keyframes:
            return {
                "keyframes": 0,
                "intervals": 0,
                "max_speed": 0.0,
                "min_speed": 0.0,
            }
        speeds = [keyframe.speed for keyframe in keyframes]
        return {
            "keyframes": len(keyframes),
            "intervals": len(keyframes),
            "max_speed": max(speeds),
            "min_speed": min(speeds),
        }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "frame_rate": self.frame_rate,
                "max_speed": self.max_speed,
                "max_keyframes": self.max_keyframes,
                "max_accel": self.max_accel,
                "max_output_frames": self.max_output_frames,
                "source_frames": self._source_frames,
                "keyframes": [
                    [keyframe.output_frame, keyframe.speed]
                    for keyframe in self._keyframes
                ],
                "plans": self._plans,
            }

    def restore(self, state: dict) -> None:
        required = {
            "version", "frame_rate", "max_speed", "max_keyframes",
            "max_accel", "max_output_frames", "source_frames",
            "keyframes", "plans",
        }
        try:
            if not isinstance(state, dict) or set(state) != required:
                raise ValueError("snapshot keys")
            if _as_int(state["version"]) != 1:
                raise ValueError("snapshot version")

            frame_rate = self._positive_int(state["frame_rate"], "frame_rate")
            max_speed = self._speed(state["max_speed"], "max_speed")
            max_keyframes = self._positive_int(state["max_keyframes"],
                                               "max_keyframes")
            max_accel = self._nonnegative_float(state["max_accel"],
                                                "max_accel")
            max_output_frames = self._nonnegative_int(
                state["max_output_frames"], "max_output_frames")

            raw_source = state["source_frames"]
            if raw_source is None:
                source_frames = None
            else:
                source_frames = self._positive_int(raw_source,
                                                   "source_frames")

            raw_keyframes = state["keyframes"]
            if not isinstance(raw_keyframes, (list, tuple)):
                raise ValueError("keyframes")
            if len(raw_keyframes) > max_keyframes:
                raise ValueError("keyframe limit")
            if raw_keyframes:
                keyframes = self._parse_keyframes(raw_keyframes, max_speed)
            else:
                keyframes = ()

            plans = self._nonnegative_int(state["plans"], "plans")
        except (SpeedRampError, TypeError, ValueError, OverflowError) as exc:
            raise SpeedRampError("SPEED_RAMP_SNAPSHOT_INVALID", state) from exc

        with self._lock:
            self.frame_rate = frame_rate
            self.max_speed = max_speed
            self.max_keyframes = max_keyframes
            self.max_accel = max_accel
            self.max_output_frames = max_output_frames
            self._source_frames = source_frames
            self._keyframes = keyframes
            self._plans = plans

    def reset(self) -> None:
        with self._lock:
            self._keyframes = ()
            self._source_frames = None
            self._plans = 0
