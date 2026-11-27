"""Cost based motion matching over indexed animation clips."""

from __future__ import annotations

import copy
import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Real


class MotionError(ValueError):
    """Raised when a clip, an index request or a query is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Frame:
    time_ms: int
    pose: tuple
    trajectory: tuple


@dataclass(frozen=True)
class Candidate:
    clip_id: str
    frame_index: int
    cost: float


@dataclass(frozen=True)
class QueryResult:
    candidates: tuple
    index_version: int


@dataclass(frozen=True)
class IndexReport:
    clips: int
    frames: int
    version: int
    rebuilt: bool


@dataclass(frozen=True)
class _IndexedFrame:
    clip_id: str
    frame_index: int
    pose: tuple
    trajectory: tuple


@dataclass(frozen=True)
class _IndexState:
    version: int
    pose_weight: float
    trajectory_weight: float
    pose_dim: int | None
    traj_dim: int | None
    entries: tuple


_FRAME_KEYS = frozenset(("time_ms", "pose", "trajectory"))
_STAT_KEYS = ("clips", "frames", "builds", "reused", "queries",
              "commits", "removals", "rejections")
_SNAPSHOT_KEYS = frozenset((
    "version", "clips", "pose_weight", "trajectory_weight",
    "exclusion_window", "index_version", "dirty", "current", "stats",
))


def _reject(code: str, detail: object = None) -> None:
    raise MotionError(code, detail)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _finite_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("feature must be a real number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("feature must be finite")
    return number


def _vector(value: object) -> tuple:
    if isinstance(value, (str, bytes, bytearray)) or isinstance(value, Mapping):
        raise ValueError("feature must be a sequence")
    try:
        items = tuple(value)
    except TypeError as exc:
        raise ValueError("feature must be a sequence") from exc
    if not items:
        raise ValueError("feature must not be empty")
    return tuple(_finite_float(item) for item in items)


def _trajectory(value: object) -> tuple:
    if isinstance(value, (str, bytes, bytearray)) or isinstance(value, Mapping):
        raise ValueError("trajectory must be a sequence")
    try:
        points = tuple(value)
    except TypeError as exc:
        raise ValueError("trajectory must be a sequence") from exc
    if not points:
        raise ValueError("trajectory must not be empty")
    return tuple(_vector(point) for point in points)


def _validate_time(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("time_ms must be a real number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("time_ms must be finite")
    return number


def _parse_clip_frames(frames: object) -> tuple:
    if frames is None:
        _reject("MOTION_EMPTY_CLIP")
    if isinstance(frames, (str, bytes, bytearray, Mapping)):
        _reject("MOTION_INVALID_CLIP")
    try:
        materialized = list(frames)
    except TypeError:
        _reject("MOTION_INVALID_CLIP")
    if not materialized:
        _reject("MOTION_EMPTY_CLIP")

    parsed = []
    previous_time = None
    pose_dim = None
    traj_dim = None
    traj_len = None
    for raw_frame in materialized:
        if not isinstance(raw_frame, Mapping):
            _reject("MOTION_INVALID_CLIP")
        if not _FRAME_KEYS.issubset(raw_frame.keys()):
            _reject("MOTION_INVALID_CLIP")
        try:
            time_ms = _validate_time(raw_frame["time_ms"])
            pose = _vector(raw_frame["pose"])
            trajectory = _trajectory(raw_frame["trajectory"])
        except (TypeError, ValueError, OverflowError) as exc:
            _reject("MOTION_INVALID_FRAMES", str(exc))

        if previous_time is not None and time_ms <= previous_time:
            _reject("MOTION_INVALID_FRAMES", "time_ms must strictly increase")
        previous_time = time_ms

        if pose_dim is None:
            pose_dim = len(pose)
            traj_dim = len(trajectory[0])
            traj_len = len(trajectory)
        if (len(pose) != pose_dim or len(trajectory) != traj_len
                or any(len(point) != traj_dim for point in trajectory)):
            _reject("MOTION_DIM_MISMATCH")

        parsed.append(Frame(time_ms, pose, trajectory))
    return tuple(parsed)


def _clip_dimensions(parsed: tuple) -> tuple:
    first = parsed[0]
    return len(first.pose), len(first.trajectory[0]), len(first.trajectory)


def _validate_weights(pose_weight: object, trajectory_weight: object) -> tuple:
    try:
        pose = _finite_float(pose_weight)
        trajectory = _finite_float(trajectory_weight)
    except (TypeError, ValueError, OverflowError):
        _reject("MOTION_INVALID_WEIGHTS")
    if pose < 0.0 or trajectory < 0.0:
        _reject("MOTION_INVALID_WEIGHTS")
    if pose == 0.0 and trajectory == 0.0:
        _reject("MOTION_INVALID_WEIGHTS")
    return pose, trajectory


def _validate_exclusion_window(value: object) -> int:
    if not _is_int(value) or value < 0:
        _reject("MOTION_INVALID_EXCLUSION_WINDOW")
    return value


def _point_distance(left: tuple, right: tuple) -> float:
    return math.sqrt(sum((a - b) * (a - b) for a, b in zip(left, right)))


def _resample_trajectory(trajectory: tuple, count: int) -> tuple:
    """Resample an equal-time trajectory to ``count`` equally spaced samples."""
    current = len(trajectory)
    if current == count:
        return trajectory
    if count <= 0:
        raise ValueError("sample count must be positive")
    if count == 1:
        return (trajectory[0],)
    if current == 1:
        return (trajectory[0],) * count

    result = []
    scale = current - 1
    for index in range(count):
        position = (index * scale) / (count - 1)
        lower = int(math.floor(position))
        upper = min(lower + 1, scale)
        fraction = position - lower
        if upper == lower:
            result.append(trajectory[lower])
        else:
            result.append(tuple(
                start + (end - start) * fraction
                for start, end in zip(trajectory[lower], trajectory[upper])
            ))
    return tuple(result)


def _trajectory_cost(trajectory: tuple, expected: tuple) -> float:
    if len(trajectory) != len(expected):
        trajectory = _resample_trajectory(expected, len(trajectory))
    if not trajectory:
        raise ValueError("trajectory must not be empty")
    return sum(_point_distance(left, right)
               for left, right in zip(trajectory, expected)) / len(trajectory)


def _rounded(value: float) -> float:
    rounded = round(value, 6)
    return 0.0 if rounded == 0.0 else rounded


class MotionMatchingIndex:
    """Index clip poses and future trajectories for cheapest frame lookup."""

    def __init__(self, *, pose_weight: float = 1.0,
                 trajectory_weight: float = 1.0,
                 exclusion_window: int = 2) -> None:
        self._lock = threading.RLock()
        pose, trajectory = _validate_weights(pose_weight, trajectory_weight)
        self._pose_weight = pose
        self._trajectory_weight = trajectory
        self._exclusion_window = _validate_exclusion_window(exclusion_window)
        self._clips: dict = {}
        self._pose_dim = None
        self._traj_dim = None
        self._traj_len = None
        self._version = 0
        self._index_version = 0
        self._index: _IndexState | None = None
        self._dirty = True
        self._current = None
        self._stats = {key: 0 for key in _STAT_KEYS}

    def _reject(self, code: str, detail: object = None) -> None:
        self._stats["rejections"] += 1
        _reject(code, detail)

    def _set_dimensions(self, dims: tuple) -> None:
        self._pose_dim, self._traj_dim, self._traj_len = dims

    def _clear_dimensions(self) -> None:
        self._pose_dim = None
        self._traj_dim = None
        self._traj_len = None

    def _mark_dirty(self) -> None:
        self._dirty = True

    def _make_index(self, version: int, weights: tuple) -> _IndexState:
        entries = []
        for clip_id, frames in self._clips.items():
            for frame_index, frame in enumerate(frames):
                entries.append(_IndexedFrame(
                    clip_id, frame_index, frame.pose, frame.trajectory))
        return _IndexState(
            version=version,
            pose_weight=weights[0],
            trajectory_weight=weights[1],
            pose_dim=self._pose_dim,
            traj_dim=self._traj_dim,
            entries=tuple(entries),
        )

    def add_clip(self, clip_id: str, frames) -> int:
        with self._lock:
            if not isinstance(clip_id, str) or not clip_id.strip():
                self._reject("MOTION_INVALID_CLIP")
            try:
                parsed = _parse_clip_frames(frames)
            except MotionError as exc:
                self._reject(exc.code, exc.detail)
            if clip_id in self._clips:
                self._reject("MOTION_DUPLICATE_CLIP", clip_id)

            dims = _clip_dimensions(parsed)
            if self._clips:
                if (dims[0] != self._pose_dim or dims[1] != self._traj_dim
                        or dims[2] != self._traj_len):
                    self._reject("MOTION_DIM_MISMATCH")
            else:
                self._set_dimensions(dims)

            self._clips[clip_id] = parsed
            self._stats["clips"] = len(self._clips)
            self._stats["frames"] += len(parsed)
            self._mark_dirty()
            return len(parsed)

    def remove_clip(self, clip_id: str) -> int:
        with self._lock:
            if not isinstance(clip_id, str) or clip_id not in self._clips:
                self._reject("MOTION_UNKNOWN_CLIP", clip_id)
            frames = self._clips.pop(clip_id)
            self._stats["clips"] = len(self._clips)
            self._stats["frames"] -= len(frames)
            self._stats["removals"] += 1
            if not self._clips:
                self._clear_dimensions()
            if self._current is not None and self._current[0] == clip_id:
                self._current = None
            self._mark_dirty()
            return len(frames)

    def build_index(self) -> IndexReport:
        with self._lock:
            if self._index is not None and not self._dirty:
                self._stats["reused"] += 1
                return IndexReport(
                    clips=len(self._clips),
                    frames=self._stats["frames"],
                    version=self._index.version,
                    rebuilt=False,
                )

            self._version += 1
            weights = (self._pose_weight, self._trajectory_weight)
            index = self._make_index(self._version, weights)
            self._index = index
            self._index_version = index.version
            self._dirty = False
            self._stats["builds"] += 1
            return IndexReport(
                clips=len(self._clips),
                frames=self._stats["frames"],
                version=index.version,
                rebuilt=True,
            )

    def _validate_state(self, state: object, index: _IndexState) -> tuple:
        if not isinstance(state, Mapping):
            self._reject("MOTION_DIM_MISMATCH", "state must be a mapping")
        if "pose" not in state or "trajectory" not in state:
            self._reject("MOTION_DIM_MISMATCH", "state is missing features")
        try:
            pose = _vector(state["pose"])
            trajectory = _trajectory(state["trajectory"])
        except (TypeError, ValueError, OverflowError) as exc:
            self._reject("MOTION_DIM_MISMATCH", str(exc))

        if index.pose_dim is None or index.traj_dim is None:
            if not index.entries:
                return pose, trajectory
        if len(pose) != index.pose_dim:
            self._reject("MOTION_DIM_MISMATCH", "pose dimension differs")
        if any(len(point) != index.traj_dim for point in trajectory):
            self._reject("MOTION_DIM_MISMATCH",
                         "trajectory point dimension differs")
        return pose, trajectory

    def _cost(self, frame: _IndexedFrame, pose: tuple, trajectory: tuple,
              weights: tuple) -> float:
        pose_cost = _point_distance(pose, frame.pose)
        trajectory_cost = _trajectory_cost(trajectory, frame.trajectory)
        return _rounded(pose_cost * weights[0]
                        + trajectory_cost * weights[1])

    def query(self, state: dict, *, limit: int = 8) -> QueryResult:
        with self._lock:
            if not _is_int(limit) or limit <= 0:
                self._reject("MOTION_INVALID_LIMIT")
            if self._index is None or self._dirty:
                self._reject("MOTION_INDEX_NOT_BUILT")

            index = self._index
            pose, trajectory = self._validate_state(state, index)
            weights = (index.pose_weight, index.trajectory_weight)

            excluded_range = None
            if self._current is not None:
                current_clip, current_frame = self._current
                excluded_range = (
                    current_clip,
                    current_frame,
                    current_frame + self._exclusion_window,
                )

            candidates = []
            seen = set()
            for frame in index.entries:
                key = (frame.clip_id, frame.frame_index)
                if key in seen:
                    continue
                seen.add(key)
                if excluded_range is not None:
                    clip_id, first, last = excluded_range
                    if (frame.clip_id == clip_id
                            and first <= frame.frame_index <= last):
                        continue
                candidates.append(Candidate(
                    frame.clip_id,
                    frame.frame_index,
                    self._cost(frame, pose, trajectory, weights),
                ))

            candidates.sort(key=lambda item: (
                item.cost, item.clip_id, item.frame_index))
            self._stats["queries"] += 1
            return QueryResult(tuple(candidates[:limit]), index.version)

    def set_weights(self, pose_weight: float,
                    trajectory_weight: float) -> tuple:
        with self._lock:
            try:
                weights = _validate_weights(pose_weight, trajectory_weight)
            except MotionError:
                self._reject("MOTION_INVALID_WEIGHTS")
            if weights != (self._pose_weight, self._trajectory_weight):
                self._pose_weight, self._trajectory_weight = weights
                self._mark_dirty()
            return weights

    def commit_choice(self, clip_id: str, frame_index: int) -> Candidate:
        with self._lock:
            if self._index is None or self._dirty:
                self._reject("MOTION_INDEX_NOT_BUILT")
            if not isinstance(clip_id, str) or not _is_int(frame_index):
                self._reject("MOTION_UNKNOWN_FRAME", (clip_id, frame_index))

            selected = None
            for frame in self._index.entries:
                if (frame.clip_id == clip_id
                        and frame.frame_index == frame_index):
                    selected = frame
                    break
            if selected is None:
                self._reject("MOTION_UNKNOWN_FRAME", (clip_id, frame_index))

            weights = (self._index.pose_weight,
                       self._index.trajectory_weight)
            zero_pose = (0.0,) * len(selected.pose)
            zero_trajectory = tuple(
                (0.0,) * len(point) for point in selected.trajectory)
            candidate = Candidate(
                clip_id,
                frame_index,
                self._cost(selected, zero_pose, zero_trajectory, weights),
            )
            self._current = (clip_id, frame_index)
            self._stats["commits"] += 1
            return candidate

    def current_choice(self) -> tuple | None:
        with self._lock:
            return self._current

    def index_version(self) -> int:
        with self._lock:
            return self._index_version

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _snapshot_clips(self) -> dict:
        clips = {}
        for clip_id, frames in self._clips.items():
            clips[clip_id] = [
                {
                    "time_ms": frame.time_ms,
                    "pose": frame.pose,
                    "trajectory": frame.trajectory,
                }
                for frame in frames
            ]
        return clips

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": self._version,
                "clips": self._snapshot_clips(),
                "pose_weight": self._pose_weight,
                "trajectory_weight": self._trajectory_weight,
                "exclusion_window": self._exclusion_window,
                "index_version": self._index_version,
                "dirty": self._dirty,
                "current": self._current,
                "stats": self._stats,
            })

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, Mapping):
            raise MotionError("MOTION_SNAPSHOT_INVALID")
        try:
            if not _SNAPSHOT_KEYS.issubset(state.keys()):
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            version = state["version"]
            index_version = state["index_version"]
            dirty = state["dirty"]
            exclusion_window = state["exclusion_window"]
            raw_stats = state["stats"]
            if not _is_int(version) or version < 0:
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            if not _is_int(index_version) or index_version < 0:
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            if index_version > version:
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            if not isinstance(dirty, bool):
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            if not _is_int(exclusion_window) or exclusion_window < 0:
                raise MotionError("MOTION_SNAPSHOT_INVALID")

            pose_weight, trajectory_weight = _validate_weights(
                state["pose_weight"], state["trajectory_weight"])

            raw_clips = state["clips"]
            if not isinstance(raw_clips, dict):
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            clips = {}
            dims = None
            frame_count = 0
            for clip_id, raw_frames in raw_clips.items():
                if not isinstance(clip_id, str) or not clip_id.strip():
                    raise MotionError("MOTION_SNAPSHOT_INVALID")
                parsed = _parse_clip_frames(raw_frames)
                clip_dims = _clip_dimensions(parsed)
                if dims is None:
                    dims = clip_dims
                elif clip_dims != dims:
                    raise MotionError("MOTION_SNAPSHOT_INVALID")
                clips[clip_id] = parsed
                frame_count += len(parsed)

            if not isinstance(raw_stats, Mapping):
                raise MotionError("MOTION_SNAPSHOT_INVALID")
            stats = {}
            for key in _STAT_KEYS:
                value = raw_stats.get(key)
                if not _is_int(value) or value < 0:
                    raise MotionError("MOTION_SNAPSHOT_INVALID")
                stats[key] = value
            if (stats["clips"] != len(clips)
                    or stats["frames"] != frame_count):
                raise MotionError("MOTION_SNAPSHOT_INVALID")

            current = state["current"]
            if current is not None:
                if (not isinstance(current, (tuple, list))
                        or len(current) != 2
                        or not isinstance(current[0], str)
                        or not _is_int(current[1])):
                    raise MotionError("MOTION_SNAPSHOT_INVALID")
                current_clip, current_frame = current
                if current_clip not in clips:
                    raise MotionError("MOTION_SNAPSHOT_INVALID")
                if not 0 <= current_frame < len(clips[current_clip]):
                    raise MotionError("MOTION_SNAPSHOT_INVALID")
                current = (current_clip, current_frame)

            if not dirty and index_version != version:
                raise MotionError("MOTION_SNAPSHOT_INVALID")

            index = None
            if not dirty:
                entries = []
                for clip_id, frames in clips.items():
                    for frame_index, frame in enumerate(frames):
                        entries.append(_IndexedFrame(
                            clip_id, frame_index, frame.pose,
                            frame.trajectory))
                index = _IndexState(
                    version=index_version,
                    pose_weight=pose_weight,
                    trajectory_weight=trajectory_weight,
                    pose_dim=None if dims is None else dims[0],
                    traj_dim=None if dims is None else dims[1],
                    entries=tuple(entries),
                )
            return {
                "clips": clips,
                "dims": dims,
                "pose_weight": pose_weight,
                "trajectory_weight": trajectory_weight,
                "exclusion_window": exclusion_window,
                "version": version,
                "index_version": index_version,
                "dirty": dirty,
                "current": current,
                "stats": stats,
                "index": index,
            }
        except MotionError as exc:
            if exc.code == "MOTION_SNAPSHOT_INVALID":
                raise
            raise MotionError("MOTION_SNAPSHOT_INVALID", exc.detail) from exc
        except (TypeError, ValueError, KeyError, OverflowError) as exc:
            raise MotionError("MOTION_SNAPSHOT_INVALID", str(exc)) from exc

    def restore(self, state: dict) -> None:
        with self._lock:
            prepared = self._parse_snapshot(state)
            self._clips = prepared["clips"]
            dims = prepared["dims"]
            if dims is None:
                self._clear_dimensions()
            else:
                self._set_dimensions(dims)
            self._pose_weight = prepared["pose_weight"]
            self._trajectory_weight = prepared["trajectory_weight"]
            self._exclusion_window = prepared["exclusion_window"]
            self._version = prepared["version"]
            self._index_version = prepared["index_version"]
            self._dirty = prepared["dirty"]
            self._current = prepared["current"]
            self._stats = prepared["stats"]
            self._index = prepared["index"]
