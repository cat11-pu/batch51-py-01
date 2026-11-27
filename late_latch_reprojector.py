"""Late-latch reprojection for a stereo compositor: prediction, depth reprojection, drop compensation."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, replace


SNAPSHOT_VERSION = 1
EYES = ("left", "right")


class ReprojectError(ValueError):
    """Raised when a reprojection request cannot be served."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Pose:
    frame: int
    eye: str
    position: tuple[float, float, float]
    orientation: tuple[float, float, float, float]
    timestamp_ms: float


@dataclass(frozen=True)
class HorizonPlan:
    requested_ms: float
    used_ms: float
    clipped: bool


@dataclass(frozen=True)
class ReprojectionPlan:
    frame: int
    eye: str
    predicted_at_ms: float
    used_horizon_ms: float
    total_samples: int
    low_confidence: int
    reprojected: bool


class LateLatchReprojector:
    """Reproject rendered frames onto the latest pose at composite time."""

    def __init__(self, *, min_horizon_ms: float = 0.0,
                 max_horizon_ms: float = 40.0, focal: float = 900.0,
                 depth_epsilon: float = 1e-3) -> None:
        self.min_horizon_ms = min_horizon_ms
        self.max_horizon_ms = max_horizon_ms
        self.focal = focal
        self.depth_epsilon = depth_epsilon
        self._lock = threading.RLock()
        self._poses: dict[tuple[int, str], Pose] = {}
        self._plans: dict[tuple[int, str], ReprojectionPlan] = {}
        self._stats = {
            "poses": 0,
            "late_poses": 0,
            "reprojects": 0,
            "latches": 0,
            "dropped": 0,
            "low_confidence": 0,
        }

    def submit_pose(self, frame, *, eye, position, orientation, timestamp_ms):
        if eye not in EYES:
            raise ReprojectError("REPROJECT_INVALID_EYE",
                                 {"eye": eye, "allowed": list(EYES)})
        key = (frame, eye)
        with self._lock:
            if key in self._poses:
                self._stats["late_poses"] += 1
                return False
            pose = Pose(
                frame=frame,
                eye=eye,
                position=tuple(float(v) for v in position),
                orientation=tuple(float(v) for v in orientation),
                timestamp_ms=float(timestamp_ms),
            )
            self._poses[key] = pose
            self._stats["poses"] += 1
            return True

    def pose_for(self, frame, *, eye):
        with self._lock:
            return self._poses.get((frame, eye))

    def prediction_horizon(self, *, render_time_ms, compose_time_ms):
        requested = float(compose_time_ms) - float(render_time_ms)
        used = min(max(requested, self.min_horizon_ms), self.max_horizon_ms)
        return HorizonPlan(requested_ms=requested, used_ms=used,
                           clipped=used != requested)

    def reproject(self, frame, *, eye, depths, rotation_only=False):
        key = (frame, eye)
        with self._lock:
            pose = self._poses.get(key)
            if pose is None:
                raise ReprojectError("REPROJECT_NO_POSE",
                                     {"frame": frame, "eye": eye})
            plan = self._build_plan(frame, eye, pose.timestamp_ms, 0.0, depths,
                                    rotation_only=rotation_only)
            self._plans[key] = plan
            self._stats["reprojects"] += 1
            return plan

    def late_latch(self, frame, *, compose_time_ms, depths):
        with self._lock:
            poses = {}
            for eye in EYES:
                pose = self._poses.get((frame, eye))
                if pose is None:
                    raise ReprojectError("REPROJECT_MISSING_EYE",
                                         {"frame": frame, "eye": eye})
                poses[eye] = pose
            predicted_at = float(compose_time_ms)
            plans = {}
            for eye in EYES:
                pose = poses[eye]
                horizon = self.prediction_horizon(
                    render_time_ms=pose.timestamp_ms,
                    compose_time_ms=compose_time_ms)
                eye_depths = depths.get(eye, ()) if depths is not None else ()
                plan = self._build_plan(frame, eye, predicted_at,
                                        horizon.used_ms, eye_depths,
                                        rotation_only=False)
                self._plans[(frame, eye)] = plan
                plans[eye] = plan
            self._stats["latches"] += 1
            return plans

    def mark_low_confidence(self, frame, *, eye, count):
        if count < 0:
            raise ReprojectError("REPROJECT_INVALID_COUNT",
                                 {"frame": frame, "eye": eye, "count": count})
        key = (frame, eye)
        with self._lock:
            plan = self._plans.get(key)
            if plan is None:
                raise ReprojectError("REPROJECT_NO_POSE",
                                     {"frame": frame, "eye": eye})
            plan = replace(plan, low_confidence=plan.low_confidence + count)
            self._plans[key] = plan
            self._stats["low_confidence"] += count
            return plan.low_confidence

    def frame_state(self, frame, *, eye=None):
        with self._lock:
            if eye is not None:
                return self._plans.get((frame, eye))
            return {e: plan for (f, e), plan in self._plans.items() if f == frame}

    def drop_frame(self, frame):
        with self._lock:
            removed = 0
            for eye in EYES:
                key = (frame, eye)
                if key in self._poses or key in self._plans:
                    removed += 1
                self._poses.pop(key, None)
                self._plans.pop(key, None)
            self._stats["dropped"] += removed
            return removed

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "poses": [
                    {"frame": p.frame, "eye": p.eye,
                     "position": list(p.position),
                     "orientation": list(p.orientation),
                     "timestamp_ms": p.timestamp_ms}
                    for p in self._poses.values()
                ],
                "plans": [
                    {"frame": pl.frame, "eye": pl.eye,
                     "predicted_at_ms": pl.predicted_at_ms,
                     "used_horizon_ms": pl.used_horizon_ms,
                     "total_samples": pl.total_samples,
                     "low_confidence": pl.low_confidence,
                     "reprojected": pl.reprojected}
                    for pl in self._plans.values()
                ],
                "stats": dict(self._stats),
            }

    def restore(self, state):
        poses, plans, stats = self._parse_snapshot(state)
        with self._lock:
            self._poses = poses
            self._plans = plans
            self._stats = stats

    def stats(self):
        with self._lock:
            return dict(self._stats)

    def _build_plan(self, frame, eye, predicted_at_ms, used_horizon_ms,
                    depths, *, rotation_only):
        samples = list(depths) if depths is not None else []
        low_confidence = 0
        max_depth = 0.0
        for depth in samples:
            if depth is None:
                low_confidence += 1
                continue
            value = float(depth)
            if math.isnan(value) or value <= 0.0:
                low_confidence += 1
                continue
            if math.isinf(value):
                continue  # treated as max depth: zero parallax shift
            if value > max_depth:
                max_depth = value
        return ReprojectionPlan(
            frame=frame,
            eye=eye,
            predicted_at_ms=float(predicted_at_ms),
            used_horizon_ms=float(used_horizon_ms),
            total_samples=len(samples),
            low_confidence=low_confidence,
            reprojected=True,
        )

    @staticmethod
    def _parse_snapshot(state):
        invalid = ReprojectError("REPROJECT_SNAPSHOT_INVALID",
                                 {"reason": "unrecognized or corrupt snapshot"})
        try:
            if not isinstance(state, dict):
                raise invalid
            if state.get("version") != SNAPSHOT_VERSION:
                raise invalid
            raw_poses = state["poses"]
            raw_plans = state["plans"]
            raw_stats = state["stats"]
            if not isinstance(raw_poses, list) or not isinstance(raw_plans, list):
                raise invalid
            if not isinstance(raw_stats, dict):
                raise invalid

            poses = {}
            for entry in raw_poses:
                pose = Pose(
                    frame=entry["frame"],
                    eye=entry["eye"],
                    position=tuple(float(v) for v in entry["position"]),
                    orientation=tuple(float(v) for v in entry["orientation"]),
                    timestamp_ms=float(entry["timestamp_ms"]),
                )
                if pose.eye not in EYES or len(pose.position) != 3 \
                        or len(pose.orientation) != 4:
                    raise invalid
                poses[(pose.frame, pose.eye)] = pose

            plans = {}
            for entry in raw_plans:
                plan = ReprojectionPlan(
                    frame=entry["frame"],
                    eye=entry["eye"],
                    predicted_at_ms=float(entry["predicted_at_ms"]),
                    used_horizon_ms=float(entry["used_horizon_ms"]),
                    total_samples=int(entry["total_samples"]),
                    low_confidence=int(entry["low_confidence"]),
                    reprojected=bool(entry["reprojected"]),
                )
                if plan.eye not in EYES:
                    raise invalid
                plans[(plan.frame, plan.eye)] = plan

            stats = {}
            for name in ("poses", "late_poses", "reprojects", "latches",
                         "dropped", "low_confidence"):
                stats[name] = int(raw_stats[name])
            return poses, plans, stats
        except ReprojectError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError):
            raise invalid
