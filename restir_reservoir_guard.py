"""ReSTIR reservoir guard: weighted resampling with history and neighbour merging."""

from __future__ import annotations

import math
import random
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


SNAPSHOT_VERSION = 1


class ReservoirError(ValueError):
    """Raised when a reservoir operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReservoirState:
    pixel: tuple[int, int]
    sample_id: str
    weight_sum: float
    sample_count: int
    depth: float
    normal: tuple[float, float, float]
    frame: int
    history_frame: int
    history_valid: bool


@dataclass(frozen=True)
class ResolveResult:
    pixel: tuple[int, int]
    sample_id: str
    weight: float
    sample_count: int
    history_frame: int
    history_valid: bool


@dataclass
class _PixelReservoir:
    pixel: tuple[int, int]
    sample_id: str
    weight_sum: float
    sample_count: int
    depth: float
    normal: tuple[float, float, float]
    frame: int
    history_frame: int = -1
    history_valid: bool = False


def _invalid_sample(detail: object) -> ReservoirError:
    return ReservoirError("RESERVOIR_INVALID_SAMPLE", detail)


def _snapshot_invalid(detail: object) -> ReservoirError:
    return ReservoirError("RESERVOIR_SNAPSHOT_INVALID", detail)


def _coerce_pixel(pixel: object) -> tuple[int, int]:
    try:
        values = tuple(pixel)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid_sample({"pixel": pixel}) from exc
    if len(values) != 2:
        raise _invalid_sample({"pixel": pixel})
    result = []
    for value in values:
        if isinstance(value, bool):
            raise _invalid_sample({"pixel": pixel})
        try:
            integer = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError, OverflowError) as exc:
            raise _invalid_sample({"pixel": pixel}) from exc
        if integer != value:
            raise _invalid_sample({"pixel": pixel})
        result.append(integer)
    return result[0], result[1]


def _coerce_normal(normal: object) -> tuple[float, float, float]:
    try:
        values = tuple(float(value) for value in normal)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise _invalid_sample({"normal": normal}) from exc
    if len(values) != 3 or not all(math.isfinite(value) for value in values):
        raise _invalid_sample({"normal": normal})
    return values[0], values[1], values[2]


def _coerce_sample_id(sample_id: object) -> str:
    if not isinstance(sample_id, str) or not sample_id.strip():
        raise _invalid_sample({"sample_id": sample_id})
    return sample_id


def _coerce_weight(value: object) -> float:
    try:
        weight = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise _invalid_sample({"target_weight": value}) from exc
    if not math.isfinite(weight) or weight <= 0.0:
        raise _invalid_sample({"target_weight": value})
    return weight


def _coerce_finite(value: object, field: str) -> float:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise _invalid_sample({field: value}) from exc
    if not math.isfinite(number):
        raise _invalid_sample({field: value})
    return number


def _coerce_frame(value: object) -> int:
    if isinstance(value, bool):
        raise _invalid_sample({"frame": value})
    try:
        frame = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise _invalid_sample({"frame": value}) from exc
    if frame != value:
        raise _invalid_sample({"frame": value})
    return frame


def _coerce_count(value: object, field: str = "sample_count") -> int:
    if isinstance(value, bool):
        raise _snapshot_invalid({field: value})
    try:
        count = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError) as exc:
        raise _snapshot_invalid({field: value}) from exc
    if count != value or count < 0:
        raise _snapshot_invalid({field: value})
    return count


class ReservoirGuard:
    """Per-pixel reservoir with history validation and neighbour merging."""

    def __init__(self, *, max_samples: int = 32, depth_threshold: float = 0.05,
                 normal_threshold: float = 0.9, seed: int = 20261127) -> None:
        if isinstance(max_samples, bool):
            raise ReservoirError("RESERVOIR_INVALID_CONFIG", {"max_samples": max_samples})
        try:
            cap = int(max_samples)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ReservoirError(
                "RESERVOIR_INVALID_CONFIG", {"max_samples": max_samples}
            ) from exc
        if cap != max_samples or cap <= 0:
            raise ReservoirError("RESERVOIR_INVALID_CONFIG", {"max_samples": max_samples})

        self.max_samples = cap
        self.depth_threshold = float(depth_threshold)
        self.normal_threshold = float(normal_threshold)
        self.seed = seed
        self._rng = random.Random(seed)
        self._lock = threading.RLock()
        self._pixels: dict[tuple[int, int], _PixelReservoir] = {}
        self._current_frame: int | None = None
        self._stats = {
            "updates": 0,
            "merged_history": 0,
            "rejected_history": 0,
            "merged_neighbors": 0,
            "resets": 0,
        }

    @staticmethod
    def _as_state(pixel: _PixelReservoir) -> ReservoirState:
        return ReservoirState(
            pixel=pixel.pixel,
            sample_id=pixel.sample_id,
            weight_sum=pixel.weight_sum,
            sample_count=pixel.sample_count,
            depth=pixel.depth,
            normal=pixel.normal,
            frame=pixel.frame,
            history_frame=pixel.history_frame,
            history_valid=pixel.history_valid,
        )

    def _require_pixel(self, pixel: object) -> _PixelReservoir:
        key = _coerce_pixel(pixel)
        state = self._pixels.get(key)
        if state is None:
            raise ReservoirError("RESERVOIR_UNKNOWN_PIXEL", key)
        return state

    def _set_current_frame(self, frame: int) -> None:
        if self._current_frame is not None and frame < self._current_frame:
            for state in self._pixels.values():
                state.history_frame = -1
                state.history_valid = False
        self._current_frame = frame

    def _effective_frame(self, state: _PixelReservoir) -> int:
        if self._current_frame is None:
            return state.frame
        return self._current_frame

    def _history_geometry_matches(
        self,
        state: _PixelReservoir,
        *,
        depth: float,
        normal: tuple[float, float, float],
        frame: int,
    ) -> bool:
        if frame != self._effective_frame(state):
            return False
        depth_delta = abs(depth - state.depth)
        depth_tolerance = 8.0 * math.ulp(
            max(abs(depth_delta), abs(self.depth_threshold), 1.0)
        )
        if depth_delta > self.depth_threshold and not math.isclose(
            depth_delta, self.depth_threshold, rel_tol=0.0, abs_tol=depth_tolerance
        ):
            return False
        dot = (
            normal[0] * state.normal[0]
            + normal[1] * state.normal[1]
            + normal[2] * state.normal[2]
        )
        normal_tolerance = 8.0 * math.ulp(
            max(abs(dot), abs(self.normal_threshold), 1.0)
        )
        return dot >= self.normal_threshold or math.isclose(
            dot, self.normal_threshold, rel_tol=0.0, abs_tol=normal_tolerance
        )

    def update_sample(self, pixel, *, sample_id, target_weight, depth, normal, frame):
        key = _coerce_pixel(pixel)
        clean_id = _coerce_sample_id(sample_id)
        weight = _coerce_weight(target_weight)
        clean_depth = _coerce_finite(depth, "depth")
        clean_normal = _coerce_normal(normal)
        clean_frame = _coerce_frame(frame)

        with self._lock:
            self._set_current_frame(clean_frame)
            self._stats["updates"] += 1
            state = self._pixels.get(key)
            if state is None:
                state = _PixelReservoir(
                    pixel=key,
                    sample_id=clean_id,
                    weight_sum=weight,
                    sample_count=1,
                    depth=clean_depth,
                    normal=clean_normal,
                    frame=clean_frame,
                )
                self._pixels[key] = state
                return self._as_state(state)

            state.depth = clean_depth
            state.normal = clean_normal
            state.frame = clean_frame
            state.history_frame = -1
            state.history_valid = False
            if state.sample_count < self.max_samples:
                state.sample_id = clean_id
                state.sample_count += 1
                state.weight_sum += weight
                return self._as_state(state)

            replacement_probability = weight / (state.weight_sum + weight)
            if self._rng.random() < replacement_probability:
                state.sample_id = clean_id
                state.weight_sum = (
                    state.weight_sum * (1.0 - replacement_probability) + weight
                )
            return self._as_state(state)

    @staticmethod
    def _history_like(history: object) -> ReservoirState:
        if isinstance(history, ReservoirState):
            return history
        try:
            return ReservoirState(
                pixel=_coerce_pixel(history.pixel),  # type: ignore[attr-defined]
                sample_id=_coerce_sample_id(history.sample_id),  # type: ignore[attr-defined]
                weight_sum=_coerce_weight(history.weight_sum),  # type: ignore[attr-defined]
                sample_count=_coerce_count(history.sample_count),  # type: ignore[attr-defined]
                depth=_coerce_finite(history.depth, "depth"),  # type: ignore[attr-defined]
                normal=_coerce_normal(history.normal),  # type: ignore[attr-defined]
                frame=_coerce_frame(history.frame),  # type: ignore[attr-defined]
                history_frame=_coerce_frame(history.history_frame),  # type: ignore[attr-defined]
                history_valid=bool(history.history_valid),  # type: ignore[attr-defined]
            )
        except AttributeError as exc:
            raise ReservoirError("RESERVOIR_INVALID_HISTORY", history) from exc

    def merge_history(self, pixel, history):
        source = self._history_like(history)
        if source.sample_count <= 0:
            raise ReservoirError("RESERVOIR_INVALID_HISTORY", source)
        with self._lock:
            state = self._require_pixel(pixel)
            if not self._history_geometry_matches(
                state,
                depth=source.depth,
                normal=source.normal,
                frame=source.frame,
            ):
                state.history_frame = -1
                state.history_valid = False
                self._stats["rejected_history"] += 1
                return self._as_state(state)

            state.weight_sum += source.weight_sum
            state.sample_count = min(
                self.max_samples, state.sample_count + source.sample_count
            )
            state.history_frame = source.frame
            state.history_valid = True
            self._stats["merged_history"] += 1
            return self._as_state(state)

    def merge_neighbors(self, pixel, neighbors):
        sources = [self._history_like(item) for item in neighbors]
        for source in sources:
            if source.sample_count <= 0:
                raise ReservoirError("RESERVOIR_INVALID_HISTORY", source)

        with self._lock:
            state = self._require_pixel(pixel)
            for source in sources:
                state.weight_sum += source.weight_sum / source.sample_count
                state.sample_count = min(
                    self.max_samples, state.sample_count + source.sample_count
                )
                self._stats["merged_neighbors"] += 1
            return self._as_state(state)

    def validate_history(self, pixel, *, depth, normal, frame):
        clean_depth = _coerce_finite(depth, "depth")
        clean_normal = _coerce_normal(normal)
        clean_frame = _coerce_frame(frame)
        with self._lock:
            state = self._require_pixel(pixel)
            return self._history_geometry_matches(
                state, depth=clean_depth, normal=clean_normal, frame=clean_frame
            )

    def advance_frame(self, frame):
        clean_frame = _coerce_frame(frame)
        with self._lock:
            self._set_current_frame(clean_frame)

    def resolve(self, pixel):
        with self._lock:
            state = self._require_pixel(pixel)
            return ResolveResult(
                pixel=state.pixel,
                sample_id=state.sample_id,
                weight=state.weight_sum / state.sample_count,
                sample_count=state.sample_count,
                history_frame=state.history_frame,
                history_valid=state.history_valid,
            )

    def pixel_state(self, pixel):
        with self._lock:
            key = _coerce_pixel(pixel)
            state = self._pixels.get(key)
            if state is None:
                return None
            return self._as_state(state)

    def reset(self, pixel=None):
        with self._lock:
            if pixel is None:
                self._pixels.clear()
            else:
                key = _coerce_pixel(pixel)
                self._pixels.pop(key, None)
            self._stats["resets"] += 1

    @staticmethod
    def _rng_state_to_data(state: tuple[Any, ...]) -> list[Any]:
        version, words, gauss_next = state
        return [int(version), [int(word) for word in words], gauss_next]

    @staticmethod
    def _rng_state_from_data(
        data: object, *, seed: int
    ) -> tuple[tuple[Any, ...], random.Random]:
        if data is None:
            rng = random.Random(seed)
            return rng.getstate(), rng
        try:
            if not isinstance(data, (list, tuple)) or len(data) != 3:
                raise ValueError
            version, words, gauss_next = data
            if isinstance(version, bool):
                raise ValueError
            version_number = int(version)
            if version_number != version:
                raise ValueError
            if not isinstance(words, (list, tuple)):
                raise ValueError
            if any(isinstance(word, bool) for word in words):
                raise ValueError
            word_tuple = tuple(int(word) for word in words)
            if gauss_next is not None:
                gauss_next = float(gauss_next)
                if not math.isfinite(gauss_next):
                    raise ValueError
            raw_state = (version_number, word_tuple, gauss_next)
            rng = random.Random(seed)
            rng.setstate(raw_state)  # type: ignore[arg-type]
            return raw_state, rng
        except (TypeError, ValueError, OverflowError) as exc:
            raise _snapshot_invalid({"rng_state": data}) from exc

    def snapshot(self):
        with self._lock:
            pixels = []
            for key in sorted(self._pixels):
                state = self._pixels[key]
                pixels.append(
                    {
                        "pixel": [state.pixel[0], state.pixel[1]],
                        "sample_id": state.sample_id,
                        "weight_sum": state.weight_sum,
                        "sample_count": state.sample_count,
                        "depth": state.depth,
                        "normal": list(state.normal),
                        "frame": state.frame,
                        "history_frame": state.history_frame,
                        "history_valid": state.history_valid,
                    }
                )
            return {
                "version": SNAPSHOT_VERSION,
                "seed": self.seed,
                "frame": self._current_frame,
                "max_samples": self.max_samples,
                "depth_threshold": self.depth_threshold,
                "normal_threshold": self.normal_threshold,
                "rng_state": self._rng_state_to_data(self._rng.getstate()),
                "stats": self.stats(),
                "pixels": pixels,
            }

    def _parse_snapshot(self, state: object):
        if not isinstance(state, Mapping):
            raise _snapshot_invalid({"state": state})
        version = state.get("version")
        if isinstance(version, bool) or version != SNAPSHOT_VERSION:
            raise _snapshot_invalid({"version": version})

        raw_pixels = state.get("pixels")
        if not isinstance(raw_pixels, list):
            raise _snapshot_invalid({"pixels": raw_pixels})

        try:
            raw_max_samples = state.get("max_samples", self.max_samples)
            if isinstance(raw_max_samples, bool):
                raise ValueError
            max_samples = int(raw_max_samples)
            if max_samples <= 0 or max_samples != raw_max_samples:
                raise ValueError
            depth_threshold = float(state.get("depth_threshold", self.depth_threshold))
            normal_threshold = float(state.get("normal_threshold", self.normal_threshold))
            if not math.isfinite(depth_threshold) or not math.isfinite(normal_threshold):
                raise ValueError
            seed = state.get("seed", self.seed)
            random.Random(seed)
            raw_frame = state.get("frame", self._current_frame)
            current_frame = None if raw_frame is None else _coerce_frame(raw_frame)
        except (TypeError, ValueError, OverflowError) as exc:
            raise _snapshot_invalid({"config": dict(state)}) from exc

        pixels: dict[tuple[int, int], _PixelReservoir] = {}
        for raw in raw_pixels:
            if not isinstance(raw, Mapping):
                raise _snapshot_invalid({"pixel": raw})
            try:
                key = _coerce_pixel(raw["pixel"])
                if key in pixels:
                    raise ValueError("duplicate pixel")
                sample_count = _coerce_count(raw["sample_count"])
                if sample_count <= 0 or sample_count > max_samples:
                    raise ValueError("sample_count out of range")
                weight_sum = _coerce_weight(raw["weight_sum"])
                history_valid = raw["history_valid"]
                if not isinstance(history_valid, bool):
                    raise ValueError("history_valid must be bool")
                pixel = _PixelReservoir(
                    pixel=key,
                    sample_id=_coerce_sample_id(raw["sample_id"]),
                    weight_sum=weight_sum,
                    sample_count=sample_count,
                    depth=_coerce_finite(raw["depth"], "depth"),
                    normal=_coerce_normal(raw["normal"]),
                    frame=_coerce_frame(raw["frame"]),
                    history_frame=_coerce_frame(raw["history_frame"]),
                    history_valid=history_valid,
                )
            except (KeyError, TypeError, ValueError, ReservoirError) as exc:
                raise _snapshot_invalid({"pixel": raw}) from exc
            pixels[key] = pixel

        raw_stats = state.get("stats", {})
        if not isinstance(raw_stats, Mapping):
            raise _snapshot_invalid({"stats": raw_stats})
        counters = {}
        for name in self._stats:
            raw_count = raw_stats.get(name, 0)
            if isinstance(raw_count, bool):
                raise _snapshot_invalid({name: raw_count})
            try:
                count = int(raw_count)
            except (TypeError, ValueError, OverflowError) as exc:
                raise _snapshot_invalid({name: raw_count}) from exc
            if count < 0 or count != raw_count:
                raise _snapshot_invalid({name: raw_count})
            counters[name] = count

        _, rng = self._rng_state_from_data(state.get("rng_state"), seed=seed)
        return {
            "seed": seed,
            "current_frame": current_frame,
            "max_samples": max_samples,
            "depth_threshold": depth_threshold,
            "normal_threshold": normal_threshold,
            "pixels": pixels,
            "stats": counters,
            "rng": rng,
        }

    def restore(self, state):
        parsed = self._parse_snapshot(state)
        with self._lock:
            self.seed = parsed["seed"]
            self._current_frame = parsed["current_frame"]
            self.max_samples = parsed["max_samples"]
            self.depth_threshold = parsed["depth_threshold"]
            self.normal_threshold = parsed["normal_threshold"]
            self._pixels = parsed["pixels"]
            self._stats = parsed["stats"]
            self._rng = parsed["rng"]

    def stats(self):
        with self._lock:
            return {
                "pixels": len(self._pixels),
                "updates": self._stats["updates"],
                "merged_history": self._stats["merged_history"],
                "rejected_history": self._stats["rejected_history"],
                "merged_neighbors": self._stats["merged_neighbors"],
                "resets": self._stats["resets"],
            }
