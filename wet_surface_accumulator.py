"""Wet surface accumulator: precipitation exposure, evaporation, puddle material blend."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass


_VERSION = 1
_PRECIPITATION_RATES = {
    "rain": {"gain": 0.50, "evaporation": 0.10},
    "snow": {"gain": 0.20, "evaporation": 0.04},
    "none": {"gain": 0.00, "evaporation": 0.10},
}
_CONFIG_KEYS = {
    "max_surfaces",
    "puddle_threshold",
    "base_roughness",
    "wet_roughness",
    "min_albedo",
}
_COUNTER_KEYS = {
    "surfaces",
    "accumulates",
    "evaporates",
    "publishes",
    "puddle_events",
    "rejected",
}
_SNAPSHOT_KEYS = {
    "version",
    "surfaces",
    "published",
    "frame",
    "config",
    "counters",
}


class WetSurfaceError(ValueError):
    """Raised when a surface update is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SurfaceState:
    """Published state of one surface patch."""

    surface_id: str
    wetness: float
    sheltered: bool
    exposure: float
    frame: int


@dataclass(frozen=True)
class MaterialState:
    """Wet material parameters derived from the published wetness."""

    surface_id: str
    roughness: float
    albedo_scale: float
    blended: bool


@dataclass(frozen=True)
class PuddleMask:
    """Puddle coverage of one surface patch."""

    surface_id: str
    depth: float
    blended: bool
    threshold: float


@dataclass(frozen=True)
class _SurfaceRecord:
    """Immutable properties of one registered surface."""

    surface_id: str
    sheltered: bool
    exposure: float


class WetSurfaceAccumulator:
    """Accumulate rain or snow per surface patch and blend a wet material on top."""

    def __init__(self, *, max_surfaces: int = 4096,
                 puddle_threshold: float = 0.6,
                 base_roughness: float = 0.85,
                 wet_roughness: float = 0.25,
                 min_albedo: float = 0.72) -> None:
        config = {
            "max_surfaces": max_surfaces,
            "puddle_threshold": puddle_threshold,
            "base_roughness": base_roughness,
            "wet_roughness": wet_roughness,
            "min_albedo": min_albedo,
        }
        self._validate_config(config)

        self._lock = threading.RLock()
        self._config = config
        self._surfaces: dict = {}
        self._working: dict = {}
        self._published: dict = {}
        self._precipitation = {"kind": "none", "intensity": 0.0}
        self._frame = 0
        self._counters: dict = {
            "surfaces": 0,
            "accumulates": 0,
            "evaporates": 0,
            "publishes": 0,
            "puddle_events": 0,
            "rejected": 0,
        }

    def register_surface(self, surface_id: str, *, sheltered: bool = False,
                         exposure: float = 1.0) -> SurfaceState:
        with self._lock:
            if not isinstance(surface_id, str) or not surface_id.strip():
                self._reject("WET_INVALID_ARGUMENT",
                             "surface_id must be a non-empty string")
            if not isinstance(sheltered, bool):
                self._reject("WET_INVALID_ARGUMENT",
                             "sheltered must be a boolean")
            if not _valid_number(exposure) or not 0.0 < exposure <= 1.0:
                self._reject("WET_INVALID_ARGUMENT",
                             "exposure must be in (0, 1]")
            if surface_id in self._surfaces:
                self._reject("WET_SURFACE_EXISTS", surface_id)
            if len(self._surfaces) >= self._config["max_surfaces"]:
                self._reject("WET_CAPACITY_EXCEEDED",
                             self._config["max_surfaces"])

            record = _SurfaceRecord(surface_id, sheltered, float(exposure))
            state = SurfaceState(
                surface_id=surface_id,
                wetness=0.0,
                sheltered=sheltered,
                exposure=float(exposure),
                frame=self._frame,
            )
            self._surfaces[surface_id] = record
            self._working[surface_id] = 0.0
            self._published[surface_id] = state
            self._counters["surfaces"] += 1
            return state

    def set_precipitation(self, kind: str, *, intensity: float = 1.0) -> dict:
        with self._lock:
            if not isinstance(kind, str) or kind not in _PRECIPITATION_RATES:
                self._reject("WET_INVALID_ARGUMENT",
                             "kind must be one of rain, snow, none")
            if not _valid_number(intensity) or not 0.0 <= intensity <= 1.0:
                self._reject("WET_INVALID_ARGUMENT",
                             "intensity must be in [0, 1]")
            self._precipitation = {
                "kind": kind,
                "intensity": float(intensity),
            }
            return dict(self._precipitation)

    def accumulate(self, surface_id: str, seconds: float) -> float:
        with self._lock:
            if not _valid_number(seconds) or seconds < 0.0:
                self._reject("WET_INVALID_ARGUMENT",
                             "seconds must be a non-negative number")
            record = self._surface_record(surface_id)

            rates = _PRECIPITATION_RATES[self._precipitation["kind"]]
            gain = rates["gain"] * self._precipitation["intensity"]
            if record.sheltered:
                gain = 0.0
            else:
                gain *= record.exposure
            loss = rates["evaporation"]
            wetness = _clamp_wetness(
                self._working[surface_id] + (gain - loss) * seconds
            )
            self._working[surface_id] = wetness
            self._counters["accumulates"] += 1
            return wetness

    def evaporate(self, surface_id: str, seconds: float) -> float:
        with self._lock:
            if not _valid_number(seconds) or seconds < 0.0:
                self._reject("WET_INVALID_ARGUMENT",
                             "seconds must be a non-negative number")
            self._surface_record(surface_id)

            rates = _PRECIPITATION_RATES[self._precipitation["kind"]]
            wetness = max(
                0.0,
                self._working[surface_id] - rates["evaporation"] * seconds,
            )
            self._working[surface_id] = wetness
            self._counters["evaporates"] += 1
            return wetness

    def publish(self, *, frame: int | None = None) -> int:
        with self._lock:
            if frame is None:
                next_frame = self._frame + 1
            else:
                if not _valid_int(frame) or frame < 0:
                    self._reject("WET_INVALID_ARGUMENT",
                                 "frame must be a non-negative integer")
                next_frame = frame

            published = {}
            puddle_events = 0
            threshold = self._config["puddle_threshold"]
            for surface_id, record in self._surfaces.items():
                wetness = self._working[surface_id]
                was_blended = _is_blended(
                    self._published[surface_id].wetness, threshold
                )
                now_blended = _is_blended(wetness, threshold)
                if now_blended and not was_blended:
                    puddle_events += 1
                published[surface_id] = SurfaceState(
                    surface_id=surface_id,
                    wetness=wetness,
                    sheltered=record.sheltered,
                    exposure=record.exposure,
                    frame=next_frame,
                )

            self._published = published
            self._frame = next_frame
            self._counters["publishes"] += 1
            self._counters["puddle_events"] += puddle_events
            return next_frame

    def wetness_of(self, surface_id: str) -> float:
        with self._lock:
            return self._published_state(surface_id).wetness

    def surface_of(self, surface_id: str) -> SurfaceState:
        with self._lock:
            return self._published_state(surface_id)

    def material_of(self, surface_id: str) -> MaterialState:
        with self._lock:
            state = self._published_state(surface_id)
            wetness = state.wetness
            roughness = (
                self._config["base_roughness"]
                + (self._config["wet_roughness"]
                   - self._config["base_roughness"]) * wetness
            )
            albedo_scale = 1.0 + (self._config["min_albedo"] - 1.0) * wetness
            return MaterialState(
                surface_id=surface_id,
                roughness=roughness,
                albedo_scale=albedo_scale,
                blended=_is_blended(wetness,
                                    self._config["puddle_threshold"]),
            )

    def puddle_mask(self, surface_id: str) -> PuddleMask:
        with self._lock:
            state = self._published_state(surface_id)
            threshold = self._config["puddle_threshold"]
            wetness = state.wetness
            blended = _is_blended(wetness, threshold)
            depth = _puddle_depth(wetness, threshold) if blended else 0.0
            return PuddleMask(
                surface_id=surface_id,
                depth=depth,
                blended=blended,
                threshold=threshold,
            )

    def snapshot(self) -> dict:
        with self._lock:
            surfaces = {
                surface_id: {
                    "surface_id": surface_id,
                    "wetness": self._working[surface_id],
                    "sheltered": record.sheltered,
                    "exposure": record.exposure,
                }
                for surface_id, record in self._surfaces.items()
            }
            published = {
                surface_id: {
                    "surface_id": state.surface_id,
                    "wetness": state.wetness,
                    "sheltered": state.sheltered,
                    "exposure": state.exposure,
                    "frame": state.frame,
                }
                for surface_id, state in self._published.items()
            }
            config = copy.deepcopy(self._config)
            config["precipitation"] = copy.deepcopy(self._precipitation)
            return copy.deepcopy({
                "version": _VERSION,
                "surfaces": surfaces,
                "published": published,
                "frame": self._frame,
                "config": config,
                "counters": dict(self._counters),
            })

    def restore(self, state: dict) -> None:
        parsed = self._parse_snapshot(state)
        with self._lock:
            config, precipitation = parsed["config"]
            self._config = config
            self._precipitation = precipitation
            self._surfaces = parsed["surfaces"]
            self._working = parsed["working"]
            self._published = parsed["published"]
            self._frame = parsed["frame"]
            self._counters = parsed["counters"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def _surface_record(self, surface_id: str) -> _SurfaceRecord:
        if not isinstance(surface_id, str):
            self._reject("WET_NO_SUCH_SURFACE", surface_id)
        try:
            return self._surfaces[surface_id]
        except KeyError:
            self._reject("WET_NO_SUCH_SURFACE", surface_id)

    def _published_state(self, surface_id: str) -> SurfaceState:
        if not isinstance(surface_id, str):
            self._reject("WET_NO_SUCH_SURFACE", surface_id)
        try:
            return self._published[surface_id]
        except KeyError:
            self._reject("WET_NO_SUCH_SURFACE", surface_id)

    def _reject(self, code: str, detail: object = None) -> None:
        self._counters["rejected"] += 1
        raise WetSurfaceError(code, detail)

    @staticmethod
    def _validate_config(config: dict) -> None:
        max_surfaces = config["max_surfaces"]
        if not _valid_int(max_surfaces) or max_surfaces < 0:
            raise WetSurfaceError(
                "WET_INVALID_ARGUMENT",
                "max_surfaces must be a non-negative integer",
            )

        threshold = config["puddle_threshold"]
        if not _valid_number(threshold) or not 0.0 <= threshold <= 1.0:
            raise WetSurfaceError(
                "WET_INVALID_ARGUMENT",
                "puddle_threshold must be in [0, 1]",
            )

        base = config["base_roughness"]
        wet = config["wet_roughness"]
        albedo = config["min_albedo"]
        if (not _valid_number(base) or not 0.0 <= base <= 1.0
                or not _valid_number(wet) or not 0.0 <= wet <= 1.0
                or wet > base):
            raise WetSurfaceError(
                "WET_INVALID_ARGUMENT",
                "roughness values must satisfy 0 <= wet <= base <= 1",
            )
        if not _valid_number(albedo) or not 0.0 <= albedo <= 1.0:
            raise WetSurfaceError(
                "WET_INVALID_ARGUMENT",
                "min_albedo must be in [0, 1]",
            )

        config["max_surfaces"] = int(max_surfaces)
        config["puddle_threshold"] = float(threshold)
        config["base_roughness"] = float(base)
        config["wet_roughness"] = float(wet)
        config["min_albedo"] = float(albedo)

    def _parse_snapshot(self, state: object) -> dict:
        try:
            return self._parse_snapshot_checked(state)
        except WetSurfaceError:
            raise
        except Exception as exc:
            raise WetSurfaceError("WET_SNAPSHOT_INVALID", str(exc)) from exc

    def _parse_snapshot_checked(self, state: object) -> dict:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "snapshot keys are invalid")
        if state["version"] != _VERSION or not _valid_int(state["version"]):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "unsupported snapshot version")

        frame = state["frame"]
        if not _valid_int(frame) or frame < 0:
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "frame must be a non-negative integer")

        config_value = state["config"]
        if not isinstance(config_value, dict):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "config must be a mapping")
        config_keys = set(config_value)
        if (not _CONFIG_KEYS.issubset(config_keys)
                or config_keys - _CONFIG_KEYS - {"precipitation"}):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "config keys are invalid")
        config = {key: config_value[key] for key in _CONFIG_KEYS}
        try:
            self._validate_config(config)
        except WetSurfaceError as exc:
            raise WetSurfaceError("WET_SNAPSHOT_INVALID", exc.detail) from exc

        precipitation = config_value.get(
            "precipitation",
            {"kind": "none", "intensity": 0.0},
        )
        if (not isinstance(precipitation, dict)
                or set(precipitation) != {"kind", "intensity"}):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "precipitation is invalid")
        kind = precipitation["kind"]
        intensity = precipitation["intensity"]
        if (not isinstance(kind, str) or kind not in _PRECIPITATION_RATES
                or not _valid_number(intensity)
                or not 0.0 <= intensity <= 1.0):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "precipitation is invalid")

        counters_value = state["counters"]
        if (not isinstance(counters_value, dict)
                or set(counters_value) != _COUNTER_KEYS):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "counters are invalid")
        counters = {}
        for key in _COUNTER_KEYS:
            value = counters_value[key]
            if not _valid_int(value) or value < 0:
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "counters are invalid")
            counters[key] = value

        surfaces_value = state["surfaces"]
        published_value = state["published"]
        if (not isinstance(surfaces_value, dict)
                or not isinstance(published_value, dict)
                or set(surfaces_value) != set(published_value)):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "surface mappings are inconsistent")
        if len(surfaces_value) > config["max_surfaces"]:
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "surface count exceeds max_surfaces")
        if counters["surfaces"] != len(surfaces_value):
            raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                  "surface counter is inconsistent")

        surfaces = {}
        working = {}
        for surface_id, value in surfaces_value.items():
            if not isinstance(surface_id, str) or not surface_id.strip():
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "surface_id is invalid")
            if not isinstance(value, dict) or set(value) != {
                    "surface_id", "wetness", "sheltered", "exposure"}:
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "surface state is invalid")
            if value["surface_id"] != surface_id:
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "surface_id does not match its key")
            wetness = value["wetness"]
            sheltered = value["sheltered"]
            exposure = value["exposure"]
            if (not _valid_number(wetness) or not 0.0 <= wetness <= 1.0
                    or not isinstance(sheltered, bool)
                    or not _valid_number(exposure)
                    or not 0.0 < exposure <= 1.0):
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "surface state is invalid")
            surfaces[surface_id] = _SurfaceRecord(
                surface_id, sheltered, float(exposure)
            )
            working[surface_id] = float(wetness)

        published = {}
        for surface_id, value in published_value.items():
            if not isinstance(surface_id, str) or not surface_id.strip():
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "surface_id is invalid")
            if not isinstance(value, dict) or set(value) != {
                    "surface_id", "wetness", "sheltered", "exposure", "frame"}:
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "published state is invalid")
            if value["surface_id"] != surface_id:
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "surface_id does not match its key")
            wetness = value["wetness"]
            sheltered = value["sheltered"]
            exposure = value["exposure"]
            surface_frame = value["frame"]
            if (not _valid_number(wetness) or not 0.0 <= wetness <= 1.0
                    or not isinstance(sheltered, bool)
                    or not _valid_number(exposure)
                    or not 0.0 < exposure <= 1.0
                    or not _valid_int(surface_frame) or surface_frame < 0):
                raise WetSurfaceError("WET_SNAPSHOT_INVALID",
                                      "published state is invalid")
            published[surface_id] = SurfaceState(
                surface_id=surface_id,
                wetness=float(wetness),
                sheltered=sheltered,
                exposure=float(exposure),
                frame=surface_frame,
            )

        return {
            "config": (config, {
                "kind": kind,
                "intensity": float(intensity),
            }),
            "surfaces": surfaces,
            "working": working,
            "published": published,
            "frame": frame,
            "counters": counters,
        }


def _valid_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _valid_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _clamp_wetness(value: float) -> float:
    return min(1.0, max(0.0, value))


def _is_blended(wetness: float, threshold: float) -> bool:
    return wetness >= threshold


def _puddle_depth(wetness: float, threshold: float) -> float:
    if wetness < threshold:
        return 0.0
    if threshold >= 1.0:
        return 1.0
    return _clamp_wetness((wetness - threshold) / (1.0 - threshold))
