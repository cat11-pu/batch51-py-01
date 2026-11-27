"""Subsurface scattering profiles: diffusion LUTs, thickness sources, backlit transmission."""

from __future__ import annotations

import dataclasses
import math
import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1
_LUT_DOMAIN = 4.0
_FALLBACK_RADIUS = 1.0
_STATS_KEYS = ("profiles", "defined", "removed", "lut_builds",
               "lut_cache_hits", "samples", "fallbacks")


class SubsurfaceError(ValueError):
    """Raised when a profile request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProfileSpec:
    name: str
    radius: float
    color: tuple[float, float, float]
    ior: float = 1.4
    resolution: int = 32


@dataclass(frozen=True)
class LutHandle:
    name: str
    version: int
    resolution: int
    cached: bool


@dataclass(frozen=True)
class ThicknessSample:
    profile: str
    value: float
    degraded: bool


@dataclass(frozen=True)
class TransmissionSample:
    profile: str
    transmittance: float
    backlit: bool
    fallback: bool


@dataclass(frozen=True)
class _Lut:
    """Immutable diffusion LUT for one profile version; safe to share across threads."""

    name: str
    version: int
    resolution: int
    values: tuple[float, ...]


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_spec(spec) -> None:
    if not isinstance(spec, ProfileSpec):
        raise SubsurfaceError("SUBSURFACE_INVALID_PROFILE", spec)
    if not isinstance(spec.name, str) or not spec.name:
        raise SubsurfaceError("SUBSURFACE_INVALID_PROFILE", "name must be a non-empty string")
    if not _is_number(spec.radius) or not math.isfinite(spec.radius) or spec.radius <= 0:
        raise SubsurfaceError("SUBSURFACE_INVALID_PROFILE", "radius must be positive")
    if not isinstance(spec.resolution, int) or isinstance(spec.resolution, bool) \
            or spec.resolution < 1:
        raise SubsurfaceError("SUBSURFACE_INVALID_PROFILE", "resolution must be >= 1")
    color = spec.color
    if not isinstance(color, (tuple, list)) or len(color) != 3 \
            or not all(_is_number(channel) and math.isfinite(channel)
                       and 0.0 <= channel <= 1.0 for channel in color):
        raise SubsurfaceError("SUBSURFACE_INVALID_PROFILE",
                              "color must be three channels in [0, 1]")


def _build_lut_values(radius: float, resolution: int) -> tuple[float, ...]:
    if resolution == 1:
        return (1.0,)
    return tuple(
        math.exp(-(_LUT_DOMAIN * index / (resolution - 1)))
        for index in range(resolution)
    )


class SubsurfaceProfile:
    """Maintain diffusion profiles and their sampled lookup tables."""

    def __init__(self, *, default_profile: str = "default",
                 default_thickness: float = 0.5,
                 max_resolution: int = 256) -> None:
        self.default_profile = default_profile
        self.default_thickness = default_thickness
        self.max_resolution = max_resolution
        self._lock = threading.RLock()
        self._profiles: dict[str, ProfileSpec] = {}
        self._versions: dict[str, int] = {}
        self._luts: dict[tuple[str, int], _Lut] = {}
        self._counters = {key: 0 for key in _STATS_KEYS}

    def define_profile(self, spec):
        _validate_spec(spec)
        with self._lock:
            previous = self._versions.get(spec.name, 0)
            version = previous + 1
            self._profiles[spec.name] = spec
            self._versions[spec.name] = version
            self._counters["defined"] += 1
            return version

    def remove_profile(self, name):
        with self._lock:
            if name not in self._profiles:
                raise SubsurfaceError("SUBSURFACE_PROFILE_NOT_FOUND", name)
            self._profiles.pop(name)
            self._versions.pop(name)
            for key in [key for key in self._luts if key[0] == name]:
                self._luts.pop(key)
            self._counters["removed"] += 1

    def build_lut(self, name):
        with self._lock:
            spec = self._profiles.get(name)
            if spec is None:
                raise SubsurfaceError("SUBSURFACE_PROFILE_NOT_FOUND", name)
            version = self._versions[name]
            key = (name, version)
            cached_lut = self._luts.get(key)
            if cached_lut is not None:
                self._counters["lut_cache_hits"] += 1
                return LutHandle(name, version, cached_lut.resolution, True)

            resolution = min(spec.resolution, self.max_resolution)
            lut = _Lut(name, version, resolution,
                       _build_lut_values(spec.radius, resolution))
            self._luts[key] = lut
            self._counters["lut_builds"] += 1
            return LutHandle(name, version, resolution, False)

    def sample_profile(self, name, distance):
        if not _is_number(distance) or not math.isfinite(distance) or distance < 0:
            raise SubsurfaceError("SUBSURFACE_INVALID_DISTANCE", distance)
        with self._lock:
            spec, _ = self._resolve(name)
            self._counters["samples"] += 1
            radius = spec.radius
        if distance == 0:
            return 1.0
        return math.exp(-distance / radius)

    def thickness_from(self, name, *, thickness_map=None, uv=None):
        with self._lock:
            if thickness_map is None:
                self._resolve(name)
                return ThicknessSample(name, self.default_thickness, True)
            if uv is None or uv not in thickness_map:
                raise SubsurfaceError("SUBSURFACE_INVALID_THICKNESS",
                                       {"profile": name, "uv": uv})
            value = thickness_map[uv]
            self._resolve(name)
            return ThicknessSample(name, value, False)

    def transmission(self, name, *, light_dot_normal, thickness):
        if not _is_number(thickness) or not math.isfinite(thickness) or thickness < 0:
            raise SubsurfaceError("SUBSURFACE_INVALID_THICKNESS", thickness)
        with self._lock:
            spec, fallback = self._resolve(name)
            radius = spec.radius
        backlit = light_dot_normal < 0
        transmittance = math.exp(-thickness / radius) if backlit else 0.0
        return TransmissionSample(name, transmittance, backlit, fallback)

    def profile_versions(self):
        with self._lock:
            return dict(self._versions)

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "profiles": {
                    name: dataclasses.asdict(spec)
                    for name, spec in self._profiles.items()
                },
                "versions": dict(self._versions),
                "luts": {
                    key: {
                        "resolution": lut.resolution,
                        "values": tuple(lut.values),
                    }
                    for key, lut in self._luts.items()
                },
                "counters": dict(self._counters),
            }

    def restore(self, state):
        profiles, versions, luts, counters = self._parse_snapshot(state)
        with self._lock:
            self._profiles = profiles
            self._versions = versions
            self._luts = luts
            self._counters = counters

    def stats(self):
        with self._lock:
            result = dict(self._counters)
            result["profiles"] = len(self._profiles)
            return result

    def _resolve(self, profile_name: str) -> tuple[ProfileSpec, bool]:
        spec = self._profiles.get(profile_name)
        if spec is not None:
            return spec, False
        self._counters["fallbacks"] += 1
        fallback = self._profiles.get(self.default_profile)
        if fallback is not None:
            return fallback, True
        return ProfileSpec(name=self.default_profile, radius=_FALLBACK_RADIUS,
                           color=(1.0, 1.0, 1.0)), True

    @staticmethod
    def _parse_snapshot(state):
        if not isinstance(state, dict) or state.get("version") != SNAPSHOT_VERSION:
            raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "unknown snapshot version")

        raw_profiles = state.get("profiles")
        raw_versions = state.get("versions")
        raw_luts = state.get("luts")
        raw_counters = state.get("counters")
        if not isinstance(raw_profiles, dict) or not isinstance(raw_versions, dict) \
                or not isinstance(raw_luts, dict) or not isinstance(raw_counters, dict):
            raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "damaged snapshot structure")

        profiles: dict[str, ProfileSpec] = {}
        for name, raw_spec in raw_profiles.items():
            if not isinstance(name, str) or not isinstance(raw_spec, dict):
                raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "damaged profile entry")
            try:
                spec = ProfileSpec(**raw_spec)
            except TypeError as exc:
                raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", str(exc))
            try:
                _validate_spec(spec)
            except SubsurfaceError as exc:
                raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", exc.detail)
            profiles[name] = spec

        versions: dict[str, int] = {}
        for name, version in raw_versions.items():
            if name not in profiles or not isinstance(version, int) \
                    or isinstance(version, bool) or version < 1:
                raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "damaged version entry")
            versions[name] = version

        luts: dict[tuple[str, int], _Lut] = {}
        for key, entry in raw_luts.items():
            if not isinstance(key, tuple) or len(key) != 2 \
                    or not isinstance(key[0], str) or not isinstance(key[1], int) \
                    or key[0] not in versions or not 1 <= key[1] <= versions[key[0]] \
                    or not isinstance(entry, dict):
                raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "damaged LUT entry")
            resolution = entry.get("resolution")
            values = entry.get("values")
            if not isinstance(resolution, int) or isinstance(resolution, bool) \
                    or resolution < 1 or not isinstance(values, tuple) \
                    or len(values) != resolution \
                    or not all(_is_number(v) and math.isfinite(v) for v in values):
                raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "damaged LUT data")
            luts[key] = _Lut(key[0], key[1], resolution, tuple(float(v) for v in values))

        if set(raw_counters) != set(_STATS_KEYS) \
                or not all(isinstance(value, int) and not isinstance(value, bool)
                           and value >= 0 for value in raw_counters.values()):
            raise SubsurfaceError("SUBSURFACE_SNAPSHOT_INVALID", "damaged counters")
        counters = dict(raw_counters)

        return profiles, versions, luts, counters
