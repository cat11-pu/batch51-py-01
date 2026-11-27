"""Subsurface scattering profiles: diffusion LUTs, thickness sources, backlit transmission."""

from __future__ import annotations

import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1


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


class SubsurfaceProfile:
    """Maintain diffusion profiles and their sampled lookup tables."""

    def __init__(self, *, default_profile: str = "default",
                 default_thickness: float = 0.5,
                 max_resolution: int = 256) -> None:
        self.default_profile = default_profile
        self.default_thickness = default_thickness
        self.max_resolution = max_resolution
        self._lock = threading.RLock()

    def define_profile(self, spec):
        raise NotImplementedError

    def remove_profile(self, name):
        raise NotImplementedError

    def build_lut(self, name):
        raise NotImplementedError

    def sample_profile(self, name, distance):
        raise NotImplementedError

    def thickness_from(self, name, *, thickness_map=None, uv=None):
        raise NotImplementedError

    def transmission(self, name, *, light_dot_normal, thickness):
        raise NotImplementedError

    def profile_versions(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
