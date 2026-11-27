"""Hair strand LOD builder: guide clustering, segment cropping, transparent ordering."""

from __future__ import annotations

import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1

DEPTH_WRITE = "write"
DEPTH_TRANSPARENT = "transparent_no_write"
DEPTH_SHADOW_WRITE = "shadow_write"


class HairError(ValueError):
    """Raised when a strand bundle request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Strand:
    strand_id: int
    root: tuple[float, float, float]
    tip: tuple[float, float, float]
    segments: int
    guide_id: int | None = None


@dataclass(frozen=True)
class BundleInfo:
    bundle: str
    guide_count: int
    child_count: int
    max_segments: int
    bbox: tuple[tuple[float, float, float], tuple[float, float, float]]


@dataclass(frozen=True)
class LodSelection:
    bundle: str
    camera: str
    lod: int
    segments: int
    child_ratio: float


class HairStrandLod:
    """Split a hair bundle into guides and children and pick a per-camera LOD."""

    def __init__(self, *, lod_levels: int = 3, segment_floor: int = 1,
                 merge_threshold: float = 0.25, far_distance: float = 40.0,
                 coverage_thresholds: tuple[float, float] = (0.5, 0.15)) -> None:
        self.lod_levels = lod_levels
        self.segment_floor = segment_floor
        self.merge_threshold = merge_threshold
        self.far_distance = far_distance
        self.coverage_thresholds = coverage_thresholds
        self._lock = threading.RLock()

    def build_strands(self, bundle, *, guides, children):
        raise NotImplementedError

    def bundle_info(self, bundle):
        raise NotImplementedError

    def select_lod(self, bundle, *, camera, coverage, distance):
        raise NotImplementedError

    def interpolate(self, bundle, strand_id, *, lod):
        raise NotImplementedError

    def sort_strands(self, bundle, *, camera, camera_position):
        raise NotImplementedError

    def depth_policy(self, bundle, *, lod, shadow_pass=False):
        raise NotImplementedError

    def strand(self, bundle, strand_id):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
