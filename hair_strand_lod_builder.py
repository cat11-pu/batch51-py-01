"""Hair strand LOD builder: guide clustering, segment cropping, transparent ordering."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, replace


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
        self._bundles: dict[str, dict] = {}
        self._builds = 0
        self._lod_selections = 0
        self._interpolations = 0
        self._sorts = 0

    def build_strands(self, bundle, *, guides, children):
        with self._lock:
            guide_list = list(guides)
            child_list = list(children)
            all_strands = guide_list + child_list

            if not guide_list:
                raise HairError("HAIR_INVALID_BUNDLE",
                                {"reason": "empty guides", "bundle": bundle})

            strand_ids = [strand.strand_id for strand in all_strands]
            if len(set(strand_ids)) != len(strand_ids):
                raise HairError("HAIR_INVALID_BUNDLE",
                                {"reason": "duplicate strand id", "bundle": bundle})

            for strand in all_strands:
                if not isinstance(strand.segments, int) or strand.segments < 1:
                    raise HairError(
                        "HAIR_INVALID_BUNDLE",
                        {"reason": "segments must be >= 1",
                         "bundle": bundle, "strand_id": strand.strand_id},
                    )

            guide_ids = {strand.strand_id for strand in guide_list}
            for strand in child_list:
                if strand.guide_id not in guide_ids:
                    raise HairError(
                        "HAIR_INVALID_BUNDLE",
                        {"reason": "child points to unknown guide",
                         "bundle": bundle, "strand_id": strand.strand_id,
                         "guide_id": strand.guide_id},
                    )

            points = [point for strand in all_strands
                      for point in (strand.root, strand.tip)]
            bbox_min = tuple(min(point[axis] for point in points) for axis in range(3))
            bbox_max = tuple(max(point[axis] for point in points) for axis in range(3))

            info = BundleInfo(
                bundle=bundle,
                guide_count=len(guide_list),
                child_count=len(child_list),
                max_segments=max(strand.segments for strand in all_strands),
                bbox=(bbox_min, bbox_max),
            )
            entry = {
                "strands": {strand.strand_id: strand for strand in all_strands},
                "guides": set(guide_ids),
                "children": {strand.strand_id for strand in child_list},
                "info": info,
                "child_ratio": len(child_list) / len(all_strands),
                "lod": {},
            }
            self._bundles[bundle] = entry
            self._builds += 1
            return info

    def bundle_info(self, bundle):
        with self._lock:
            return self._require_bundle(bundle)["info"]

    def select_lod(self, bundle, *, camera, coverage, distance):
        with self._lock:
            entry = self._require_bundle(bundle)
            near_threshold, far_threshold = self.coverage_thresholds
            if coverage >= near_threshold:
                lod = 0
            elif coverage >= far_threshold:
                lod = 1
            else:
                lod = self.lod_levels - 1

            if distance > self.far_distance:
                lod += 1
            lod = max(0, min(lod, self.lod_levels - 1))

            segments = max(
                self._reduce_segments(strand.segments, lod)
                for strand in entry["strands"].values()
            )
            selection = LodSelection(
                bundle=bundle,
                camera=camera,
                lod=lod,
                segments=segments,
                child_ratio=entry["child_ratio"],
            )
            entry["lod"][camera] = selection
            self._lod_selections += 1
            return selection

    def interpolate(self, bundle, strand_id, *, lod):
        with self._lock:
            entry = self._require_bundle(bundle)
            base = self._require_strand(entry, strand_id)
            lod = max(0, min(int(lod), self.lod_levels - 1))
            if lod == 0:
                result = base
            else:
                segments = self._reduce_segments(base.segments, lod)
                guide_id = base.guide_id
                if base.guide_id is not None:
                    nearest, root_distance, _weights = self._nearest_guide(entry, base)
                    if root_distance <= self.merge_threshold:
                        guide_id = nearest.strand_id
                result = replace(base, segments=segments, guide_id=guide_id)
            self._interpolations += 1
            return result

    def sort_strands(self, bundle, *, camera, camera_position):
        with self._lock:
            entry = self._require_bundle(bundle)
            strands = entry["strands"]
            order = sorted(
                strands,
                key=lambda sid: (
                    _camera_depth(camera_position, strands[sid].root),
                    sid,
                ),
            )
            self._sorts += 1
            return order

    def depth_policy(self, bundle, *, lod, shadow_pass=False):
        with self._lock:
            self._require_bundle(bundle)
            if shadow_pass:
                return DEPTH_SHADOW_WRITE
            if lod == 0:
                return DEPTH_WRITE
            return DEPTH_TRANSPARENT

    def strand(self, bundle, strand_id):
        with self._lock:
            entry = self._require_bundle(bundle)
            return self._require_strand(entry, strand_id)

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "lod_levels": self.lod_levels,
                    "segment_floor": self.segment_floor,
                    "merge_threshold": self.merge_threshold,
                    "far_distance": self.far_distance,
                    "coverage_thresholds": tuple(self.coverage_thresholds),
                },
                "counts": self._current_counts(),
                "bundles": {
                    name: {
                        "strands": dict(entry["strands"]),
                        "guides": set(entry["guides"]),
                        "children": set(entry["children"]),
                        "info": entry["info"],
                        "child_ratio": entry["child_ratio"],
                        "lod": dict(entry["lod"]),
                    }
                    for name, entry in self._bundles.items()
                },
            }

    def restore(self, state):
        with self._lock:
            bundles, counts, config = self._parse_snapshot(state)
            self._bundles = bundles
            self._builds = counts["builds"]
            self._lod_selections = counts["lod_selections"]
            self._interpolations = counts["interpolations"]
            self._sorts = counts["sorts"]
            if config is not None:
                self.lod_levels = config["lod_levels"]
                self.segment_floor = config["segment_floor"]
                self.merge_threshold = config["merge_threshold"]
                self.far_distance = config["far_distance"]
                self.coverage_thresholds = config["coverage_thresholds"]

    def stats(self):
        with self._lock:
            return self._current_counts()

    def _require_bundle(self, bundle):
        entry = self._bundles.get(bundle)
        if entry is None:
            raise HairError("HAIR_UNKNOWN_BUNDLE", {"bundle": bundle})
        return entry

    def _require_strand(self, entry, strand_id):
        strand = entry["strands"].get(strand_id)
        if strand is None:
            raise HairError("HAIR_UNKNOWN_STRAND",
                            {"bundle": entry["info"].bundle,
                             "strand_id": strand_id})
        return strand

    def _reduce_segments(self, segments, lod):
        return max(self.segment_floor, segments // (1 << lod))

    def _nearest_guide(self, entry, strand):
        guides = entry["strands"]
        distances = {
            guide_id: _distance(strand.root, guides[guide_id].root)
            for guide_id in entry["guides"]
        }
        nearest_id = min(distances,
                         key=lambda guide_id: (distances[guide_id], guide_id))
        inverse = {
            guide_id: 1.0 / (distance + _DISTANCE_EPS)
            for guide_id, distance in distances.items()
        }
        weight_total = sum(inverse.values())
        weights = {
            guide_id: value / weight_total for guide_id, value in inverse.items()
        }
        return guides[nearest_id], distances[nearest_id], weights

    def _current_counts(self):
        return {
            "bundles": len(self._bundles),
            "strands": sum(len(entry["strands"])
                           for entry in self._bundles.values()),
            "builds": self._builds,
            "lod_selections": self._lod_selections,
            "interpolations": self._interpolations,
            "sorts": self._sorts,
        }

    def _parse_snapshot(self, state):
        try:
            if not isinstance(state, dict) or \
                    state.get("version") != SNAPSHOT_VERSION:
                raise HairError("HAIR_SNAPSHOT_INVALID",
                                {"reason": "unknown version"})
            raw_bundles = state.get("bundles")
            if not isinstance(raw_bundles, dict):
                raise HairError("HAIR_SNAPSHOT_INVALID",
                                {"reason": "bundles mapping missing"})

            bundles = {}
            for name, raw_entry in raw_bundles.items():
                if not isinstance(raw_entry, dict):
                    raise HairError("HAIR_SNAPSHOT_INVALID",
                                    {"reason": "corrupt bundle", "bundle": name})
                raw_strands = raw_entry.get("strands")
                if not isinstance(raw_strands, dict) or not raw_strands or \
                        not all(isinstance(item, Strand)
                                for item in raw_strands.values()):
                    raise HairError("HAIR_SNAPSHOT_INVALID",
                                    {"reason": "corrupt strands", "bundle": name})
                guides = raw_entry.get("guides")
                children = raw_entry.get("children")
                if not isinstance(guides, set) or not isinstance(children, set) or \
                        not guides or not guides.issubset(raw_strands) or \
                        not children.issubset(raw_strands):
                    raise HairError("HAIR_SNAPSHOT_INVALID",
                                    {"reason": "corrupt guide grouping",
                                     "bundle": name})
                info = raw_entry.get("info")
                if not isinstance(info, BundleInfo):
                    raise HairError("HAIR_SNAPSHOT_INVALID",
                                    {"reason": "corrupt bundle info",
                                     "bundle": name})
                raw_lod = raw_entry.get("lod")
                if not isinstance(raw_lod, dict) or \
                        not all(isinstance(item, LodSelection)
                                for item in raw_lod.values()):
                    raise HairError("HAIR_SNAPSHOT_INVALID",
                                    {"reason": "corrupt lod results",
                                     "bundle": name})
                child_ratio = raw_entry.get("child_ratio")
                if not isinstance(child_ratio, (int, float)):
                    raise HairError("HAIR_SNAPSHOT_INVALID",
                                    {"reason": "corrupt child ratio",
                                     "bundle": name})
                bundles[name] = {
                    "strands": dict(raw_strands),
                    "guides": set(guides),
                    "children": set(children),
                    "info": info,
                    "child_ratio": float(child_ratio),
                    "lod": dict(raw_lod),
                }

            counts = state.get("counts")
            expected = ("bundles", "strands", "builds",
                        "lod_selections", "interpolations", "sorts")
            if not isinstance(counts, dict) or \
                    any(key not in counts or not isinstance(counts[key], int)
                        for key in expected):
                raise HairError("HAIR_SNAPSHOT_INVALID",
                                {"reason": "corrupt counters"})

            config = None
            raw_config = state.get("config")
            if isinstance(raw_config, dict):
                config = {
                    "lod_levels": raw_config["lod_levels"],
                    "segment_floor": raw_config["segment_floor"],
                    "merge_threshold": raw_config["merge_threshold"],
                    "far_distance": raw_config["far_distance"],
                    "coverage_thresholds": tuple(
                        raw_config["coverage_thresholds"]),
                }
        except HairError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise HairError("HAIR_SNAPSHOT_INVALID",
                            {"reason": str(exc)}) from exc
        return bundles, dict(counts), config


_DISTANCE_EPS = 1e-9

# Canonical view axis used when no per-camera orientation is supplied: near
# closeups look down +z while profile shots look down -x, so depth is measured
# along this diagonal rather than radial distance from the camera origin.
_DEPTH_AXIS = (-1.0, 0.0, 1.0)


def _distance(left, right):
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)))


def _camera_depth(camera_position, root):
    relative = tuple(component - camera_position[axis]
                     for axis, component in enumerate(root))
    return sum(relative[axis] * _DEPTH_AXIS[axis] for axis in range(3))
