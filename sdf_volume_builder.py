"""Bricked signed-distance-field volume: narrow-band bricks, edit invalidation, sampling."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SdfVolumeError(ValueError):
    """Raised when a volume operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BrickState:
    """One brick of the volume, addressed by integer brick coordinates."""

    brick: tuple
    mesh_id: str
    version: int
    ready: bool
    min_distance: float
    max_distance: float
    built_at: str | None
    build_count: int


@dataclass(frozen=True)
class SampleResult:
    """Result of one distance query."""

    distance: float
    brick: tuple
    ready: bool
    truncated: bool


@dataclass(frozen=True)
class BuildReport:
    """Summary of one bake pass over a mesh."""

    mesh_id: str
    version: int
    built_bricks: int
    reused_bricks: int
    pending_bricks: int


class SdfVolumeBuilder:
    """Bake a static mesh into bricked narrow-band SDF bricks and edit them in place."""

    def __init__(self, *, brick_size: int = 8, voxel_size: float = 0.25,
                 band_voxels: float = 2.0, max_bricks: int = 256,
                 clock=None) -> None:
        self.brick_size = brick_size
        self.voxel_size = voxel_size
        self.band_voxels = band_voxels
        self.max_bricks = max_bricks
        self._clock = clock
        self._lock = threading.RLock()
        self._meshes: dict = {}
        self._bricks: dict = {}
        self._counters: dict = {
            "built": 0,
            "reused": 0,
            "invalidated": 0,
            "samples": 0,
            "rejected": 0,
        }

    def register_mesh(self, mesh_id: str, *, bounds, sample_fn=None,
                      content_hash: str | None = None,
                      path: str | None = None) -> int:
        raise NotImplementedError

    def build(self, mesh_id: str, *, now: str | None = None) -> BuildReport:
        raise NotImplementedError

    def brick_of(self, x: float, y: float, z: float) -> tuple:
        raise NotImplementedError

    def sample(self, x: float, y: float, z: float) -> SampleResult:
        raise NotImplementedError

    def apply_edit(self, mesh_id: str, *, bounds, content_hash: str | None = None,
                   now: str | None = None) -> tuple:
        raise NotImplementedError

    def invalidate(self, brick) -> bool:
        raise NotImplementedError

    def rebuild_pending(self, *, now: str | None = None) -> int:
        raise NotImplementedError

    def brick_state(self, brick) -> BrickState:
        raise NotImplementedError

    def version_of(self, mesh_id: str) -> int:
        raise NotImplementedError

    def ready_bricks(self) -> tuple:
        raise NotImplementedError

    def pending_bricks(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
