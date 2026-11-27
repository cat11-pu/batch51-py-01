"""Bricked signed-distance-field volume: narrow-band bricks, edit invalidation, sampling."""

from __future__ import annotations

import itertools
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timezone


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


@dataclass
class _Mesh:
    mesh_id: str
    bounds: tuple
    sample_fn: object
    content_hash: str | None
    path: str | None
    version: int
    bricks: list
    active_builds: int = 0


@dataclass
class _Brick:
    brick: tuple
    mesh_id: str
    version: int
    status: str
    nodes: tuple | None = None
    min_distance: float = 0.0
    max_distance: float = 0.0
    built_at: str | None = None
    build_count: int = 0
    generation: int = 0


class SdfVolumeBuilder:
    """Bake a static mesh into bricked narrow-band SDF bricks and edit them in place."""

    _COUNTER_KEYS = ("built", "reused", "invalidated", "samples", "rejected")
    _SNAPSHOT_KEYS = ("version", "meshes", "bricks", "counters")
    _SNAPSHOT_VERSION = 1

    def __init__(self, *, brick_size: int = 8, voxel_size: float = 0.25,
                 band_voxels: float = 2.0, max_bricks: int = 256,
                 clock=None) -> None:
        if isinstance(brick_size, bool) or not isinstance(brick_size, int) or brick_size <= 0:
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"brick_size": brick_size})
        if not self._finite(voxel_size) or float(voxel_size) <= 0.0:
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"voxel_size": voxel_size})
        if not self._finite(band_voxels) or float(band_voxels) <= 0.0:
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"band_voxels": band_voxels})
        if isinstance(max_bricks, bool) or not isinstance(max_bricks, int) or max_bricks <= 0:
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"max_bricks": max_bricks})

        self.brick_size = brick_size
        self.voxel_size = float(voxel_size)
        self.band_voxels = float(band_voxels)
        self.max_bricks = max_bricks
        self._clock = clock
        self._edge = self.brick_size * self.voxel_size
        self._band = self.band_voxels * self.voxel_size
        self._node_axis = self.brick_size + 1
        self._node_count = self._node_axis ** 3

        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._meshes: dict[str, _Mesh] = {}
        self._bricks: dict[tuple, _Brick] = {}
        self._counters: dict[str, int] = {key: 0 for key in self._COUNTER_KEYS}

    @staticmethod
    def _finite(value) -> bool:
        try:
            return math.isfinite(float(value))
        except (TypeError, ValueError, OverflowError):
            return False

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _parse_bounds(self, bounds, *, registration: bool = False,
                      strict: bool = True) -> tuple:
        try:
            values = tuple(bounds)
            if len(values) != 2:
                raise ValueError
            low = tuple(float(axis) for axis in values[0])
            high = tuple(float(axis) for axis in values[1])
            if len(low) != 3 or len(high) != 3:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            if registration:
                self._counters["rejected"] += 1
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"bounds": bounds}) from None

        if not all(math.isfinite(value) for value in low + high):
            if registration:
                self._counters["rejected"] += 1
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"bounds": bounds})
        ordered = all(lo < hi for lo, hi in zip(low, high)) if strict else \
            all(lo <= hi for lo, hi in zip(low, high))
        if not ordered:
            if registration:
                self._counters["rejected"] += 1
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"bounds": bounds})
        return low, high

    def _grid(self, bounds) -> tuple[list[range], int]:
        low, high = bounds
        ranges = []
        count = 1
        for lo, hi in zip(low, high):
            first = math.floor(lo / self._edge)
            last = math.floor(hi / self._edge)
            ranges.append(range(first, last + 1))
            count *= last - first + 1
        return ranges, count

    @staticmethod
    def _coords(ranges) -> list[tuple]:
        return [tuple(coord) for coord in itertools.product(*ranges)]

    def _validate_mesh_id(self, mesh_id, *, registration: bool) -> None:
        if not isinstance(mesh_id, str) or not mesh_id:
            if registration:
                self._counters["rejected"] += 1
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"mesh_id": mesh_id})

    def _new_brick(self, coord: tuple, mesh_id: str, version: int) -> _Brick:
        return _Brick(brick=coord, mesh_id=mesh_id, version=version, status="pending")

    def _mark_pending_locked(self, brick: _Brick, version: int) -> bool:
        changed = brick.status != "pending"
        if changed:
            self._counters["invalidated"] += 1
            brick.generation += 1
        brick.status = "pending"
        brick.version = version
        return changed

    def _resolve_now(self, now):
        if now is not None:
            return now
        if self._clock is not None:
            if callable(self._clock):
                value = self._clock()
            elif hasattr(self._clock, "now"):
                value = self._clock.now()
            else:
                value = self._clock
            return value
        return datetime.now(timezone.utc).isoformat()

    def register_mesh(self, mesh_id: str, *, bounds, sample_fn=None,
                      content_hash: str | None = None,
                      path: str | None = None) -> int:
        with self._condition:
            self._validate_mesh_id(mesh_id, registration=True)
            parsed_bounds = self._parse_bounds(bounds, registration=True)
            if sample_fn is not None and not callable(sample_fn):
                self._counters["rejected"] += 1
                raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"sample_fn": sample_fn})
            if content_hash is not None and not isinstance(content_hash, str):
                self._counters["rejected"] += 1
                raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"content_hash": content_hash})
            if path is not None and not isinstance(path, str):
                self._counters["rejected"] += 1
                raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"path": path})

            ranges, count = self._grid(parsed_bounds)
            existing = self._meshes.get(mesh_id)
            old_coords = set(existing.bricks) if existing is not None else set()
            total = len(self._bricks) - len(old_coords) + count
            if total > self.max_bricks:
                self._counters["rejected"] += 1
                raise SdfVolumeError("SDF_CAPACITY_EXCEEDED", {
                    "requested": count,
                    "existing": len(self._bricks) - len(old_coords),
                    "max_bricks": self.max_bricks,
                })

            coords = self._coords(ranges)
            new_coords = set(coords)
            for coord in new_coords:
                parked = self._bricks.get(coord)
                if parked is not None and parked.mesh_id != mesh_id:
                    self._counters["rejected"] += 1
                    raise SdfVolumeError("SDF_INVALID_ARGUMENT", {
                        "brick": coord,
                        "owner": parked.mesh_id,
                    })

            if existing is None:
                mesh = _Mesh(
                    mesh_id=mesh_id,
                    bounds=parsed_bounds,
                    sample_fn=sample_fn,
                    content_hash=content_hash,
                    path=path,
                    version=1,
                    bricks=coords,
                )
                bricks = {coord: self._new_brick(coord, mesh_id, 1) for coord in coords}
                self._meshes[mesh_id] = mesh
                self._bricks.update(bricks)
                self._condition.notify_all()
                return 1

            hash_changed = content_hash is not None and content_hash != existing.content_hash
            version = existing.version + 1 if hash_changed else existing.version

            for coord in old_coords - new_coords:
                del self._bricks[coord]

            for coord in coords:
                brick = self._bricks.get(coord)
                if brick is None:
                    self._bricks[coord] = self._new_brick(coord, mesh_id, version)
                elif hash_changed:
                    self._mark_pending_locked(brick, version)

            existing.bounds = parsed_bounds
            if sample_fn is not None:
                existing.sample_fn = sample_fn
            if content_hash is not None:
                existing.content_hash = content_hash
            if path is not None:
                existing.path = path
            existing.version = version
            existing.bricks = coords
            self._condition.notify_all()
            return version

    def _bake(self, mesh: _Mesh, coord: tuple) -> tuple[tuple, float, float]:
        sample_fn = mesh.sample_fn
        base_x = coord[0] * self._edge
        base_y = coord[1] * self._edge
        base_z = coord[2] * self._edge
        side = self._node_axis
        nodes = [0.0] * self._node_count
        minimum = math.inf
        maximum = -math.inf
        band = self._band

        for i in range(side):
            x = base_x + i * self.voxel_size
            for j in range(side):
                y = base_y + j * self.voxel_size
                offset = (i * side + j) * side
                for k in range(side):
                    z = base_z + k * self.voxel_size
                    if sample_fn is None:
                        value = 0.0
                    else:
                        try:
                            value = float(sample_fn(x, y, z))
                        except (TypeError, ValueError, OverflowError):
                            raise SdfVolumeError(
                                "SDF_INVALID_ARGUMENT",
                                {"sample": (x, y, z)},
                            ) from None
                    if not math.isfinite(value):
                        raise SdfVolumeError(
                            "SDF_INVALID_ARGUMENT",
                            {"sample": (x, y, z), "value": value},
                        )
                    if value > band:
                        value = band
                    elif value < -band:
                        value = -band
                    nodes[offset + k] = value
                    if value < minimum:
                        minimum = value
                    if value > maximum:
                        maximum = value
        return tuple(nodes), minimum, maximum

    def _find_pending_locked(self, mesh_id: str | None, version: int | None) -> _Brick | None:
        candidates = sorted(self._bricks.values(), key=lambda brick: brick.brick)
        for brick in candidates:
            if brick.status != "pending":
                continue
            if mesh_id is not None and brick.mesh_id != mesh_id:
                continue
            if version is not None and brick.version != version:
                continue
            return brick
        return None

    def _has_building_locked(self, mesh_id: str | None, version: int | None) -> bool:
        for brick in self._bricks.values():
            if brick.status != "building":
                continue
            if mesh_id is not None and brick.mesh_id != mesh_id:
                continue
            if version is not None and brick.version != version:
                continue
            return True
        return False

    def build(self, mesh_id: str, *, now: str | None = None) -> BuildReport:
        with self._condition:
            mesh = self._meshes.get(mesh_id)
            if mesh is None:
                raise SdfVolumeError("SDF_NO_SUCH_MESH", {"mesh_id": mesh_id})
            start_version = mesh.version
            wave_start = mesh.active_builds == 0
            if wave_start:
                reused = sum(
                    1 for coord in mesh.bricks
                    if (brick := self._bricks.get(coord)) is not None
                    and brick.version == start_version
                    and brick.status == "ready"
                )
            else:
                reused = 0
            mesh.active_builds += 1

        timestamp = self._resolve_now(now)
        built = 0
        try:
            while True:
                with self._condition:
                    if mesh.version != start_version:
                        break
                    brick = self._find_pending_locked(mesh_id, start_version)
                    if brick is not None:
                        brick.status = "building"
                        token = brick.generation
                    else:
                        if self._has_building_locked(mesh_id, start_version):
                            self._condition.wait()
                            continue
                        break

                try:
                    nodes, minimum, maximum = self._bake(mesh, brick.brick)
                except BaseException:
                    with self._condition:
                        if brick.status == "building" and brick.generation == token:
                            brick.status = "pending"
                        self._condition.notify_all()
                    raise

                with self._condition:
                    if (mesh.version == start_version
                            and self._bricks.get(brick.brick) is brick
                            and brick.status == "building"
                            and brick.version == start_version
                            and brick.generation == token):
                        brick.nodes = nodes
                        brick.min_distance = minimum
                        brick.max_distance = maximum
                        brick.status = "ready"
                        brick.built_at = timestamp
                        brick.build_count += 1
                        self._counters["built"] += 1
                        built += 1
                    self._condition.notify_all()
        finally:
            with self._condition:
                mesh.active_builds = max(0, mesh.active_builds - 1)
                self._condition.notify_all()

        with self._condition:
            if wave_start:
                self._counters["reused"] += reused
            pending = sum(
                1 for coord in mesh.bricks
                if (brick := self._bricks.get(coord)) is not None
                and brick.status != "ready"
            )
            return BuildReport(
                mesh_id=mesh_id,
                version=start_version,
                built_bricks=built,
                reused_bricks=reused,
                pending_bricks=pending,
            )

    def brick_of(self, x: float, y: float, z: float) -> tuple:
        if not all(self._finite(value) for value in (x, y, z)):
            raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"point": (x, y, z)})
        return (
            math.floor(float(x) / self._edge),
            math.floor(float(y) / self._edge),
            math.floor(float(z) / self._edge),
        )

    def sample(self, x: float, y: float, z: float) -> SampleResult:
        with self._lock:
            if not all(self._finite(value) for value in (x, y, z)):
                raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"point": (x, y, z)})

            self._counters["samples"] += 1
            x = float(x)
            y = float(y)
            z = float(z)
            coord = (
                math.floor(x / self._edge),
                math.floor(y / self._edge),
                math.floor(z / self._edge),
            )
            brick = self._bricks.get(coord)
            if brick is None or brick.status != "ready" or brick.nodes is None:
                return SampleResult(
                    distance=self._band,
                    brick=coord,
                    ready=False,
                    truncated=True,
                )

            side = self._node_axis
            local_x = (x - coord[0] * self._edge) / self.voxel_size
            local_y = (y - coord[1] * self._edge) / self.voxel_size
            local_z = (z - coord[2] * self._edge) / self.voxel_size

            corner_x, frac_x = self._cell(local_x)
            corner_y, frac_y = self._cell(local_y)
            corner_z, frac_z = self._cell(local_z)

            def node(i: int, j: int, k: int) -> float:
                return brick.nodes[(i * side + j) * side + k]

            x00 = node(corner_x, corner_y, corner_z) * (1.0 - frac_x) + \
                node(corner_x + 1, corner_y, corner_z) * frac_x
            x01 = node(corner_x, corner_y, corner_z + 1) * (1.0 - frac_x) + \
                node(corner_x + 1, corner_y, corner_z + 1) * frac_x
            x10 = node(corner_x, corner_y + 1, corner_z) * (1.0 - frac_x) + \
                node(corner_x + 1, corner_y + 1, corner_z) * frac_x
            x11 = node(corner_x, corner_y + 1, corner_z + 1) * (1.0 - frac_x) + \
                node(corner_x + 1, corner_y + 1, corner_z + 1) * frac_x
            y0 = x00 * (1.0 - frac_y) + x10 * frac_y
            y1 = x01 * (1.0 - frac_y) + x11 * frac_y
            distance = y0 * (1.0 - frac_z) + y1 * frac_z

            return SampleResult(
                distance=distance,
                brick=coord,
                ready=True,
                truncated=abs(distance) >= self._band - 1e-12,
            )

    def _cell(self, local: float) -> tuple[int, float]:
        if local <= 0.0:
            return 0, 0.0
        if local >= self.brick_size:
            return self.brick_size - 1, 1.0
        corner = int(math.floor(local))
        return corner, local - corner

    def apply_edit(self, mesh_id: str, *, bounds, content_hash: str | None = None,
                   now: str | None = None) -> tuple:
        with self._condition:
            mesh = self._meshes.get(mesh_id)
            if mesh is None:
                raise SdfVolumeError("SDF_NO_SUCH_MESH", {"mesh_id": mesh_id})
            parsed_bounds = self._parse_bounds(bounds, strict=False)
            if content_hash is not None and not isinstance(content_hash, str):
                raise SdfVolumeError("SDF_INVALID_ARGUMENT", {"content_hash": content_hash})

            hash_changed = content_hash is not None and content_hash != mesh.content_hash
            if hash_changed:
                mesh.version += 1
                mesh.content_hash = content_hash
                for coord in mesh.bricks:
                    brick = self._bricks.get(coord)
                    if brick is None:
                        continue
                    if brick.status == "building":
                        self._mark_pending_locked(brick, mesh.version)
                    else:
                        brick.version = mesh.version

            low, high = parsed_bounds
            expanded_low = tuple(value - self._band for value in low)
            expanded_high = tuple(value + self._band for value in high)
            touched = []
            for coord in mesh.bricks:
                brick = self._bricks.get(coord)
                if brick is None:
                    continue
                brick_low = (
                    coord[0] * self._edge,
                    coord[1] * self._edge,
                    coord[2] * self._edge,
                )
                brick_high = (
                    brick_low[0] + self._edge,
                    brick_low[1] + self._edge,
                    brick_low[2] + self._edge,
                )
                intersects = all(
                    brick_high[axis] >= expanded_low[axis]
                    and brick_low[axis] <= expanded_high[axis]
                    for axis in range(3)
                )
                if not intersects:
                    continue
                touched.append(coord)
                self._mark_pending_locked(brick, mesh.version)
            self._condition.notify_all()
            return tuple(sorted(touched))

    def invalidate(self, brick) -> bool:
        with self._condition:
            coord = self._brick_key(brick)
            parked = self._bricks.get(coord)
            if parked is None:
                raise SdfVolumeError("SDF_UNKNOWN_BRICK", {"brick": coord})
            if parked.status == "pending":
                return False
            mesh = self._meshes.get(parked.mesh_id)
            version = mesh.version if mesh is not None else parked.version
            self._mark_pending_locked(parked, version)
            self._condition.notify_all()
            return True

    def _brick_key(self, brick) -> tuple:
        try:
            values = tuple(brick)
            if len(values) != 3 or not all(self._is_int(value) for value in values):
                raise ValueError
            return values
        except (TypeError, ValueError):
            raise SdfVolumeError("SDF_UNKNOWN_BRICK", {"brick": brick}) from None

    def rebuild_pending(self, *, now: str | None = None) -> int:
        timestamp = self._resolve_now(now)
        built = 0
        while True:
            with self._condition:
                brick = self._find_pending_locked(None, None)
                if brick is not None:
                    brick.status = "building"
                    token = brick.generation
                    mesh = self._meshes.get(brick.mesh_id)
                else:
                    if self._has_building_locked(None, None):
                        self._condition.wait()
                        continue
                    return built

            try:
                nodes, minimum, maximum = self._bake(mesh, brick.brick)
            except BaseException:
                with self._condition:
                    if brick.status == "building" and brick.generation == token:
                        brick.status = "pending"
                    self._condition.notify_all()
                raise

            with self._condition:
                if (mesh is not None
                        and self._bricks.get(brick.brick) is brick
                        and brick.status == "building"
                        and brick.version == mesh.version
                        and brick.generation == token):
                    brick.nodes = nodes
                    brick.min_distance = minimum
                    brick.max_distance = maximum
                    brick.status = "ready"
                    brick.built_at = timestamp
                    brick.build_count += 1
                    self._counters["built"] += 1
                    built += 1
                self._condition.notify_all()

    def brick_state(self, brick) -> BrickState:
        with self._lock:
            coord = self._brick_key(brick)
            parked = self._bricks.get(coord)
            if parked is None:
                raise SdfVolumeError("SDF_UNKNOWN_BRICK", {"brick": coord})
            return BrickState(
                brick=coord,
                mesh_id=parked.mesh_id,
                version=parked.version,
                ready=parked.status == "ready",
                min_distance=parked.min_distance,
                max_distance=parked.max_distance,
                built_at=parked.built_at,
                build_count=parked.build_count,
            )

    def version_of(self, mesh_id: str) -> int:
        with self._lock:
            mesh = self._meshes.get(mesh_id)
            if mesh is None:
                raise SdfVolumeError("SDF_NO_SUCH_MESH", {"mesh_id": mesh_id})
            return mesh.version

    def ready_bricks(self) -> tuple:
        with self._lock:
            return tuple(sorted(
                coord for coord, brick in self._bricks.items()
                if brick.status == "ready"
            ))

    def pending_bricks(self) -> tuple:
        with self._lock:
            return tuple(sorted(
                coord for coord, brick in self._bricks.items()
                if brick.status != "ready"
            ))

    def snapshot(self) -> dict:
        with self._lock:
            meshes = {}
            for mesh_id, mesh in self._meshes.items():
                meshes[mesh_id] = {
                    "bounds": tuple(tuple(axis) for axis in mesh.bounds),
                    "sample_fn": mesh.sample_fn,
                    "content_hash": mesh.content_hash,
                    "path": mesh.path,
                    "version": mesh.version,
                    "bricks": list(mesh.bricks),
                }
            bricks = {}
            for coord, brick in self._bricks.items():
                bricks[coord] = {
                    "mesh_id": brick.mesh_id,
                    "version": brick.version,
                    "status": "pending" if brick.status == "building" else brick.status,
                    "nodes": list(brick.nodes) if brick.nodes is not None else None,
                    "min_distance": brick.min_distance,
                    "max_distance": brick.max_distance,
                    "built_at": brick.built_at,
                    "build_count": brick.build_count,
                    "generation": brick.generation,
                }
            return {
                "version": self._SNAPSHOT_VERSION,
                "meshes": meshes,
                "bricks": bricks,
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        def invalid(detail):
            raise SdfVolumeError("SDF_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != set(self._SNAPSHOT_KEYS):
            invalid({"keys": None if not isinstance(state, dict) else sorted(state)})
        if (not self._is_int(state["version"])
                or state["version"] != self._SNAPSHOT_VERSION):
            invalid({"version": state["version"]})

        raw_meshes = state["meshes"]
        raw_bricks = state["bricks"]
        raw_counters = state["counters"]
        if not isinstance(raw_meshes, dict) or not isinstance(raw_bricks, dict):
            invalid({"meshes": type(raw_meshes).__name__, "bricks": type(raw_bricks).__name__})
        if not isinstance(raw_counters, dict) or set(raw_counters) != set(self._COUNTER_KEYS):
            invalid({"counters": raw_counters})
        if not all(self._is_int(value) and value >= 0 for value in raw_counters.values()):
            invalid({"counters": raw_counters})

        new_meshes: dict[str, _Mesh] = {}
        mesh_brick_sets: dict[str, set] = {}
        for mesh_id, meta in raw_meshes.items():
            if not isinstance(mesh_id, str) or not mesh_id or not isinstance(meta, dict):
                invalid({"mesh": mesh_id})
            required = {
                "bounds", "sample_fn", "content_hash", "path", "version", "bricks",
            }
            if not required.issubset(meta):
                invalid({"mesh": mesh_id, "keys": sorted(meta)})
            try:
                bounds = self._parse_bounds(meta["bounds"])
            except SdfVolumeError:
                invalid({"mesh": mesh_id, "bounds": meta["bounds"]})
            if not self._is_int(meta["version"]) or meta["version"] < 1:
                invalid({"mesh": mesh_id, "version": meta["version"]})
            if meta["sample_fn"] is not None and not callable(meta["sample_fn"]):
                invalid({"mesh": mesh_id, "sample_fn": meta["sample_fn"]})
            if meta["content_hash"] is not None and not isinstance(meta["content_hash"], str):
                invalid({"mesh": mesh_id, "content_hash": meta["content_hash"]})
            if meta["path"] is not None and not isinstance(meta["path"], str):
                invalid({"mesh": mesh_id, "path": meta["path"]})
            try:
                mesh_bricks = tuple(self._brick_key(coord) for coord in meta["bricks"])
            except (SdfVolumeError, TypeError):
                invalid({"mesh": mesh_id, "bricks": meta["bricks"]})
            if len(set(mesh_bricks)) != len(mesh_bricks):
                invalid({"mesh": mesh_id, "bricks": "duplicate"})
            mesh_brick_sets[mesh_id] = set(mesh_bricks)
            new_meshes[mesh_id] = _Mesh(
                mesh_id=mesh_id,
                bounds=bounds,
                sample_fn=meta["sample_fn"],
                content_hash=meta["content_hash"],
                path=meta["path"],
                version=meta["version"],
                bricks=list(mesh_bricks),
            )

        new_bricks: dict[tuple, _Brick] = {}
        for raw_coord, data in raw_bricks.items():
            try:
                coord = self._brick_key(raw_coord)
            except SdfVolumeError:
                invalid({"brick": raw_coord})
            if not isinstance(data, dict):
                invalid({"brick": coord})
            required = {
                "mesh_id", "version", "status", "nodes", "min_distance",
                "max_distance", "built_at", "build_count", "generation",
            }
            if not required.issubset(data):
                invalid({"brick": coord, "keys": sorted(data)})
            mesh_id = data["mesh_id"]
            if not isinstance(mesh_id, str):
                invalid({"brick": coord, "mesh_id": mesh_id})
            if mesh_id not in new_meshes:
                invalid({"brick": coord, "mesh_id": mesh_id})
            if coord not in mesh_brick_sets[mesh_id]:
                invalid({"brick": coord, "mesh_id": mesh_id})
            if not self._is_int(data["version"]) or data["version"] != new_meshes[mesh_id].version:
                invalid({"brick": coord, "version": data["version"]})
            if data["status"] not in ("ready", "pending"):
                invalid({"brick": coord, "status": data["status"]})
            if data["nodes"] is not None:
                try:
                    nodes = tuple(float(value) for value in data["nodes"])
                except (TypeError, ValueError, OverflowError):
                    invalid({"brick": coord, "nodes": data["nodes"]})
                if len(nodes) != self._node_count or not all(math.isfinite(value) for value in nodes):
                    invalid({"brick": coord, "nodes": "shape"})
            else:
                nodes = None
            if data["status"] == "ready" and nodes is None:
                invalid({"brick": coord, "nodes": None})
            if not self._finite(data["min_distance"]) or not self._finite(data["max_distance"]):
                invalid({"brick": coord, "range": (data["min_distance"], data["max_distance"])})
            if data["built_at"] is not None and not isinstance(data["built_at"], str):
                invalid({"brick": coord, "built_at": data["built_at"]})
            if not self._is_int(data["build_count"]) or data["build_count"] < 0:
                invalid({"brick": coord, "build_count": data["build_count"]})
            if not self._is_int(data["generation"]) or data["generation"] < 0:
                invalid({"brick": coord, "generation": data["generation"]})
            new_bricks[coord] = _Brick(
                brick=coord,
                mesh_id=mesh_id,
                version=data["version"],
                status=data["status"],
                nodes=nodes,
                min_distance=float(data["min_distance"]),
                max_distance=float(data["max_distance"]),
                built_at=data["built_at"],
                build_count=data["build_count"],
                generation=data["generation"],
            )

        for mesh_id, expected in mesh_brick_sets.items():
            actual = {coord for coord, brick in new_bricks.items() if brick.mesh_id == mesh_id}
            if actual != expected:
                invalid({"mesh": mesh_id, "bricks": "mismatch"})

        with self._condition:
            self._meshes = new_meshes
            self._bricks = new_bricks
            self._counters = dict(raw_counters)
            self._condition.notify_all()

    def stats(self) -> dict:
        with self._lock:
            ready = sum(1 for brick in self._bricks.values() if brick.status == "ready")
            return {
                "bricks": len(self._bricks),
                "ready": ready,
                "pending": len(self._bricks) - ready,
                "built": self._counters["built"],
                "reused": self._counters["reused"],
                "invalidated": self._counters["invalidated"],
                "samples": self._counters["samples"],
                "rejected": self._counters["rejected"],
            }
