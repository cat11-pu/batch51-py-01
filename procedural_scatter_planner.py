"""Deterministic procedural scatter placement over streamed chunks."""

from __future__ import annotations

import copy
import math
import numbers
import threading
from dataclasses import dataclass


class ScatterError(ValueError):
    """Raised when a layer, a chunk request or a terrain upload is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ScatterPoint:
    x: float
    y: float
    z: float
    yaw_deg: float
    layer: str
    cell_x: int
    cell_y: int


@dataclass(frozen=True)
class ChunkResult:
    cx: int
    cy: int
    points: tuple
    clipped: int
    filtered: int


@dataclass(frozen=True)
class _Layer:
    name: str
    density: float
    seed_offset: int
    min_height: float | None
    max_height: float | None
    max_slope: float | None
    water_level: float | None
    exclusion: tuple[float, float, float, float] | None

    def public_spec(self) -> dict:
        return {
            "name": self.name,
            "density": self.density,
            "seed_offset": self.seed_offset,
            "min_height": self.min_height,
            "max_height": self.max_height,
            "max_slope": self.max_slope,
            "water_level": self.water_level,
            "exclusion": self.exclusion,
        }


_MASK64 = (1 << 64) - 1
_RANDOM_DENOMINATOR = float(1 << 53)
_SLOPE_PROBE_RADIUS = 1.0
_SNAPSHOT_VERSION = 1
_STAT_KEYS = (
    "seed",
    "layers",
    "cached",
    "placed",
    "points",
    "filtered",
    "clipped",
    "evicted",
    "rejected",
)
_COUNTER_KEYS = ("placed", "points", "filtered", "clipped", "evicted",
                 "rejected")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (isinstance(value, numbers.Real)
            and not isinstance(value, bool)
            and math.isfinite(float(value)))


def _mix64(value: int) -> int:
    value = (value + 0x9E3779B97F4A7C15) & _MASK64
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _MASK64
    return (value ^ (value >> 31)) & _MASK64


def _random_u64(seed: int, layer_index: int, seed_offset: int,
                gx: int, gy: int, salt: int) -> int:
    value = _mix64(seed & _MASK64)
    value = _mix64(value ^ ((layer_index + 1) * 0xD6E8FEB86659FD93
                            & _MASK64))
    value = _mix64(value ^ (seed_offset & _MASK64))
    value = _mix64(value ^ (gx & _MASK64))
    value = _mix64(value ^ (gy & _MASK64))
    return _mix64(value ^ (salt & _MASK64))


def _random_unit(seed: int, layer_index: int, seed_offset: int,
                 gx: int, gy: int, salt: int) -> float:
    return ((_random_u64(seed, layer_index, seed_offset, gx, gy, salt) >> 11)
            / _RANDOM_DENOMINATOR)


class ProceduralScatterPlanner:
    """Place vegetation and props per chunk from density layers and a seed."""

    def __init__(self, *, chunk_size: int = 32, cache_limit: int = 16,
                 chunk_point_cap: int = 512, max_layers: int = 16,
                 max_chunk_coord: int = 1_000_000) -> None:
        if not _is_int(chunk_size) or chunk_size <= 0:
            raise ScatterError("SCATTER_INVALID_CHUNK", chunk_size)
        if not _is_int(cache_limit) or cache_limit <= 0:
            raise ScatterError("SCATTER_INVALID_CACHE_LIMIT", cache_limit)
        if not _is_int(chunk_point_cap) or chunk_point_cap < 0:
            raise ScatterError("SCATTER_INVALID_CHUNK", chunk_point_cap)
        if not _is_int(max_layers) or max_layers <= 0:
            raise ScatterError("SCATTER_INVALID_LAYER", max_layers)
        if not _is_int(max_chunk_coord) or max_chunk_coord < 0:
            raise ScatterError("SCATTER_INVALID_CHUNK", max_chunk_coord)

        self._lock = threading.RLock()
        self._chunk_size = chunk_size
        self._cache_limit = cache_limit
        self._chunk_point_cap = chunk_point_cap
        self._max_layers = max_layers
        self._max_chunk_coord = max_chunk_coord
        self._seed = 0
        self._layers: dict[str, _Layer] = {}
        self._height = None
        self._slope = None
        self._chunks: dict[tuple[int, int], ChunkResult] = {}
        self._cache_order: list[tuple[int, int]] = []
        self._stats = {
            "placed": 0,
            "points": 0,
            "filtered": 0,
            "clipped": 0,
            "evicted": 0,
            "rejected": 0,
        }

    def _reject(self, code: str, detail: object = None) -> None:
        self._stats["rejected"] += 1
        raise ScatterError(code, detail)

    @staticmethod
    def _snapshot_reject(detail: object = None) -> None:
        raise ScatterError("SCATTER_SNAPSHOT_INVALID", detail)

    def _validate_chunk_locked(self, cx: object, cy: object) -> None:
        if (not _is_int(cx) or not _is_int(cy)
                or abs(cx) > self._max_chunk_coord
                or abs(cy) > self._max_chunk_coord):
            self._reject("SCATTER_INVALID_CHUNK", (cx, cy))

    @staticmethod
    def _stride_for_density(density: float, chunk_size: int,
                            *, allow_zero: bool) -> int | None:
        if density == 0:
            if not allow_zero:
                raise ScatterError("SCATTER_INVALID_DENSITY", density)
            return None
        stride = max(1, int(round(1.0 / math.sqrt(density))))
        if chunk_size % stride != 0:
            raise ScatterError("SCATTER_INVALID_DENSITY", density)
        return stride

    def _parse_density_locked(self, density: object) -> float:
        if not _is_number(density):
            self._reject("SCATTER_INVALID_DENSITY", density)
        value = float(density)
        if value <= 0.0 or value > 1.0:
            self._reject("SCATTER_INVALID_DENSITY", density)
        try:
            self._stride_for_density(value, self._chunk_size,
                                     allow_zero=False)
        except ScatterError as exc:
            self._reject(exc.code, exc.detail)
        return value

    @staticmethod
    def _parse_optional_number(value: object) -> float | None:
        if value is None:
            return None
        if not _is_number(value):
            raise ScatterError("SCATTER_INVALID_LAYER", value)
        return float(value)

    @staticmethod
    def _parse_exclusion(
            value: object) -> tuple[float, float, float, float] | None:
        if value is None:
            return None
        if not isinstance(value, (tuple, list)) or len(value) != 4:
            raise ScatterError("SCATTER_INVALID_LAYER", value)
        x0, y0, x1, y1 = value
        if not all(_is_number(item) for item in (x0, y0, x1, y1)):
            raise ScatterError("SCATTER_INVALID_LAYER", value)
        result = (float(x0), float(y0), float(x1), float(y1))
        if not (result[0] < result[2] and result[1] < result[3]):
            raise ScatterError("SCATTER_INVALID_LAYER", value)
        return result

    def _validate_layer_name_locked(self, name: object) -> str:
        if (not isinstance(name, str) or not name.strip()
                or name in self._layers):
            if isinstance(name, str) and name in self._layers:
                self._reject("SCATTER_DUPLICATE_LAYER", name)
            self._reject("SCATTER_INVALID_LAYER", name)
        return name

    def _clear_chunks_locked(self) -> None:
        self._chunks.clear()
        self._cache_order.clear()

    def set_seed(self, seed: int) -> int:
        with self._lock:
            if not _is_int(seed) or seed < 0:
                self._reject("SCATTER_INVALID_SEED", seed)
            if seed != self._seed:
                self._seed = seed
                self._clear_chunks_locked()
            return seed

    def add_layer(self, name: str, *, density: float, seed_offset: int = 0,
                  min_height: float | None = None,
                  max_height: float | None = None,
                  max_slope: float | None = None,
                  water_level: float | None = None,
                  exclusion: tuple | None = None) -> dict:
        with self._lock:
            name = self._validate_layer_name_locked(name)
            if len(self._layers) >= self._max_layers:
                self._reject("SCATTER_INVALID_LAYER", "layer limit")
            if not _is_int(seed_offset):
                self._reject("SCATTER_INVALID_LAYER", seed_offset)
            density_value = self._parse_density_locked(density)
            try:
                min_value = self._parse_optional_number(min_height)
                max_value = self._parse_optional_number(max_height)
                slope_value = self._parse_optional_number(max_slope)
                water_value = self._parse_optional_number(water_level)
                exclusion_value = self._parse_exclusion(exclusion)
            except ScatterError as exc:
                self._reject(exc.code, exc.detail)

            layer = _Layer(
                name=name,
                density=density_value,
                seed_offset=seed_offset,
                min_height=min_value,
                max_height=max_value,
                max_slope=slope_value,
                water_level=water_value,
                exclusion=exclusion_value,
            )
            self._layers[name] = layer
            self._clear_chunks_locked()
            return layer.public_spec()

    def remove_layer(self, name: str) -> dict:
        with self._lock:
            if not isinstance(name, str) or name not in self._layers:
                self._reject("SCATTER_UNKNOWN_LAYER", name)
            layer = self._layers.pop(name)
            self._clear_chunks_locked()
            return layer.public_spec()

    def set_terrain(self, height, slope=None) -> int:
        with self._lock:
            if not callable(height) or (slope is not None
                                        and not callable(slope)):
                self._reject("SCATTER_INVALID_TERRAIN", height)
            invalidated = len(self._chunks)
            self._height = height
            self._slope = slope
            self._clear_chunks_locked()
            return invalidated

    def _sample_height_locked(self, x: float, y: float) -> float:
        try:
            value = self._height(x, y)
        except Exception as exc:
            raise ScatterError("SCATTER_INVALID_TERRAIN", exc) from exc
        if not _is_number(value):
            raise ScatterError("SCATTER_INVALID_TERRAIN", value)
        return float(value)

    def _sample_slope_locked(self, x: float, y: float, center_x: float,
                             center_y: float) -> float:
        if self._slope is not None:
            try:
                value = self._slope(center_x, center_y)
            except Exception as exc:
                raise ScatterError("SCATTER_INVALID_TERRAIN", exc) from exc
            if not _is_number(value):
                raise ScatterError("SCATTER_INVALID_TERRAIN", value)
            return float(value)

        radius = _SLOPE_PROBE_RADIUS
        center = (x, y, self._sample_height_locked(x, y))
        east = (x + radius, y, self._sample_height_locked(x + radius, y))
        north = (x, y + radius, self._sample_height_locked(x, y + radius))
        west = (x - radius, y, self._sample_height_locked(x - radius, y))
        south = (x, y - radius, self._sample_height_locked(x, y - radius))

        def triangle_slope(pa, pb, pc) -> float:
            ux = pb[0] - pa[0]
            uy = pb[1] - pa[1]
            uz = pb[2] - pa[2]
            vx = pc[0] - pa[0]
            vy = pc[1] - pa[1]
            vz = pc[2] - pa[2]
            nx = uy * vz - uz * vy
            ny = uz * vx - ux * vz
            nz = ux * vy - uy * vx
            horizontal = math.hypot(nx, ny)
            return math.degrees(math.atan2(horizontal, abs(nz)))

        return max(
            triangle_slope(center, east, north),
            triangle_slope(center, north, west),
            triangle_slope(center, west, south),
            triangle_slope(center, south, east),
        )

    def _candidate_filtered_locked(self, layer: _Layer, x: float, y: float,
                                   z: float, cell_center_x: float,
                                   cell_center_y: float) -> bool:
        if layer.min_height is not None and z < layer.min_height:
            return True
        if layer.max_height is not None and z >= layer.max_height:
            return True
        if layer.water_level is not None and z < layer.water_level:
            return True
        if layer.max_slope is not None:
            slope = self._sample_slope_locked(
                x, y, cell_center_x, cell_center_y)
            if slope > layer.max_slope:
                return True
        if layer.exclusion is not None:
            x0, y0, x1, y1 = layer.exclusion
            if x0 <= x < x1 and y0 <= y < y1:
                return True
        return False

    def _generate_chunk_locked(self, cx: int, cy: int) -> ChunkResult:
        accepted: list[ScatterPoint] = []
        filtered = 0
        chunk_size = self._chunk_size

        for layer_index, layer in enumerate(self._layers.values()):
            stride = self._stride_for_density(
                layer.density, chunk_size, allow_zero=True)
            if stride is None:
                continue
            candidates_per_axis = chunk_size // stride
            first_gx = cx * candidates_per_axis
            first_gy = cy * candidates_per_axis

            for local_gy in range(candidates_per_axis):
                gy = first_gy + local_gy
                base_y = gy * stride
                for local_gx in range(candidates_per_axis):
                    gx = first_gx + local_gx
                    base_x = gx * stride

                    jitter_x = _random_unit(
                        self._seed, layer_index, layer.seed_offset,
                        gx, gy, 0xA0761D6478BD642F)
                    jitter_y = _random_unit(
                        self._seed, layer_index, layer.seed_offset,
                        gx, gy, 0xE7037ED1A0B428DB)
                    x = base_x + jitter_x * stride
                    y = base_y + jitter_y * stride

                    owner_x = math.floor(x / chunk_size)
                    owner_y = math.floor(y / chunk_size)
                    if owner_x != cx or owner_y != cy:
                        continue

                    z = self._sample_height_locked(x, y)
                    center_x = base_x + stride * 0.5
                    center_y = base_y + stride * 0.5
                    if self._candidate_filtered_locked(
                            layer, x, y, z, center_x, center_y):
                        filtered += 1
                        continue

                    yaw = _random_unit(
                        self._seed, layer_index, layer.seed_offset,
                        gx, gy, 0x8EBC6AF09C88C6E3) * 360.0
                    accepted.append(ScatterPoint(
                        x=x,
                        y=y,
                        z=z,
                        yaw_deg=yaw,
                        layer=layer.name,
                        cell_x=gx,
                        cell_y=gy,
                    ))

        clipped = 0
        if len(accepted) > self._chunk_point_cap:
            clipped = len(accepted) - self._chunk_point_cap
            del accepted[self._chunk_point_cap:]
        return ChunkResult(cx, cy, tuple(accepted), clipped, filtered)

    def _evict_lru_locked(self) -> None:
        key = self._cache_order.pop(0)
        del self._chunks[key]
        self._stats["evicted"] += 1

    def place_chunk(self, cx: int, cy: int) -> ChunkResult:
        with self._lock:
            if self._height is None:
                self._reject("SCATTER_NO_TERRAIN", None)
            if not self._layers:
                self._reject("SCATTER_NO_LAYERS", None)
            self._validate_chunk_locked(cx, cy)
            key = (cx, cy)
            cached = self._chunks.get(key)
            if cached is not None:
                return cached

            try:
                result = self._generate_chunk_locked(cx, cy)
            except ScatterError:
                self._stats["rejected"] += 1
                raise

            while len(self._chunks) >= self._cache_limit:
                self._evict_lru_locked()
            self._chunks[key] = result
            self._cache_order.append(key)
            self._stats["placed"] += 1
            self._stats["points"] += len(result.points)
            self._stats["filtered"] += result.filtered
            self._stats["clipped"] += result.clipped
            return result

    def points_in_chunk(self, cx: int, cy: int) -> tuple:
        with self._lock:
            self._validate_chunk_locked(cx, cy)
            result = self._chunks.get((cx, cy))
            if result is None:
                self._reject("SCATTER_NOT_CACHED", (cx, cy))
            return result.points

    def evict_chunk(self, cx: int, cy: int) -> bool:
        with self._lock:
            self._validate_chunk_locked(cx, cy)
            key = (cx, cy)
            if key not in self._chunks:
                self._reject("SCATTER_NOT_CACHED", key)
            del self._chunks[key]
            self._cache_order.remove(key)
            self._stats["evicted"] += 1
            return True

    def cached_chunks(self) -> tuple:
        with self._lock:
            return tuple(self._cache_order)

    def chunk_of(self, x: float, y: float) -> tuple:
        with self._lock:
            if not _is_number(x) or not _is_number(y):
                self._reject("SCATTER_INVALID_CHUNK", (x, y))
            return (math.floor(float(x) / self._chunk_size),
                    math.floor(float(y) / self._chunk_size))

    def set_cache_limit(self, limit: int) -> int:
        with self._lock:
            if not _is_int(limit) or limit <= 0:
                self._reject("SCATTER_INVALID_CACHE_LIMIT", limit)
            self._cache_limit = limit
            while len(self._chunks) > limit:
                self._evict_lru_locked()
            return limit

    def stats(self) -> dict:
        with self._lock:
            return {
                "seed": self._seed,
                "layers": len(self._layers),
                "cached": len(self._chunks),
                "placed": self._stats["placed"],
                "points": self._stats["points"],
                "filtered": self._stats["filtered"],
                "clipped": self._stats["clipped"],
                "evicted": self._stats["evicted"],
                "rejected": self._stats["rejected"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "seed": self._seed,
                "chunk_size": self._chunk_size,
                "cache_limit": self._cache_limit,
                "chunk_point_cap": self._chunk_point_cap,
                "layers": [layer.public_spec()
                           for layer in self._layers.values()],
                "terrain": None if self._height is None else {
                    "height": self._height,
                    "slope": self._slope,
                },
                "chunks": {key: self._chunks[key]
                           for key in self._cache_order},
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def _parse_layer_snapshot(self, spec: object, chunk_size: int
                              ) -> _Layer:
        required = {
            "name", "density", "seed_offset", "min_height", "max_height",
            "max_slope", "water_level", "exclusion",
        }
        if not isinstance(spec, dict) or set(spec) != required:
            self._snapshot_reject("layer structure")
        name = spec["name"]
        if not isinstance(name, str) or not name.strip():
            self._snapshot_reject("layer name")
        density = spec["density"]
        if not _is_number(density):
            self._snapshot_reject("layer density")
        density_value = float(density)
        if density_value < 0.0 or density_value > 1.0:
            self._snapshot_reject("layer density")
        try:
            self._stride_for_density(
                density_value, chunk_size, allow_zero=True)
        except ScatterError as exc:
            self._snapshot_reject(exc.detail)
        seed_offset = spec["seed_offset"]
        if not _is_int(seed_offset):
            self._snapshot_reject("layer seed_offset")
        try:
            min_value = self._parse_optional_number(spec["min_height"])
            max_value = self._parse_optional_number(spec["max_height"])
            slope_value = self._parse_optional_number(spec["max_slope"])
            water_value = self._parse_optional_number(spec["water_level"])
            exclusion_value = self._parse_exclusion(spec["exclusion"])
        except ScatterError as exc:
            self._snapshot_reject(exc.detail)
        return _Layer(
            name=name,
            density=density_value,
            seed_offset=seed_offset,
            min_height=min_value,
            max_height=max_value,
            max_slope=slope_value,
            water_level=water_value,
            exclusion=exclusion_value,
        )

    def _parse_snapshot_locked(self, state: object) -> dict:
        required = {
            "version", "seed", "chunk_size", "cache_limit",
            "chunk_point_cap", "layers", "terrain", "chunks", "stats",
        }
        if not isinstance(state, dict) or set(state) != required:
            self._snapshot_reject("snapshot structure")
        if state["version"] != _SNAPSHOT_VERSION:
            self._snapshot_reject("version")

        seed = state["seed"]
        chunk_size = state["chunk_size"]
        cache_limit = state["cache_limit"]
        chunk_point_cap = state["chunk_point_cap"]
        if not _is_int(seed) or seed < 0:
            self._snapshot_reject("seed")
        if not _is_int(chunk_size) or chunk_size <= 0:
            self._snapshot_reject("chunk_size")
        if not _is_int(cache_limit) or cache_limit <= 0:
            self._snapshot_reject("cache_limit")
        if not _is_int(chunk_point_cap) or chunk_point_cap < 0:
            self._snapshot_reject("chunk_point_cap")

        raw_layers = state["layers"]
        if not isinstance(raw_layers, list):
            self._snapshot_reject("layers")
        if len(raw_layers) > self._max_layers:
            self._snapshot_reject("layers")
        layers: dict[str, _Layer] = {}
        for raw_layer in raw_layers:
            layer = self._parse_layer_snapshot(raw_layer, chunk_size)
            if layer.name in layers:
                self._snapshot_reject("duplicate layer")
            layers[layer.name] = layer

        terrain = state["terrain"]
        if terrain is None:
            height = None
            slope = None
        else:
            if (not isinstance(terrain, dict)
                    or set(terrain) != {"height", "slope"}):
                self._snapshot_reject("terrain")
            height = terrain["height"]
            slope = terrain["slope"]
            if not callable(height) or (slope is not None
                                        and not callable(slope)):
                self._snapshot_reject("terrain")

        raw_chunks = state["chunks"]
        if not isinstance(raw_chunks, dict):
            self._snapshot_reject("chunks")
        if len(raw_chunks) > cache_limit:
            self._snapshot_reject("chunks")
        chunks: dict[tuple[int, int], ChunkResult] = {}
        cache_order: list[tuple[int, int]] = []
        for key, value in raw_chunks.items():
            if (not isinstance(key, tuple) or len(key) != 2
                    or not _is_int(key[0]) or not _is_int(key[1])
                    or abs(key[0]) > self._max_chunk_coord
                    or abs(key[1]) > self._max_chunk_coord):
                self._snapshot_reject("chunk key")
            if not isinstance(value, ChunkResult):
                self._snapshot_reject("chunk value")
            if (value.cx != key[0] or value.cy != key[1]
                    or not _is_int(value.clipped)
                    or not _is_int(value.filtered)
                    or value.clipped < 0 or value.filtered < 0
                    or not isinstance(value.points, tuple)
                    or len(value.points) > chunk_point_cap):
                self._snapshot_reject("chunk value")
            points = []
            for point in value.points:
                if not isinstance(point, ScatterPoint):
                    self._snapshot_reject("point")
                if (not _is_number(point.x) or not _is_number(point.y)
                        or not _is_number(point.z)
                        or not _is_number(point.yaw_deg)
                        or not isinstance(point.layer, str)
                        or point.layer not in layers
                        or not _is_int(point.cell_x)
                        or not _is_int(point.cell_y)):
                    self._snapshot_reject("point")
                points.append(ScatterPoint(
                    x=float(point.x),
                    y=float(point.y),
                    z=float(point.z),
                    yaw_deg=float(point.yaw_deg),
                    layer=point.layer,
                    cell_x=point.cell_x,
                    cell_y=point.cell_y,
                ))
            chunks[key] = ChunkResult(
                key[0], key[1], tuple(points), value.clipped, value.filtered)
            cache_order.append(key)

        raw_stats = state["stats"]
        if (not isinstance(raw_stats, dict)
                or set(raw_stats) != set(_STAT_KEYS)):
            self._snapshot_reject("stats")
        counters = {}
        for stat_key in _STAT_KEYS:
            value = raw_stats[stat_key]
            if not _is_int(value) or value < 0:
                self._snapshot_reject("stats")
            counters[stat_key] = value
        if (counters["seed"] != seed
                or counters["layers"] != len(layers)
                or counters["cached"] != len(chunks)
                or counters["placed"] < len(chunks)):
            self._snapshot_reject("stats")

        return {
            "seed": seed,
            "chunk_size": chunk_size,
            "cache_limit": cache_limit,
            "chunk_point_cap": chunk_point_cap,
            "layers": layers,
            "height": height,
            "slope": slope,
            "chunks": chunks,
            "cache_order": cache_order,
            "counters": {key: counters[key] for key in _COUNTER_KEYS},
        }

    def restore(self, state: dict) -> None:
        with self._lock:
            parsed = self._parse_snapshot_locked(state)
            self._seed = parsed["seed"]
            self._chunk_size = parsed["chunk_size"]
            self._cache_limit = parsed["cache_limit"]
            self._chunk_point_cap = parsed["chunk_point_cap"]
            self._layers = parsed["layers"]
            self._height = parsed["height"]
            self._slope = parsed["slope"]
            self._chunks = parsed["chunks"]
            self._cache_order = parsed["cache_order"]
            self._stats = parsed["counters"]
