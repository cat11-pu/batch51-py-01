"""Cubemap mip chain builder that keeps face borders and poles seamless."""

from __future__ import annotations

import copy
import math
import threading
from collections.abc import Mapping, Sequence

FACE_NAMES = ("+x", "-x", "+y", "-y", "+z", "-z")
EDGES = ("top", "bottom", "left", "right")

SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = frozenset(("version", "size", "faces", "mips", "stats"))
STATS_KEYS = frozenset(("faces", "size", "levels", "builds", "samples"))

# A face is described by its outward normal, its local +u axis and its local
# +v axis. Rows are stored top to bottom, so +v points down the image.
_FACE_BASIS = {
    "+x": ((1, 0, 0), (0, 0, -1), (0, -1, 0)),
    "-x": ((-1, 0, 0), (0, 0, 1), (0, -1, 0)),
    "+y": ((0, 1, 0), (1, 0, 0), (0, 0, 1)),
    "-y": ((0, -1, 0), (1, 0, 0), (0, 0, -1)),
    "+z": ((0, 0, 1), (1, 0, 0), (0, -1, 0)),
    "-z": ((0, 0, -1), (-1, 0, 0), (0, -1, 0)),
}


class CubemapError(ValueError):
    """Raised when a cubemap upload, build or lookup is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (isinstance(value, (int, float)) and
            not isinstance(value, bool))


class CubemapSeamMipBuilder:
    """Build per-face mip levels with seam aware filtering and lookups."""

    def __init__(self, *, max_size: int = 1024) -> None:
        if not _is_integer(max_size) or max_size <= 0:
            raise ValueError("max_size must be a positive integer")
        self.max_size = max_size
        self._lock = threading.RLock()
        self._faces: dict[str, tuple[tuple[int, ...], ...]] = {}
        self._mips: dict[
            int, dict[str, tuple[tuple[int, ...], ...]]
        ] = {}
        self._size = 0
        self._levels = 0
        self._built = False
        self._stats = {
            "faces": 0,
            "size": 0,
            "levels": 0,
            "builds": 0,
            "samples": 0,
        }

    @staticmethod
    def _error(code: str, detail: object = None) -> None:
        raise CubemapError(code, detail)

    @staticmethod
    def _expected_levels(size: int) -> int:
        return size.bit_length() if size > 0 else 0

    @staticmethod
    def _is_power_of_two(value: int) -> bool:
        return value > 0 and (value & (value - 1)) == 0

    def _validate_face_mapping(
        self, faces: object
    ) -> tuple[int, dict[str, tuple[tuple[int, ...], ...]]]:
        if not isinstance(faces, Mapping):
            self._error(
                "CUBEMAP_INVALID_SHAPE",
                {"reason": "faces must be a mapping"},
            )

        keys = set(faces.keys())
        unknown = sorted(
            (key for key in keys if key not in FACE_NAMES), key=repr
        )
        if unknown:
            self._error(
                "CUBEMAP_FACE_UNKNOWN",
                {"faces": unknown},
            )

        missing = [name for name in FACE_NAMES if name not in keys]
        if missing:
            self._error(
                "CUBEMAP_FACE_MISSING",
                {"faces": missing},
            )

        raw_faces: dict[str, list] = {}
        sides: dict[str, int] = {}
        for name in FACE_NAMES:
            value = faces[name]
            if (isinstance(value, (str, bytes, bytearray)) or
                    not isinstance(value, Sequence)):
                self._error(
                    "CUBEMAP_INVALID_SHAPE",
                    {
                        "face": name,
                        "reason": "face must be a sequence of rows",
                    },
                )

            rows = list(value)
            side = len(rows)
            for y, row in enumerate(rows):
                if (isinstance(row, (str, bytes, bytearray)) or
                        not isinstance(row, Sequence)):
                    self._error(
                        "CUBEMAP_INVALID_SHAPE",
                        {
                            "face": name,
                            "row": y,
                            "reason": "row must be a sequence",
                        },
                    )
                if len(row) != side:
                    self._error(
                        "CUBEMAP_INVALID_SHAPE",
                        {
                            "face": name,
                            "row": y,
                            "expected_length": side,
                            "actual_length": len(row),
                        },
                    )
            raw_faces[name] = rows
            sides[name] = side

        distinct_sides = set(sides.values())
        if len(distinct_sides) != 1:
            self._error(
                "CUBEMAP_INVALID_SHAPE",
                {"reason": "face sizes differ", "sizes": dict(sides)},
            )

        size = next(iter(distinct_sides))
        if not self._is_power_of_two(size):
            self._error(
                "CUBEMAP_SIZE_NOT_POWER_OF_TWO",
                {"size": size},
            )
        if size > self.max_size:
            self._error(
                "CUBEMAP_SIZE_TOO_LARGE",
                {"size": size, "max_size": self.max_size},
            )

        normalized: dict[str, tuple[tuple[int, ...], ...]] = {}
        for name in FACE_NAMES:
            out_rows = []
            for y, row in enumerate(raw_faces[name]):
                out_row = []
                for x, texel in enumerate(row):
                    if (not _is_integer(texel) or
                            texel < 0 or texel > 255):
                        self._error(
                            "CUBEMAP_INVALID_TEXEL",
                            {
                                "face": name,
                                "x": x,
                                "y": y,
                                "value": texel,
                            },
                        )
                    out_row.append(texel)
                out_rows.append(tuple(out_row))
            normalized[name] = tuple(out_rows)

        return size, normalized

    def _face_name(self, face: object) -> str:
        if face not in FACE_NAMES:
            self._error("CUBEMAP_FACE_UNKNOWN", {"face": face})
        return face

    def _level_number(self, level: object) -> int:
        if not _is_integer(level):
            self._error("CUBEMAP_NO_SUCH_LEVEL", {"level": level})
        count = self._expected_levels(self._size)
        if level < 0 or level >= count:
            self._error(
                "CUBEMAP_NO_SUCH_LEVEL",
                {"level": level, "levels": count},
            )
        return level

    def _level_data(self, level: object) -> tuple[int, dict]:
        level_number = self._level_number(level)
        data = self._mips.get(level_number)
        if data is None:
            self._error(
                "CUBEMAP_NO_SUCH_LEVEL",
                {
                    "level": level_number,
                    "built_levels": sorted(self._mips),
                },
            )
        return level_number, data

    def load_faces(self, faces) -> int:
        with self._lock:
            size, normalized = self._validate_face_mapping(faces)
            self._faces = normalized
            self._mips = {0: normalized}
            self._size = size
            self._levels = 1
            self._built = False
            self._stats = {
                "faces": len(FACE_NAMES),
                "size": size,
                "levels": 1,
                "builds": 0,
                "samples": 0,
            }
            return size

    @staticmethod
    def _downsample_faces(faces: dict, size: int) -> dict:
        next_size = size // 2
        result: dict[str, tuple[tuple[int, ...], ...]] = {}
        for name in FACE_NAMES:
            source = faces[name]
            rows = []
            for y in range(next_size):
                row = []
                top = source[2 * y]
                bottom = source[2 * y + 1]
                for x in range(next_size):
                    x0 = 2 * x
                    total = (top[x0] + top[x0 + 1] +
                             bottom[x0] + bottom[x0 + 1])
                    row.append(total // 4)
                rows.append(tuple(row))
            result[name] = tuple(rows)
        return result

    def build_mips(self) -> tuple:
        with self._lock:
            if not self._faces:
                self._error("CUBEMAP_NO_FACES", {"faces": 0})

            mips: dict[int, dict] = {0: self._faces}
            sizes = [self._size]
            current = self._faces
            current_size = self._size

            # A 1x1 level is the final level: there is nothing below it.
            while current_size > 1:
                current = self._downsample_faces(current, current_size)
                current_size //= 2
                mips[len(sizes)] = current
                sizes.append(current_size)

            # Publish the entire chain with one assignment. Readers either see
            # the previous complete chain or this complete chain.
            self._mips = mips
            self._levels = len(sizes)
            self._built = True
            self._stats["levels"] = self._levels
            self._stats["builds"] += 1
            return tuple(sizes)

    def mip_count(self) -> int:
        with self._lock:
            return self._expected_levels(self._size)

    def level_size(self, level: int) -> int:
        with self._lock:
            level_number = self._level_number(level)
            return self._size >> level_number

    def texel(self, face: str, level: int, x: int, y: int) -> int:
        with self._lock:
            name = self._face_name(face)
            level_number, data = self._level_data(level)
            size = self._size >> level_number
            if (not _is_integer(x) or not _is_integer(y) or
                    x < 0 or y < 0 or x >= size or y >= size):
                self._error(
                    "CUBEMAP_OUT_OF_RANGE",
                    {
                        "face": name,
                        "level": level_number,
                        "x": x,
                        "y": y,
                        "size": size,
                    },
                )
            return data[name][y][x]

    def face(self, face: str, level: int = 0) -> tuple:
        with self._lock:
            name = self._face_name(face)
            _, data = self._level_data(level)
            return data[name]

    @staticmethod
    def _face_for_direction(direction: tuple[float, float, float]):
        x, y, z = direction
        ax, ay, az = abs(x), abs(y), abs(z)
        scale = max(ax, ay, az)
        tolerance = max(1e-15, scale * 1e-12)

        if ax >= ay - tolerance and ax >= az - tolerance:
            if x >= 0:
                return "+x", -z / x, -y / x
            return "-x", z / -x, -y / -x
        if ay >= az - tolerance:
            if y >= 0:
                return "+y", x / y, z / y
            return "-y", x / -y, -z / -y
        if z >= 0:
            return "+z", x / z, -y / z
        return "-z", -x / -z, -y / -z

    @classmethod
    def _virtual_texel(
        cls, face: str, size: int, tx: int, ty: int
    ) -> tuple[str, int, int]:
        normal, right, down = _FACE_BASIS[face]
        a = -1.0 + 2.0 * (tx + 0.5) / size
        b = -1.0 + 2.0 * (ty + 0.5) / size
        direction = (
            normal[0] + a * right[0] + b * down[0],
            normal[1] + a * right[1] + b * down[1],
            normal[2] + a * right[2] + b * down[2],
        )
        target, target_a, target_b = cls._face_for_direction(direction)
        fx = (target_a + 1.0) * size / 2.0 - 0.5
        fy = (target_b + 1.0) * size / 2.0 - 0.5
        xi = int(math.floor(fx + 0.5))
        yi = int(math.floor(fy + 0.5))
        xi = min(size - 1, max(0, xi))
        yi = min(size - 1, max(0, yi))
        return target, xi, yi

    @staticmethod
    def _solid_angle_weight(face: str, size: int, x: int, y: int) -> float:
        a0 = 2.0 * x / size - 1.0
        a1 = 2.0 * (x + 1) / size - 1.0
        b0 = 2.0 * y / size - 1.0
        b1 = 2.0 * (y + 1) / size - 1.0

        def corner(a: float, b: float) -> float:
            return math.atan2(a * b, math.sqrt(a * a + b * b + 1.0))

        weight = (corner(a1, b1) - corner(a0, b1) -
                  corner(a1, b0) + corner(a0, b0))
        return max(weight, 1e-15)

    def sample(self, face: str, level: int, u: float, v: float) -> float:
        with self._lock:
            name = self._face_name(face)
            level_number, data = self._level_data(level)
            size = self._size >> level_number

            if (not _is_number(u) or not _is_number(v) or
                    not math.isfinite(float(u)) or
                    not math.isfinite(float(v))):
                self._error(
                    "CUBEMAP_OUT_OF_RANGE",
                    {
                        "face": name,
                        "level": level_number,
                        "u": u,
                        "v": v,
                    },
                )

            u = min(1.0, max(0.0, float(u)))
            v = min(1.0, max(0.0, float(v)))

            # On a face edge, evaluate through one canonical face.  Both
            # sides of the seam then build exactly the same filtering kernel.
            if u in (0.0, 1.0) or v in (0.0, 1.0):
                normal, right, down = _FACE_BASIS[name]
                a = 2.0 * u - 1.0
                b = 2.0 * v - 1.0
                direction = (
                    normal[0] + a * right[0] + b * down[0],
                    normal[1] + a * right[1] + b * down[1],
                    normal[2] + a * right[2] + b * down[2],
                )
                name, a, b = self._face_for_direction(direction)
                u = (a + 1.0) / 2.0
                v = (b + 1.0) / 2.0

            # A geometric cube corner is shared by three faces.  The ordinary
            # four-tap footprint has no fourth face there, so use the three
            # actual corner texels to avoid a source-face-dependent value.
            if ((u == 0.0 or u == 1.0) and
                    (v == 0.0 or v == 1.0)):
                ix = 0 if u == 0.0 else size - 1
                iy = 0 if v == 0.0 else size - 1
                outside_x = -1 if u == 0.0 else size
                outside_y = -1 if v == 0.0 else size
                corner_taps = [
                    (name, ix, iy),
                    self._virtual_texel(
                        name, size, outside_x, iy
                    ),
                    self._virtual_texel(
                        name, size, ix, outside_y
                    ),
                ]
                weighted = []
                for tap_face, tx, ty in corner_taps:
                    weight = self._solid_angle_weight(
                        tap_face, size, tx, ty
                    )
                    weighted.append(
                        (weight, tap_face, tx, ty)
                    )
                total_weight = sum(item[0] for item in weighted)
                total = sum(
                    item[0] * data[item[1]][item[3]][item[2]]
                    for item in weighted
                )
                self._stats["samples"] += 1
                return float(total / total_weight)

            gx = u * size - 0.5
            gy = v * size - 0.5
            x0 = int(math.floor(gx))
            y0 = int(math.floor(gy))
            fx = gx - x0
            fy = gy - y0

            contributions = []
            for ix, wx in ((x0, 1.0 - fx), (x0 + 1, fx)):
                for iy, wy in ((y0, 1.0 - fy), (y0 + 1, fy)):
                    weight = wx * wy
                    if weight <= 0.0:
                        continue
                    if 0 <= ix < size and 0 <= iy < size:
                        tap_face, tx, ty = name, ix, iy
                    else:
                        tap_face, tx, ty = self._virtual_texel(
                            name, size, ix, iy
                        )
                    contributions.append([
                        weight,
                        tap_face,
                        tx,
                        ty,
                        self._solid_angle_weight(tap_face, size, tx, ty),
                    ])

            # Within one face the requested bilinear weights are exact. When
            # the footprint crosses a seam, use solid-angle weights for the
            # whole kernel. This is symmetric no matter which face the sample
            # was requested from and keeps the two sides of the seam equal.
            crosses_seam = any(
                item[1] != name for item in contributions
            )
            if crosses_seam:
                angles = [item[4] for item in contributions]
                uniform_angles = (
                    max(angles) - min(angles) <=
                    max(1e-15, max(angles) * 1e-12)
                )
                if not uniform_angles:
                    base_total = sum(item[0] for item in contributions)
                    weighted_total = sum(
                        item[0] * item[4] for item in contributions
                    )
                    if weighted_total > 0.0:
                        for item in contributions:
                            item[0] = (item[0] * item[4] /
                                       weighted_total * base_total)

            total_weight = sum(item[0] for item in contributions)
            if total_weight <= 0.0:
                self._error(
                    "CUBEMAP_OUT_OF_RANGE",
                    {
                        "face": name,
                        "level": level_number,
                        "u": u,
                        "v": v,
                    },
                )

            total = 0.0
            for weight, tap_face, tx, ty, _ in contributions:
                total += weight * data[tap_face][ty][tx]

            self._stats["samples"] += 1
            return float(total / total_weight)

    def edge_texels(
        self, face: str, edge: str, level: int = 0
    ) -> tuple:
        with self._lock:
            name = self._face_name(face)
            if edge not in EDGES:
                self._error("CUBEMAP_INVALID_EDGE", {"edge": edge})
            level_number, data = self._level_data(level)
            grid = data[name]
            size = self._size >> level_number
            if edge == "top":
                return tuple(grid[0])
            if edge == "bottom":
                return tuple(grid[size - 1])
            if edge == "left":
                return tuple(grid[y][0] for y in range(size))
            return tuple(grid[y][size - 1] for y in range(size))

    def validate(self) -> dict:
        with self._lock:
            issues = []
            if not self._faces:
                issues.append("no faces loaded")
            else:
                expected_levels = self._expected_levels(self._size)
                if not self._built:
                    issues.append("mip chain not built")
                elif set(self._mips) != set(range(expected_levels)):
                    issues.append("mip chain is incomplete")
                else:
                    for level in range(expected_levels):
                        size = self._size >> level
                        for name in FACE_NAMES:
                            grid = self._mips[level].get(name)
                            if (grid is None or len(grid) != size or
                                    any(len(row) != size for row in grid)):
                                issues.append(
                                    f"invalid level {level} face {name}"
                                )
                                break
                        if issues:
                            break

            return {
                "ready": bool(self._faces and self._built and not issues),
                "size": self._size,
                "levels": self._levels,
                "issues": tuple(issues),
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "size": self._size,
                "faces": copy.deepcopy(self._faces),
                "mips": copy.deepcopy(self._mips),
                "stats": copy.deepcopy(self._stats),
            }

    @staticmethod
    def _validated_stats(
        stats: object, size: int, levels: int
    ) -> dict:
        if not isinstance(stats, Mapping) or set(stats) != STATS_KEYS:
            raise ValueError("invalid stats structure")

        faces = stats["faces"]
        stat_size = stats["size"]
        stat_levels = stats["levels"]
        builds = stats["builds"]
        samples = stats["samples"]
        expected_faces = len(FACE_NAMES) if size > 0 else 0
        if (not _is_integer(faces) or faces != expected_faces or
                not _is_integer(stat_size) or stat_size != size or
                not _is_integer(stat_levels) or stat_levels != levels or
                not _is_integer(builds) or builds < 0 or
                not _is_integer(samples) or samples < 0):
            raise ValueError("invalid stats values")
        return {
            "faces": faces,
            "size": stat_size,
            "levels": stat_levels,
            "builds": builds,
            "samples": samples,
        }

    def _state_from_snapshot(self, state: object) -> dict:
        if not isinstance(state, Mapping) or set(state) != SNAPSHOT_KEYS:
            raise ValueError("invalid snapshot structure")

        version = state["version"]
        if not _is_integer(version) or version != SNAPSHOT_VERSION:
            raise ValueError("unsupported snapshot version")

        size = state["size"]
        if not _is_integer(size) or size < 0:
            raise ValueError("invalid snapshot size")

        if size == 0:
            if state["faces"] != {} or state["mips"] != {}:
                raise ValueError("invalid empty snapshot")
            stats = self._validated_stats(state["stats"], 0, 0)
            return {
                "faces": {},
                "mips": {},
                "size": 0,
                "levels": 0,
                "built": False,
                "stats": stats,
            }

        if not self._is_power_of_two(size) or size > self.max_size:
            raise ValueError("invalid snapshot size")

        face_size, faces = self._validate_face_mapping(state["faces"])
        if face_size != size:
            raise ValueError("snapshot size does not match faces")

        raw_mips = state["mips"]
        if not isinstance(raw_mips, Mapping) or not raw_mips:
            raise ValueError("invalid mips structure")
        if any(not _is_integer(level) or level < 0
               for level in raw_mips.keys()):
            raise ValueError("invalid mip level")

        max_level = max(raw_mips)
        expected_levels = self._expected_levels(size)
        if set(raw_mips) != set(range(max_level + 1)):
            raise ValueError("mip levels are not contiguous")
        if max_level >= expected_levels:
            raise ValueError("too many mip levels")
        if max_level not in (0, expected_levels - 1):
            raise ValueError("incomplete mip chain")

        mips: dict[int, dict] = {}
        for level in range(max_level + 1):
            level_size, level_faces = self._validate_face_mapping(
                raw_mips[level]
            )
            if level_size != (size >> level):
                raise ValueError("mip level size mismatch")
            mips[level] = level_faces

        if mips[0] != faces:
            raise ValueError("faces and level zero differ")

        levels = max_level + 1
        stats = self._validated_stats(state["stats"], size, levels)
        built = (levels == expected_levels and
                 (expected_levels > 1 or stats["builds"] > 0))

        return {
            "faces": faces,
            "mips": mips,
            "size": size,
            "levels": levels,
            "built": built,
            "stats": stats,
        }

    def restore(self, state: dict) -> None:
        try:
            snapshot = copy.deepcopy(state)
            restored = self._state_from_snapshot(snapshot)
        except Exception as exc:
            self._error(
                "CUBEMAP_SNAPSHOT_INVALID",
                {"reason": str(exc)},
            )

        with self._lock:
            self._faces = restored["faces"]
            self._mips = restored["mips"]
            self._size = restored["size"]
            self._levels = restored["levels"]
            self._built = restored["built"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
