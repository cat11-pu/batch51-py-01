"""Luminance driven importance sampling tables with alias lookups."""

from __future__ import annotations

import copy
import math
import sys
import threading
from dataclasses import dataclass, field
from typing import Mapping


class TableError(ValueError):
    """Raised when a luminance grid, a region or a sample is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BuildReport:
    rows: int
    cols: int
    total: float
    version: int


@dataclass(frozen=True)
class AliasEntry:
    prob: float
    alias: int
    _threshold: float | None = field(default=None, repr=False, compare=False)


class ImportanceSampleTable:
    """Two level sampling table built from an environment luminance grid."""

    def __init__(self, *, max_dimension: int = 256,
                 min_luminance: float = 1e-12) -> None:
        self._lock = threading.RLock()
        try:
            self._max_dimension = max(0, int(max_dimension))
        except (TypeError, ValueError, OverflowError):
            self._max_dimension = 0
        try:
            floor = float(min_luminance)
        except (TypeError, ValueError, OverflowError):
            floor = 0.0
        if not math.isfinite(floor) or floor < 0.0:
            floor = 0.0
        self._min_luminance = floor
        self._weight_floor = floor if floor > 0.0 else sys.float_info.min
        self._luminance: list = []
        self._row_sums: list = []
        self._row_probs: tuple = ()
        self._total = 0.0
        self._alias: tuple = ()
        self._version = 0
        self._stats = {"builds": 0, "rebuilds": 0, "updates": 0,
                       "row_rebuilds": 0, "samples": 0, "rejections": 0,
                       "version": 0, "rows": 0, "cols": 0}

    def build(self, luminance) -> BuildReport:
        grid, rows, cols = self._normalize_grid(luminance)
        row_sums = []
        for row in grid:
            row_sum = self._finite_sum(row)
            if row_sum is None:
                self._reject("TABLE_INVALID_LUMINANCE",
                             "row sum is not finite")
            row_sums.append(row_sum)
        total = self._finite_sum(row_sums)
        if total is None:
            self._reject("TABLE_INVALID_LUMINANCE", "total is not finite")
        if total <= 0.0:
            self._reject("TABLE_ZERO_LUMINANCE", "total luminance is zero")
        row_probs = tuple(value / total for value in row_sums)
        alias = tuple(self._build_alias_row(row) for row in grid)

        with self._lock:
            self._luminance = [list(row) for row in grid]
            self._row_sums = list(row_sums)
            self._row_probs = row_probs
            self._total = total
            self._alias = alias
            self._version += 1
            self._stats["builds"] += 1
            self._stats["version"] = self._version
            self._stats["rows"] = rows
            self._stats["cols"] = cols
            return BuildReport(rows, cols, total, self._version)

    def sample(self, u: float, v: float) -> tuple:
        u_value = self._normalize_uv(u)
        v_value = self._normalize_uv(v)
        if u_value is None or v_value is None:
            self._reject("TABLE_INVALID_UV", (u, v))

        with self._lock:
            if not self._luminance:
                self._stats["rejections"] += 1
                raise TableError("TABLE_NOT_BUILT")

            row = self._select_row(u_value)
            col = self._select_column(v_value, self._alias[row])
            self._stats["samples"] += 1
            return col, row

    def pdf(self, x: int, y: int) -> float:
        with self._lock:
            if not self._luminance:
                self._stats["rejections"] += 1
                raise TableError("TABLE_NOT_BUILT")
            if not self._valid_cell(x, y):
                self._stats["rejections"] += 1
                raise TableError("TABLE_OUT_OF_RANGE", (x, y))
            return self._luminance[y][x] / self._total

    def update_region(self, x0: int, y0: int, x1: int, y1: int,
                      values) -> int:
        with self._lock:
            region = self._normalize_region(x0, y0, x1, y1)
            if region is None:
                self._stats["rejections"] += 1
                raise TableError("TABLE_INVALID_REGION",
                                 (x0, y0, x1, y1))
            values_grid = self._normalize_values(values, region)
            if values_grid is None:
                self._stats["rejections"] += 1
                raise TableError("TABLE_INVALID_REGION",
                                 (x0, y0, x1, y1))
            for row in values_grid:
                for value in row:
                    if not self._valid_luminance(value):
                        self._stats["rejections"] += 1
                        raise TableError("TABLE_INVALID_LUMINANCE", value)

            left, top, right, bottom = region
            luminance = [list(row) for row in self._luminance]
            for y, value_row in enumerate(values_grid, start=top):
                for x, value in enumerate(value_row, start=left):
                    luminance[y][x] = float(value)

            changed_rows = range(top, bottom + 1)
            row_sums = list(self._row_sums)
            for y in changed_rows:
                row_sum = self._finite_sum(luminance[y])
                if row_sum is None:
                    self._stats["rejections"] += 1
                    raise TableError("TABLE_INVALID_LUMINANCE",
                                     "row sum is not finite")
                row_sums[y] = row_sum
            total = self._finite_sum(row_sums)
            if total is None:
                self._stats["rejections"] += 1
                raise TableError("TABLE_INVALID_LUMINANCE",
                                 "total is not finite")
            if total <= 0.0:
                self._stats["rejections"] += 1
                raise TableError("TABLE_ZERO_LUMINANCE",
                                 "total luminance is zero")

            alias = list(self._alias)
            for y in changed_rows:
                alias[y] = self._build_alias_row(luminance[y])
            row_probs = tuple(value / total for value in row_sums)

            self._luminance = luminance
            self._row_sums = row_sums
            self._row_probs = row_probs
            self._total = total
            self._alias = tuple(alias)
            self._version += 1
            self._stats["updates"] += 1
            self._stats["row_rebuilds"] += len(changed_rows)
            self._stats["version"] = self._version
            return self._version

    def rebuild(self) -> int:
        with self._lock:
            if not self._luminance:
                self._stats["rejections"] += 1
                raise TableError("TABLE_NOT_BUILT")

            row_sums = []
            for row in self._luminance:
                row_sum = self._finite_sum(row)
                if row_sum is None:
                    self._stats["rejections"] += 1
                    raise TableError("TABLE_INVALID_LUMINANCE",
                                     "row sum is not finite")
                row_sums.append(row_sum)
            total = self._finite_sum(row_sums)
            if total is None:
                self._stats["rejections"] += 1
                raise TableError("TABLE_INVALID_LUMINANCE",
                                 "total is not finite")
            if total <= 0.0:
                self._stats["rejections"] += 1
                raise TableError("TABLE_ZERO_LUMINANCE",
                                 "total luminance is zero")

            self._row_sums = row_sums
            self._row_probs = tuple(value / total for value in row_sums)
            self._total = total
            self._alias = tuple(self._build_alias_row(row)
                                for row in self._luminance)
            self._version += 1
            self._stats["rebuilds"] += 1
            self._stats["version"] = self._version
            return self._version

    def row_distribution(self) -> tuple:
        with self._lock:
            if not self._luminance:
                self._stats["rejections"] += 1
                raise TableError("TABLE_NOT_BUILT")
            return tuple(enumerate(self._row_probs))

    def alias_table(self, row: int) -> tuple:
        with self._lock:
            if not self._luminance:
                self._stats["rejections"] += 1
                raise TableError("TABLE_NOT_BUILT")
            if not self._valid_int(row) or not 0 <= row < len(self._alias):
                self._stats["rejections"] += 1
                raise TableError("TABLE_OUT_OF_RANGE", row)
            return tuple(self._alias[row])

    def version(self) -> int:
        with self._lock:
            return self._version

    def stats(self) -> dict:
        with self._lock:
            result = dict(self._stats)
            result["version"] = self._version
            result["rows"] = len(self._luminance)
            result["cols"] = len(self._luminance[0]) if self._luminance else 0
            return result

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self._version,
                "luminance": copy.deepcopy(self._luminance),
                "row_sums": copy.deepcopy(self._row_sums),
                "total": self._total,
                "alias": copy.deepcopy(self._alias),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        restored = self._validate_snapshot(state)
        with self._lock:
            (self._version, self._luminance, self._row_sums,
             self._row_probs, self._total, self._alias,
             self._stats) = restored

    def _normalize_grid(self, luminance) -> tuple:
        try:
            rows = list(luminance)
        except TypeError:
            self._reject("TABLE_INVALID_SHAPE", "not an iterable of rows")
        if not rows:
            self._reject("TABLE_INVALID_SHAPE", "empty grid")

        raw_grid = []
        cols = None
        for row in rows:
            if isinstance(row, (str, bytes)):
                self._reject("TABLE_INVALID_SHAPE", "row is not an array")
            try:
                values = list(row)
            except TypeError:
                self._reject("TABLE_INVALID_SHAPE", "row is not iterable")
            if cols is None:
                cols = len(values)
            if len(values) != cols:
                self._reject("TABLE_INVALID_SHAPE", "rows are not rectangular")
            raw_grid.append(values)

        if cols is None or cols == 0:
            self._reject("TABLE_INVALID_SHAPE", "no columns")
        if (len(raw_grid) > self._max_dimension
                or cols > self._max_dimension):
            self._reject("TABLE_INVALID_SHAPE",
                         (len(raw_grid), cols, self._max_dimension))

        grid = []
        for values in raw_grid:
            for value in values:
                if not self._valid_luminance(value):
                    self._reject("TABLE_INVALID_LUMINANCE", value)
            grid.append([float(value) for value in values])
        return grid, len(grid), cols

    @staticmethod
    def _valid_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _valid_luminance(cls, value) -> bool:
        if isinstance(value, (str, bytes)):
            return False
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return False
        return math.isfinite(number) and number >= 0.0

    @classmethod
    def _normalize_uv(cls, value):
        if isinstance(value, (str, bytes)):
            return None
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(number) or not 0.0 <= number <= 1.0:
            return None
        return number

    @staticmethod
    def _finite_sum(values):
        try:
            total = math.fsum(values)
        except (OverflowError, ValueError):
            return None
        return total if math.isfinite(total) else None

    def _valid_cell(self, x, y) -> bool:
        return (self._valid_int(x) and self._valid_int(y)
                and 0 <= y < len(self._luminance)
                and 0 <= x < len(self._luminance[y]))

    def _normalize_region(self, x0, y0, x1, y1):
        if not all(self._valid_int(value) for value in (x0, y0, x1, y1)):
            return None
        if not self._luminance:
            self._reject("TABLE_NOT_BUILT")
        rows = len(self._luminance)
        cols = len(self._luminance[0])
        if not (0 <= x0 <= x1 < cols and 0 <= y0 <= y1 < rows):
            return None
        return x0, y0, x1, y1

    def _normalize_values(self, values, region):
        left, top, right, bottom = region
        expected_rows = bottom - top + 1
        expected_cols = right - left + 1
        try:
            rows = list(values)
        except TypeError:
            return None
        if len(rows) != expected_rows:
            return None

        grid = []
        for row in rows:
            if isinstance(row, (str, bytes)):
                return None
            try:
                values_row = list(row)
            except TypeError:
                return None
            if len(values_row) != expected_cols:
                return None
            grid.append(values_row)
        return grid

    def _select_row(self, u: float) -> int:
        if u >= 1.0:
            return len(self._row_probs) - 1
        cumulative = 0.0
        last_nonzero = 0
        for row, probability in enumerate(self._row_probs):
            if probability > 0.0:
                last_nonzero = row
            cumulative += probability
            if u <= cumulative:
                return row
        return last_nonzero

    def _select_column(self, v: float, entries: tuple) -> int:
        count = len(entries)
        if count == 1:
            return 0
        if v <= 0.0:
            return 0
        if v >= 1.0:
            return count - 1
        scaled = v * count
        bucket = int(scaled)
        fraction = scaled - bucket
        entry = entries[bucket]
        if 0.0 < fraction <= entry._threshold:
            return entry.alias
        return bucket

    def _build_alias_row(self, row) -> tuple:
        count = len(row)
        if count == 0:
            return ()
        weights = [max(float(value), self._weight_floor) for value in row]
        total = math.fsum(weights)
        if not math.isfinite(total) or total <= 0.0:
            weights = [1.0] * count
            total = float(count)

        scaled = [weight / total * count for weight in weights]
        probabilities = [1.0] * count
        aliases = list(range(count))
        small = []
        large = []
        for index, value in enumerate(scaled):
            if value < 1.0:
                small.append(index)
            else:
                large.append(index)

        while small and large:
            small_index = small.pop()
            large_index = large[-1]
            probabilities[small_index] = min(1.0,
                                             max(0.0, scaled[small_index]))
            aliases[small_index] = large_index
            scaled[large_index] = (scaled[large_index]
                                   + scaled[small_index] - 1.0)
            if scaled[large_index] < 1.0:
                large.pop()
                small.append(large_index)

        return tuple(AliasEntry(1.0, alias, 1.0 - probability)
                     for probability, alias in zip(probabilities, aliases))

    def _validate_snapshot(self, state):
        required = {"version", "luminance", "row_sums", "total",
                    "alias", "stats"}
        if not isinstance(state, Mapping) or not required.issubset(state):
            self._snapshot_error("missing fields")

        try:
            version = state["version"]
            total = float(state["total"])
            luminance = state["luminance"]
            row_sums = state["row_sums"]
            alias = state["alias"]
            stats = state["stats"]
        except (TypeError, ValueError, OverflowError, KeyError):
            self._snapshot_error("unreadable fields")

        if not self._valid_int(version) or version < 0:
            self._snapshot_error("invalid version")

        if isinstance(luminance, (list, tuple)) and len(luminance) == 0:
            if (version != 0 or total != 0.0
                    or not isinstance(row_sums, (list, tuple))
                    or len(row_sums) != 0
                    or not isinstance(alias, (list, tuple))
                    or len(alias) != 0):
                self._snapshot_error("invalid unbuilt snapshot")
            valid_stats = self._snapshot_stats(stats, 0, 0, 0)
            return 0, [], [], (), 0.0, (), valid_stats

        if not math.isfinite(total) or total <= 0.0:
            self._snapshot_error("invalid total")

        grid, rows, cols = self._snapshot_grid(luminance)
        if not isinstance(row_sums, (list, tuple)) or len(row_sums) != rows:
            self._snapshot_error("invalid row sums")
        normalized_sums = []
        for index, value in enumerate(row_sums):
            if not self._valid_luminance(value):
                self._snapshot_error("invalid row sum")
            normalized = float(value)
            grid_sum = self._finite_sum(grid[index])
            if grid_sum is None or not math.isclose(
                    normalized, grid_sum,
                    rel_tol=1e-12, abs_tol=1e-15):
                self._snapshot_error("inconsistent row sum")
            normalized_sums.append(normalized)
        snapshot_total = self._finite_sum(normalized_sums)
        if snapshot_total is None or not math.isclose(
                total, snapshot_total,
                rel_tol=1e-12, abs_tol=1e-15):
            self._snapshot_error("inconsistent total")

        if not isinstance(alias, (list, tuple)) or len(alias) != rows:
            self._snapshot_error("invalid alias table")
        normalized_alias = []
        thresholds_complete = True
        for entries in alias:
            if not isinstance(entries, (list, tuple)) or len(entries) != cols:
                self._snapshot_error("invalid alias row")
            normalized_entries = []
            probability_sum = 0.0
            for entry in entries:
                try:
                    if isinstance(entry, Mapping):
                        probability = float(entry["prob"])
                        alias_index = entry["alias"]
                        threshold = entry.get("_threshold")
                    elif hasattr(entry, "prob") and hasattr(entry, "alias"):
                        probability = float(entry.prob)
                        alias_index = entry.alias
                        threshold = getattr(entry, "_threshold", None)
                    elif (isinstance(entry, (list, tuple))
                          and len(entry) in (2, 3)):
                        probability = float(entry[0])
                        alias_index = entry[1]
                        threshold = entry[2] if len(entry) == 3 else None
                    else:
                        raise TypeError
                except (AttributeError, KeyError, TypeError, ValueError,
                        OverflowError):
                    self._snapshot_error("invalid alias entry")
                if (not math.isfinite(probability)
                        or not 0.0 <= probability <= 1.0
                        or not self._valid_int(alias_index)
                        or not 0 <= alias_index < cols):
                    self._snapshot_error("invalid alias entry")
                if threshold is not None:
                    try:
                        threshold = float(threshold)
                    except (TypeError, ValueError, OverflowError):
                        self._snapshot_error("invalid alias threshold")
                    if (not math.isfinite(threshold)
                            or not 0.0 <= threshold <= 1.0):
                        self._snapshot_error("invalid alias threshold")
                else:
                    thresholds_complete = False
                probability_sum += probability
                normalized_entries.append(AliasEntry(probability,
                                                     alias_index,
                                                     threshold))
            if not math.isclose(probability_sum, float(cols),
                                rel_tol=1e-12, abs_tol=1e-12):
                self._snapshot_error("invalid alias probabilities")
            normalized_alias.append(tuple(normalized_entries))

        valid_stats = self._snapshot_stats(stats, version, rows, cols)
        row_probs = tuple(value / total for value in normalized_sums)
        if thresholds_complete:
            internal_alias = tuple(normalized_alias)
        else:
            internal_alias = tuple(self._build_alias_row(row) for row in grid)
        return (version, [list(row) for row in grid], normalized_sums,
                row_probs, total, internal_alias, valid_stats)

    def _snapshot_grid(self, luminance):
        if isinstance(luminance, (str, bytes)):
            self._snapshot_error("invalid luminance")
        try:
            rows = list(luminance)
        except TypeError:
            self._snapshot_error("invalid luminance")
        if not rows:
            self._snapshot_error("empty luminance")
        grid = []
        cols = None
        for row in rows:
            if isinstance(row, (str, bytes)):
                self._snapshot_error("invalid luminance row")
            try:
                values = list(row)
            except TypeError:
                self._snapshot_error("invalid luminance row")
            if cols is None:
                cols = len(values)
            if cols == 0 or len(values) != cols:
                self._snapshot_error("invalid luminance shape")
            normalized = []
            for value in values:
                if not self._valid_luminance(value):
                    self._snapshot_error("invalid luminance value")
                normalized.append(float(value))
            grid.append(normalized)
        if (len(grid) > self._max_dimension
                or cols > self._max_dimension):
            self._snapshot_error("luminance exceeds max dimension")
        return grid, len(grid), cols

    def _snapshot_stats(self, stats, version, rows, cols) -> dict:
        keys = {"builds", "rebuilds", "updates", "row_rebuilds",
                "samples", "rejections", "version", "rows", "cols"}
        if not isinstance(stats, Mapping) or not keys.issubset(stats):
            self._snapshot_error("invalid stats")
        result = {}
        for key in keys:
            value = stats[key]
            if not self._valid_int(value) or value < 0:
                self._snapshot_error("invalid stats")
            result[key] = value
        if (result["version"] != version or result["rows"] != rows
                or result["cols"] != cols):
            self._snapshot_error("inconsistent stats")
        return result

    def _snapshot_error(self, detail):
        raise TableError("TABLE_SNAPSHOT_INVALID", detail)

    def _reject(self, code: str, detail=None):
        with self._lock:
            self._stats["rejections"] += 1
        raise TableError(code, detail)
