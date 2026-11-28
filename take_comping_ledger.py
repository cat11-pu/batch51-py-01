"""Take comping ledger: region placement, overlap priority, crossfade and undo stack."""

from __future__ import annotations

import copy
import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass


_SNAPSHOT_VERSION = 1
_STATS_KEYS = (
    "takes",
    "regions",
    "audible_regions",
    "placed",
    "removed",
    "bounces",
    "undone",
)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _clean_take_id(take_id: object) -> str | None:
    if not isinstance(take_id, str):
        return None
    cleaned = take_id.strip()
    return cleaned or None


def _valid_gain(gain_db: object) -> bool:
    if isinstance(gain_db, bool) or not isinstance(gain_db, (int, float)):
        return False
    try:
        if not math.isfinite(float(gain_db)):
            return False
    except (OverflowError, ValueError):
        return False
    return -60.0 <= gain_db <= 24.0


class TakeError(ValueError):
    """Raised when a comping operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TakeInfo:
    """One recorded take lane."""

    take_id: str
    length_samples: int
    gain_db: float
    muted: bool


@dataclass(frozen=True)
class RegionInfo:
    """One region placed on the timeline."""

    region_id: int
    take_id: str
    start: int
    end: int
    at: int
    priority: int


@dataclass(frozen=True)
class Segment:
    """One resolved piece of the bounced track."""

    take_id: str
    start_sample: int
    end_sample: int
    gain_db: float
    fade_in: int
    fade_out: int


@dataclass(frozen=True)
class BounceResult:
    """Result of bouncing one span of the timeline."""

    segments: tuple
    total_samples: int
    silent_samples: int


class TakeCompingLedger:
    """Keep take lanes, placed regions and the undo stack for one comp."""

    def __init__(self, *, max_takes: int = 8, max_regions: int = 32,
                 crossfade_samples: int = 64) -> None:
        if not _is_int(max_takes) or max_takes < 0:
            raise TakeError("TAKE_INVALID", "max_takes")
        if not _is_int(max_regions) or max_regions < 0:
            raise TakeError("TAKE_INVALID", "max_regions")
        if not _is_int(crossfade_samples) or crossfade_samples < 0:
            raise TakeError("TAKE_INVALID", "crossfade_samples")
        self.max_takes = max_takes
        self.max_regions = max_regions
        self.crossfade_samples = crossfade_samples
        self._lock = threading.RLock()
        self._takes: dict[str, TakeInfo] = {}
        self._regions: dict[int, RegionInfo] = {}
        self._next_region = 1
        self._undo: list = []
        self._counters = {
            "placed": 0,
            "removed": 0,
            "bounces": 0,
            "undone": 0,
        }

    def add_take(self, take_id: str, *, length_samples: int,
                 gain_db: float = 0.0, muted: bool = False) -> TakeInfo:
        cleaned = _clean_take_id(take_id)
        if (cleaned is None or not _is_int(length_samples)
                or length_samples <= 0 or not _valid_gain(gain_db)
                or not isinstance(muted, bool)):
            raise TakeError("TAKE_INVALID", take_id)

        with self._lock:
            if cleaned in self._takes:
                raise TakeError("TAKE_EXISTS", cleaned)
            if len(self._takes) >= self.max_takes:
                raise TakeError("TAKE_CAPACITY", self.max_takes)

            info = TakeInfo(
                take_id=cleaned,
                length_samples=length_samples,
                gain_db=float(gain_db),
                muted=muted,
            )
            self._takes[cleaned] = info
            return info

    @staticmethod
    def _validate_region_fields(take: TakeInfo, start: object, end: object,
                                at: object, priority: object) -> None:
        if not (_is_int(start) and _is_int(end) and _is_int(at)
                and _is_int(priority)):
            raise TakeError("TAKE_REGION_INVALID", "region fields must be integers")
        if start < 0 or start >= end or end > take.length_samples:
            raise TakeError("TAKE_REGION_INVALID", (start, end))
        if at < 0:
            raise TakeError("TAKE_REGION_INVALID", at)
        if priority < -1000 or priority > 1000:
            raise TakeError("TAKE_REGION_INVALID", priority)

    @staticmethod
    def _validate_priority(priority: object) -> None:
        if not _is_int(priority) or priority < -1000 or priority > 1000:
            raise TakeError("TAKE_REGION_INVALID", priority)

    @staticmethod
    def _region_to_dict(region: RegionInfo) -> dict:
        return {
            "region_id": region.region_id,
            "take_id": region.take_id,
            "start": region.start,
            "end": region.end,
            "at": region.at,
            "priority": region.priority,
        }

    def place_region(self, take_id: str, *, start: int, end: int,
                     at: int, priority: int = 0) -> RegionInfo:
        cleaned = _clean_take_id(take_id)
        with self._lock:
            take = self._takes.get(cleaned) if cleaned is not None else None
            if take is None:
                raise TakeError("TAKE_UNKNOWN", take_id)
            self._validate_region_fields(take, start, end, at, priority)
            if len(self._regions) >= self.max_regions:
                raise TakeError("TAKE_CAPACITY", self.max_regions)

            region = RegionInfo(
                region_id=self._next_region,
                take_id=take.take_id,
                start=start,
                end=end,
                at=at,
                priority=priority,
            )
            self._next_region += 1
            self._regions[region.region_id] = region
            self._undo.append({
                "op": "place",
                "regions": [self._region_to_dict(region)],
            })
            self._counters["placed"] += 1
            return region

    def place_batch(self, *, placements) -> tuple:
        try:
            entries = list(placements)
        except TypeError:
            raise TakeError("TAKE_REGION_INVALID", "placements") from None

        required = {"take_id", "start", "end", "at", "priority"}
        parsed = []
        with self._lock:
            for entry in entries:
                if not isinstance(entry, Mapping) or not required.issubset(entry):
                    raise TakeError("TAKE_REGION_INVALID", entry)
                cleaned = _clean_take_id(entry["take_id"])
                take = self._takes.get(cleaned) if cleaned is not None else None
                if take is None:
                    raise TakeError("TAKE_UNKNOWN", entry["take_id"])
                self._validate_region_fields(
                    take,
                    entry["start"],
                    entry["end"],
                    entry["at"],
                    entry["priority"],
                )
                parsed.append((
                    take,
                    entry["start"],
                    entry["end"],
                    entry["at"],
                    entry["priority"],
                ))

            if len(self._regions) + len(parsed) > self.max_regions:
                raise TakeError("TAKE_CAPACITY", self.max_regions)

            new_regions = []
            next_region = self._next_region
            for take, start, end, at, priority in parsed:
                region = RegionInfo(
                    region_id=next_region,
                    take_id=take.take_id,
                    start=start,
                    end=end,
                    at=at,
                    priority=priority,
                )
                next_region += 1
                new_regions.append(region)

            if not new_regions:
                return ()

            self._next_region = next_region
            for region in new_regions:
                self._regions[region.region_id] = region
            self._undo.append({
                "op": "place",
                "regions": [self._region_to_dict(region)
                            for region in new_regions],
            })
            self._counters["placed"] += len(new_regions)
            return tuple(new_regions)

    def set_priority(self, region_id: int, priority: int) -> RegionInfo:
        with self._lock:
            region = (self._regions.get(region_id)
                      if _is_int(region_id) else None)
            if region is None:
                raise TakeError("TAKE_UNKNOWN", region_id)
            self._validate_priority(priority)
            updated = RegionInfo(
                region_id=region.region_id,
                take_id=region.take_id,
                start=region.start,
                end=region.end,
                at=region.at,
                priority=priority,
            )
            self._regions[region_id] = updated
            return updated

    def set_muted(self, take_id: str, muted: bool) -> TakeInfo:
        cleaned = _clean_take_id(take_id)
        with self._lock:
            take = self._takes.get(cleaned) if cleaned is not None else None
            if take is None:
                raise TakeError("TAKE_UNKNOWN", take_id)
            updated = TakeInfo(
                take_id=take.take_id,
                length_samples=take.length_samples,
                gain_db=take.gain_db,
                muted=bool(muted),
            )
            self._takes[take.take_id] = updated
            return updated

    def remove_region(self, region_id: int) -> RegionInfo:
        with self._lock:
            region = (self._regions.get(region_id)
                      if _is_int(region_id) else None)
            if region is None:
                raise TakeError("TAKE_UNKNOWN", region_id)
            del self._regions[region_id]
            self._undo.append({
                "op": "remove",
                "regions": [self._region_to_dict(region)],
            })
            self._counters["removed"] += 1
            return region

    @staticmethod
    def _validate_span(start: object, end: object) -> None:
        if (not _is_int(start) or not _is_int(end)
                or start < 0 or end < 0 or start >= end):
            raise TakeError("TAKE_INVALID", (start, end))

    def _resolve_locked(self, start: int, end: int) -> tuple:
        spans = []
        for region in self._regions.values():
            take = self._takes[region.take_id]
            if take.muted:
                continue
            region_start = max(start, region.at)
            region_end = min(end, region.at + (region.end - region.start))
            if region_start < region_end:
                spans.append((region, region_start, region_end))

        if not spans:
            return ()

        boundaries = {start, end}
        for _, region_start, region_end in spans:
            boundaries.add(region_start)
            boundaries.add(region_end)
        points = sorted(boundaries)

        runs: list[list] = []
        for left, right in zip(points, points[1:]):
            active = [
                region for region, region_start, region_end in spans
                if region_start <= left and right <= region_end
            ]
            if not active:
                continue
            winner = max(active, key=lambda region: (
                region.priority, region.region_id))
            if runs and runs[-1][0].region_id == winner.region_id:
                runs[-1][2] = right
            else:
                runs.append([winner, left, right])

        fade_ins = [0] * len(runs)
        fade_outs = [0] * len(runs)
        for index in range(1, len(runs)):
            left_region, left_start, left_end = runs[index - 1]
            right_region, right_start, right_end = runs[index]
            if left_end != right_start:
                continue
            left_length = left_end - left_start
            right_length = right_end - right_start
            fade = min(
                self.crossfade_samples,
                left_length // 2,
                right_length // 2,
            )
            fade_outs[index - 1] = fade
            fade_ins[index] = fade

        segments = []
        for index, (region, segment_start, segment_end) in enumerate(runs):
            take = self._takes[region.take_id]
            segments.append(Segment(
                take_id=region.take_id,
                start_sample=segment_start,
                end_sample=segment_end,
                gain_db=take.gain_db,
                fade_in=fade_ins[index],
                fade_out=fade_outs[index],
            ))
        return tuple(segments)

    def resolve_overlaps(self, *, start: int, end: int) -> tuple:
        with self._lock:
            self._validate_span(start, end)
            return self._resolve_locked(start, end)

    def bounce(self, *, start: int, end: int) -> BounceResult:
        with self._lock:
            self._validate_span(start, end)
            segments = self._resolve_locked(start, end)
            total_samples = end - start
            sounding_samples = sum(
                segment.end_sample - segment.start_sample
                for segment in segments
            )
            result = BounceResult(
                segments=segments,
                total_samples=total_samples,
                silent_samples=total_samples - sounding_samples,
            )
            self._counters["bounces"] += 1
            return result

    def _region_from_record(self, record: Mapping) -> RegionInfo:
        return self._parse_snapshot_region(
            record, self._takes, self._next_region)

    def undo(self) -> int:
        with self._lock:
            if not self._undo:
                raise TakeError("TAKE_NOTHING_TO_UNDO")

            entry = self._undo[-1]
            records = entry["regions"]
            regions = [self._region_from_record(record)
                       for record in records]
            self._undo.pop()

            if entry["op"] == "place":
                for region in regions:
                    self._regions.pop(region.region_id, None)
            else:
                for region in regions:
                    self._regions[region.region_id] = region

            count = len(regions)
            self._counters["undone"] += count
            return count

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "next_region": self._next_region,
                "takes": [
                    {
                        "take_id": take.take_id,
                        "length_samples": take.length_samples,
                        "gain_db": take.gain_db,
                        "muted": take.muted,
                    }
                    for take in self._takes.values()
                ],
                "regions": [
                    self._region_to_dict(region)
                    for region in self._regions.values()
                ],
                "undo": copy.deepcopy(self._undo),
                "stats": self.stats(),
            }

    @staticmethod
    def _parse_snapshot_take(record: object) -> TakeInfo:
        if not isinstance(record, Mapping):
            raise ValueError("take record")
        required = {"take_id", "length_samples", "gain_db", "muted"}
        if not required.issubset(record):
            raise ValueError("take record")

        take_id = _clean_take_id(record["take_id"])
        length_samples = record["length_samples"]
        gain_db = record["gain_db"]
        muted = record["muted"]
        if (take_id is None or not _is_int(length_samples)
                or length_samples <= 0 or not _valid_gain(gain_db)
                or not isinstance(muted, bool)):
            raise ValueError("take record")
        return TakeInfo(
            take_id=take_id,
            length_samples=length_samples,
            gain_db=float(gain_db),
            muted=muted,
        )

    @staticmethod
    def _parse_snapshot_region(record: object,
                               takes: Mapping[str, TakeInfo],
                               next_region: int) -> RegionInfo:
        if not isinstance(record, Mapping):
            raise ValueError("region record")
        required = {"region_id", "take_id", "start", "end", "at", "priority"}
        if not required.issubset(record):
            raise ValueError("region record")

        region_id = record["region_id"]
        take_id = _clean_take_id(record["take_id"])
        start = record["start"]
        end = record["end"]
        at = record["at"]
        priority = record["priority"]
        if (not _is_int(region_id) or region_id <= 0
                or region_id >= next_region or take_id not in takes):
            raise ValueError("region record")
        take = takes[take_id]
        TakeCompingLedger._validate_region_fields(
            take, start, end, at, priority)
        return RegionInfo(
            region_id=region_id,
            take_id=take_id,
            start=start,
            end=end,
            at=at,
            priority=priority,
        )

    def _parse_snapshot(self, state: object):
        if not isinstance(state, Mapping):
            raise ValueError("snapshot")
        required = {"version", "next_region", "takes", "regions",
                    "undo", "stats"}
        if not required.issubset(state):
            raise ValueError("snapshot")

        version = state["version"]
        if (not _is_int(version)
                or version != _SNAPSHOT_VERSION):
            raise ValueError("snapshot version")

        next_region = state["next_region"]
        if not _is_int(next_region) or next_region <= 0:
            raise ValueError("next_region")

        takes_raw = state["takes"]
        regions_raw = state["regions"]
        undo_raw = state["undo"]
        stats_raw = state["stats"]
        if (not isinstance(takes_raw, list)
                or not isinstance(regions_raw, list)
                or not isinstance(undo_raw, list)
                or not isinstance(stats_raw, Mapping)):
            raise ValueError("snapshot collections")
        if len(takes_raw) > self.max_takes:
            raise ValueError("take capacity")
        if len(regions_raw) > self.max_regions:
            raise ValueError("region capacity")

        takes: dict[str, TakeInfo] = {}
        for record in takes_raw:
            take = self._parse_snapshot_take(record)
            if take.take_id in takes:
                raise ValueError("duplicate take")
            takes[take.take_id] = take

        regions: dict[int, RegionInfo] = {}
        max_region_id = 0
        for record in regions_raw:
            region = self._parse_snapshot_region(
                record, takes, next_region)
            if region.region_id in regions:
                raise ValueError("duplicate region")
            regions[region.region_id] = region
            max_region_id = max(max_region_id, region.region_id)

        undo = []
        for entry in undo_raw:
            if not isinstance(entry, Mapping):
                raise ValueError("undo")
            op = entry.get("op")
            records = entry.get("regions")
            if op not in ("place", "remove") or not isinstance(records, list):
                raise ValueError("undo")
            if not records:
                raise ValueError("undo")
            parsed_records = []
            for record in records:
                region = self._parse_snapshot_region(
                    record, takes, next_region)
                max_region_id = max(max_region_id, region.region_id)
                parsed_records.append(self._region_to_dict(region))
            undo.append({"op": op, "regions": parsed_records})

        if next_region <= max_region_id:
            raise ValueError("next_region")

        if not all(key in stats_raw for key in _STATS_KEYS):
            raise ValueError("stats")
        stats = {}
        for key in _STATS_KEYS:
            value = stats_raw[key]
            if not _is_int(value) or value < 0:
                raise ValueError("stats")
            stats[key] = value

        audible_regions = sum(
            1 for region in regions.values()
            if not takes[region.take_id].muted
        )
        if (stats["takes"] != len(takes)
                or stats["regions"] != len(regions)
                or stats["audible_regions"] != audible_regions):
            raise ValueError("stats")

        counters = {
            "placed": stats["placed"],
            "removed": stats["removed"],
            "bounces": stats["bounces"],
            "undone": stats["undone"],
        }
        return takes, regions, next_region, undo, counters

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                takes, regions, next_region, undo, counters = (
                    self._parse_snapshot(state))
            except Exception:
                raise TakeError("TAKE_SNAPSHOT_INVALID") from None

            self._takes = takes
            self._regions = regions
            self._next_region = next_region
            self._undo = undo
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            audible_regions = sum(
                1 for region in self._regions.values()
                if not self._takes[region.take_id].muted
            )
            return {
                "takes": len(self._takes),
                "regions": len(self._regions),
                "audible_regions": audible_regions,
                "placed": self._counters["placed"],
                "removed": self._counters["removed"],
                "bounces": self._counters["bounces"],
                "undone": self._counters["undone"],
            }
