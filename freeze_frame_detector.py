"""Freeze frame and black frame interval detection over per-stream frame fingerprints."""

from __future__ import annotations

import math
import numbers
import threading
from dataclasses import dataclass, field


class FreezeError(ValueError):
    """Raised when a detector operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FrameRange:
    """One closed interval of a stream."""

    stream: str
    kind: str
    start_ms: int
    end_ms: int
    frames: int
    confidence: float
    overlap: bool


@dataclass
class _StreamState:
    name: str
    last_pts: int | None = None
    last_epoch: int | None = None
    last_fingerprint: int | None = None
    freeze_start: int | None = None
    freeze_frames: int = 0
    black_start: int | None = None
    black_frames: int = 0
    overrides: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _RangeEntry:
    stream: str
    kind: str
    start_ms: int
    end_ms: int
    frames: int
    confidence: float


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (
        isinstance(value, numbers.Real)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _stream_name(stream: object) -> str | None:
    if not isinstance(stream, str):
        return None
    name = stream.strip()
    return name or None


def _validate_ms(value: object, detail: str) -> int | float:
    if not _is_number(value) or value < 0:
        raise FreezeError("FREEZE_INVALID", detail)
    return value


def _validate_luma(value: object, detail: str) -> float:
    if not _is_number(value) or not 0 <= value <= 1:
        raise FreezeError("FREEZE_INVALID", detail)
    return float(value)


def _snapshot_error(detail: object) -> FreezeError:
    return FreezeError("FREEZE_SNAPSHOT_INVALID", detail)


def _snapshot_int(value: object, detail: str, *, minimum: int = 0,
                  optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if not _is_int(value) or value < minimum:
        raise _snapshot_error(detail)
    return value


def _snapshot_number(value: object, detail: str, *, low: float,
                     high: float) -> float:
    if not _is_number(value) or not low <= value <= high:
        raise _snapshot_error(detail)
    return float(value)


class FreezeFrameDetector:
    """Track per-stream frame runs and emit freeze/black intervals."""

    _THRESHOLD_KEYS = ("min_freeze_ms", "min_black_ms", "black_luma")

    def __init__(self, *, min_freeze_ms: int = 200, min_black_ms: int = 300,
                 black_luma: float = 0.08, max_ranges: int = 32) -> None:
        self.min_freeze_ms = _validate_ms(min_freeze_ms, "min_freeze_ms")
        self.min_black_ms = _validate_ms(min_black_ms, "min_black_ms")
        self.black_luma = _validate_luma(black_luma, "black_luma")
        if not _is_int(max_ranges) or max_ranges < 0:
            raise FreezeError("FREEZE_INVALID", "max_ranges")
        self.max_ranges = max_ranges
        self._lock = threading.RLock()
        self._streams: dict[str, _StreamState] = {}
        self._ranges: list[_RangeEntry] = []
        self._counters = {
            "frames": 0,
            "freeze_ranges": 0,
            "black_ranges": 0,
            "discarded": 0,
            "evicted": 0,
            "resets": 0,
        }

    def _default_thresholds(self) -> dict:
        return {
            "min_freeze_ms": self.min_freeze_ms,
            "min_black_ms": self.min_black_ms,
            "black_luma": self.black_luma,
        }

    def _effective_thresholds(self, state: _StreamState) -> dict:
        result = self._default_thresholds()
        result.update(state.overrides)
        return result

    @staticmethod
    def _sort_key(entry: _RangeEntry) -> tuple:
        return (entry.start_ms, entry.kind, entry.stream, entry.end_ms,
                entry.frames)

    def _sort_ranges(self) -> None:
        self._ranges.sort(key=self._sort_key)

    @staticmethod
    def _overlaps(entry: _RangeEntry, entries: list[_RangeEntry]) -> bool:
        for other in entries:
            if (
                other.stream == entry.stream
                and other.kind != entry.kind
                and other.start_ms <= entry.end_ms
                and entry.start_ms <= other.end_ms
            ):
                return True
        return False

    def _public(self, entry: _RangeEntry,
                entries: list[_RangeEntry]) -> FrameRange:
        return FrameRange(
            stream=entry.stream,
            kind=entry.kind,
            start_ms=entry.start_ms,
            end_ms=entry.end_ms,
            frames=entry.frames,
            confidence=entry.confidence,
            overlap=self._overlaps(entry, entries),
        )

    def _public_tuple(self, entries: list[_RangeEntry],
                      overlap_entries: list[_RangeEntry]) -> tuple:
        rows = [self._public(entry, overlap_entries) for entry in entries]
        rows.sort(key=lambda row: (
            row.start_ms, row.kind, row.stream, row.end_ms, row.frames
        ))
        return tuple(rows)

    def _trim_ranges(self) -> None:
        while len(self._ranges) > self.max_ranges:
            self._ranges.pop(0)
            self._counters["evicted"] += 1

    def _append_range(self, entry: _RangeEntry) -> None:
        self._ranges.append(entry)
        self._sort_ranges()
        self._trim_ranges()

    @staticmethod
    def _confidence(duration: int, threshold: int | float) -> float:
        if threshold <= 0:
            return 1.0
        return min(1.0, duration / (2.0 * float(threshold)))

    def _finalize(self, state: _StreamState, kind: str, start_ms: int,
                  end_ms: int, frames: int,
                  closed: list[_RangeEntry]) -> None:
        thresholds = self._effective_thresholds(state)
        if kind == "freeze":
            threshold = thresholds["min_freeze_ms"]
        else:
            threshold = thresholds["min_black_ms"]

        duration = end_ms - start_ms
        if duration < threshold:
            self._counters["discarded"] += 1
            return

        entry = _RangeEntry(
            stream=state.name,
            kind=kind,
            start_ms=start_ms,
            end_ms=end_ms,
            frames=frames,
            confidence=self._confidence(duration, threshold),
        )
        counter = "freeze_ranges" if kind == "freeze" else "black_ranges"
        self._counters[counter] += 1
        self._append_range(entry)
        closed.append(entry)

    def _close_freeze(self, state: _StreamState, end_ms: int,
                      closed: list[_RangeEntry]) -> None:
        if state.freeze_start is None:
            return
        start_ms = state.freeze_start
        frames = state.freeze_frames
        state.freeze_start = None
        state.freeze_frames = 0
        self._finalize(state, "freeze", start_ms, end_ms, frames, closed)

    def _close_black(self, state: _StreamState, end_ms: int,
                     closed: list[_RangeEntry]) -> None:
        if state.black_start is None:
            return
        start_ms = state.black_start
        frames = state.black_frames
        state.black_start = None
        state.black_frames = 0
        self._finalize(state, "black", start_ms, end_ms, frames, closed)

    def _reset_window(self, state: _StreamState) -> None:
        state.last_fingerprint = None
        state.freeze_start = None
        state.freeze_frames = 0
        state.black_start = None
        state.black_frames = 0

    def feed(self, stream: str, *, pts_ms: int, fingerprint: int,
             luma: float, epoch: int = 1) -> tuple:
        name = _stream_name(stream)
        if name is None:
            raise FreezeError("FREEZE_INVALID", "stream")
        if not _is_int(pts_ms) or pts_ms < 0:
            raise FreezeError("FREEZE_INVALID", "pts_ms")
        if not _is_int(fingerprint) or fingerprint < 0:
            raise FreezeError("FREEZE_INVALID", "fingerprint")
        if not _is_number(luma) or not 0 <= luma <= 1:
            raise FreezeError("FREEZE_INVALID", "luma")
        if not _is_int(epoch) or epoch < 1:
            raise FreezeError("FREEZE_INVALID", "epoch")

        with self._lock:
            state = self._streams.get(name)
            if state is None:
                state = _StreamState(name=name)
                self._streams[name] = state
            elif (
                state.last_epoch is not None
                and state.last_epoch == epoch
                and state.last_pts is not None
                and pts_ms <= state.last_pts
            ):
                raise FreezeError("FREEZE_PTS_NON_MONOTONIC", pts_ms)

            closed: list[_RangeEntry] = []
            if state.last_epoch is not None and state.last_epoch != epoch:
                self._close_freeze(state, state.last_pts, closed)
                self._close_black(state, state.last_pts, closed)
                self._reset_window(state)

            self._counters["frames"] += 1

            if state.freeze_start is None:
                state.freeze_start = pts_ms
                state.freeze_frames = 1
                state.last_fingerprint = fingerprint
            elif fingerprint == state.last_fingerprint:
                state.freeze_frames += 1
            else:
                self._close_freeze(state, state.last_pts, closed)
                state.freeze_start = pts_ms
                state.freeze_frames = 1
                state.last_fingerprint = fingerprint

            thresholds = self._effective_thresholds(state)
            if luma <= thresholds["black_luma"]:
                if state.black_start is None:
                    state.black_start = pts_ms
                    state.black_frames = 1
                else:
                    state.black_frames += 1
            else:
                self._close_black(state, state.last_pts, closed)

            state.last_pts = pts_ms
            state.last_epoch = epoch
            return self._public_tuple(closed, self._ranges)

    def flush(self, stream: str) -> tuple:
        name = _stream_name(stream)
        with self._lock:
            state = self._streams.get(name) if name is not None else None
            if state is None:
                raise FreezeError("FREEZE_UNKNOWN_STREAM", stream)

            closed: list[_RangeEntry] = []
            self._close_freeze(state, state.last_pts, closed)
            self._close_black(state, state.last_pts, closed)
            state.last_fingerprint = None
            return self._public_tuple(closed, self._ranges)

    def ranges(self, stream: str | None = None) -> tuple:
        with self._lock:
            entries = self._ranges
            if stream is not None:
                name = _stream_name(stream)
                entries = [entry for entry in entries if entry.stream == name]
            return self._public_tuple(entries, self._ranges)

    def open_range(self, stream: str) -> dict | None:
        name = _stream_name(stream)
        with self._lock:
            state = self._streams.get(name) if name is not None else None
            if state is None:
                return None
            return {
                "freeze_start": state.freeze_start,
                "freeze_frames": state.freeze_frames,
                "black_start": state.black_start,
                "black_frames": state.black_frames,
                "last_pts": state.last_pts,
            }

    def confidence_of(self, stream: str, start_ms: int,
                      kind: str = "freeze") -> float:
        name = _stream_name(stream)
        with self._lock:
            for entry in self._ranges:
                if (
                    entry.stream == name
                    and entry.start_ms == start_ms
                    and entry.kind == kind
                ):
                    return entry.confidence
        raise FreezeError("FREEZE_RANGE_UNKNOWN", (stream, start_ms, kind))

    def set_threshold(self, stream: str | None = None, *,
                      min_freeze_ms: int | None = None,
                      min_black_ms: int | None = None,
                      black_luma: float | None = None) -> dict:
        updates: dict = {}
        if min_freeze_ms is not None:
            updates["min_freeze_ms"] = _validate_ms(
                min_freeze_ms, "min_freeze_ms"
            )
        if min_black_ms is not None:
            updates["min_black_ms"] = _validate_ms(min_black_ms, "min_black_ms")
        if black_luma is not None:
            updates["black_luma"] = _validate_luma(black_luma, "black_luma")

        with self._lock:
            if stream is None:
                previous = self._default_thresholds()
                self.min_freeze_ms = updates.get(
                    "min_freeze_ms", self.min_freeze_ms
                )
                self.min_black_ms = updates.get(
                    "min_black_ms", self.min_black_ms
                )
                self.black_luma = updates.get("black_luma", self.black_luma)
                return previous

            name = _stream_name(stream)
            state = self._streams.get(name) if name is not None else None
            if state is None:
                raise FreezeError("FREEZE_UNKNOWN_STREAM", stream)
            previous = self._effective_thresholds(state)
            if updates:
                if not state.overrides:
                    state.overrides.update(previous)
                state.overrides.update(updates)
            return previous

    def reset_stream(self, stream: str) -> int:
        name = _stream_name(stream)
        with self._lock:
            state = self._streams.get(name) if name is not None else None
            if state is None:
                raise FreezeError("FREEZE_UNKNOWN_STREAM", stream)

            removed = 0
            kept = []
            for entry in self._ranges:
                if entry.stream == name:
                    removed += 1
                else:
                    kept.append(entry)
            self._ranges = kept

            state.last_pts = None
            state.last_epoch = None
            self._reset_window(state)
            self._counters["resets"] += 1
            return removed

    def streams(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._streams))

    def snapshot(self) -> dict:
        with self._lock:
            entries = list(self._ranges)
            stream_rows = []
            for name in sorted(self._streams):
                state = self._streams[name]
                stream_rows.append({
                    "stream": state.name,
                    "last_pts": state.last_pts,
                    "last_epoch": state.last_epoch,
                    "last_fingerprint": state.last_fingerprint,
                    "freeze_start": state.freeze_start,
                    "freeze_frames": state.freeze_frames,
                    "black_start": state.black_start,
                    "black_frames": state.black_frames,
                    "thresholds": dict(state.overrides),
                })

            range_rows = []
            for entry in entries:
                row = self._public(entry, entries)
                range_rows.append({
                    "stream": row.stream,
                    "kind": row.kind,
                    "start_ms": row.start_ms,
                    "end_ms": row.end_ms,
                    "frames": row.frames,
                    "confidence": row.confidence,
                    "overlap": row.overlap,
                })

            return {
                "version": 1,
                "streams": stream_rows,
                "ranges": range_rows,
                "stats": self.stats(),
                "defaults": self._default_thresholds(),
                "max_ranges": self.max_ranges,
            }

    def _parse_thresholds(self, raw: object, detail: str) -> dict:
        if not isinstance(raw, dict):
            raise _snapshot_error(detail)
        parsed = {}
        for key in self._THRESHOLD_KEYS:
            if key not in raw:
                raise _snapshot_error(f"{detail}.{key}")
            if key == "black_luma":
                parsed[key] = _snapshot_number(
                    raw[key], f"{detail}.{key}", low=0.0, high=1.0
                )
            else:
                value = raw[key]
                if not _is_number(value) or value < 0:
                    raise _snapshot_error(f"{detail}.{key}")
                parsed[key] = value
        return parsed

    def _parse_overrides(self, raw: object, detail: str) -> dict:
        if not isinstance(raw, dict):
            raise _snapshot_error(detail)
        parsed = {}
        for key, value in raw.items():
            if key not in self._THRESHOLD_KEYS:
                raise _snapshot_error(f"{detail}.{key}")
            if key == "black_luma":
                parsed[key] = _snapshot_number(
                    value, f"{detail}.{key}", low=0.0, high=1.0
                )
            else:
                if not _is_number(value) or value < 0:
                    raise _snapshot_error(f"{detail}.{key}")
                parsed[key] = value
        return parsed

    def _parse_stream(self, raw: object) -> _StreamState:
        if not isinstance(raw, dict):
            raise _snapshot_error("stream")
        required = (
            "stream", "last_pts", "last_epoch", "last_fingerprint",
            "freeze_start", "freeze_frames", "black_start", "black_frames",
            "thresholds",
        )
        for key in required:
            if key not in raw:
                raise _snapshot_error(f"stream.{key}")

        name = _stream_name(raw["stream"])
        if name is None:
            raise _snapshot_error("stream.stream")
        last_pts = _snapshot_int(
            raw["last_pts"], "stream.last_pts", optional=True
        )
        last_epoch = _snapshot_int(
            raw["last_epoch"], "stream.last_epoch", minimum=1, optional=True
        )
        last_fingerprint = _snapshot_int(
            raw["last_fingerprint"], "stream.last_fingerprint", optional=True
        )
        freeze_start = _snapshot_int(
            raw["freeze_start"], "stream.freeze_start", optional=True
        )
        freeze_frames = _snapshot_int(
            raw["freeze_frames"], "stream.freeze_frames"
        )
        black_start = _snapshot_int(
            raw["black_start"], "stream.black_start", optional=True
        )
        black_frames = _snapshot_int(
            raw["black_frames"], "stream.black_frames"
        )
        overrides = self._parse_overrides(
            raw["thresholds"], "stream.thresholds"
        )

        if (last_pts is None) != (last_epoch is None):
            raise _snapshot_error("stream.last_pts")
        if last_pts is None:
            if (
                last_fingerprint is not None
                or freeze_start is not None
                or black_start is not None
            ):
                raise _snapshot_error("stream.last_pts")
        if freeze_start is None:
            if freeze_frames != 0:
                raise _snapshot_error("stream.freeze_frames")
        else:
            if (
                freeze_frames < 1
                or last_pts is None
                or freeze_start > last_pts
            ):
                raise _snapshot_error("stream.freeze_start")
            if last_fingerprint is None:
                raise _snapshot_error("stream.last_fingerprint")
        if black_start is None:
            if black_frames != 0:
                raise _snapshot_error("stream.black_frames")
        else:
            if black_frames < 1 or last_pts is None or black_start > last_pts:
                raise _snapshot_error("stream.black_start")
        if freeze_start is None and last_fingerprint is not None:
            raise _snapshot_error("stream.last_fingerprint")

        return _StreamState(
            name=name,
            last_pts=last_pts,
            last_epoch=last_epoch,
            last_fingerprint=last_fingerprint,
            freeze_start=freeze_start,
            freeze_frames=freeze_frames,
            black_start=black_start,
            black_frames=black_frames,
            overrides=overrides,
        )

    def _parse_range(self, raw: object) -> _RangeEntry:
        if not isinstance(raw, dict):
            raise _snapshot_error("range")
        required = (
            "stream", "kind", "start_ms", "end_ms", "frames",
            "confidence", "overlap",
        )
        for key in required:
            if key not in raw:
                raise _snapshot_error(f"range.{key}")

        name = _stream_name(raw["stream"])
        if name is None:
            raise _snapshot_error("range.stream")
        kind = raw["kind"]
        if kind not in ("freeze", "black"):
            raise _snapshot_error("range.kind")
        start_ms = _snapshot_int(raw["start_ms"], "range.start_ms")
        end_ms = _snapshot_int(raw["end_ms"], "range.end_ms")
        frames = _snapshot_int(raw["frames"], "range.frames", minimum=1)
        confidence = _snapshot_number(
            raw["confidence"], "range.confidence", low=0.0, high=1.0
        )
        if not isinstance(raw["overlap"], bool):
            raise _snapshot_error("range.overlap")
        if end_ms < start_ms:
            raise _snapshot_error("range.end_ms")

        return _RangeEntry(
            stream=name,
            kind=kind,
            start_ms=start_ms,
            end_ms=end_ms,
            frames=frames,
            confidence=confidence,
        )

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict):
            raise _snapshot_error("state")
        if not _is_int(state.get("version")) or state.get("version") != 1:
            raise _snapshot_error("version")
        if not isinstance(state.get("streams"), list):
            raise _snapshot_error("streams")
        if not isinstance(state.get("ranges"), list):
            raise _snapshot_error("ranges")
        if not isinstance(state.get("stats"), dict):
            raise _snapshot_error("stats")

        stats_keys = (
            "streams", "frames", "freeze_ranges", "black_ranges",
            "discarded", "evicted", "resets",
        )
        stats_raw = state["stats"]
        parsed_stats = {}
        for key in stats_keys:
            if key not in stats_raw:
                raise _snapshot_error(f"stats.{key}")
            parsed_stats[key] = _snapshot_int(
                stats_raw[key], f"stats.{key}"
            )

        parsed_streams: dict[str, _StreamState] = {}
        for raw in state["streams"]:
            parsed = self._parse_stream(raw)
            if parsed.name in parsed_streams:
                raise _snapshot_error("duplicate stream")
            parsed_streams[parsed.name] = parsed
        if parsed_stats["streams"] != len(parsed_streams):
            raise _snapshot_error("stats.streams")

        parsed_ranges = []
        for raw in state["ranges"]:
            parsed = self._parse_range(raw)
            if parsed.stream not in parsed_streams:
                raise _snapshot_error("range.stream")
            parsed_ranges.append(parsed)
        parsed_ranges.sort(key=self._sort_key)

        defaults = self._default_thresholds()
        if "defaults" in state:
            defaults = self._parse_thresholds(
                state["defaults"], "defaults"
            )

        max_ranges = self.max_ranges
        if "max_ranges" in state:
            max_ranges = _snapshot_int(
                state["max_ranges"], "max_ranges"
            )
        if len(parsed_ranges) > max_ranges:
            raise _snapshot_error("ranges")

        counters = {
            "frames": parsed_stats["frames"],
            "freeze_ranges": parsed_stats["freeze_ranges"],
            "black_ranges": parsed_stats["black_ranges"],
            "discarded": parsed_stats["discarded"],
            "evicted": parsed_stats["evicted"],
            "resets": parsed_stats["resets"],
        }

        with self._lock:
            self.max_ranges = max_ranges
            self.min_freeze_ms = defaults["min_freeze_ms"]
            self.min_black_ms = defaults["min_black_ms"]
            self.black_luma = defaults["black_luma"]
            self._streams = parsed_streams
            self._ranges = parsed_ranges
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return {
                "streams": len(self._streams),
                "frames": self._counters["frames"],
                "freeze_ranges": self._counters["freeze_ranges"],
                "black_ranges": self._counters["black_ranges"],
                "discarded": self._counters["discarded"],
                "evicted": self._counters["evicted"],
                "resets": self._counters["resets"],
            }
