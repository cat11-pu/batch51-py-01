"""AV1-style OBU framing: incremental parsing and temporal-unit assembly."""

from __future__ import annotations

import copy
import threading
from collections import deque
from dataclasses import dataclass


OBU_SNAPSHOT_VERSION = 1

_STAT_KEYS = (
    "bytes_in",
    "obu_seen",
    "units",
    "frames",
    "tiles",
    "skipped",
    "rejected",
)

_OBU_SEQUENCE_HEADER = 1
_OBU_TEMPORAL_DELIMITER = 2
_OBU_FRAME_HEADER = 3
_OBU_TILE_GROUP = 4
_OBU_METADATA = 5
_OBU_PADDING = 6


class ObuError(ValueError):
    """Raised when an OBU stream cannot be accepted."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SequenceHeader:
    """Decoded sequence header parameters."""

    profile: int
    bit_depth: int
    width: int


@dataclass(frozen=True)
class FrameHeader:
    """Decoded frame header."""

    frame_id: int
    frame_type: str
    ref_frame_id: int | None
    show_frame: bool


@dataclass(frozen=True)
class TemporalUnit:
    """One assembled temporal unit."""

    index: int
    frames: tuple
    tiles: tuple
    size_bytes: int


class _SnapshotFrames(dict):
    """Frame mapping with parser-only metadata attached to the snapshot."""


class ObuTemporalParser:
    """Parse an OBU byte stream into temporal units for one decoder instance."""

    def __init__(self, *, max_buffer_bytes: int = 65536,
                 max_pending_frames: int = 32) -> None:
        if not isinstance(max_buffer_bytes, int) or max_buffer_bytes <= 0:
            raise ObuError("OBU_INVALID_ARG", "max_buffer_bytes")
        if not isinstance(max_pending_frames, int) or max_pending_frames <= 0:
            raise ObuError("OBU_INVALID_ARG", "max_pending_frames")
        self.max_buffer_bytes = max_buffer_bytes
        self.max_pending_frames = max_pending_frames
        self._lock = threading.RLock()
        self._buffer = bytearray()
        self._sequence: SequenceHeader | None = None
        self._frames: dict[int, FrameHeader] = {}
        self._pending: list[int] = []
        self._open_frame_ids: list[int] = []
        self._open_tile_ids: list[int] = []
        self._open_frames: set[int] = set()
        self._open_size = 0
        self._open = False
        self._next_unit_index = 0
        self._ready_units: deque[TemporalUnit] = deque()
        self._counters = {key: 0 for key in _STAT_KEYS}

    def push(self, data) -> int:
        """Append bytes to the buffer and report the buffered size."""
        try:
            chunk = bytes(data)
        except (TypeError, ValueError) as exc:
            raise TypeError("data must be bytes-like") from exc

        with self._lock:
            if len(self._buffer) + len(chunk) > self.max_buffer_bytes:
                raise ObuError(
                    "OBU_BUFFER_LIMIT",
                    {
                        "buffered": len(self._buffer),
                        "incoming": len(chunk),
                        "limit": self.max_buffer_bytes,
                    },
                )
            self._buffer.extend(chunk)
            self._counters["bytes_in"] += len(chunk)
            return len(self._buffer)

    def buffered_bytes(self) -> int:
        """Number of bytes waiting for a complete object."""
        with self._lock:
            return len(self._buffer)

    def next_temporal_unit(self):
        """Return the next finalised temporal unit, or None."""
        with self._lock:
            start_buffer = bytes(self._buffer)
            start_seen = self._counters["obu_seen"]
            while True:
                if self._ready_units:
                    return self._ready_units.popleft()
                if not self._buffer:
                    return None
                if not self._parse_one_object():
                    if not self._open:
                        self._buffer = bytearray(start_buffer)
                        self._counters["obu_seen"] = start_seen
                    return None

    def flush(self) -> int:
        """Close the open unit without waiting for a delimiter."""
        with self._lock:
            start_buffer = bytes(self._buffer)
            start_seen = self._counters["obu_seen"]
            finalised = 0
            while True:
                before = len(self._ready_units)
                if not self._parse_one_object():
                    break
                finalised += len(self._ready_units) - before
            if self._finalise_open_unit():
                finalised += 1
            elif (
                finalised == 0
                and not self._open
                and self._buffer
            ):
                self._buffer = bytearray(start_buffer)
                self._counters["obu_seen"] = start_seen
            return finalised

    def sequence_header(self):
        """Last accepted sequence header, or None."""
        with self._lock:
            return self._sequence

    def frame_header(self, frame_id: int):
        """Accepted frame header for the identifier, or None."""
        with self._lock:
            return self._frames.get(frame_id)

    def pending_frames(self) -> tuple:
        """Frame identifiers that still wait for a tile group."""
        with self._lock:
            return tuple(self._pending)

    def frame_count(self) -> int:
        """Number of accepted frame headers."""
        with self._lock:
            return len(self._frames)

    def stats(self) -> dict:
        """Current counters."""
        with self._lock:
            return dict(self._counters)

    def reset(self) -> None:
        """Drop buffer, headers, counters and pending frames."""
        with self._lock:
            self._buffer.clear()
            self._sequence = None
            self._frames.clear()
            self._pending.clear()
            self._open_frame_ids.clear()
            self._open_tile_ids.clear()
            self._open_frames.clear()
            self._open_size = 0
            self._open = False
            self._next_unit_index = 0
            self._ready_units.clear()
            for key in _STAT_KEYS:
                self._counters[key] = 0

    def snapshot(self) -> dict:
        """Deep copy of parser state."""
        with self._lock:
            frames = _SnapshotFrames(self._frames)
            frames.unit_frames = list(self._open_frame_ids)
            frames.unit_tiles = list(self._open_tile_ids)
            frames.unit_size = self._open_size
            frames.unit_open = self._open
            frames.next_unit_index = self._next_unit_index
            frames.ready = list(self._ready_units)
            return copy.deepcopy(
                {
                    "version": OBU_SNAPSHOT_VERSION,
                    "buffer": bytes(self._buffer),
                    "sequence": self._sequence,
                    "frames": frames,
                    "pending": list(self._pending),
                    "stats": dict(self._counters),
                }
            )

    def restore(self, state: dict) -> None:
        """Replace parser state with a snapshot."""
        with self._lock:
            restored = self._validate_snapshot(state)
            (
                buffer,
                sequence,
                frames,
                open_frame_ids,
                open_tile_ids,
                open_size,
                is_open,
                next_unit_index,
                pending,
                ready_units,
                counters,
            ) = restored

            self._buffer = buffer
            self._sequence = sequence
            self._frames = frames
            self._pending = pending
            self._open_frame_ids = open_frame_ids
            self._open_tile_ids = open_tile_ids
            self._open_frames = set(open_frame_ids)
            self._open_size = open_size
            self._open = is_open
            self._next_unit_index = next_unit_index
            self._ready_units = deque(ready_units)
            self._counters = counters

    # ------------------------------------------------------------------
    # Parsing internals

    def _reject(self, code: str, detail: object = None) -> None:
        self._buffer.clear()
        self._counters["rejected"] += 1
        raise ObuError(code, detail)

    def _scan_object(self):
        """Return (type, total_size, payload) or None if more bytes are needed."""
        if not self._buffer:
            return None

        header = self._buffer[0]
        obu_type = header >> 4
        if obu_type == 0 or obu_type > _OBU_PADDING:
            self._reject("OBU_INVALID_TYPE", {"type": obu_type, "header": header})

        pos = 1
        value = 0
        shift = 0
        leb_bytes = 0
        while True:
            if pos >= len(self._buffer):
                return None
            byte = self._buffer[pos]
            pos += 1
            leb_bytes += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            if leb_bytes == 4:
                self._reject(
                    "OBU_LENGTH_OVERFLOW",
                    {"reason": "leb128", "bytes": leb_bytes},
                )
            shift += 7

        if value > self.max_buffer_bytes:
            self._reject(
                "OBU_LENGTH_OVERFLOW",
                {"declared": value, "limit": self.max_buffer_bytes},
            )

        total_size = pos + value
        if len(self._buffer) < total_size:
            return None

        payload = bytes(self._buffer[pos:total_size])
        return obu_type, total_size, payload

    def _consume(self, total_size: int) -> None:
        del self._buffer[:total_size]
        self._counters["obu_seen"] += 1

    def _parse_one_object(self) -> bool:
        scanned = self._scan_object()
        if scanned is None:
            return False

        obu_type, total_size, payload = scanned

        if obu_type == _OBU_TEMPORAL_DELIMITER:
            if payload:
                self._reject(
                    "OBU_INVALID_PAYLOAD",
                    {"type": obu_type, "length": len(payload), "expected": 0},
                )
            self._consume(total_size)
            self._finalise_open_unit()
            return True

        if obu_type == _OBU_SEQUENCE_HEADER:
            self._parse_sequence_header(payload, total_size)
            return True

        if obu_type == _OBU_FRAME_HEADER:
            self._parse_frame_header(payload, total_size)
            return True

        if obu_type == _OBU_TILE_GROUP:
            self._parse_tile_group(payload, total_size)
            return True

        # Metadata and padding have arbitrary payloads, including empty ones.
        self._consume(total_size)
        self._counters["skipped"] += 1
        self._open = True
        self._open_size += total_size
        return True

    def _parse_sequence_header(self, payload: bytes, total_size: int) -> None:
        if len(payload) != 4:
            self._reject(
                "OBU_INVALID_PAYLOAD",
                {
                    "type": _OBU_SEQUENCE_HEADER,
                    "length": len(payload),
                    "expected": 4,
                },
            )

        sequence = SequenceHeader(
            profile=payload[0],
            bit_depth=payload[1],
            width=(payload[2] << 8) | payload[3],
        )

        if self._sequence is not None and sequence != self._sequence:
            self._consume(total_size)
            self._finalise_open_unit()
            self._sequence = sequence
            self._frames.clear()
            self._pending.clear()
            self._open_frame_ids.clear()
            self._open_tile_ids.clear()
            self._open_frames.clear()
            self._open_size = total_size
            self._open = True
            self._counters["rejected"] += 1
            self._buffer.clear()
            raise ObuError("OBU_SEQUENCE_CHANGED", sequence)

        self._consume(total_size)
        self._sequence = sequence
        self._open = True
        self._open_size += total_size

    def _parse_frame_header(self, payload: bytes, total_size: int) -> None:
        if len(payload) != 6:
            self._reject(
                "OBU_INVALID_PAYLOAD",
                {
                    "type": _OBU_FRAME_HEADER,
                    "length": len(payload),
                    "expected": 6,
                },
            )
        if self._sequence is None:
            self._reject("OBU_SEQUENCE_MISSING", {"frame_id": self._u16(payload, 0)})

        frame_id = self._u16(payload, 0)
        type_byte = payload[2]
        if type_byte not in (0, 1):
            self._reject(
                "OBU_INVALID_PAYLOAD",
                {"type": _OBU_FRAME_HEADER, "frame_type": type_byte},
            )
        frame_type = "key" if type_byte == 0 else "inter"
        ref_value = self._u16(payload, 3)
        ref_frame_id = None if ref_value == 0xFFFF else ref_value
        show_frame = bool(payload[5])

        if frame_type == "inter" and ref_frame_id not in self._frames:
            self._reject(
                "OBU_UNKNOWN_FRAME",
                {"frame_id": frame_id, "reference": ref_frame_id},
            )

        starts_unit = (
            self._open
            and bool(self._open_frame_ids)
            and frame_type == "key"
            and show_frame
        )
        if len(self._pending) + 1 > self.max_pending_frames:
            self._reject(
                "OBU_PENDING_LIMIT",
                {
                    "pending": len(self._pending),
                    "incoming": 1,
                    "limit": self.max_pending_frames,
                },
            )

        self._consume(total_size)
        if starts_unit:
            self._finalise_open_unit()

        frame = FrameHeader(
            frame_id=frame_id,
            frame_type=frame_type,
            ref_frame_id=ref_frame_id,
            show_frame=show_frame,
        )
        self._frames[frame_id] = frame
        self._pending.append(frame_id)
        self._open_frame_ids.append(frame_id)
        self._open_frames.add(frame_id)
        self._open = True
        self._open_size += total_size
        self._counters["frames"] += 1

    def _parse_tile_group(self, payload: bytes, total_size: int) -> None:
        if len(payload) < 2:
            self._reject(
                "OBU_INVALID_PAYLOAD",
                {"type": _OBU_TILE_GROUP, "length": len(payload), "minimum": 2},
            )

        frame_id = self._u16(payload, 0)
        if frame_id not in self._open_frames:
            if frame_id in self._frames:
                self._reject("OBU_ORDER", {"frame_id": frame_id})
            self._reject("OBU_UNKNOWN_FRAME", {"frame_id": frame_id})

        self._consume(total_size)
        self._open_tile_ids.append(frame_id)
        self._open_size += total_size
        self._counters["tiles"] += 1
        try:
            self._pending.remove(frame_id)
        except ValueError:
            pass

    def _finalise_open_unit(self) -> bool:
        if not self._open:
            return False

        unit = TemporalUnit(
            index=self._next_unit_index,
            frames=tuple(self._open_frame_ids),
            tiles=tuple(self._open_tile_ids),
            size_bytes=self._open_size,
        )
        self._ready_units.append(unit)
        self._next_unit_index += 1
        self._counters["units"] += 1

        self._open_frame_ids.clear()
        self._open_tile_ids.clear()
        self._open_frames.clear()
        self._open_size = 0
        self._open = False
        return True

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        return (data[offset] << 8) | data[offset + 1]

    # ------------------------------------------------------------------
    # Snapshot validation

    def _validate_snapshot(self, state):
        if not isinstance(state, dict):
            self._snapshot_invalid("state")
        try:
            value = copy.deepcopy(state)
        except Exception as exc:  # pragma: no cover - defensive
            raise ObuError("OBU_SNAPSHOT_INVALID", "state") from exc

        required = {"version", "buffer", "sequence", "frames", "pending", "stats"}
        if set(value) != required:
            self._snapshot_invalid("keys")

        version = value["version"]
        if type(version) is not int or version != OBU_SNAPSHOT_VERSION:
            self._snapshot_invalid("version")

        raw_buffer = value["buffer"]
        if not isinstance(raw_buffer, (bytes, bytearray, memoryview)):
            self._snapshot_invalid("buffer")
        buffer = bytearray(raw_buffer)
        if len(buffer) > self.max_buffer_bytes:
            self._snapshot_invalid("buffer")

        sequence = self._validated_sequence(value["sequence"])

        stats_value = value["stats"]
        if not isinstance(stats_value, dict) or set(stats_value) != set(_STAT_KEYS):
            self._snapshot_invalid("stats")
        counters = {}
        for key in _STAT_KEYS:
            item = stats_value[key]
            if type(item) is not int or item < 0:
                self._snapshot_invalid("stats")
            counters[key] = item

        frames_value = value["frames"]
        frame_meta_keys = {
            "headers",
            "unit_frames",
            "unit_tiles",
            "unit_size",
            "unit_open",
            "next_unit_index",
            "ready",
        }
        frame_meta_attrs = {
            "unit_frames",
            "unit_tiles",
            "unit_size",
            "unit_open",
            "next_unit_index",
            "ready",
        }
        if not isinstance(frames_value, dict):
            self._snapshot_invalid("frames")

        if set(getattr(frames_value, "__dict__", {})) == frame_meta_attrs:
            raw_headers = dict(frames_value)
            raw_open_frames = frames_value.unit_frames
            raw_open_tiles = frames_value.unit_tiles
            raw_open_size = frames_value.unit_size
            raw_is_open = frames_value.unit_open
            raw_next_index = frames_value.next_unit_index
            raw_ready = frames_value.ready
        elif set(frames_value) == frame_meta_keys:
            raw_headers = frames_value["headers"]
            raw_open_frames = frames_value["unit_frames"]
            raw_open_tiles = frames_value["unit_tiles"]
            raw_open_size = frames_value["unit_size"]
            raw_is_open = frames_value["unit_open"]
            raw_next_index = frames_value["next_unit_index"]
            raw_ready = frames_value["ready"]
        else:
            raw_headers = frames_value
            raw_open_frames = []
            raw_open_tiles = []
            raw_open_size = 0
            raw_is_open = False
            raw_next_index = counters["units"]
            raw_ready = []

        if not isinstance(raw_headers, dict):
            self._snapshot_invalid("frames.headers")
        frames: dict[int, FrameHeader] = {}
        for key, header_value in raw_headers.items():
            if type(key) is not int:
                self._snapshot_invalid("frames.headers")
            header = self._validated_frame(header_value)
            if header.frame_id != key:
                self._snapshot_invalid("frames.headers")
            frames[key] = header

        if sequence is None and frames:
            self._snapshot_invalid("frames.headers")

        open_frame_ids = self._validated_ids(
            raw_open_frames, "frames.unit_frames"
        )
        open_tile_ids = self._validated_ids(
            raw_open_tiles, "frames.unit_tiles"
        )
        for frame_id in open_frame_ids:
            if frame_id not in frames:
                self._snapshot_invalid("frames.unit_frames")
        for frame_id in open_tile_ids:
            if frame_id not in open_frame_ids:
                self._snapshot_invalid("frames.unit_tiles")

        open_size = raw_open_size
        if type(open_size) is not int or open_size < 0:
            self._snapshot_invalid("frames.unit_size")

        is_open = raw_is_open
        if type(is_open) is not bool:
            self._snapshot_invalid("frames.unit_open")
        if not is_open and (open_frame_ids or open_tile_ids or open_size):
            self._snapshot_invalid("frames.unit_open")
        if is_open and open_size == 0:
            self._snapshot_invalid("frames.unit_size")

        next_unit_index = raw_next_index
        if type(next_unit_index) is not int or next_unit_index < 0:
            self._snapshot_invalid("frames.next_unit_index")

        if not isinstance(raw_ready, (list, tuple)):
            self._snapshot_invalid("frames.ready")
        ready_units = [
            self._validated_temporal_unit(item) for item in raw_ready
        ]
        ready_indices = [unit.index for unit in ready_units]
        if ready_indices != sorted(set(ready_indices)):
            self._snapshot_invalid("frames.ready")
        if any(index >= next_unit_index for index in ready_indices):
            self._snapshot_invalid("frames.ready")

        pending = self._validated_ids(value["pending"], "pending")
        if len(pending) > self.max_pending_frames:
            self._snapshot_invalid("pending")
        pending_counts = self._count_values(pending)
        for frame_id in pending_counts:
            if frame_id not in frames:
                self._snapshot_invalid("pending")

        if counters["units"] != next_unit_index:
            self._snapshot_invalid("stats.units")

        return (
            buffer,
            sequence,
            frames,
            open_frame_ids,
            open_tile_ids,
            open_size,
            is_open,
            next_unit_index,
            pending,
            ready_units,
            counters,
        )

    def _validated_sequence(self, value):
        if value is None:
            return None
        if isinstance(value, SequenceHeader):
            sequence = value
        elif isinstance(value, dict):
            if set(value) != {"profile", "bit_depth", "width"}:
                self._snapshot_invalid("sequence")
            try:
                sequence = SequenceHeader(
                    profile=value["profile"],
                    bit_depth=value["bit_depth"],
                    width=value["width"],
                )
            except (TypeError, ValueError) as exc:
                raise ObuError("OBU_SNAPSHOT_INVALID", "sequence") from exc
        else:
            self._snapshot_invalid("sequence")

        if (
            type(sequence.profile) is not int
            or not 0 <= sequence.profile <= 0xFF
            or type(sequence.bit_depth) is not int
            or not 0 <= sequence.bit_depth <= 0xFF
            or type(sequence.width) is not int
            or not 0 <= sequence.width <= 0xFFFF
        ):
            self._snapshot_invalid("sequence")
        return sequence

    def _validated_frame(self, value):
        if isinstance(value, FrameHeader):
            frame = value
        elif isinstance(value, dict):
            if set(value) != {
                "frame_id",
                "frame_type",
                "ref_frame_id",
                "show_frame",
            }:
                self._snapshot_invalid("frames.headers")
            try:
                frame = FrameHeader(
                    frame_id=value["frame_id"],
                    frame_type=value["frame_type"],
                    ref_frame_id=value["ref_frame_id"],
                    show_frame=value["show_frame"],
                )
            except (TypeError, ValueError) as exc:
                raise ObuError("OBU_SNAPSHOT_INVALID", "frames.headers") from exc
        else:
            self._snapshot_invalid("frames.headers")

        if type(frame.frame_id) is not int or not 0 <= frame.frame_id <= 0xFFFF:
            self._snapshot_invalid("frames.headers")
        if frame.frame_type not in ("key", "inter"):
            self._snapshot_invalid("frames.headers")
        if frame.ref_frame_id is not None:
            if (
                type(frame.ref_frame_id) is not int
                or not 0 <= frame.ref_frame_id <= 0xFFFF
            ):
                self._snapshot_invalid("frames.headers")
        if type(frame.show_frame) is not bool:
            self._snapshot_invalid("frames.headers")
        return frame

    def _validated_temporal_unit(self, value):
        if isinstance(value, TemporalUnit):
            unit = value
        elif isinstance(value, dict):
            if set(value) != {"index", "frames", "tiles", "size_bytes"}:
                self._snapshot_invalid("frames.ready")
            try:
                unit = TemporalUnit(
                    index=value["index"],
                    frames=tuple(value["frames"]),
                    tiles=tuple(value["tiles"]),
                    size_bytes=value["size_bytes"],
                )
            except (TypeError, ValueError) as exc:
                raise ObuError("OBU_SNAPSHOT_INVALID", "frames.ready") from exc
        else:
            self._snapshot_invalid("frames.ready")

        if type(unit.index) is not int or unit.index < 0:
            self._snapshot_invalid("frames.ready")
        if not isinstance(unit.frames, tuple) or not isinstance(unit.tiles, tuple):
            self._snapshot_invalid("frames.ready")
        if any(type(item) is not int or not 0 <= item <= 0xFFFF
               for item in unit.frames + unit.tiles):
            self._snapshot_invalid("frames.ready")
        if type(unit.size_bytes) is not int or unit.size_bytes < 0:
            self._snapshot_invalid("frames.ready")
        return unit

    def _validated_ids(self, value, detail: str) -> list[int]:
        if not isinstance(value, (list, tuple)):
            self._snapshot_invalid(detail)
        result = list(value)
        if any(type(item) is not int or not 0 <= item <= 0xFFFF
               for item in result):
            self._snapshot_invalid(detail)
        return result

    @staticmethod
    def _count_values(values) -> dict:
        counts: dict[int, int] = {}
        for item in values:
            counts[item] = counts.get(item, 0) + 1
        return counts

    @staticmethod
    def _snapshot_invalid(detail: str) -> None:
        raise ObuError("OBU_SNAPSHOT_INVALID", detail)
