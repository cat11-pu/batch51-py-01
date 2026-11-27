"""AV1-style OBU framing: incremental parsing and temporal-unit assembly."""

from __future__ import annotations

import threading
from dataclasses import dataclass


OBU_SNAPSHOT_VERSION = 1


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
        self._frames: dict = {}
        self._pending: list = []
        self._open_size = 0
        self._open = False
        self._flushed = False
        self._counters = {
            "bytes_in": 0,
            "obu_seen": 0,
            "units": 0,
            "frames": 0,
            "tiles": 0,
            "skipped": 0,
            "rejected": 0,
        }

    def push(self, data) -> int:
        """Append bytes to the buffer and report the buffered size."""
        raise NotImplementedError("push")

    def buffered_bytes(self) -> int:
        """Number of bytes waiting for a complete object."""
        raise NotImplementedError("buffered_bytes")

    def next_temporal_unit(self):
        """Return the next finalised temporal unit, or None."""
        raise NotImplementedError("next_temporal_unit")

    def flush(self) -> int:
        """Close the open unit without waiting for a delimiter."""
        raise NotImplementedError("flush")

    def sequence_header(self):
        """Last accepted sequence header, or None."""
        raise NotImplementedError("sequence_header")

    def frame_header(self, frame_id: int):
        """Accepted frame header for the identifier, or None."""
        raise NotImplementedError("frame_header")

    def pending_frames(self) -> tuple:
        """Frame identifiers that still wait for a tile group."""
        raise NotImplementedError("pending_frames")

    def frame_count(self) -> int:
        """Number of accepted frame headers."""
        raise NotImplementedError("frame_count")

    def stats(self) -> dict:
        """Current counters."""
        raise NotImplementedError("stats")

    def reset(self) -> None:
        """Drop buffer, headers, counters and pending frames."""
        raise NotImplementedError("reset")

    def snapshot(self) -> dict:
        """Deep copy of parser state."""
        raise NotImplementedError("snapshot")

    def restore(self, state: dict) -> None:
        """Replace parser state with a snapshot."""
        raise NotImplementedError("restore")
