"""MP4 faststart relocation: box scanning, chunk offset rewrite and verification."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class FaststartError(ValueError):
    """Raised when a relocation request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BoxInfo:
    """One top level box found in the scanned file."""

    type: str
    offset: int
    size: int


@dataclass(frozen=True)
class OffsetEntry:
    """One chunk offset before and after relocation."""

    index: int
    old_offset: int
    new_offset: int


@dataclass(frozen=True)
class RelocationPlan:
    """What a relocation would do to the scanned file."""

    moved: bool
    delta: int
    moov_size: int
    chunk_count: int
    co64: bool
    new_size: int


class FaststartRelocator:
    """Move the movie index to the head of the file and patch chunk offsets."""

    def __init__(self, *, max_boxes: int = 128, alignment: int = 8) -> None:
        self.max_boxes = max_boxes
        self.alignment = alignment
        self._lock = threading.RLock()
        self._blob: bytes | None = None
        self._boxes: tuple[BoxInfo, ...] = ()
        self._chunks: tuple[int, ...] = ()
        self._width = 32
        self._plan: RelocationPlan | None = None
        self._applied: bytes | None = None

    def scan(self, blob: bytes) -> tuple[BoxInfo, ...]:
        raise NotImplementedError

    def boxes(self) -> tuple[BoxInfo, ...]:
        raise NotImplementedError

    def plan(self, *, force_co64: bool = False) -> RelocationPlan:
        raise NotImplementedError

    def offset_table(self) -> tuple[OffsetEntry, ...]:
        raise NotImplementedError

    def apply(self) -> bytes:
        raise NotImplementedError

    def verify(self, blob: bytes) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
