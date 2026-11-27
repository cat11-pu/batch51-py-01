"""Freeze frame and black frame interval detection over per-stream frame fingerprints."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class FreezeFrameDetector:
    """Track per-stream frame runs and emit freeze/black intervals."""

    def __init__(self, *, min_freeze_ms: int = 200, min_black_ms: int = 300,
                 black_luma: float = 0.08, max_ranges: int = 32) -> None:
        self.min_freeze_ms = min_freeze_ms
        self.min_black_ms = min_black_ms
        self.black_luma = black_luma
        self.max_ranges = max_ranges
        self._lock = threading.RLock()
        self._streams: dict = {}
        self._ranges: list = []
        self._counters = {
            "frames": 0,
            "freeze_ranges": 0,
            "black_ranges": 0,
            "discarded": 0,
            "evicted": 0,
            "resets": 0,
        }

    def feed(self, stream: str, *, pts_ms: int, fingerprint: int,
             luma: float, epoch: int = 1) -> tuple:
        raise NotImplementedError

    def flush(self, stream: str) -> tuple:
        raise NotImplementedError

    def ranges(self, stream: str | None = None) -> tuple:
        raise NotImplementedError

    def open_range(self, stream: str) -> dict | None:
        raise NotImplementedError

    def confidence_of(self, stream: str, start_ms: int, kind: str = "freeze") -> float:
        raise NotImplementedError

    def set_threshold(self, stream: str | None = None, *,
                      min_freeze_ms: int | None = None,
                      min_black_ms: int | None = None,
                      black_luma: float | None = None) -> dict:
        raise NotImplementedError

    def reset_stream(self, stream: str) -> int:
        raise NotImplementedError

    def streams(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
