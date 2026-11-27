"""Audio packet concealment: gap detection, pitch wrap fill and silence fallback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class AudioConcealError(ValueError):
    """Raised when a concealment request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PacketSlot:
    """One slot of the reconstructed output timeline."""

    seq: int
    kind: str
    samples: tuple


class AudioPacketConcealer:
    """Detect sequence gaps per stream and fill them from a bounded history."""

    def __init__(self, *, frame_samples: int = 160, history_frames: int = 8,
                 max_conceal: int = 3, reorder_window: int = 8) -> None:
        self.frame_samples = frame_samples
        self.history_frames = history_frames
        self.max_conceal = max_conceal
        self.reorder_window = reorder_window
        self._lock = threading.RLock()
        self._streams: dict = {}

    def push(self, stream: str, seq: int, samples) -> int:
        raise NotImplementedError

    def gap_ranges(self, stream: str) -> tuple:
        raise NotImplementedError

    def conceal(self, stream: str) -> int:
        raise NotImplementedError

    def set_max_conceal(self, stream: str, frames: int) -> int:
        raise NotImplementedError

    def set_sample_rate(self, stream: str, rate: int) -> int:
        raise NotImplementedError

    def history(self, stream: str) -> tuple:
        raise NotImplementedError

    def timeline(self, stream: str) -> tuple:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def reset(self, stream=None) -> None:
        raise NotImplementedError
