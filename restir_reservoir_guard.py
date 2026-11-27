"""ReSTIR reservoir guard: weighted resampling with history and neighbour merging."""

from __future__ import annotations

import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1


class ReservoirError(ValueError):
    """Raised when a reservoir operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReservoirState:
    pixel: tuple[int, int]
    sample_id: str
    weight_sum: float
    sample_count: int
    depth: float
    normal: tuple[float, float, float]
    frame: int
    history_frame: int
    history_valid: bool


@dataclass(frozen=True)
class ResolveResult:
    pixel: tuple[int, int]
    sample_id: str
    weight: float
    sample_count: int
    history_frame: int
    history_valid: bool


class ReservoirGuard:
    """Per-pixel reservoir with history validation and neighbour merging."""

    def __init__(self, *, max_samples: int = 32, depth_threshold: float = 0.05,
                 normal_threshold: float = 0.9, seed: int = 20261127) -> None:
        self.max_samples = max_samples
        self.depth_threshold = depth_threshold
        self.normal_threshold = normal_threshold
        self.seed = seed
        self._lock = threading.RLock()

    def update_sample(self, pixel, *, sample_id, target_weight, depth, normal, frame):
        raise NotImplementedError

    def merge_history(self, pixel, history):
        raise NotImplementedError

    def merge_neighbors(self, pixel, neighbors):
        raise NotImplementedError

    def validate_history(self, pixel, *, depth, normal, frame):
        raise NotImplementedError

    def advance_frame(self, frame):
        raise NotImplementedError

    def resolve(self, pixel):
        raise NotImplementedError

    def pixel_state(self, pixel):
        raise NotImplementedError

    def reset(self, pixel=None):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
