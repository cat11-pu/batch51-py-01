"""Screen space contact shadow tracing with temporal accumulation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ShadowTraceError(ValueError):
    """Raised when a trace request or a scene upload is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TileResult:
    """Outcome of one traced tile."""

    x0: int
    y0: int
    x1: int
    y1: int
    pixels: int
    steps: int


class ContactShadowTracer:
    """March the depth profile of each pixel and accumulate the result over time."""

    def __init__(self, *, width: int = 64, height: int = 64,
                 camera_id: str = "cam-0", max_steps: int = 8,
                 thickness: float = 1.0, step_size: float = 1.0,
                 history_weight: float = 0.5,
                 far_plane: float = 100.0) -> None:
        self._lock = threading.RLock()
        self._config = {"width": width, "height": height,
                        "camera_id": camera_id, "max_steps": max_steps,
                        "thickness": thickness, "step_size": step_size,
                        "history_weight": history_weight,
                        "far_plane": far_plane}
        self._surface: list = []
        self._occluders: list = []
        self._current: dict = {}
        self._history: dict = {}
        self._stats = {"tiles": 0, "pixels": 0, "steps": 0,
                       "accumulations": 0, "resets": 0}

    def configure(self, **kwargs) -> dict:
        raise NotImplementedError

    def load_scene(self, *, surface, occluders) -> int:
        raise NotImplementedError

    def trace_tile(self, x0: int, y0: int, x1: int, y1: int) -> TileResult:
        raise NotImplementedError

    def sample_occlusion(self, x: int, y: int) -> float:
        raise NotImplementedError

    def occlusion_map(self) -> tuple:
        raise NotImplementedError

    def accumulate(self) -> int:
        raise NotImplementedError

    def reset_history(self, reason: str = "manual") -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
