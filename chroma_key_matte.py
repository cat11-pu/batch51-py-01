"""Chroma key matte: chroma distance matte, spill suppression and temporal blend."""

from __future__ import annotations

import threading


class ChromaKeyError(ValueError):
    """Raised when a matte operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ChromaKeyMatte:
    """Build per pixel coverage from a key colour and keep a short alpha history."""

    def __init__(self, *, width: int, height: int, key_color=(0, 255, 0),
                 similarity: int = 60, softness: int = 40,
                 feather_radius: int = 1, history_limit: int = 4,
                 shadow_luma: int = 48, shadow_keep: float = 0.6,
                 history_weight: float = 0.5,
                 motion_penalty: float = 0.25) -> None:
        self.width = width
        self.height = height
        self.similarity = similarity
        self.softness = softness
        self.feather_radius = feather_radius
        self.history_limit = history_limit
        self.shadow_luma = shadow_luma
        self.shadow_keep = shadow_keep
        self.history_weight = history_weight
        self.motion_penalty = motion_penalty
        self._key_color = tuple(key_color)
        self._lock = threading.RLock()
        self._history: list = []
        self._stats = {"frames": 0, "keyed": 0, "partial": 0, "opaque": 0,
                       "spill": 0, "stabilized": 0}

    def set_key_color(self, color) -> tuple:
        raise NotImplementedError

    def set_thresholds(self, *, similarity=None, softness=None) -> None:
        raise NotImplementedError

    def matte(self, frame) -> list:
        raise NotImplementedError

    def despill(self, frame, *, strength: float = 1.0) -> list:
        raise NotImplementedError

    def feather(self, alpha, radius=None) -> list:
        raise NotImplementedError

    def temporal_stabilize(self, alpha, *, motion: float = 0.0) -> list:
        raise NotImplementedError

    def history(self) -> tuple:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
