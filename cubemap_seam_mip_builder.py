"""Cubemap mip chain builder that keeps face borders and poles seamless."""

from __future__ import annotations

import threading

FACE_NAMES = ("+x", "-x", "+y", "-y", "+z", "-z")
EDGES = ("top", "bottom", "left", "right")


class CubemapError(ValueError):
    """Raised when a cubemap upload, build or lookup is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class CubemapSeamMipBuilder:
    """Build per-face mip levels with seam aware filtering and lookups."""

    def __init__(self, *, max_size: int = 1024) -> None:
        self.max_size = max_size
        self._lock = threading.RLock()
        self._faces: dict = {}
        self._mips: dict = {}
        self._size = 0
        self._stats = {"faces": 0, "size": 0, "levels": 0,
                       "builds": 0, "samples": 0}

    def load_faces(self, faces) -> int:
        raise NotImplementedError

    def build_mips(self) -> tuple:
        raise NotImplementedError

    def mip_count(self) -> int:
        raise NotImplementedError

    def level_size(self, level: int) -> int:
        raise NotImplementedError

    def texel(self, face: str, level: int, x: int, y: int) -> int:
        raise NotImplementedError

    def face(self, face: str, level: int = 0) -> tuple:
        raise NotImplementedError

    def sample(self, face: str, level: int, u: float, v: float) -> float:
        raise NotImplementedError

    def edge_texels(self, face: str, edge: str, level: int = 0) -> tuple:
        raise NotImplementedError

    def validate(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
