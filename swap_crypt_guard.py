"""Encrypted swap lifecycle: key binding, writeback drain, and hibernate resume checks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SwapError(ValueError):
    """Raised when a swap lifecycle request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_DISABLED = "disabled"
STATE_ENABLED = "enabled"
STATE_DRAINING = "draining"


@dataclass(frozen=True)
class SwapState:
    device: str
    state: str
    key_id: str | None
    cipher: str | None
    size_pages: int
    resume_offset: int
    generation: int
    dirty_pages: int


class SwapCryptGuard:
    """Track encrypted swap devices, their keys, and pending writeback."""

    def __init__(self, *, max_devices: int = 8) -> None:
        self.max_devices = max_devices
        self._lock = threading.RLock()

    def enable(self, device: str, *, size_pages: int, key_id: str,
               cipher: str, resume_offset: int, now: int) -> SwapState:
        raise NotImplementedError

    def disable(self, device: str, *, now: int) -> SwapState:
        raise NotImplementedError

    def mark_dirty(self, device: str, pages: int) -> int:
        raise NotImplementedError

    def rotate_key(self, device: str, *, new_key_id: str,
                   cipher: str | None = None, now: int) -> SwapState:
        raise NotImplementedError

    def resume(self, device: str, *, image_device: str, image_offset: int) -> bool:
        raise NotImplementedError

    def status(self, device: str) -> SwapState:
        raise NotImplementedError

    def devices(self) -> tuple[str, ...]:
        raise NotImplementedError

    def pending_writeback(self) -> dict:
        raise NotImplementedError

    def recover(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
