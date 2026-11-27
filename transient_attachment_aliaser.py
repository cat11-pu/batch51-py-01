"""Planner that aliases transient render attachments over a frame-local heap."""

from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class PassRecord:
    """One declared render pass."""

    index: int
    name: str


@dataclass(frozen=True)
class AttachmentRecord:
    """One declared transient attachment."""

    name: str
    width: int
    height: int
    bytes_per_pixel: int
    kind: str
    external: bool
    backbuffer: bool


class TransientAttachmentAliaser:
    """Assign heap offsets so disjoint attachment lifetimes share memory."""

    def __init__(self, *, heap_bytes: int = 1 << 20, alignment: int = 256,
                 max_passes: int = 64, max_attachments: int = 32) -> None:
        self.heap_bytes = heap_bytes
        self.alignment = alignment
        self.max_passes = max_passes
        self.max_attachments = max_attachments
        self._lock = threading.RLock()
        self._passes: dict = {}
        self._attachments: dict = {}
        self._uses: dict = {}
        self._plan: dict | None = None

    def declare_pass(self, index: int, name: str) -> PassRecord:
        raise NotImplementedError

    def declare_attachment(self, name: str, *, width: int, height: int,
                           bytes_per_pixel: int = 4, kind: str = "color",
                           external: bool = False,
                           backbuffer: bool = False) -> AttachmentRecord:
        raise NotImplementedError

    def declare_use(self, name: str, pass_index: int,
                    mode: str = "write") -> None:
        raise NotImplementedError

    def plan(self) -> dict:
        raise NotImplementedError

    def offset_of(self, name: str) -> int:
        raise NotImplementedError

    def heap_usage(self) -> int:
        raise NotImplementedError

    def attachment_state(self, name: str) -> AttachmentRecord:
        raise NotImplementedError

    def uses_of(self, name: str) -> tuple:
        raise NotImplementedError

    def barriers(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
