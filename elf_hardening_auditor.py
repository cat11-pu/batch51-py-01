"""Hardening audit for executable images.

The auditor reads a little endian ELF64 image, reports the hardening items
that the loader and the toolchain ought to provide (position independence,
non executable stack, read only relocations, immediate symbol binding and the
stack protector), and applies baselines and time limited exemptions on top of
the raw verdict.  Images are keyed by path and content digest so a replaced
file can never inherit the result of its predecessor.
"""

from __future__ import annotations

import hashlib
import struct
import threading
from dataclasses import dataclass

ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 1
PF_W = 2
PF_R = 4
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
EHDR_SIZE = 64
PHDR_SIZE = 56
ITEM_ORDER = ("pie", "nx_stack", "relro", "bind_now", "stack_canary")


class ElfAuditError(ValueError):
    """Refusal raised while reading an image or restoring a snapshot."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Segment:
    type: int
    flags: int
    offset: int
    filesz: int


@dataclass(frozen=True)
class ImageInfo:
    file_type: int
    entry: int
    phentsize: int
    phnum: int
    size: int
    digest: str
    segments: tuple
    dynamic: tuple


@dataclass(frozen=True)
class HardeningItem:
    name: str
    status: str
    reason: str


@dataclass(frozen=True)
class ScanResult:
    path: str
    package: str
    digest: str
    items: tuple
    failing: tuple
    verdict: str


class ElfHardeningAuditor:
    """Parse images, judge hardening items and apply baseline exemptions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images = {}
        self._exemptions = {}
        self._baselines = {}
        self._stats = {"parses": 0, "scans": 0, "cache_hits": 0,
                       "exemptions": 0, "restores": 0}

    def parse_image(self, data: bytes) -> ImageInfo:
        """Parse an ELF64 little endian image into an :class:`ImageInfo`."""
        raise NotImplementedError

    def check_image(self, info: ImageInfo, *, symbols=()) -> tuple:
        """Judge the hardening items of one parsed image."""
        raise NotImplementedError

    def verdict_for(self, items) -> str:
        """Return ``pass`` when no item failed, otherwise ``fail``."""
        raise NotImplementedError

    def scan(self, path: str, data: bytes, *, package: str = "",
             symbols=(), now: str | None = None) -> ScanResult:
        """Parse (once per path and digest) and audit one image."""
        raise NotImplementedError

    def set_baseline(self, package: str, items) -> None:
        """Declare which items are tolerated for ``package``."""
        raise NotImplementedError

    def baseline_for(self, package: str) -> tuple:
        """Return the tolerated items of ``package``."""
        raise NotImplementedError

    def add_exemption(self, path: str, digest: str, items, *,
                      expires_at: str | None = None) -> None:
        """Exempt ``items`` of the image at ``path``/``digest``."""
        raise NotImplementedError

    def drop_exemption(self, path: str, digest: str) -> int:
        """Drop the exemption of one image and return how many items it held."""
        raise NotImplementedError

    def is_exempt(self, path: str, digest: str, item: str, *,
                  now: str | None = None) -> bool:
        """Report whether ``item`` is exempt for this path and digest."""
        raise NotImplementedError

    def report(self) -> dict:
        """Aggregate the scanned images by package and failing item."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of images, exemptions and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def clear(self) -> None:
        """Forget every scanned image, exemption and baseline."""
        raise NotImplementedError
