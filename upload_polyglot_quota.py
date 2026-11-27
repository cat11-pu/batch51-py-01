"""上传内容嗅探、文件名归一、解压配额与整体回滚。

类型判定以字节内容为准，声明类型只用来交叉核对；解压按层累计条目数与
展开字节，超出任一硬顶整包拒绝并归还该次上传的预留。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

MAGIC_TABLE = (
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("jpeg", b"\xff\xd8\xff"),
    ("gif", b"GIF87a"),
    ("gif", b"GIF89a"),
    ("pdf", b"%PDF-"),
    ("elf", b"\x7fELF"),
    ("zip", b"PK\x03\x04"),
    ("html", b"<html"),
    ("html", b"<script"),
)

EXECUTABLE_TYPES = frozenset({"elf", "html"})

SCRIPT_EXTENSIONS = frozenset({
    "php", "phtml", "phar", "jsp", "jspx", "asp", "aspx", "cgi",
    "sh", "py", "js", "mjs", "html", "htm", "exe", "elf",
})

DECLARED_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpeg",
    "image/gif": "gif",
    "application/pdf": "pdf",
    "application/zip": "zip",
}

STAT_KEYS = ("screened", "reserved_bytes", "expanded_bytes", "rejected", "rollbacks",
             "restores")


class UploadError(ValueError):
    """参数非法或配额冲突时抛出，code 为大写原因码。"""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SniffResult:
    primary: str
    matched: tuple[str, ...]
    polyglot: bool
    severity: str


@dataclass(frozen=True)
class ScreeningVerdict:
    filename: str
    declared_type: str
    sniffed: SniffResult
    extension: str
    allowed: bool
    reason: str
    reserved_bytes: int


@dataclass(frozen=True)
class ExtractionReport:
    entries: int
    bytes_written: int
    depth: int
    rejected: bool
    reason: str


class UploadPolyglotQuota:
    """维护在途预留、展开配额与判定审计。"""

    def __init__(self, *, allowed_types=("png", "jpeg", "gif", "pdf"),
                 max_bytes: int = 8 * 1024 * 1024,
                 max_inflight_bytes: int = 32 * 1024 * 1024,
                 max_expanded_bytes: int = 64 * 1024 * 1024,
                 max_entries: int = 256, max_depth: int = 2) -> None:
        self.allowed_types = tuple(allowed_types)
        self.max_bytes = max_bytes
        self.max_inflight_bytes = max_inflight_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self.max_entries = max_entries
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._reservations: dict[str, int] = {}
        self._expanded_bytes = 0
        self._audit: list[dict] = []
        self._stats = {name: 0 for name in STAT_KEYS}

    def sniff(self, data: bytes) -> SniffResult:
        raise NotImplementedError

    def normalize_filename(self, raw: str) -> str:
        raise NotImplementedError

    def screen(self, *, filename: str, declared_type: str, data: bytes) -> ScreeningVerdict:
        raise NotImplementedError

    def reserve(self, upload_id: str, *, byte_count: int) -> int:
        raise NotImplementedError

    def release(self, upload_id: str) -> int:
        raise NotImplementedError

    def pending_reservations(self) -> dict:
        raise NotImplementedError

    def expand(self, upload_id: str, archive_bytes: bytes, *, depth: int = 0) -> ExtractionReport:
        raise NotImplementedError

    def audit_log(self) -> tuple[dict, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
