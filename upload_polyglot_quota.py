"""上传内容嗅探、文件名归一、解压配额与整体回滚。

类型判定以字节内容为准，声明类型只用来交叉核对；解压按层累计条目数与
展开字节，超出任一硬顶整包拒绝并归还该次上传的预留。
"""

from __future__ import annotations

import copy
import io
import threading
import unicodedata
import zipfile
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
    ("zip", b"PK\x05\x06"),
    ("zip", b"PK\x07\x08"),
    ("zip", b"PK\x08\x08"),
    ("html", b"<HTML"),
    ("html", b"<SCRIPT"),
    ("html", b"<!doctype html"),
    ("html", b"<!DOCTYPE HTML"),
    ("html", b"<?php"),
    ("html", b"<?PHP"),
    ("html", b"<?="),
)

EXECUTABLE_TYPES = frozenset({"elf", "html"})

SCRIPT_EXTENSIONS = frozenset({
    "php", "php3", "php4", "php5", "php7", "php8", "pht", "phtml",
    "phps", "phar", "inc", "jsp", "jspf", "jspx", "asp", "aspx",
    "asa", "cer", "cgi", "cfm", "cfml", "sh", "bash", "zsh", "py",
    "pyc", "pyo", "js", "mjs", "cjs", "jsx", "ts", "tsx", "html",
    "htm", "shtml", "shtm", "xhtml", "exe", "elf", "dll", "so", "bin",
    "bat", "cmd", "com", "vbs", "vb", "ps1", "pl", "rb", "lua", "jar",
    "war", "class", "htaccess",
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

SNAPSHOT_KEYS = frozenset({
    "version", "reservations", "expanded_bytes", "audit", "stats",
})

SNAPSHOT_VERSION = 1


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


_UNKNOWN_SNIFF = SniffResult("unknown", (), False, "suspicious")


class _ExpansionRejected(Exception):
    def __init__(self, reason: str, entries: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.entries = entries


class _ScanState:
    def __init__(self) -> None:
        self.entries = 0
        self.bytes = 0


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise UploadError("UPLOAD_INVALID_REQUEST", {"value": type(value).__name__})


def _remove_format_and_control(value: str) -> str:
    return "".join(
        character for character in value
        if unicodedata.category(character) not in {"Cc", "Cf"}
    )


def _clean_filename(value: str) -> str:
    # Format characters include the Unicode bidi controls which can make the
    # displayed suffix differ from the on-disk suffix.
    cleaned = _remove_format_and_control(value.lower())
    start = 0
    end = len(cleaned)
    while start < end and (cleaned[start].isspace() or cleaned[start] == "."):
        start += 1
    while end > start and (cleaned[end - 1].isspace() or cleaned[end - 1] == "."):
        end -= 1
    return cleaned[start:end]


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1]


def _has_double_extension(filename: str) -> bool:
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    return parts[-2].strip() in SCRIPT_EXTENSIONS


class UploadPolyglotQuota:
    """维护在途预留、展开配额与判定审计。"""

    def __init__(self, *, allowed_types=("png", "jpeg", "gif", "pdf"),
                 max_bytes: int = 8 * 1024 * 1024,
                 max_inflight_bytes: int = 32 * 1024 * 1024,
                 max_expanded_bytes: int = 64 * 1024 * 1024,
                 max_entries: int = 256, max_depth: int = 2) -> None:
        if isinstance(allowed_types, (str, bytes)):
            raise UploadError("UPLOAD_INVALID_REQUEST", {"allowed_types": "iterable"})
        try:
            allowed = tuple(allowed_types)
        except TypeError as exc:
            raise UploadError("UPLOAD_INVALID_REQUEST", {"allowed_types": "iterable"}) from exc
        if any(not isinstance(item, str) or not item for item in allowed):
            raise UploadError("UPLOAD_INVALID_REQUEST", {"allowed_types": "str"})
        for name, value in (
            ("max_bytes", max_bytes),
            ("max_inflight_bytes", max_inflight_bytes),
            ("max_expanded_bytes", max_expanded_bytes),
            ("max_entries", max_entries),
            ("max_depth", max_depth),
        ):
            if not _is_int(value) or value < 0:
                raise UploadError("UPLOAD_INVALID_REQUEST", {name: value})

        self.allowed_types = allowed
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
        payload = _as_bytes(data)
        matched: list[str] = []
        seen: set[str] = set()
        for family, magic in MAGIC_TABLE:
            if not magic or family in seen:
                continue
            if magic in payload:
                seen.add(family)
                matched.append(family)

        if not matched:
            return _UNKNOWN_SNIFF

        primary = next(
            (family for family in matched if family in EXECUTABLE_TYPES),
            matched[0],
        )
        severity = "reject" if any(
            family in EXECUTABLE_TYPES for family in matched
        ) else "ok"
        return SniffResult(
            primary=primary,
            matched=tuple(matched),
            polyglot=len(matched) >= 2,
            severity=severity,
        )

    def normalize_filename(self, raw: str) -> str:
        if not isinstance(raw, str):
            raise UploadError("UPLOAD_FILENAME_REJECTED", {"filename": raw})
        filename = _clean_filename(raw)
        if not filename or "/" in filename or "\\" in filename:
            raise UploadError("UPLOAD_FILENAME_REJECTED", {"filename": raw})
        return filename

    def screen(self, *, filename: str, declared_type: str, data: bytes) -> ScreeningVerdict:
        with self._lock:
            payload = _as_bytes(data)
            sniffed = self.sniff(payload)
            declared = declared_type if isinstance(declared_type, str) else ""
            if isinstance(filename, str):
                normal = _clean_filename(filename)
            else:
                normal = ""
            extension = _extension(normal)

            def verdict(allowed: bool, reason: str) -> ScreeningVerdict:
                reserved = len(payload) if allowed else 0
                result = ScreeningVerdict(
                    filename=normal,
                    declared_type=declared,
                    sniffed=sniffed,
                    extension=extension,
                    allowed=allowed,
                    reason=reason,
                    reserved_bytes=reserved,
                )
                if allowed:
                    self._stats["screened"] += 1
                else:
                    self._stats["rejected"] += 1
                self._audit.append({
                    "filename": normal,
                    "declared_type": declared,
                    "sniffed": sniffed.primary,
                    "reason": reason,
                    "reserved_bytes": reserved,
                })
                return result

            try:
                normal = self.normalize_filename(filename)
            except UploadError as exc:
                return verdict(False, exc.code)

            extension = _extension(normal)
            if _has_double_extension(normal):
                return verdict(False, "UPLOAD_DOUBLE_EXTENSION")
            if (extension in SCRIPT_EXTENSIONS or normal in SCRIPT_EXTENSIONS
                    or sniffed.severity == "reject"):
                return verdict(False, "UPLOAD_EXECUTABLE_REJECTED")
            if sniffed.polyglot:
                return verdict(False, "UPLOAD_POLYGLOT_REJECTED")

            expected = DECLARED_TYPES.get(declared.strip().lower())
            if expected is None or expected != sniffed.primary:
                return verdict(False, "UPLOAD_TYPE_MISMATCH")
            if sniffed.primary not in self.allowed_types:
                return verdict(False, "UPLOAD_UNSUPPORTED_TYPE")
            if len(payload) > self.max_bytes:
                return verdict(False, "UPLOAD_LIMIT_EXCEEDED")
            return verdict(True, "UPLOAD_OK")

    def reserve(self, upload_id: str, *, byte_count: int) -> int:
        if not isinstance(upload_id, str) or not upload_id:
            raise UploadError("UPLOAD_INVALID_REQUEST", {"upload_id": upload_id})
        if not _is_int(byte_count) or byte_count < 0:
            raise UploadError("UPLOAD_INVALID_REQUEST", {"byte_count": byte_count})

        with self._lock:
            current = self._reservations.get(upload_id)
            if current is not None:
                if current != byte_count:
                    raise UploadError(
                        "UPLOAD_INVALID_REQUEST",
                        {"upload_id": upload_id, "reserved": current,
                         "requested": byte_count},
                    )
                return current

            total = sum(self._reservations.values()) + byte_count
            if total > self.max_inflight_bytes:
                raise UploadError(
                    "UPLOAD_QUOTA_EXCEEDED",
                    {"pending_bytes": total, "limit": self.max_inflight_bytes},
                )
            self._reservations[upload_id] = byte_count
            self._stats["reserved_bytes"] = total
            return byte_count

    def release(self, upload_id: str) -> int:
        if not isinstance(upload_id, str) or not upload_id:
            raise UploadError("UPLOAD_INVALID_REQUEST", {"upload_id": upload_id})
        with self._lock:
            amount = self._reservations.pop(upload_id, 0)
            self._stats["reserved_bytes"] = sum(self._reservations.values())
            return amount

    def pending_reservations(self) -> dict:
        with self._lock:
            return dict(self._reservations)

    def expand(self, upload_id: str, archive_bytes: bytes, *, depth: int = 0) -> ExtractionReport:
        if not isinstance(upload_id, str) or not upload_id:
            raise UploadError("UPLOAD_INVALID_REQUEST", {"upload_id": upload_id})
        if not _is_int(depth) or depth < 0:
            raise UploadError("UPLOAD_INVALID_REQUEST", {"depth": depth})
        payload = _as_bytes(archive_bytes)

        with self._lock:
            if upload_id not in self._reservations:
                raise UploadError("UPLOAD_INVALID_REQUEST", {"upload_id": upload_id})

            state = _ScanState()
            try:
                self._scan_archive(payload, depth, state)
            except _ExpansionRejected as exc:
                self._reservations.pop(upload_id)
                self._stats["reserved_bytes"] = sum(self._reservations.values())
                self._stats["rollbacks"] += 1
                return ExtractionReport(
                    entries=exc.entries,
                    bytes_written=0,
                    depth=depth,
                    rejected=True,
                    reason=exc.reason,
                )
            except Exception:
                self._reservations.pop(upload_id)
                self._stats["reserved_bytes"] = sum(self._reservations.values())
                self._stats["rollbacks"] += 1
                return ExtractionReport(
                    entries=state.entries,
                    bytes_written=0,
                    depth=depth,
                    rejected=True,
                    reason="UPLOAD_ENTRY_REJECTED",
                )

            self._reservations.pop(upload_id)
            self._stats["reserved_bytes"] = sum(self._reservations.values())
            self._expanded_bytes += state.bytes
            self._stats["expanded_bytes"] = self._expanded_bytes
            return ExtractionReport(
                entries=state.entries,
                bytes_written=state.bytes,
                depth=depth,
                rejected=False,
                reason="UPLOAD_OK",
            )

    def _scan_archive(self, archive_bytes: bytes, depth: int,
                      state: _ScanState) -> None:
        if depth > self.max_depth:
            raise _ExpansionRejected("UPLOAD_ENTRY_REJECTED", state.entries)

        try:
            archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            raise _ExpansionRejected("UPLOAD_ENTRY_REJECTED", state.entries) from exc

        with archive:
            for info in archive.infolist():
                state.entries += 1
                if state.entries > self.max_entries:
                    raise _ExpansionRejected("UPLOAD_ENTRY_REJECTED", state.entries)

                name = info.filename
                if "\x00" in name:
                    raise _ExpansionRejected("UPLOAD_ENTRY_REJECTED", state.entries)
                safe_name = _remove_format_and_control(name)
                if self._unsafe_entry_name(safe_name):
                    raise _ExpansionRejected("UPLOAD_ENTRY_REJECTED", state.entries)

                size = info.file_size
                if not _is_int(size) or size < 0:
                    raise _ExpansionRejected("UPLOAD_ENTRY_REJECTED", state.entries)
                state.bytes += size
                if (self._expanded_bytes + state.bytes >
                        self.max_expanded_bytes):
                    raise _ExpansionRejected("UPLOAD_QUOTA_EXCEEDED", state.entries)

                if info.is_dir() or size == 0:
                    continue

                try:
                    with archive.open(info, "r") as handle:
                        head = handle.read(4)
                        if not self._is_zip_magic(head):
                            continue
                        nested = head + handle.read()
                except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
                    raise _ExpansionRejected(
                        "UPLOAD_ENTRY_REJECTED", state.entries
                    ) from exc

                self._scan_archive(nested, depth + 1, state)

    @staticmethod
    def _unsafe_entry_name(name: str) -> bool:
        if "\x00" in name:
            return True
        normalized = name.replace("\\", "/")
        if normalized.startswith("/"):
            return True
        if len(normalized) >= 2 and normalized[1] == ":":
            return True
        return any(part == ".." for part in normalized.split("/"))

    @staticmethod
    def _is_zip_magic(head: bytes) -> bool:
        return (
            head in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}
            or head == b"PK\x08\x08"
        )

    def audit_log(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(copy.deepcopy(entry) for entry in self._audit)

    def snapshot(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["reserved_bytes"] = sum(self._reservations.values())
            stats["expanded_bytes"] = self._expanded_bytes
            return {
                "version": SNAPSHOT_VERSION,
                "reservations": dict(self._reservations),
                "expanded_bytes": self._expanded_bytes,
                "audit": copy.deepcopy(self._audit),
                "stats": copy.deepcopy(stats),
            }

    def restore(self, state: dict) -> None:
        try:
            candidate = self._validated_snapshot(state)
        except Exception as exc:
            if isinstance(exc, UploadError):
                raise
            raise UploadError("UPLOAD_SNAPSHOT_INVALID") from exc

        with self._lock:
            restores = self._stats["restores"]
            self._reservations = candidate["reservations"]
            self._expanded_bytes = candidate["expanded_bytes"]
            self._audit = candidate["audit"]
            self._stats = candidate["stats"]
            self._stats["restores"] = max(restores, self._stats["restores"]) + 1

    def stats(self) -> dict:
        with self._lock:
            result = dict(self._stats)
            result["reserved_bytes"] = sum(self._reservations.values())
            result["expanded_bytes"] = self._expanded_bytes
            return result

    def _validated_snapshot(self, state: Any) -> dict:
        def invalid(detail: Any = None) -> None:
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != SNAPSHOT_KEYS:
            invalid({"keys": sorted(state) if isinstance(state, dict) else None})

        version = state["version"]
        if not _is_int(version) or version != SNAPSHOT_VERSION:
            invalid({"version": version})

        reservations_raw = state["reservations"]
        if not isinstance(reservations_raw, dict):
            invalid({"reservations": type(reservations_raw).__name__})
        reservations: dict[str, int] = {}
        for upload_id, amount in reservations_raw.items():
            if not isinstance(upload_id, str) or not upload_id:
                invalid({"reservation_id": upload_id})
            if not _is_int(amount) or amount < 0:
                invalid({"reservation": amount})
            reservations[upload_id] = amount

        expanded = state["expanded_bytes"]
        if not _is_int(expanded) or expanded < 0:
            invalid({"expanded_bytes": expanded})

        audit_raw = state["audit"]
        if not isinstance(audit_raw, list):
            invalid({"audit": type(audit_raw).__name__})
        audit: list[dict] = []
        audit_keys = {
            "filename", "declared_type", "sniffed", "reason", "reserved_bytes",
        }
        for entry in audit_raw:
            if not isinstance(entry, dict) or not audit_keys <= set(entry):
                invalid({"audit_entry": type(entry).__name__})
            if not all(isinstance(entry[key], str) for key in
                       ("filename", "declared_type", "sniffed", "reason")):
                invalid({"audit_entry": "str"})
            if not _is_int(entry["reserved_bytes"]) or entry["reserved_bytes"] < 0:
                invalid({"audit_entry": "reserved_bytes"})
            audit.append(copy.deepcopy(entry))

        stats_raw = state["stats"]
        if not isinstance(stats_raw, dict) or set(stats_raw) != set(STAT_KEYS):
            invalid({"stats": sorted(stats_raw) if isinstance(stats_raw, dict) else None})
        stats: dict[str, int] = {}
        for name in STAT_KEYS:
            value = stats_raw[name]
            if not _is_int(value) or value < 0:
                invalid({"stat": name, "value": value})
            stats[name] = value

        # Counters derived from the other snapshot fields are recomputed so a
        # restored instance can never advertise half-applied bookkeeping.
        stats["reserved_bytes"] = sum(reservations.values())
        stats["expanded_bytes"] = expanded
        if stats["reserved_bytes"] > self.max_inflight_bytes:
            invalid({"reserved_bytes": stats["reserved_bytes"]})
        if expanded > self.max_expanded_bytes:
            invalid({"expanded_bytes": expanded})
        return {
            "reservations": reservations,
            "expanded_bytes": expanded,
            "audit": audit,
            "stats": stats,
        }
