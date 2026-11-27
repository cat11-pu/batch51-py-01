"""Hardening audit for executable images.

The auditor reads a little endian ELF64 image, reports the hardening items
that the loader and the toolchain ought to provide (position independence,
non executable stack, read only relocations, immediate symbol binding and the
stack protector), and applies baselines and time limited exemptions on top of
the raw verdict.  Images are keyed by path and content digest so a replaced
file can never inherit the result of its predecessor.
"""

from __future__ import annotations

import copy
import hashlib
import os
import struct
import threading
from dataclasses import dataclass
from datetime import date, datetime, timezone

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
DYNAMIC_ENTRY_SIZE = 16
ITEM_ORDER = ("pie", "nx_stack", "relro", "bind_now", "stack_canary")


class ElfAuditError(ValueError):
    """Refusal raised while reading an image or restoring a snapshot."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class HardeningItems(tuple):
    """An ordered item sequence with the ``items`` view used by reports."""

    @property
    def items(self):
        return tuple(self)


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


def _path_key(path) -> str:
    value = os.fspath(path)
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    return value


def _item_names(items, *, reject_unknown: bool = True) -> tuple:
    if isinstance(items, str):
        items = (items,)
    try:
        requested = set(items)
    except TypeError as exc:
        raise ElfAuditError("ELF_BAD_ITEM", items) from exc

    unknown = requested.difference(ITEM_ORDER)
    if unknown and reject_unknown:
        raise ElfAuditError("ELF_BAD_ITEM", sorted(unknown))
    return tuple(item for item in ITEM_ORDER if item in requested)


def _utc_datetime(value, *, allow_none: bool = False):
    if value is None and allow_none:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ElfAuditError("ELF_BAD_TIME", value) from exc
    else:
        raise ElfAuditError("ELF_BAD_TIME", value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _current_time() -> datetime:
    return datetime.now(timezone.utc)


class ElfHardeningAuditor:
    """Parse images, judge hardening items and apply baseline exemptions."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images = {}
        self._exemptions = {}
        self._baselines = {}
        self._stats = {
            "parses": 0,
            "scans": 0,
            "cache_hits": 0,
            "exemptions": 0,
            "restores": 0,
        }

    def parse_image(self, data: bytes) -> ImageInfo:
        """Parse an ELF64 little endian image into an :class:`ImageInfo`."""
        try:
            raw = bytes(data)
        except (TypeError, ValueError) as exc:
            raise ElfAuditError("ELF_BAD_DATA", type(data).__name__) from exc

        size = len(raw)
        if size < 4:
            raise ElfAuditError("ELF_TRUNCATED", "header")
        if raw[:4] != b"\x7fELF":
            raise ElfAuditError("ELF_BAD_MAGIC")
        if size < EHDR_SIZE:
            raise ElfAuditError("ELF_TRUNCATED", "header")
        if raw[4] != 2:
            raise ElfAuditError("ELF_BAD_CLASS", raw[4])
        if raw[5] != 1:
            raise ElfAuditError("ELF_BAD_ENDIAN", raw[5])

        file_type = struct.unpack_from("<H", raw, 16)[0]
        entry = struct.unpack_from("<Q", raw, 24)[0]
        phoff = struct.unpack_from("<Q", raw, 32)[0]
        phentsize = struct.unpack_from("<H", raw, 54)[0]
        phnum = struct.unpack_from("<H", raw, 56)[0]

        if phentsize != PHDR_SIZE:
            raise ElfAuditError("ELF_BAD_PHDR", phentsize)
        if phoff > size:
            raise ElfAuditError("ELF_BAD_PHDR", "phoff")
        table_end = phoff + phnum * phentsize
        if table_end > size:
            raise ElfAuditError("ELF_TRUNCATED", "program headers")

        segments = []
        dynamic = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            (seg_type, flags, seg_offset, _vaddr, _paddr, filesz,
             _memsz, _align) = struct.unpack_from("<IIQQQQQQ", raw, offset)
            segments.append(Segment(seg_type, flags, seg_offset, filesz))

            if seg_type != PT_DYNAMIC:
                continue
            if seg_offset > size or filesz > size - seg_offset:
                raise ElfAuditError("ELF_TRUNCATED", "dynamic segment")
            if filesz % DYNAMIC_ENTRY_SIZE:
                raise ElfAuditError("ELF_BAD_DYNAMIC", filesz)
            for dyn_offset in range(seg_offset, seg_offset + filesz,
                                    DYNAMIC_ENTRY_SIZE):
                dynamic.append(struct.unpack_from("<QQ", raw, dyn_offset))

        info = ImageInfo(
            file_type=file_type,
            entry=entry,
            phentsize=phentsize,
            phnum=phnum,
            size=size,
            digest=hashlib.sha256(raw).hexdigest(),
            segments=tuple(segments),
            dynamic=tuple(dynamic),
        )
        with self._lock:
            self._stats["parses"] += 1
        return info

    def check_image(self, info: ImageInfo, *, symbols=()) -> tuple:
        """Judge the hardening items of one parsed image."""
        if isinstance(symbols, str):
            symbol_set = {symbols}
        else:
            symbol_set = set(symbols)

        items = []

        if info.file_type == ET_DYN:
            items.append(HardeningItem("pie", "ok", "ET_DYN is position independent"))
        else:
            items.append(HardeningItem(
                "pie", "fail", f"ELF type {info.file_type} is not ET_DYN"))

        stack_headers = [
            segment for segment in info.segments
            if segment.type == PT_GNU_STACK
        ]
        if not stack_headers:
            items.append(HardeningItem(
                "nx_stack", "fail", "PT_GNU_STACK is missing"))
        elif any(segment.flags & PF_X for segment in stack_headers):
            items.append(HardeningItem(
                "nx_stack", "fail", "PT_GNU_STACK has the execute flag"))
        else:
            items.append(HardeningItem(
                "nx_stack", "ok", "PT_GNU_STACK is not executable"))

        has_dynamic_segment = any(
            segment.type == PT_DYNAMIC for segment in info.segments)
        if not has_dynamic_segment:
            items.append(HardeningItem(
                "relro", "n/a", "static executable has no dynamic segment"))
        elif any(segment.type == PT_GNU_RELRO for segment in info.segments):
            items.append(HardeningItem(
                "relro", "ok", "PT_GNU_RELRO is present"))
        else:
            items.append(HardeningItem(
                "relro", "fail", "PT_GNU_RELRO is missing"))

        if not has_dynamic_segment:
            items.append(HardeningItem(
                "bind_now", "n/a", "static executable has no dynamic segment"))
        else:
            bind_now = False
            for tag, value in info.dynamic:
                if tag == DT_BIND_NOW:
                    bind_now = True
                    break
                if tag == DT_FLAGS and value & DF_BIND_NOW:
                    bind_now = True
                    break
                if tag == DT_FLAGS_1 and value & DF_1_NOW:
                    bind_now = True
                    break
            if bind_now:
                items.append(HardeningItem(
                    "bind_now", "ok", "immediate binding is requested"))
            else:
                items.append(HardeningItem(
                    "bind_now", "fail", "no immediate binding flag is present"))

        if "__stack_chk_fail" in symbol_set:
            items.append(HardeningItem(
                "stack_canary", "ok", "__stack_chk_fail is referenced"))
        else:
            items.append(HardeningItem(
                "stack_canary", "fail", "__stack_chk_fail is not referenced"))

        return HardeningItems(items)

    def verdict_for(self, items) -> str:
        """Return ``pass`` when no item failed, otherwise ``fail``."""
        for item in items:
            if isinstance(item, str):
                status = item
            elif isinstance(item, HardeningItem):
                status = item.status
            elif isinstance(item, dict):
                status = item.get("status")
            else:
                status = getattr(item, "status", None)
            if status == "fail":
                return "fail"
        return "pass"

    @staticmethod
    def _read_disk(path: str):
        try:
            if not os.path.isfile(path):
                return None
            with open(path, "rb") as image:
                return image.read()
        except OSError:
            return None

    def _effective_failing(self, record, now=None) -> tuple:
        package = record["package"]
        baselined = self._baselines.get(package, ())
        digest = record["digest"]
        path = record["path"]
        failing = []
        for item in record["raw_failing"]:
            if item in baselined:
                continue
            if self.is_exempt(path, digest, item, now=now):
                continue
            failing.append(item)
        return tuple(failing)

    def scan(self, path: str, data: bytes, *, package: str = "",
             symbols=(), now: str | None = None) -> ScanResult:
        """Parse (once per path and digest) and audit one image."""
        path = _path_key(path)
        try:
            supplied = bytes(data)
        except (TypeError, ValueError) as exc:
            raise ElfAuditError("ELF_BAD_DATA", type(data).__name__) from exc
        if isinstance(symbols, str):
            symbols_tuple = (symbols,)
        else:
            symbols_tuple = tuple(symbols)

        with self._lock:
            self._stats["scans"] += 1
            current = supplied
            disk_before = self._read_disk(path)
            if (disk_before is not None and
                    hashlib.sha256(disk_before).digest() !=
                    hashlib.sha256(current).digest()):
                current = disk_before
            attempts = 0

            while True:
                attempts += 1
                digest = hashlib.sha256(current).hexdigest()
                key = (path, digest)
                record = self._images.get(key)
                try:
                    if record is None:
                        info = self.parse_image(current)
                    else:
                        info = record["info"]
                        self._stats["cache_hits"] += 1

                    items = self.check_image(info, symbols=symbols_tuple)
                    raw_failing = tuple(
                        item.name for item in items if item.status == "fail")
                    candidate = {
                        "path": path,
                        "package": package,
                        "digest": digest,
                        "info": info,
                        "symbols": symbols_tuple,
                        "items": items,
                        "raw_failing": raw_failing,
                    }
                    failing = self._effective_failing(candidate, now=now)
                    result = ScanResult(
                        path=path,
                        package=package,
                        digest=digest,
                        items=items,
                        failing=failing,
                        verdict="fail" if failing else "pass",
                    )
                except ElfAuditError:
                    disk_after = self._read_disk(path)
                    if self._disk_changed(disk_before, disk_after):
                        if attempts >= 5:
                            raise ElfAuditError("ELF_CHANGING", path)
                        disk_before = disk_after
                        if disk_after is not None:
                            current = disk_after
                        continue
                    raise

                disk_after = self._read_disk(path)
                if self._disk_changed(disk_before, disk_after):
                    if attempts >= 5:
                        raise ElfAuditError("ELF_CHANGING", path)
                    disk_before = disk_after
                    if disk_after is not None:
                        current = disk_after
                    continue

                candidate["failing"] = failing
                candidate["verdict"] = result.verdict
                self._images[key] = candidate
                return result

    @staticmethod
    def _disk_changed(before, after) -> bool:
        if before is None:
            return after is not None
        if after is None:
            return True
        return hashlib.sha256(before).digest() != hashlib.sha256(after).digest()

    def set_baseline(self, package: str, items) -> None:
        """Declare which items are tolerated for ``package``."""
        normalized = _item_names(items)
        with self._lock:
            if normalized:
                self._baselines[package] = normalized
            else:
                self._baselines.pop(package, None)

    def baseline_for(self, package: str) -> tuple:
        """Return the tolerated items of ``package``."""
        with self._lock:
            return tuple(self._baselines.get(package, ()))

    def add_exemption(self, path: str, digest: str, items, *,
                      expires_at=None) -> None:
        """Exempt ``items`` of the image at ``path``/``digest``."""
        path = _path_key(path)
        digest = str(digest).lower()
        normalized = _item_names(items)
        expiry = _utc_datetime(expires_at, allow_none=True)
        expiry_text = expiry.isoformat() if expiry is not None else None

        with self._lock:
            by_digest = self._exemptions.setdefault(path, {})
            exempted = by_digest.setdefault(digest, {})
            for item in normalized:
                if item not in exempted:
                    self._stats["exemptions"] += 1
                exempted[item] = expiry_text
            if not exempted:
                by_digest.pop(digest, None)
            if not by_digest:
                self._exemptions.pop(path, None)

    def drop_exemption(self, path: str, digest: str) -> int:
        """Drop the exemption of one image and return how many items it held."""
        path = _path_key(path)
        digest = str(digest).lower()
        with self._lock:
            by_digest = self._exemptions.get(path)
            if not by_digest or digest not in by_digest:
                return 0
            removed = len(by_digest.pop(digest))
            self._stats["exemptions"] = max(
                0, self._stats["exemptions"] - removed)
            if not by_digest:
                self._exemptions.pop(path, None)
            return removed

    def is_exempt(self, path: str, digest: str, item: str, *,
                  now: str | None = None) -> bool:
        """Report whether ``item`` is exempt for this path and digest."""
        path = _path_key(path)
        digest = str(digest).lower()
        with self._lock:
            by_digest = self._exemptions.get(path, {})
            exempted = by_digest.get(digest)
            if not exempted or item not in exempted:
                return False
            expiry_text = exempted[item]
            if expiry_text is None:
                return True
            expiry = _utc_datetime(expiry_text)
            moment = _current_time() if now is None else _utc_datetime(now)
            return moment < expiry

    def report(self) -> dict:
        """Aggregate the scanned images by package and failing item."""
        with self._lock:
            packages = {}
            failing_items = {item: 0 for item in ITEM_ORDER}
            now = _current_time()

            for record in self._images.values():
                package = record["package"]
                bucket = packages.setdefault(
                    package, {"images": 0, "failing": set()})
                bucket["images"] += 1
                failing = self._effective_failing(record, now=now)
                bucket["failing"].update(failing)
                for item in failing:
                    failing_items[item] += 1

            return {
                "images": len(self._images),
                "packages": {
                    package: {
                        "images": values["images"],
                        "failing": tuple(
                            item for item in ITEM_ORDER
                            if item in values["failing"]),
                    }
                    for package, values in packages.items()
                },
                "failing_items": {
                    item: failing_items[item]
                    for item in ITEM_ORDER if failing_items[item]
                },
            }

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return copy.deepcopy(self._stats)

    @staticmethod
    def _image_state(record) -> dict:
        info = record["info"]
        return {
            "path": record["path"],
            "package": record["package"],
            "digest": record["digest"],
            "file_type": info.file_type,
            "entry": info.entry,
            "phentsize": info.phentsize,
            "phnum": info.phnum,
            "size": info.size,
            "segments": [
                {
                    "type": segment.type,
                    "flags": segment.flags,
                    "offset": segment.offset,
                    "filesz": segment.filesz,
                }
                for segment in info.segments
            ],
            "dynamic": [
                [tag, value] for tag, value in info.dynamic
            ],
            "symbols": list(record["symbols"]),
            "items": [
                {
                    "name": item.name,
                    "status": item.status,
                    "reason": item.reason,
                }
                for item in record["items"]
            ],
            "raw_failing": list(record["raw_failing"]),
            "failing": list(record["failing"]),
            "verdict": record["verdict"],
        }

    def snapshot(self) -> dict:
        """Return a detached snapshot of images, exemptions and counters."""
        with self._lock:
            return {
                "images": [
                    self._image_state(record)
                    for record in self._images.values()
                ],
                "exemptions": copy.deepcopy(self._exemptions),
                "baselines": {
                    package: list(items)
                    for package, items in self._baselines.items()
                },
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        if not isinstance(state, dict):
            raise ElfAuditError("ELF_BAD_STATE", "snapshot")
        required = {"images", "exemptions", "baselines", "stats"}
        if not required.issubset(state):
            raise ElfAuditError(
                "ELF_BAD_STATE", sorted(required.difference(state)))

        detached = copy.deepcopy(state)
        images = {}
        try:
            for image_state in detached["images"]:
                segments = tuple(
                    Segment(
                        int(segment["type"]),
                        int(segment["flags"]),
                        int(segment["offset"]),
                        int(segment["filesz"]),
                    )
                    for segment in image_state["segments"]
                )
                dynamic = tuple(
                    (int(tag), int(value))
                    for tag, value in image_state["dynamic"]
                )
                info = ImageInfo(
                    file_type=int(image_state["file_type"]),
                    entry=int(image_state["entry"]),
                    phentsize=int(image_state["phentsize"]),
                    phnum=int(image_state["phnum"]),
                    size=int(image_state["size"]),
                    digest=str(image_state["digest"]).lower(),
                    segments=segments,
                    dynamic=dynamic,
                )
                items = tuple(
                    HardeningItem(
                        str(item["name"]),
                        str(item["status"]),
                        str(item["reason"]),
                    )
                    for item in image_state["items"]
                )
                record = {
                    "path": _path_key(image_state["path"]),
                    "package": str(image_state["package"]),
                    "digest": info.digest,
                    "info": info,
                    "symbols": tuple(image_state.get("symbols", ())),
                    "items": items,
                    "raw_failing": tuple(image_state.get("raw_failing", ())),
                    "failing": tuple(image_state.get("failing", ())),
                    "verdict": str(image_state.get("verdict", "fail")),
                }
                images[(record["path"], record["digest"])] = record

            exemptions = {}
            for path, by_digest in detached["exemptions"].items():
                if not isinstance(by_digest, dict):
                    raise ElfAuditError("ELF_BAD_STATE", "exemptions")
                exemptions[_path_key(path)] = {}
                for digest, exempted in by_digest.items():
                    if not isinstance(exempted, dict):
                        raise ElfAuditError("ELF_BAD_STATE", "exemptions")
                    normalized = {}
                    for item, expiry in exempted.items():
                        if item not in ITEM_ORDER:
                            raise ElfAuditError("ELF_BAD_STATE", item)
                        parsed = _utc_datetime(expiry, allow_none=True)
                        normalized[item] = (
                            parsed.isoformat() if parsed is not None else None)
                    exemptions[_path_key(path)][
                        str(digest).lower()] = normalized

            baselines = {
                str(package): _item_names(items)
                for package, items in detached["baselines"].items()
            }
            stats = {
                "parses": int(detached["stats"]["parses"]),
                "scans": int(detached["stats"]["scans"]),
                "cache_hits": int(detached["stats"]["cache_hits"]),
                "exemptions": int(detached["stats"]["exemptions"]),
                "restores": int(detached["stats"]["restores"]),
            }
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ElfAuditError):
                raise
            raise ElfAuditError("ELF_BAD_STATE", str(exc)) from exc

        with self._lock:
            self._images = images
            self._exemptions = exemptions
            self._baselines = baselines
            self._stats = stats

    def clear(self) -> None:
        """Forget every scanned image, exemption and baseline."""
        with self._lock:
            self._images = {}
            self._exemptions = {}
            self._baselines = {}
            self._stats = {
                "parses": 0,
                "scans": 0,
                "cache_hits": 0,
                "exemptions": 0,
                "restores": 0,
            }
