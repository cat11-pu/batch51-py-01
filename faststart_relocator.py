"""MP4 faststart relocation: box scanning, chunk offset rewrite and verification."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable


class FaststartError(ValueError):
    """Raised when a relocation request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BoxInfo:
    """One top level box found in the scanned file."""

    type: str
    offset: int
    size: int


@dataclass(frozen=True)
class OffsetEntry:
    """One chunk offset before and after relocation."""

    index: int
    old_offset: int
    new_offset: int


@dataclass(frozen=True)
class RelocationPlan:
    """What a relocation would do to the scanned file."""

    moved: bool
    delta: int
    moov_size: int
    chunk_count: int
    co64: bool
    new_size: int


@dataclass(frozen=True)
class _ChunkTable:
    box_type: bytes
    header_size: int
    count: int
    offsets: tuple[int, ...]


@dataclass(frozen=True)
class _Inspection:
    boxes: tuple[BoxInfo, ...]
    ftyp: BoxInfo
    moov: BoxInfo
    mdats: tuple[BoxInfo, ...]
    mdat_ranges: tuple[tuple[int, int], ...]
    tables: tuple[_ChunkTable, ...]
    chunks: tuple[int, ...]


@dataclass(frozen=True)
class _RewriteContext:
    mapping: Callable[[int], int]
    convert_stco: bool


@dataclass(frozen=True)
class _Computed:
    plan: RelocationPlan
    force_co64: bool
    entries: tuple[OffsetEntry, ...]
    mapping: Callable[[int], int]
    convert_stco: bool
    raw_moov_size: int
    free_size: int
    relocated_moov: bytes | None


_CONTAINER_TYPES = frozenset(
    {
        b"moov",
        b"trak",
        b"mdia",
        b"minf",
        b"stbl",
        b"edts",
        b"mvex",
        b"moof",
        b"traf",
        b"mfra",
    }
)
_MAX_CHUNKS = 1_000_000
_U32_MAX = (1 << 32) - 1


def _error(code: str, detail: object = None) -> FaststartError:
    return FaststartError(code, detail)


def _as_bytes(blob: object, code: str) -> bytes:
    if isinstance(blob, bytes):
        return blob
    if isinstance(blob, (bytearray, memoryview)):
        return bytes(blob)
    raise _error(code, {"type": type(blob).__name__})


def _parse_top_level(blob: bytes, max_boxes: int) -> tuple[BoxInfo, ...]:
    boxes: list[BoxInfo] = []
    offset = 0
    total = len(blob)
    while offset < total:
        if total - offset < 8:
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "reason": "short header"})
        size = int.from_bytes(blob[offset : offset + 4], "big")
        box_type = blob[offset + 4 : offset + 8]
        if size < 8:
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "size": size})
        if offset + size > total:
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "size": size})
        if not box_type.strip(b"\x00"):
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "reason": "empty type"})
        if len(boxes) >= max_boxes:
            raise _error("FASTSTART_BOX_LIMIT", {"limit": max_boxes})
        boxes.append(BoxInfo(box_type.decode("latin-1"), offset, size))
        offset += size
    return tuple(boxes)


def _split_box(raw: bytes) -> tuple[bytes, bytes]:
    if len(raw) < 8:
        raise _error("FASTSTART_BAD_BOX", {"reason": "short box"})
    size = int.from_bytes(raw[:4], "big")
    if size < 8 or size > len(raw):
        raise _error("FASTSTART_BAD_BOX", {"size": size, "available": len(raw)})
    box_type = raw[4:8]
    if not box_type.strip(b"\x00"):
        raise _error("FASTSTART_BAD_BOX", {"reason": "empty type"})
    return box_type, raw[8:size]


def _children(payload: bytes, prefix: int = 0) -> tuple[bytes, ...]:
    if len(payload) < prefix:
        raise _error("FASTSTART_BAD_BOX", {"reason": "short full box header"})
    children: list[bytes] = []
    offset = prefix
    while offset < len(payload):
        if len(payload) - offset < 8:
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "reason": "short child"})
        size = int.from_bytes(payload[offset : offset + 4], "big")
        if size < 8 or offset + size > len(payload):
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "size": size})
        child_type = payload[offset + 4 : offset + 8]
        if not child_type.strip(b"\x00"):
            raise _error("FASTSTART_BAD_BOX", {"offset": offset, "reason": "empty type"})
        children.append(payload[offset : offset + size])
        offset += size
    return tuple(children)


def _make_box(box_type: bytes, payload: bytes) -> bytes:
    size = 8 + len(payload)
    if size > _U32_MAX:
        raise _error("FASTSTART_BAD_BOX", {"reason": "box too large", "size": size})
    return size.to_bytes(4, "big") + box_type + payload


def _chunk_table(box_type: bytes, payload: bytes) -> _ChunkTable:
    if len(payload) < 4:
        raise _error("FASTSTART_BAD_BOX", {"type": box_type.decode("latin-1")})
    width = 4 if box_type == b"stco" else 8
    first_count = int.from_bytes(payload[:4], "big")
    simple_size = 4 + first_count * width
    standard_count = int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else -1
    standard_size = 8 + standard_count * width
    if simple_size == len(payload):
        header_size = 4
        count = first_count
    elif standard_count >= 0 and standard_size <= len(payload):
        header_size = 8
        count = standard_count
    elif simple_size <= len(payload):
        header_size = 4
        count = first_count
    else:
        raise _error(
            "FASTSTART_BAD_BOX",
            {"type": box_type.decode("latin-1"), "count": first_count},
        )
    if count > _MAX_CHUNKS:
        raise _error("FASTSTART_BOX_LIMIT", {"chunks": count, "limit": _MAX_CHUNKS})
    needed = header_size + count * width
    if needed > len(payload):
        raise _error(
            "FASTSTART_BAD_BOX",
            {"type": box_type.decode("latin-1"), "count": count, "available": len(payload)},
        )
    offsets = tuple(
        int.from_bytes(
            payload[
                header_size + index * width : header_size + (index + 1) * width
            ],
            "big",
        )
        for index in range(count)
    )
    return _ChunkTable(box_type, header_size, count, offsets)


def _walk_chunk_tables(raw: bytes, target: list[_ChunkTable]) -> None:
    box_type, payload = _split_box(raw)
    if box_type in (b"stco", b"co64"):
        target.append(_chunk_table(box_type, payload))
        return
    if box_type in _CONTAINER_TYPES:
        for child in _children(payload):
            _walk_chunk_tables(child, target)


def _inspect(blob: bytes, max_boxes: int) -> _Inspection:
    boxes = _parse_top_level(blob, max_boxes)
    ftyp = next((box for box in boxes if box.type == "ftyp"), None)
    moov = next((box for box in boxes if box.type == "moov"), None)
    mdats = tuple(box for box in boxes if box.type == "mdat")
    missing = [
        name
        for name, value in (("ftyp", ftyp), ("moov", moov), ("mdat", mdats))
        if not value
    ]
    if missing:
        raise _error("FASTSTART_MISSING_BOX", {"missing": missing})
    assert ftyp is not None and moov is not None
    tables: list[_ChunkTable] = []
    _walk_chunk_tables(blob[moov.offset : moov.offset + moov.size], tables)
    chunks = tuple(offset for table in tables for offset in table.offsets)
    ranges = tuple((box.offset + 8, box.offset + box.size) for box in mdats)
    for index, offset in enumerate(chunks):
        if not any(start <= offset < end for start, end in ranges):
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"index": index, "offset": offset, "mdat_ranges": ranges},
            )
    return _Inspection(
        boxes=boxes,
        ftyp=ftyp,
        moov=moov,
        mdats=mdats,
        mdat_ranges=ranges,
        tables=tuple(tables),
        chunks=chunks,
    )


def _is_optimized(inspection: _Inspection) -> bool:
    return inspection.moov.offset < min(box.offset for box in inspection.mdats)


def _free_size(raw_moov_size: int, ftyp_end: int, alignment: int) -> int:
    needed = (-(ftyp_end + raw_moov_size)) % alignment
    if needed == 0:
        return 0
    size = needed
    while size < 8:
        size += alignment
    return size


def _make_mapping(
    ftyp_end: int, moov_start: int, moov_end: int, segment_size: int
) -> Callable[[int], int]:
    growth = segment_size - (moov_end - moov_start)

    def mapping(value: int) -> int:
        if value < ftyp_end:
            return value
        if value < moov_start:
            return value + segment_size
        if value < moov_end:
            return ftyp_end + (value - moov_start)
        return value + growth

    return mapping


def _rewrite_chunk_table(
    box_type: bytes, payload: bytes, context: _RewriteContext
) -> bytes:
    table = _chunk_table(box_type, payload)
    convert = box_type == b"stco" and context.convert_stco
    width = 8 if convert or box_type == b"co64" else 4
    limit = (1 << (width * 8)) - 1
    output = bytearray(payload[: table.header_size])
    for offset in table.offsets:
        new_offset = context.mapping(offset)
        if new_offset < 0 or new_offset > limit:
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"offset": offset, "new_offset": new_offset, "width": width * 8},
            )
        output.extend(new_offset.to_bytes(width, "big"))
    source_width = 8 if box_type == b"co64" else 4
    output.extend(payload[table.header_size + table.count * source_width :])
    new_type = b"co64" if convert else box_type
    return _make_box(new_type, bytes(output))


def _rewrite_elst(payload: bytes, context: _RewriteContext) -> bytes | None:
    if len(payload) < 8:
        raise _error("FASTSTART_BAD_BOX", {"type": "elst"})
    version = payload[0]
    if version not in (0, 1):
        return None
    count = int.from_bytes(payload[4:8], "big")
    entry_size = 12 if version == 0 else 20
    if count > _MAX_CHUNKS:
        raise _error("FASTSTART_BOX_LIMIT", {"chunks": count, "limit": _MAX_CHUNKS})
    if 8 + count * entry_size > len(payload):
        raise _error("FASTSTART_BAD_BOX", {"type": "elst", "count": count})
    output = bytearray(payload)
    signed_limit = (1 << (31 if version == 0 else 63)) - 1
    for index in range(count):
        start = 8 + index * entry_size
        duration_size = 4 if version == 0 else 8
        media_start = start + duration_size
        media_size = 4 if version == 0 else 8
        media_time = int.from_bytes(
            payload[media_start : media_start + media_size],
            "big",
            signed=True,
        )
        if media_time < 0:
            continue
        new_time = context.mapping(media_time)
        if new_time > signed_limit:
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"box": "elst", "index": index, "offset": media_time},
            )
        output[media_start : media_start + media_size] = new_time.to_bytes(
            media_size, "big", signed=True
        )
    return bytes(output)


def _rewrite_tfhd(payload: bytes, context: _RewriteContext) -> bytes | None:
    if len(payload) < 8:
        raise _error("FASTSTART_BAD_BOX", {"type": "tfhd"})
    flags = int.from_bytes(payload[1:4], "big")
    if not flags & 0x000001:
        return None
    if len(payload) < 16:
        raise _error("FASTSTART_BAD_BOX", {"type": "tfhd", "reason": "base_data_offset"})
    base_offset = int.from_bytes(payload[8:16], "big")
    new_offset = context.mapping(base_offset)
    if new_offset < 0 or new_offset > (1 << 64) - 1:
        raise _error("FASTSTART_BAD_OFFSET", {"box": "tfhd", "offset": base_offset})
    output = bytearray(payload)
    output[8:16] = new_offset.to_bytes(8, "big")
    return bytes(output)


def _rewrite_tfra(payload: bytes, context: _RewriteContext) -> bytes | None:
    if len(payload) < 16:
        raise _error("FASTSTART_BAD_BOX", {"type": "tfra"})
    version = payload[0]
    if version not in (0, 1):
        raise _error("FASTSTART_BAD_BOX", {"type": "tfra", "version": version})
    count = int.from_bytes(payload[12:16], "big")
    if count > _MAX_CHUNKS:
        raise _error("FASTSTART_BOX_LIMIT", {"chunks": count, "limit": _MAX_CHUNKS})
    lengths = int.from_bytes(payload[8:12], "big")
    traf_size = ((lengths >> 4) & 0x3) + 1
    trun_size = ((lengths >> 2) & 0x3) + 1
    sample_size = (lengths & 0x3) + 1
    time_width = 4 if version == 0 else 8
    offset_width = time_width
    entry_size = time_width + offset_width + traf_size + trun_size + sample_size
    if 16 + count * entry_size > len(payload):
        raise _error("FASTSTART_BAD_BOX", {"type": "tfra", "count": count})
    output = bytearray(payload)
    limit = (1 << (offset_width * 8)) - 1
    for index in range(count):
        start = 16 + index * entry_size
        offset_start = start + time_width
        old_offset = int.from_bytes(
            payload[offset_start : offset_start + offset_width], "big"
        )
        new_offset = context.mapping(old_offset)
        if new_offset < 0 or new_offset > limit:
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"box": "tfra", "index": index, "offset": old_offset},
            )
        output[offset_start : offset_start + offset_width] = new_offset.to_bytes(
            offset_width, "big"
        )
    return bytes(output)


def _rewrite_saio(payload: bytes, context: _RewriteContext) -> bytes | None:
    if len(payload) < 8:
        raise _error("FASTSTART_BAD_BOX", {"type": "saio"})
    version = payload[0]
    flags = int.from_bytes(payload[1:4], "big")
    position = 4
    if flags & 0x000001:
        position += 8
    if len(payload) < position + 4:
        raise _error("FASTSTART_BAD_BOX", {"type": "saio", "reason": "entry count"})
    count = int.from_bytes(payload[position : position + 4], "big")
    if count > _MAX_CHUNKS:
        raise _error("FASTSTART_BOX_LIMIT", {"chunks": count, "limit": _MAX_CHUNKS})
    width = 4 if version == 0 else 8
    start = position + 4
    if start + count * width > len(payload):
        raise _error("FASTSTART_BAD_BOX", {"type": "saio", "count": count})
    output = bytearray(payload)
    limit = (1 << (width * 8)) - 1
    for index in range(count):
        item_start = start + index * width
        old_offset = int.from_bytes(payload[item_start : item_start + width], "big")
        new_offset = context.mapping(old_offset)
        if new_offset < 0 or new_offset > limit:
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"box": "saio", "index": index, "offset": old_offset},
            )
        output[item_start : item_start + width] = new_offset.to_bytes(width, "big")
    return bytes(output)


def _looks_like_mdat_offset(value: int, mdat_ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= value < end for start, end in mdat_ranges)


def _rewrite_sidx(
    payload: bytes,
    context: _RewriteContext,
    mdat_ranges: tuple[tuple[int, int], ...],
) -> bytes | None:
    if len(payload) < 16:
        raise _error("FASTSTART_BAD_BOX", {"type": "sidx"})
    version = payload[0]
    if version == 0:
        offset_at = 16
        width = 4
    elif version == 1:
        offset_at = 20
        width = 8
    else:
        raise _error("FASTSTART_BAD_BOX", {"type": "sidx", "version": version})
    if len(payload) < offset_at + width:
        raise _error("FASTSTART_BAD_BOX", {"type": "sidx", "reason": "first_offset"})
    old_offset = int.from_bytes(payload[offset_at : offset_at + width], "big")
    if not _looks_like_mdat_offset(old_offset, mdat_ranges):
        return None
    new_offset = context.mapping(old_offset)
    if new_offset < 0 or new_offset > (1 << (width * 8)) - 1:
        raise _error("FASTSTART_BAD_OFFSET", {"box": "sidx", "offset": old_offset})
    output = bytearray(payload)
    output[offset_at : offset_at + width] = new_offset.to_bytes(width, "big")
    return bytes(output)


def _rewrite_box(
    raw: bytes,
    context: _RewriteContext,
    mdat_ranges: tuple[tuple[int, int], ...],
) -> bytes:
    box_type, payload = _split_box(raw)
    if box_type in _CONTAINER_TYPES:
        rewritten = bytearray()
        for child in _children(payload):
            rewritten.extend(_rewrite_box(child, context, mdat_ranges))
        return _make_box(box_type, bytes(rewritten))
    if box_type in (b"stco", b"co64"):
        return _rewrite_chunk_table(box_type, payload, context)
    if box_type == b"elst":
        new_payload = _rewrite_elst(payload, context)
    elif box_type == b"tfhd":
        new_payload = _rewrite_tfhd(payload, context)
    elif box_type == b"tfra":
        new_payload = _rewrite_tfra(payload, context)
    elif box_type == b"saio":
        new_payload = _rewrite_saio(payload, context)
    elif box_type == b"sidx":
        new_payload = _rewrite_sidx(payload, context, mdat_ranges)
    else:
        return raw
    if new_payload is None:
        return raw
    return _make_box(box_type, new_payload)


class FaststartRelocator:
    """Move the movie index to the head of the file and patch chunk offsets."""

    def __init__(self, *, max_boxes: int = 128, alignment: int = 8) -> None:
        if not isinstance(max_boxes, int) or isinstance(max_boxes, bool) or max_boxes < 1:
            raise _error("FASTSTART_BOX_LIMIT", {"limit": max_boxes})
        if not isinstance(alignment, int) or isinstance(alignment, bool) or alignment < 1:
            raise _error("FASTSTART_BAD_BOX", {"alignment": alignment})
        self.max_boxes = max_boxes
        self.alignment = alignment
        self._lock = threading.RLock()
        self._blob: bytes | None = None
        self._inspection: _Inspection | None = None
        self._computed: _Computed | None = None
        self._applied: bytes | None = None
        self._applied_plan: RelocationPlan | None = None
        self._restored_force: bool | None = None

    def _require_inspection(self) -> _Inspection:
        if self._blob is None or self._inspection is None:
            raise _error("FASTSTART_STATE", {"reason": "scan required"})
        return self._inspection

    def _computed_for(self, force_co64: bool) -> _Computed:
        inspection = self._require_inspection()
        force_co64 = bool(force_co64)
        if self._computed is not None and self._computed.force_co64 == force_co64:
            return self._computed
        if self._computed is not None and self._computed.force_co64 != force_co64:
            self._applied = None
            self._applied_plan = None
        assert self._blob is not None
        if _is_optimized(inspection):
            entries = tuple(
                OffsetEntry(index, offset, offset)
                for index, offset in enumerate(inspection.chunks)
            )
            co64 = any(table.box_type == b"co64" for table in inspection.tables)
            plan = RelocationPlan(
                moved=False,
                delta=0,
                moov_size=inspection.moov.size,
                chunk_count=len(inspection.chunks),
                co64=co64,
                new_size=len(self._blob),
            )
            computed = _Computed(
                plan=plan,
                force_co64=force_co64,
                entries=entries,
                mapping=lambda value: value,
                convert_stco=False,
                raw_moov_size=inspection.moov.size,
                free_size=0,
                relocated_moov=None,
            )
            self._computed = computed
            return computed

        moov_start = inspection.moov.offset
        moov_end = moov_start + inspection.moov.size
        ftyp_end = inspection.ftyp.offset + inspection.ftyp.size
        stco_chunks = sum(
            table.count for table in inspection.tables if table.box_type == b"stco"
        )
        has_stco = any(
            table.box_type == b"stco" for table in inspection.tables
        )
        convert_stco = force_co64
        while True:
            raw_moov_size = inspection.moov.size + (
                4 * stco_chunks if convert_stco else 0
            )
            free_size = (
                0
                if force_co64 and has_stco
                else _free_size(raw_moov_size, ftyp_end, self.alignment)
            )
            segment_size = raw_moov_size + free_size
            mapping = _make_mapping(ftyp_end, moov_start, moov_end, segment_size)
            new_chunks = tuple(mapping(offset) for offset in inspection.chunks)
            if not convert_stco:
                position = 0
                needs_co64 = False
                for table in inspection.tables:
                    end = position + table.count
                    if table.box_type == b"stco" and any(
                        offset > _U32_MAX for offset in new_chunks[position:end]
                    ):
                        needs_co64 = True
                        break
                    position = end
                if needs_co64:
                    convert_stco = True
                    continue
            break

        if free_size and len(inspection.boxes) + 1 > self.max_boxes:
            raise _error("FASTSTART_BOX_LIMIT", {"limit": self.max_boxes})

        context = _RewriteContext(mapping=mapping, convert_stco=convert_stco)
        moov_raw = self._blob[moov_start:moov_end]
        relocated_moov = _rewrite_box(moov_raw, context, inspection.mdat_ranges)
        if len(relocated_moov) != raw_moov_size:
            raise _error(
                "FASTSTART_BAD_BOX",
                {"reason": "moov size mismatch", "expected": raw_moov_size},
            )
        entries = tuple(
            OffsetEntry(index, old_offset, new_offset)
            for index, (old_offset, new_offset) in enumerate(
                zip(inspection.chunks, new_chunks, strict=True)
            )
        )
        co64 = (convert_stco and has_stco) or any(
            table.box_type == b"co64" for table in inspection.tables
        )
        plan = RelocationPlan(
            moved=True,
            delta=segment_size,
            moov_size=segment_size,
            chunk_count=len(inspection.chunks),
            co64=co64,
            new_size=len(self._blob) + (segment_size - inspection.moov.size),
        )
        computed = _Computed(
            plan=plan,
            force_co64=force_co64,
            entries=entries,
            mapping=mapping,
            convert_stco=convert_stco,
            raw_moov_size=raw_moov_size,
            free_size=free_size,
            relocated_moov=relocated_moov,
        )
        self._computed = computed
        return computed

    def _build_output(self, computed: _Computed) -> bytes:
        inspection = self._require_inspection()
        assert self._blob is not None
        if not computed.plan.moved:
            return self._blob
        ftyp_end = inspection.ftyp.offset + inspection.ftyp.size
        context = _RewriteContext(
            mapping=computed.mapping, convert_stco=computed.convert_stco
        )
        parts: list[bytes] = [self._blob[:ftyp_end]]
        assert computed.relocated_moov is not None
        parts.append(computed.relocated_moov)
        if computed.free_size:
            parts.append(_make_box(b"free", b"\x00" * (computed.free_size - 8)))
        for box in inspection.boxes:
            if box.offset < ftyp_end or box is inspection.moov:
                continue
            raw = self._blob[box.offset : box.offset + box.size]
            rewritten = _rewrite_box(raw, context, inspection.mdat_ranges)
            if len(rewritten) != len(raw):
                raise _error(
                    "FASTSTART_BAD_BOX",
                    {"reason": "top level box resized unexpectedly", "type": box.type},
                )
            parts.append(rewritten)
        output = b"".join(parts)
        if len(output) != computed.plan.new_size:
            raise _error(
                "FASTSTART_BAD_BOX",
                {"reason": "output size mismatch", "expected": computed.plan.new_size},
            )
        result = _inspect(output, self.max_boxes)
        if not _is_optimized(result):
            raise _error("FASTSTART_BAD_OFFSET", {"reason": "moov not before mdat"})
        expected_offsets = tuple(entry.new_offset for entry in computed.entries)
        if result.chunks != expected_offsets:
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"expected": expected_offsets, "actual": result.chunks},
            )
        actual_co64 = any(table.box_type == b"co64" for table in result.tables)
        if actual_co64 != computed.plan.co64:
            raise _error(
                "FASTSTART_BAD_OFFSET",
                {"reason": "offset width mismatch", "co64": computed.plan.co64},
            )
        return output

    def scan(self, blob: bytes) -> tuple[BoxInfo, ...]:
        with self._lock:
            data = _as_bytes(blob, "FASTSTART_BAD_BOX")
            inspection = _inspect(data, self.max_boxes)
            self._blob = data
            self._inspection = inspection
            self._computed = None
            self._applied = None
            self._applied_plan = None
            self._restored_force = None
            return inspection.boxes

    def boxes(self) -> tuple[BoxInfo, ...]:
        with self._lock:
            return self._inspection.boxes if self._inspection is not None else ()

    def plan(self, *, force_co64: bool = False) -> RelocationPlan:
        with self._lock:
            if force_co64 is False and self._restored_force is True:
                force_co64 = True
            return self._computed_for(force_co64).plan

    def offset_table(self) -> tuple[OffsetEntry, ...]:
        with self._lock:
            force = self._computed.force_co64 if self._computed is not None else False
            return self._computed_for(force).entries

    def apply(self) -> bytes:
        with self._lock:
            self._require_inspection()
            force = self._computed.force_co64 if self._computed is not None else False
            computed = self._computed_for(force)
            if self._applied is not None and self._applied_plan == computed.plan:
                return self._applied
            output = self._build_output(computed)
            self._applied = output
            self._applied_plan = computed.plan
            return output

    def verify(self, blob: bytes) -> dict:
        with self._lock:
            try:
                data = _as_bytes(blob, "FASTSTART_VERIFY_FAILED")
                result = _inspect(data, self.max_boxes)
                if not _is_optimized(result):
                    raise _error(
                        "FASTSTART_VERIFY_FAILED", {"reason": "moov after mdat"}
                    )
                actual_offsets = result.chunks
                if self._blob is not None and self._inspection is not None:
                    if len(actual_offsets) != len(self._inspection.chunks):
                        raise _error(
                            "FASTSTART_VERIFY_FAILED",
                            {
                                "reason": "chunk count mismatch",
                                "expected": len(self._inspection.chunks),
                                "actual": len(actual_offsets),
                            },
                        )
                    force = (
                        self._computed.force_co64
                        if self._computed is not None
                        else False
                    )
                    previous = self._computed
                    try:
                        expected = tuple(
                            entry.new_offset
                            for entry in self._computed_for(force).entries
                        )
                    finally:
                        self._computed = previous
                    if actual_offsets != expected:
                        raise _error(
                            "FASTSTART_VERIFY_FAILED",
                            {
                                "reason": "offset mismatch",
                                "expected": expected,
                                "actual": actual_offsets,
                            },
                        )
                width = (
                    64
                    if any(table.box_type == b"co64" for table in result.tables)
                    else 32
                )
                return {
                    "ok": True,
                    "moov_before_mdat": True,
                    "chunks": len(actual_offsets),
                    "offset_width": width,
                    "size": len(data),
                }
            except FaststartError as exc:
                if exc.code == "FASTSTART_VERIFY_FAILED":
                    raise
                raise _error(
                    "FASTSTART_VERIFY_FAILED",
                    {"cause": exc.code, "detail": exc.detail},
                ) from None
            except Exception as exc:
                raise _error(
                    "FASTSTART_VERIFY_FAILED",
                    {"cause": type(exc).__name__, "detail": str(exc)},
                ) from None

    def stats(self) -> dict:
        with self._lock:
            if self._inspection is None:
                return {"boxes": 0, "chunks": 0, "moov_bytes": 0, "optimized": False}
            return {
                "boxes": len(self._inspection.boxes),
                "chunks": len(self._inspection.chunks),
                "moov_bytes": self._inspection.moov.size,
                "optimized": _is_optimized(self._inspection),
            }

    def snapshot(self) -> dict:
        with self._lock:
            plan = None
            if self._computed is not None:
                planned = self._computed.plan
                plan = {
                    "moved": planned.moved,
                    "delta": planned.delta,
                    "moov_size": planned.moov_size,
                    "chunk_count": planned.chunk_count,
                    "co64": planned.co64,
                    "new_size": planned.new_size,
                }
            return {
                "version": 1,
                "blob": self._blob,
                "boxes": [
                    [box.type, box.offset, box.size]
                    for box in (
                        self._inspection.boxes if self._inspection is not None else ()
                    )
                ],
                "chunks": (
                    list(self._inspection.chunks)
                    if self._inspection is not None
                    else []
                ),
                "plan": plan,
                "limits": {
                    "max_boxes": self.max_boxes,
                    "alignment": self.alignment,
                },
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                version = state.get("version") if isinstance(state, Mapping) else None
                if (
                    not isinstance(version, int)
                    or isinstance(version, bool)
                    or version != 1
                ):
                    raise _error("FASTSTART_SNAPSHOT_INVALID", {"version": None})
                required = ("blob", "boxes", "chunks", "plan", "limits")
                if any(key not in state for key in required):
                    raise _error("FASTSTART_SNAPSHOT_INVALID", {"reason": "missing key"})
                limits = state["limits"]
                if not isinstance(limits, Mapping):
                    raise _error("FASTSTART_SNAPSHOT_INVALID", {"reason": "limits"})
                max_boxes = limits.get("max_boxes")
                alignment = limits.get("alignment")
                if (
                    not isinstance(max_boxes, int)
                    or isinstance(max_boxes, bool)
                    or max_boxes < 1
                    or not isinstance(alignment, int)
                    or isinstance(alignment, bool)
                    or alignment < 1
                ):
                    raise _error("FASTSTART_SNAPSHOT_INVALID", {"reason": "limits"})
                blob_state = state["blob"]
                boxes_state = state["boxes"]
                chunks_state = state["chunks"]
                plan_state = state["plan"]
                if not isinstance(boxes_state, (list, tuple)) or not isinstance(
                    chunks_state, (list, tuple)
                ):
                    raise _error(
                        "FASTSTART_SNAPSHOT_INVALID", {"reason": "boxes/chunks"}
                    )
                if not all(
                    isinstance(item, (list, tuple)) and len(item) == 3
                    for item in boxes_state
                ):
                    raise _error(
                        "FASTSTART_SNAPSHOT_INVALID", {"reason": "box shape"}
                    )
                if not all(
                    isinstance(item, int) and not isinstance(item, bool)
                    for item in chunks_state
                ):
                    raise _error(
                        "FASTSTART_SNAPSHOT_INVALID", {"reason": "chunk shape"}
                    )
                temporary = FaststartRelocator(
                    max_boxes=max_boxes, alignment=alignment
                )
                if blob_state is None:
                    if boxes_state or chunks_state or plan_state is not None:
                        raise _error(
                            "FASTSTART_SNAPSHOT_INVALID",
                            {"reason": "unscanned state is not empty"},
                        )
                else:
                    if not isinstance(blob_state, (bytes, bytearray, memoryview)):
                        raise _error(
                            "FASTSTART_SNAPSHOT_INVALID", {"reason": "blob"}
                        )
                    temporary.scan(bytes(blob_state))
                    assert temporary._inspection is not None
                    expected_boxes = [
                        [box.type, box.offset, box.size]
                        for box in temporary._inspection.boxes
                    ]
                    if [list(item) for item in boxes_state] != expected_boxes:
                        raise _error(
                            "FASTSTART_SNAPSHOT_INVALID", {"reason": "boxes"}
                        )
                    if list(chunks_state) != list(temporary._inspection.chunks):
                        raise _error(
                            "FASTSTART_SNAPSHOT_INVALID", {"reason": "chunks"}
                        )
                    if plan_state is not None:
                        if not isinstance(plan_state, Mapping):
                            raise _error(
                                "FASTSTART_SNAPSHOT_INVALID", {"reason": "plan"}
                            )
                        plan_keys = (
                            "moved",
                            "delta",
                            "moov_size",
                            "chunk_count",
                            "co64",
                            "new_size",
                        )
                        if any(key not in plan_state for key in plan_keys):
                            raise _error(
                                "FASTSTART_SNAPSHOT_INVALID",
                                {"reason": "plan keys"},
                            )
                        if not isinstance(plan_state["moved"], bool) or not isinstance(
                            plan_state["co64"], bool
                        ):
                            raise _error(
                                "FASTSTART_SNAPSHOT_INVALID",
                                {"reason": "plan types"},
                            )
                        if any(
                            not isinstance(plan_state[key], int)
                            or isinstance(plan_state[key], bool)
                            for key in (
                                "delta",
                                "moov_size",
                                "chunk_count",
                                "new_size",
                            )
                        ):
                            raise _error(
                                "FASTSTART_SNAPSHOT_INVALID",
                                {"reason": "plan types"},
                            )
                        matched_force: bool | None = None
                        for force in (False, True):
                            planned = temporary.plan(force_co64=force)
                            expected_plan = {
                                "moved": planned.moved,
                                "delta": planned.delta,
                                "moov_size": planned.moov_size,
                                "chunk_count": planned.chunk_count,
                                "co64": planned.co64,
                                "new_size": planned.new_size,
                            }
                            if all(
                                plan_state[key] == expected_plan[key]
                                for key in expected_plan
                            ):
                                matched_force = force
                                break
                        if matched_force is None:
                            raise _error(
                                "FASTSTART_SNAPSHOT_INVALID",
                                {"reason": "plan contents"},
                            )
                        temporary._restored_force = matched_force or None
            except FaststartError as exc:
                if exc.code == "FASTSTART_SNAPSHOT_INVALID":
                    raise
                raise _error(
                    "FASTSTART_SNAPSHOT_INVALID",
                    {"cause": exc.code, "detail": exc.detail},
                ) from None
            except Exception as exc:
                raise _error(
                    "FASTSTART_SNAPSHOT_INVALID",
                    {"cause": type(exc).__name__, "detail": str(exc)},
                ) from None
            else:
                self.max_boxes = temporary.max_boxes
                self.alignment = temporary.alignment
                self._blob = temporary._blob
                self._inspection = temporary._inspection
                self._computed = temporary._computed
                self._applied = None
                self._applied_plan = None
                self._restored_force = temporary._restored_force

    def reset(self) -> None:
        with self._lock:
            self._blob = None
            self._inspection = None
            self._computed = None
            self._applied = None
            self._applied_plan = None
            self._restored_force = None
