import struct

import pytest

import faststart_relocator as fr


def box(btype, payload):
    return struct.pack(">I", 8 + len(payload)) + btype + payload


def stco_box(offsets):
    return box(b"stco", struct.pack(">I", len(offsets))
               + b"".join(struct.pack(">I", offset) for offset in offsets))


def make_file(*, offsets=None, extra=b""):
    ftyp = box(b"ftyp", b"isom\x00\x00\x02\x00")
    mdat = box(b"mdat", b"AAAABBBBCCCC")
    if offsets is None:
        base = len(ftyp) + 8
        offsets = [base, base + 4, base + 8]
    stbl = box(b"stbl", stco_box(offsets))
    minf = box(b"minf", stbl)
    mdia = box(b"mdia", minf)
    trak = box(b"trak", mdia)
    moov = box(b"moov", trak)
    return ftyp + mdat + extra + moov, list(offsets), len(moov)


def top_level(blob):
    out = []
    off = 0
    while off + 8 <= len(blob):
        size = struct.unpack(">I", blob[off:off + 4])[0]
        assert size >= 8
        out.append(blob[off + 4:off + 8].decode("latin-1"))
        off += size
    assert off == len(blob)
    return out


def read_offsets(blob):
    for marker, width in ((b"co64", 8), (b"stco", 4)):
        idx = blob.find(marker)
        if idx != -1:
            count = struct.unpack(">I", blob[idx + 4:idx + 8])[0]
            start = idx + 8
            fmt = ">Q" if width == 8 else ">I"
            return marker.decode("latin-1"), [
                struct.unpack(fmt, blob[start + i * width:start + (i + 1) * width])[0]
                for i in range(count)
            ]
    raise AssertionError("no chunk table found")


def test_scan_lists_top_level_boxes():
    blob, offsets, moov_size = make_file()
    r = fr.FaststartRelocator()
    boxes = r.scan(blob)
    assert [(b.type, b.offset, b.size) for b in boxes] == [
        ("ftyp", 0, 16), ("mdat", 16, 20), ("moov", 36, moov_size)]
    assert [b.type for b in r.boxes()] == ["ftyp", "mdat", "moov"]


def test_scan_requires_ftyp_moov_mdat():
    ftyp = box(b"ftyp", b"isom\x00\x00\x02\x00")
    mdat = box(b"mdat", b"AAAA")
    r = fr.FaststartRelocator()
    for blob in (ftyp + mdat, ftyp):
        with pytest.raises(fr.FaststartError) as exc:
            r.scan(blob)
        assert exc.value.code == "FASTSTART_MISSING_BOX"


def test_scan_rejects_broken_box_length():
    ftyp = box(b"ftyp", b"isom")
    r = fr.FaststartRelocator()
    for tail in (b"\x00\x00\x00\x06mdat", b"\x00\x00\x00\x40mdat"):
        with pytest.raises(fr.FaststartError) as exc:
            r.scan(ftyp + tail)
        assert exc.value.code == "FASTSTART_BAD_BOX"


def test_scan_rejects_chunk_offset_outside_mdat():
    blob, _, _ = make_file(offsets=[24, 500])
    r = fr.FaststartRelocator()
    with pytest.raises(fr.FaststartError) as exc:
        r.scan(blob)
    assert exc.value.code == "FASTSTART_BAD_OFFSET"


def test_plan_reports_move_delta():
    blob, offsets, moov_size = make_file()
    assert moov_size == 64
    r = fr.FaststartRelocator()
    r.scan(blob)
    plan = r.plan()
    assert plan.moved is True
    assert plan.delta == 64
    assert plan.moov_size == 64
    assert plan.chunk_count == 3
    assert plan.co64 is False
    assert plan.new_size == len(blob) == 100


def test_plan_is_read_only():
    blob, _, _ = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    first = r.plan()
    second = r.plan()
    assert first == second
    assert [b.type for b in r.boxes()] == ["ftyp", "mdat", "moov"]


def test_apply_puts_moov_before_mdat():
    blob, _, _ = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    new = r.apply()
    assert len(new) == len(blob)
    assert top_level(new) == ["ftyp", "moov", "mdat"]


def test_offset_table_patches_every_chunk():
    blob, offsets, moov_size = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    r.plan()
    table = r.offset_table()
    assert [(e.index, e.old_offset, e.new_offset) for e in table] == [
        (0, 24, 24 + 64), (1, 28, 28 + 64), (2, 32, 32 + 64)]
    new = r.apply()
    marker, patched = read_offsets(new)
    assert marker == "stco"
    assert patched == [24 + 64, 28 + 64, 32 + 64]


def test_verify_checks_position_and_sample_offsets():
    blob, _, _ = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    with pytest.raises(fr.FaststartError) as exc:
        r.verify(blob)
    assert exc.value.code == "FASTSTART_VERIFY_FAILED"
    new = r.apply()
    assert r.verify(new) == {"ok": True, "moov_before_mdat": True,
                             "chunks": 3, "offset_width": 32, "size": 100}


def test_unknown_boxes_are_preserved():
    extra = box(b"uuid", b"unique-payload")
    blob, _, _ = make_file(extra=extra)
    r = fr.FaststartRelocator()
    r.scan(blob)
    new = r.apply()
    assert top_level(new) == ["ftyp", "moov", "mdat", "uuid"]
    assert extra in new


def test_apply_is_idempotent():
    blob, _, _ = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    first = r.apply()
    second = r.apply()
    assert first == second
    assert top_level(first).count("moov") == 1
    assert len(first) == 100


def test_force_co64_switches_table_width():
    blob, _, moov_size = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    plan = r.plan(force_co64=True)
    assert plan.co64 is True
    assert plan.delta == moov_size + 12
    new = r.apply()
    assert b"co64" in new
    assert b"stco" not in new
    marker, patched = read_offsets(new)
    assert marker == "co64"
    assert patched == [e.new_offset for e in r.offset_table()]
    assert patched[0] == 24 + plan.delta
    info = r.verify(new)
    assert info["offset_width"] == 64
    assert info["size"] == len(new) == 112


def test_plan_and_apply_require_scan():
    r = fr.FaststartRelocator()
    for call in (r.plan, r.offset_table, r.apply):
        with pytest.raises(fr.FaststartError) as exc:
            call()
        assert exc.value.code == "FASTSTART_STATE"
    blob, _, _ = make_file()
    r.scan(blob)
    r.plan()
    r.reset()
    with pytest.raises(fr.FaststartError) as exc:
        r.plan()
    assert exc.value.code == "FASTSTART_STATE"


def test_snapshot_is_deep_copy_and_restore_continues():
    blob, _, _ = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    plan = r.plan()
    snap = r.snapshot()
    assert snap["version"] == 1
    assert snap["boxes"][0] == ["ftyp", 0, 16]
    assert snap["chunks"] == [24, 28, 32]
    snap["chunks"].append(999)
    assert r.snapshot()["chunks"] == [24, 28, 32]
    q = fr.FaststartRelocator()
    q.restore(r.snapshot())
    assert q.plan() == plan
    assert q.apply() == r.apply()
    before = q.snapshot()
    with pytest.raises(fr.FaststartError) as exc:
        q.restore({"version": 2})
    assert exc.value.code == "FASTSTART_SNAPSHOT_INVALID"
    assert q.snapshot() == before


def test_stats_and_box_limit():
    blob, _, moov_size = make_file()
    r = fr.FaststartRelocator()
    r.scan(blob)
    assert r.stats() == {"boxes": 3, "chunks": 3,
                         "moov_bytes": moov_size, "optimized": False}
    small = fr.FaststartRelocator(max_boxes=2)
    with pytest.raises(fr.FaststartError) as exc:
        small.scan(blob)
    assert exc.value.code == "FASTSTART_BOX_LIMIT"
