import copy

import pytest

import obu_temporal_parser as op


def leb128(value):
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def obu(obu_type, payload=b""):
    return bytes([obu_type << 4]) + leb128(len(payload)) + payload


def seq(profile=0, bit_depth=8, width=1920):
    return obu(1, bytes([profile, bit_depth, width >> 8, width & 0xFF]))


def delimiter():
    return obu(2)


def frame_header(frame_id, frame_type=0, ref=0xFFFF, show=1):
    return obu(3, bytes([frame_id >> 8, frame_id & 0xFF, frame_type,
                        ref >> 8, ref & 0xFF, show]))


def tile_group(frame_id, payload=b"\x7f"):
    return obu(4, bytes([frame_id >> 8, frame_id & 0xFF]) + payload)


def parser(**kwargs):
    return op.ObuTemporalParser(**kwargs)


def test_push_buffers_partial_object():
    p = parser()
    data = delimiter() + seq() + frame_header(1) + tile_group(1) + delimiter()
    assert p.push(data[:5]) == 5
    assert p.next_temporal_unit() is None
    assert p.buffered_bytes() == 5

    p.push(data[5:])
    unit = p.next_temporal_unit()
    assert (unit.index, unit.frames, unit.tiles) == (0, (1,), (1,))
    assert p.buffered_bytes() == 0


def test_buffer_limit_is_atomic():
    p = parser(max_buffer_bytes=8)
    assert p.push(delimiter()) == 2
    with pytest.raises(op.ObuError) as exc:
        p.push(b"\x00" * 9)
    assert exc.value.code == "OBU_BUFFER_LIMIT"
    assert p.buffered_bytes() == 2


def test_invalid_obu_type_clears_buffer():
    p = parser()
    p.push(bytes([0x00, 0x00]) + delimiter())
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_INVALID_TYPE"
    assert p.buffered_bytes() == 0
    assert p.stats()["rejected"] == 1

    p.push(seq() + frame_header(1) + tile_group(1) + delimiter())
    assert p.next_temporal_unit().frames == (1,)


def test_length_overflow_rejected():
    p = parser(max_buffer_bytes=64)
    p.push(bytes([0x50]) + leb128(4096) + b"\x00" * 4)
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_LENGTH_OVERFLOW"
    assert p.buffered_bytes() == 0
    assert p.stats()["rejected"] == 1


def test_temporal_delimiter_bounds_units():
    p = parser()
    p.push(delimiter() + seq() + frame_header(1) + tile_group(1) + delimiter()
           + frame_header(2, 1, 1) + tile_group(2) + delimiter())
    first = p.next_temporal_unit()
    second = p.next_temporal_unit()
    assert (first.index, first.frames, first.tiles) == (0, (1,), (1,))
    assert (second.index, second.frames, second.tiles) == (1, (2,), (2,))
    assert p.next_temporal_unit() is None
    assert p.stats()["units"] == 2


def test_flush_finalizes_open_unit():
    p = parser()
    p.push(seq() + frame_header(1) + tile_group(1))
    assert p.next_temporal_unit() is None
    assert p.flush() == 1
    unit = p.next_temporal_unit()
    assert (unit.index, unit.frames) == (0, (1,))
    assert p.flush() == 0


def test_sequence_header_required_before_first_frame():
    p = parser()
    p.push(frame_header(1) + tile_group(1) + delimiter())
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_SEQUENCE_MISSING"
    assert p.frame_header(1) is None


def test_sequence_header_fields():
    p = parser()
    p.push(seq(profile=2, bit_depth=10, width=3860) + delimiter())
    unit = p.next_temporal_unit()
    assert unit.frames == ()
    header = p.sequence_header()
    assert (header.profile, header.bit_depth, header.width) == (2, 10, 3860)


def test_frame_header_fields():
    p = parser()
    p.push(seq() + frame_header(7, 0, 0xFFFF, 1) + frame_header(8, 1, 7, 0)
           + tile_group(7) + tile_group(8) + delimiter())
    unit = p.next_temporal_unit()
    assert (unit.frames, unit.tiles) == ((7, 8), (7, 8))

    key = p.frame_header(7)
    assert (key.frame_id, key.frame_type, key.ref_frame_id, key.show_frame) == (
        7, "key", None, True)
    inter = p.frame_header(8)
    assert (inter.frame_id, inter.frame_type, inter.ref_frame_id,
            inter.show_frame) == (8, "inter", 7, False)
    assert p.frame_header(99) is None
    assert p.frame_count() == 2


def test_inter_frame_requires_known_reference():
    p = parser()
    p.push(seq() + frame_header(3, 1, 99) + tile_group(3) + delimiter())
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_UNKNOWN_FRAME"
    assert p.frame_header(3) is None
    assert p.frame_count() == 0


def test_tile_group_requires_frame_in_same_unit():
    p = parser()
    p.push(seq() + frame_header(1) + tile_group(1) + delimiter())
    assert p.next_temporal_unit().frames == (1,)

    p.push(tile_group(1) + delimiter())
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_ORDER"


def test_pending_frame_cap():
    p = parser(max_pending_frames=1)
    p.push(seq() + frame_header(1) + frame_header(2, 1, 1))
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_PENDING_LIMIT"
    assert p.pending_frames() == (1,)
    assert p.frame_count() == 1


def test_unknown_tile_group_frame():
    p = parser()
    p.push(seq() + tile_group(5) + delimiter())
    with pytest.raises(op.ObuError) as exc:
        p.next_temporal_unit()
    assert exc.value.code == "OBU_UNKNOWN_FRAME"
    assert p.stats()["tiles"] == 0


def test_snapshot_restore_round_trip():
    p = parser()
    p.push(seq() + frame_header(1) + frame_header(2, 1, 1))
    assert p.next_temporal_unit() is None
    assert p.pending_frames() == (1, 2)

    state = p.snapshot()
    pristine = copy.deepcopy(state)
    state["frames"].clear()
    assert p.frame_header(2) is not None

    clone = parser()
    clone.restore(pristine)
    assert clone.stats() == p.stats()
    assert clone.pending_frames() == (1, 2)
    assert clone.frame_header(2).ref_frame_id == 1
    assert clone.sequence_header().width == 1920

    clone.push(tile_group(1) + tile_group(2) + delimiter())
    unit = clone.next_temporal_unit()
    assert (unit.index, unit.frames, unit.tiles) == (0, (1, 2), (1, 2))

    fresh = parser()
    bad_states = [
        None,
        {},
        {"version": 9, "buffer": b"", "sequence": None, "frames": [],
         "pending": [], "stats": {}},
        {"version": 1, "buffer": "nope", "sequence": None, "frames": [],
         "pending": [], "stats": {}},
        {"version": 1, "buffer": b"", "sequence": {"profile": 0}, "frames": [],
         "pending": [], "stats": {}},
        {"version": 1, "buffer": b"", "sequence": None, "frames": [],
         "pending": [], "stats": {"units": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(op.ObuError) as exc:
            fresh.restore(bad)
        assert exc.value.code == "OBU_SNAPSHOT_INVALID"
    assert fresh.stats()["obu_seen"] == 0


def test_stats_and_reset():
    p = parser()
    p.push(delimiter() + seq() + frame_header(1) + tile_group(1)
           + obu(6, b"\x00\x00") + obu(5, b"\x01") + delimiter())
    unit = p.next_temporal_unit()
    assert unit.frames == (1,)

    stats = p.stats()
    assert (stats["units"], stats["frames"], stats["tiles"],
            stats["skipped"], stats["obu_seen"]) == (1, 1, 1, 2, 7)
    assert stats["bytes_in"] == len(delimiter() + seq() + frame_header(1)
                                    + tile_group(1) + obu(6, b"\x00\x00")
                                    + obu(5, b"\x01") + delimiter())

    p.reset()
    assert p.stats() == {"bytes_in": 0, "obu_seen": 0, "units": 0,
                         "frames": 0, "tiles": 0, "skipped": 0,
                         "rejected": 0}
    assert p.sequence_header() is None
    assert p.buffered_bytes() == 0
    assert p.pending_frames() == ()
