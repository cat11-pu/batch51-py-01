import copy

import pytest

import cubemap_seam_mip_builder as cb


def make_faces(size=4, offset=0):
    return {
        name: [[(index * 17 + y * size + x + offset) % 256 for x in range(size)]
               for y in range(size)]
        for index, name in enumerate(cb.FACE_NAMES)
    }


def builder(**kwargs):
    return cb.CubemapSeamMipBuilder(**kwargs)


def loaded(size=4):
    instance = builder()
    instance.load_faces(make_faces(size))
    return instance


def code_of(call):
    with pytest.raises(cb.CubemapError) as exc:
        call()
    return exc.value.code


def test_load_faces_requires_all_six_names():
    data = make_faces()
    missing = dict(data)
    del missing["-y"]
    assert code_of(lambda: builder().load_faces(missing)) == \
        "CUBEMAP_FACE_MISSING"

    extra = dict(data)
    extra["w"] = data["+x"]
    assert code_of(lambda: builder().load_faces(extra)) == \
        "CUBEMAP_FACE_UNKNOWN"


def test_load_faces_rejects_non_square_and_mismatched_sizes():
    ragged = make_faces()
    ragged["+x"][1] = ragged["+x"][1][:3]
    assert code_of(lambda: builder().load_faces(ragged)) == \
        "CUBEMAP_INVALID_SHAPE"

    wide = make_faces()
    wide["+z"] = [[1, 2, 3, 4] for _ in range(2)]
    assert code_of(lambda: builder().load_faces(wide)) == \
        "CUBEMAP_INVALID_SHAPE"


def test_load_faces_rejects_bad_size_and_bad_texels():
    odd = make_faces(3)
    assert code_of(lambda: builder().load_faces(odd)) == \
        "CUBEMAP_SIZE_NOT_POWER_OF_TWO"

    assert code_of(lambda: builder(max_size=2).load_faces(make_faces(4))) == \
        "CUBEMAP_SIZE_TOO_LARGE"

    for bad in (300, -1, 1.5, "7"):
        broken = make_faces()
        broken["+x"][0][0] = bad
        assert code_of(lambda: builder().load_faces(broken)) == \
            "CUBEMAP_INVALID_TEXEL"


def test_load_returns_size_and_stays_unready_until_built():
    instance = builder()
    assert instance.validate()["ready"] is False
    assert instance.load_faces(make_faces()) == 4
    assert instance.stats()["faces"] == 6
    assert instance.validate()["ready"] is False
    assert instance.validate()["issues"] != ()


def test_build_requires_loaded_faces():
    assert code_of(lambda: builder().build_mips()) == "CUBEMAP_NO_FACES"


def test_mip_chain_sizes_follow_the_face_size():
    instance = loaded()
    assert instance.build_mips() == (4, 2, 1)
    assert instance.mip_count() == 3
    assert instance.level_size(0) == 4
    assert instance.level_size(2) == 1
    assert instance.stats()["levels"] == 3
    assert instance.validate()["ready"] is True
    assert instance.validate()["issues"] == ()
    assert code_of(lambda: instance.level_size(3)) == "CUBEMAP_NO_SUCH_LEVEL"
    assert code_of(lambda: instance.level_size(-1)) == "CUBEMAP_NO_SUCH_LEVEL"


def test_mip_level_averages_each_two_by_two_block():
    instance = loaded()
    instance.build_mips()
    assert instance.face("+x", 1) == ((2, 4), (10, 12))
    assert instance.texel("+x", 1, 0, 0) == 2
    assert instance.texel("+x", 1, 1, 0) == 4
    assert instance.texel("+x", 1, 0, 1) == 10
    assert instance.texel("+x", 1, 1, 1) == 12


def test_every_face_gets_the_same_level_shapes():
    instance = loaded()
    instance.build_mips()
    for name in cb.FACE_NAMES:
        level_one = instance.face(name, 1)
        assert len(level_one) == 2
        assert [len(row) for row in level_one] == [2, 2]
        level_two = instance.face(name, 2)
        assert len(level_two) == 1
        assert len(level_two[0]) == 1


def test_build_is_identical_regardless_of_load_order():
    data = make_faces()
    first = builder()
    first.load_faces(data)
    first.build_mips()

    second = builder()
    second.load_faces({name: data[name] for name in reversed(cb.FACE_NAMES)})
    second.build_mips()

    for name in cb.FACE_NAMES:
        for level in range(3):
            assert first.face(name, level) == second.face(name, level)


def test_face_access_returns_the_uploaded_rows():
    data = make_faces()
    instance = builder()
    instance.load_faces(data)
    assert instance.face("+x", 0) == tuple(tuple(row) for row in data["+x"])
    assert instance.face("+x", 0)[0] == (0, 1, 2, 3)


def test_texel_rejects_coordinates_outside_the_level():
    instance = loaded()
    instance.build_mips()
    for x, y in ((4, 0), (0, 4), (-1, 0), (0, -1)):
        assert code_of(lambda: instance.texel("+x", 0, x, y)) == \
            "CUBEMAP_OUT_OF_RANGE"
    assert code_of(lambda: instance.texel("+x", 2, 1, 0)) == \
        "CUBEMAP_OUT_OF_RANGE"
    assert instance.texel("+x", 2, 0, 0) in range(256)


def test_sample_at_a_texel_center_returns_that_texel():
    instance = loaded()
    instance.build_mips()
    assert instance.sample("+x", 0, 0.625, 0.375) == 6.0
    assert instance.sample("+x", 0, 0.125, 0.125) == 0.0
    assert instance.sample("+x", 1, 0.75, 0.75) == 12.0


def test_sample_between_texels_blends_them_linearly():
    instance = loaded()
    instance.build_mips()
    assert instance.sample("+x", 0, 0.25, 0.25) == pytest.approx(2.5)
    assert instance.sample("+x", 0, 0.75, 0.25) == pytest.approx(4.5)
    assert instance.stats()["samples"] == 2


def test_edge_texels_follow_face_edges():
    instance = loaded()
    instance.build_mips()
    assert instance.edge_texels("+x", "top") == (0, 1, 2, 3)
    assert instance.edge_texels("+x", "bottom") == (12, 13, 14, 15)
    assert instance.edge_texels("+x", "left") == (0, 4, 8, 12)
    assert instance.edge_texels("+x", "right") == (3, 7, 11, 15)
    assert instance.edge_texels("+x", "top", 1) == (2, 4)
    assert code_of(lambda: instance.edge_texels("+x", "middle")) == \
        "CUBEMAP_INVALID_EDGE"


def test_snapshot_restore_roundtrip_and_malformed_state():
    instance = loaded()
    instance.build_mips()
    state = instance.snapshot()
    assert set(state) == {"version", "size", "faces", "mips", "stats"}
    pristine = copy.deepcopy(state)
    state["mips"].clear()
    state["stats"]["builds"] = 99
    assert instance.stats()["builds"] == 1
    assert instance.face("+x", 1) == ((2, 4), (10, 12))

    clone = builder()
    clone.restore(pristine)
    assert clone.stats()["builds"] == 1
    assert clone.face("+x", 1) == ((2, 4), (10, 12))
    assert clone.texel("+x", 0, 0, 0) == 0

    for broken in (None, {}, {"version": 1}):
        assert code_of(lambda: instance.restore(broken)) == \
            "CUBEMAP_SNAPSHOT_INVALID"
    assert instance.stats()["builds"] == 1
