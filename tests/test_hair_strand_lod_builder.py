import pytest

import hair_strand_lod_builder as hl

WRITE = hl.DEPTH_WRITE
TRANSPARENT = hl.DEPTH_TRANSPARENT
SHADOW = hl.DEPTH_SHADOW_WRITE


def builder(**kwargs):
    return hl.HairStrandLod(**kwargs)


def strand(strand_id, root, tip, segments, guide_id=None):
    return hl.Strand(strand_id=strand_id, root=root, tip=tip,
                     segments=segments, guide_id=guide_id)


def sample_build(b):
    return b.build_strands(
        "bob",
        guides=[strand(1, (0.0, 0.0, 0.0), (0.0, 0.0, 1.0), 8),
                strand(2, (1.0, 0.0, 0.0), (1.0, 0.0, 1.0), 8)],
        children=[strand(3, (0.1, 0.0, 0.0), (0.1, 0.0, 1.0), 6,
                         guide_id=1)],
    )


def test_build_strands_counts_and_bounds():
    b = builder()
    info = sample_build(b)
    assert info.bundle == "bob"
    assert info.guide_count == 2
    assert info.child_count == 1
    assert info.max_segments == 8
    assert info.bbox == ((0.0, 0.0, 0.0), (1.0, 0.0, 1.0))
    assert b.bundle_info("bob") == info
    assert b.strand("bob", 3).guide_id == 1
    assert b.stats()["bundles"] == 1
    assert b.stats()["strands"] == 3


def test_build_rejects_malformed_bundle():
    b = builder()
    with pytest.raises(hl.HairError) as exc:
        b.build_strands("bob", guides=[],
                        children=[strand(3, (0.0, 0.0, 0.0), (0.0, 0.0, 1.0), 4)])
    assert exc.value.code == "HAIR_INVALID_BUNDLE"
    with pytest.raises(hl.HairError) as exc2:
        b.build_strands(
            "bob",
            guides=[strand(1, (0.0, 0.0, 0.0), (0.0, 0.0, 1.0), 8)],
            children=[strand(3, (0.1, 0.0, 0.0), (0.1, 0.0, 1.0), 4,
                             guide_id=99)],
        )
    assert exc2.value.code == "HAIR_INVALID_BUNDLE"
    with pytest.raises(hl.HairError) as exc3:
        b.build_strands(
            "bob",
            guides=[strand(1, (0.0, 0.0, 0.0), (0.0, 0.0, 1.0), 8)],
            children=[strand(1, (0.1, 0.0, 0.0), (0.1, 0.0, 1.0), 4,
                             guide_id=1)],
        )
    assert exc3.value.code == "HAIR_INVALID_BUNDLE"


def test_select_lod_for_near_full_coverage():
    b = builder()
    sample_build(b)
    selection = b.select_lod("bob", camera="main", coverage=0.8, distance=5.0)
    assert selection.bundle == "bob"
    assert selection.camera == "main"
    assert selection.lod == 0
    assert selection.segments == 8
    assert selection.child_ratio == pytest.approx(1.0 / 3.0)


def test_select_lod_for_distant_sparse_bundle():
    b = builder()
    sample_build(b)
    selection = b.select_lod("bob", camera="main", coverage=0.02,
                             distance=120.0)
    assert selection.lod == 2


def test_select_lod_differs_per_camera():
    b = builder()
    sample_build(b)
    near = b.select_lod("bob", camera="closeup", coverage=0.9, distance=4.0)
    far = b.select_lod("bob", camera="wide", coverage=0.05, distance=4.0)
    assert near.lod == 0
    assert far.lod == 2
    assert near.camera != far.camera


def test_interpolate_at_full_lod_returns_original():
    b = builder()
    sample_build(b)
    original = b.strand("bob", 1)
    assert b.interpolate("bob", 1, lod=0) == original


def test_interpolate_at_mid_lod_keeps_endpoints():
    b = builder()
    sample_build(b)
    reduced = b.interpolate("bob", 1, lod=1)
    assert reduced.strand_id == 1
    assert reduced.segments == 4
    assert reduced.root == (0.0, 0.0, 0.0)
    assert reduced.tip == (0.0, 0.0, 1.0)
    assert b.strand("bob", 1).segments == 8
    assert b.stats()["interpolations"] == 1


def test_interpolate_unknown_strand_raises():
    b = builder()
    sample_build(b)
    with pytest.raises(hl.HairError) as exc:
        b.interpolate("bob", 42, lod=1)
    assert exc.value.code == "HAIR_UNKNOWN_STRAND"


def test_sort_strands_orders_by_camera_depth():
    b = builder()
    b.build_strands(
        "bob",
        guides=[strand(1, (0.0, 0.0, 5.0), (0.0, 0.0, 6.0), 8),
                strand(2, (0.0, 0.0, 1.0), (0.0, 0.0, 2.0), 8)],
        children=[strand(3, (0.0, 0.0, 3.0), (0.0, 0.0, 4.0), 6,
                         guide_id=1)],
    )
    order = b.sort_strands("bob", camera="main",
                           camera_position=(0.0, 0.0, 0.0))
    assert order == [2, 3, 1]
    assert b.stats()["sorts"] == 1


def test_sort_strands_breaks_depth_ties_by_id():
    b = builder()
    b.build_strands(
        "ties",
        guides=[strand(9, (0.0, 0.0, 2.0), (0.0, 0.0, 3.0), 4),
                strand(4, (0.0, 0.0, 2.0), (0.0, 0.0, 3.0), 4)],
        children=[],
    )
    order = b.sort_strands("ties", camera="main",
                           camera_position=(0.0, 0.0, 0.0))
    assert order == [4, 9]
    again = b.sort_strands("ties", camera="main",
                           camera_position=(0.0, 0.0, 0.0))
    assert again == order


def test_depth_policy_shadow_pass_writes_depth():
    b = builder()
    sample_build(b)
    assert b.depth_policy("bob", lod=2, shadow_pass=True) == SHADOW
    assert b.depth_policy("bob", lod=0, shadow_pass=True) == SHADOW


def test_depth_policy_skips_depth_for_transparent_lods():
    b = builder()
    sample_build(b)
    assert b.depth_policy("bob", lod=0) == WRITE
    assert b.depth_policy("bob", lod=2) == TRANSPARENT


def test_snapshot_restore_round_trip():
    b = builder()
    info = sample_build(b)
    b.select_lod("bob", camera="main", coverage=0.8, distance=5.0)
    snap = b.snapshot()
    b.build_strands("extra", guides=[strand(7, (0.0, 0.0, 0.0),
                                           (0.0, 0.0, 1.0), 4)],
                    children=[])
    other = builder()
    other.restore(snap)
    assert other.bundle_info("bob") == info
    assert other.strand("bob", 1) == b.strand("bob", 1)
    assert other.sort_strands("bob", camera="main",
                              camera_position=(0.0, 0.0, 0.0)) == [2, 3, 1]
    with pytest.raises(hl.HairError) as exc:
        other.bundle_info("extra")
    assert exc.value.code == "HAIR_UNKNOWN_BUNDLE"


def test_restore_rejects_unknown_snapshot():
    b = builder()
    sample_build(b)
    with pytest.raises(hl.HairError) as exc:
        b.restore({"version": 999, "bundles": {}})
    assert exc.value.code == "HAIR_SNAPSHOT_INVALID"
    assert b.bundle_info("bob").guide_count == 2


def test_stats_reports_all_counters():
    b = builder()
    sample_build(b)
    b.select_lod("bob", camera="main", coverage=0.8, distance=5.0)
    b.interpolate("bob", 1, lod=1)
    b.sort_strands("bob", camera="main", camera_position=(0.0, 0.0, 0.0))
    assert b.stats() == {"bundles": 1, "strands": 3, "builds": 1,
                         "lod_selections": 1, "interpolations": 1,
                         "sorts": 1}
