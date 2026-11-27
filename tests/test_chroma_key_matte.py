import threading

import pytest

import chroma_key_matte as ck

KEY = (0, 255, 0)
GRAY = (128, 128, 128)


def machine(**kwargs):
    width = kwargs.pop("width", 3)
    height = kwargs.pop("height", 3)
    return ck.ChromaKeyMatte(width=width, height=height, **kwargs)


def solid(width, height, pixel):
    return [[pixel for _ in range(width)] for _ in range(height)]


def test_set_key_color_accepts_only_byte_triples():
    m = machine(width=2, height=2)
    assert m.set_key_color((0, 0, 255)) == (0, 0, 255)
    for bad in [(0, 256, 0), (0, -1, 0), (0, 255), ("0", 255, 0)]:
        with pytest.raises(ck.ChromaKeyError) as exc:
            m.set_key_color(bad)
        assert exc.value.code == "CHROMA_KEY_INVALID_COLOR"


def test_matte_reports_exact_coverage():
    m = machine(width=5, height=1)
    frame = [[KEY, (0, 195, 0), (0, 175, 0), (0, 155, 0), GRAY]]
    alpha = m.matte(frame)
    assert len(alpha) == 1
    assert alpha[0] == pytest.approx([0.0, 0.0, 0.5, 1.0, 1.0], abs=1e-9)


def test_matte_is_monotonic_and_bounded():
    m = machine(width=7, height=1)
    row = [KEY, (0, 235, 0), (0, 215, 0), (0, 195, 0),
           (0, 175, 0), (0, 155, 0), GRAY]
    alpha = m.matte([row])
    assert alpha[0] == pytest.approx([0.0, 0.0, 0.0, 0.0, 0.5, 1.0, 1.0], abs=1e-9)
    assert alpha[0] == sorted(alpha[0])
    assert all(0.0 <= value <= 1.0 for value in alpha[0])


def test_zero_softness_becomes_a_hard_matte():
    m = machine(width=3, height=1)
    m.set_thresholds(similarity=60, softness=0)
    alpha = m.matte([[(0, 196, 0), (0, 195, 0), (0, 194, 0)]])
    assert alpha == [[0.0, 0.0, 1.0]]


def test_feather_radius_is_validated():
    m = machine(width=2, height=2)
    alpha = solid(2, 2, 1.0)
    for bad in (-1, 65, "1"):
        with pytest.raises(ck.ChromaKeyError) as exc:
            m.feather(alpha, bad)
        assert exc.value.code == "CHROMA_KEY_INVALID_RADIUS"
    zero = m.feather(alpha, 0)
    assert zero == alpha
    assert zero is not alpha


def test_feather_averages_the_clipped_window():
    m = machine(width=3, height=3)
    alpha = [[1.0, 1.0, 1.0], [1.0, 0.0, 1.0], [1.0, 1.0, 1.0]]
    out = m.feather(alpha)
    corner = 3.0 / 4.0
    edge = 5.0 / 6.0
    centre = 8.0 / 9.0
    assert out == pytest.approx(
        [[corner, edge, corner], [edge, centre, edge], [corner, edge, corner]],
        abs=1e-9,
    )


def test_feather_does_not_punch_holes_in_opaque_area():
    m = machine(width=4, height=4)
    out = m.feather(solid(4, 4, 1.0), 2)
    assert out == solid(4, 4, 1.0)


def test_despill_keeps_neutral_pixels_and_clears_key_channel():
    m = machine(width=3, height=1)
    frame = [[(100, 100, 100), (80, 80, 80), KEY]]
    out = m.despill(frame)
    assert out[0][0] == (100, 100, 100)
    assert out[0][1] == (80, 80, 80)
    assert out[0][2] == (0, 0, 0)
    assert len(out) == 1 and len(out[0]) == 3


def test_temporal_stabilize_blends_with_history():
    m = machine(width=2, height=2)
    first = m.temporal_stabilize(solid(2, 2, 1.0))
    assert first == solid(2, 2, 1.0)
    second = m.temporal_stabilize(solid(2, 2, 0.0))
    assert second == solid(2, 2, 0.5)
    assert len(m.history()) == 2


def test_history_keeps_only_the_latest_frames():
    m = machine(width=1, height=1, history_limit=3)
    last = None
    for i in range(5):
        last = m.matte([[(0, 255 - i * 10, 0)]])
        assert len(m.history()) <= 3
    assert len(m.history()) == 3
    assert m.history()[-1] == last


def test_stats_count_pixel_classes():
    m = machine(width=3, height=3)
    frame = [[KEY, (0, 175, 0), GRAY],
             [GRAY, GRAY, GRAY],
             [GRAY, GRAY, GRAY]]
    m.matte(frame)
    assert m.stats() == {"frames": 1, "keyed": 1, "partial": 1, "opaque": 7,
                         "spill": 0, "stabilized": 0}


def test_snapshot_is_deep_copy_and_restore_resumes():
    m = machine(width=2, height=2)
    frame = solid(2, 2, GRAY)
    m.matte(frame)
    snap = m.snapshot()
    assert snap["version"] == 1
    assert snap["key_color"] == [0, 255, 0]
    assert len(snap["history"]) == 1
    snap["history"].append(solid(2, 2, 0.25))
    assert len(m.history()) == 1
    q = machine(width=2, height=2)
    q.restore(m.snapshot())
    assert q.history() == m.history()
    assert q.stats() == m.stats()
    assert q.matte(frame) == m.matte(frame)


def test_restore_rejects_bad_state_without_change():
    m = machine(width=2, height=2)
    m.matte(solid(2, 2, GRAY))
    before = m.snapshot()
    for bad in ({"version": 2}, {"version": 1, "width": "x"}, None):
        with pytest.raises(ck.ChromaKeyError) as exc:
            m.restore(bad)
        assert exc.value.code == "CHROMA_KEY_SNAPSHOT_INVALID"
    assert m.snapshot() == before


def test_reset_clears_history_and_counters():
    m = machine(width=2, height=2)
    m.matte(solid(2, 2, GRAY))
    m.matte(solid(2, 2, KEY))
    m.reset()
    assert m.history() == ()
    assert m.stats() == {"frames": 0, "keyed": 0, "partial": 0, "opaque": 0,
                         "spill": 0, "stabilized": 0}
    assert m.snapshot()["key_color"] == [0, 255, 0]


def test_parallel_matte_calls_return_the_same_field():
    m = machine(width=3, height=3)
    frame = solid(3, 3, GRAY)
    results = []

    def worker():
        results.append(m.matte(frame))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 2
    assert results[0] == results[1]
    assert m.stats()["frames"] == 2
