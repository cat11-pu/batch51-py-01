import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

import importance_sample_table as ist


def table(**kwargs):
    t = ist.ImportanceSampleTable(**kwargs)
    t.build([[1.0, 3.0], [5.0, 7.0]])
    return t


GRID = [(0.05 + 0.1 * i, 0.07 + 0.1 * j) for i in range(4) for j in range(4)]


def test_build_validates_shape_and_dimensions():
    t = ist.ImportanceSampleTable(max_dimension=4)
    for grid in ([], [[]], [[1.0, 2.0], [3.0]], [[1.0] * 5]):
        with pytest.raises(ist.TableError) as exc:
            t.build(grid)
        assert exc.value.code == "TABLE_INVALID_SHAPE"
    assert t.version() == 0


def test_build_validates_luminance_values():
    t = ist.ImportanceSampleTable()
    for grid in ([[1.0, -1.0]], [[1.0, float("nan")]],
                 [[1.0, float("inf")]], [["1.0", 2.0]]):
        with pytest.raises(ist.TableError) as exc:
            t.build(grid)
        assert exc.value.code == "TABLE_INVALID_LUMINANCE"
    with pytest.raises(ist.TableError) as exc:
        t.build([[0.0, 0.0], [0.0, 0.0]])
    assert exc.value.code == "TABLE_ZERO_LUMINANCE"


def test_pdf_reports_luminance_fraction():
    t = table()
    assert t.pdf(0, 0) == pytest.approx(1.0 / 16.0)
    assert t.pdf(1, 0) == pytest.approx(3.0 / 16.0)
    assert t.pdf(0, 1) == pytest.approx(5.0 / 16.0)
    assert t.pdf(1, 1) == pytest.approx(7.0 / 16.0)
    for coords in ((2, 0), (0, 2), (-1, 0)):
        with pytest.raises(ist.TableError) as exc:
            t.pdf(*coords)
        assert exc.value.code == "TABLE_OUT_OF_RANGE"

    fresh = ist.ImportanceSampleTable()
    with pytest.raises(ist.TableError) as exc:
        fresh.pdf(0, 0)
    assert exc.value.code == "TABLE_NOT_BUILT"


def test_row_distribution_matches_row_sums():
    t = table()
    assert t.row_distribution() == ((0, pytest.approx(0.25)),
                                    (1, pytest.approx(0.75)))
    wide = ist.ImportanceSampleTable()
    wide.build([[2.0, 2.0, 2.0, 2.0], [1.0, 1.0, 1.0, 1.0]])
    assert wide.row_distribution() == ((0, pytest.approx(2.0 / 3.0)),
                                       (1, pytest.approx(1.0 / 3.0)))


def test_sample_follows_the_cumulative_distribution():
    t = table()
    assert t.sample(0.0, 0.0) == (0, 0)
    assert t.sample(0.2, 0.9) == (1, 0)
    assert t.sample(0.25, 0.1) == (1, 0)
    assert t.sample(0.3, 0.9) == (1, 1)
    assert t.sample(1.0, 1.0) == (1, 1)


def test_sample_rejects_out_of_range_uv():
    t = table()
    for bad in ((-0.1, 0.5), (0.5, 1.5), (float("nan"), 0.5),
                (0.5, float("inf"))):
        with pytest.raises(ist.TableError) as exc:
            t.sample(*bad)
        assert exc.value.code == "TABLE_INVALID_UV"
    assert t.stats()["rejections"] == 4


def test_sampling_is_reproducible_across_rebuilds_and_restores():
    t = table()
    first = [t.sample(u, v) for u, v in GRID]
    t.rebuild()
    assert [t.sample(u, v) for u, v in GRID] == first

    clone = ist.ImportanceSampleTable()
    clone.restore(t.snapshot())
    assert [clone.sample(u, v) for u, v in GRID] == first
    assert clone.pdf(1, 1) == pytest.approx(7.0 / 16.0)


def test_alias_table_is_consistent_with_the_row():
    t = table()
    for row in (0, 1):
        entries = t.alias_table(row)
        assert len(entries) == 2
        assert all(0.0 <= entry.prob <= 1.0 for entry in entries)
        assert all(0 <= entry.alias < 2 for entry in entries)
        assert sum(entry.prob for entry in entries) == pytest.approx(2.0)

    with pytest.raises(ist.TableError) as exc:
        t.alias_table(2)
    assert exc.value.code == "TABLE_OUT_OF_RANGE"
    fresh = ist.ImportanceSampleTable()
    with pytest.raises(ist.TableError) as exc:
        fresh.alias_table(0)
    assert exc.value.code == "TABLE_NOT_BUILT"


def test_update_region_rebuilds_the_affected_row():
    t = table()
    assert t.version() == 1
    assert t.update_region(0, 0, 0, 0, [[7.0]]) == 2
    assert t.version() == 2
    assert t.pdf(0, 0) == pytest.approx(7.0 / 22.0)
    assert t.row_distribution() == ((0, pytest.approx(10.0 / 22.0)),
                                    (1, pytest.approx(12.0 / 22.0)))
    assert t.stats()["updates"] == 1
    assert t.stats()["row_rebuilds"] == 1


def test_update_region_validates_values_and_bounds():
    t = table()
    with pytest.raises(ist.TableError) as exc:
        t.update_region(0, 0, 0, 0, [[-1.0]])
    assert exc.value.code == "TABLE_INVALID_LUMINANCE"
    assert t.pdf(0, 0) == pytest.approx(1.0 / 16.0)
    assert t.version() == 1

    for args in ((0, 0, 1, 0, [[1.0]]), (1, 0, 0, 0, [[1.0]]),
                 (0, 0, 2, 0, [[1.0, 1.0, 1.0]]), (-1, 0, 0, 0, [[1.0]])):
        with pytest.raises(ist.TableError) as exc:
            t.update_region(*args)
        assert exc.value.code == "TABLE_INVALID_REGION"
    assert t.version() == 1
    assert t.stats()["rejections"] >= 4


def test_full_rebuild_bumps_version_and_keeps_probabilities():
    t = table()
    assert t.rebuild() == 2
    assert t.version() == 2
    assert t.stats()["builds"] == 1
    assert t.stats()["rebuilds"] == 1
    assert t.pdf(1, 1) == pytest.approx(7.0 / 16.0)
    assert t.sample(0.2, 0.9) == (1, 0)


def test_version_tracks_build_update_and_rebuild():
    fresh = ist.ImportanceSampleTable()
    assert fresh.version() == 0
    fresh.build([[2.0, 2.0]])
    assert fresh.version() == 1
    fresh.update_region(0, 0, 0, 0, [[3.0]])
    assert fresh.version() == 2
    fresh.rebuild()
    assert fresh.version() == 3
    assert fresh.stats()["version"] == 3


def test_region_updates_never_expose_a_partial_table():
    t = table()

    def updater():
        for value in (9.0, 7.0):
            t.update_region(1, 1, 1, 1, [[value]])

    def sampler():
        return [t.sample(0.37, 0.61) for _ in range(30)]

    with ThreadPoolExecutor(max_workers=4) as pool:
        changing = pool.submit(updater)
        futures = [pool.submit(sampler) for _ in range(3)]
        collected = [sample for future in futures for sample in future.result()]
        changing.result()

    assert len(collected) == 90
    assert all(0 <= x < 2 and 0 <= y < 2 for x, y in collected)
    assert t.pdf(1, 1) == pytest.approx(7.0 / 16.0)
    assert t.version() == 3
    assert t.stats()["updates"] == 2


def test_parallel_sampling_matches_a_serial_run():
    serial = table()
    expected = [serial.sample(u, v) for u, v in GRID]

    parallel = table()
    with ThreadPoolExecutor(max_workers=4) as pool:
        got = list(pool.map(lambda uv: parallel.sample(*uv), GRID))
    assert got == expected
    assert parallel.stats()["samples"] == len(GRID)


def test_snapshot_restore_roundtrip_and_malformed_state():
    t = table()
    first = [t.sample(u, v) for u, v in GRID]
    saved = t.snapshot()
    assert set(saved) == {"version", "luminance", "row_sums", "total",
                          "alias", "stats"}
    pristine = copy.deepcopy(saved)
    saved["stats"]["samples"] = 99
    saved["luminance"].clear()
    assert t.stats()["samples"] == len(GRID)
    assert t.pdf(1, 1) == pytest.approx(7.0 / 16.0)

    clone = ist.ImportanceSampleTable()
    clone.restore(pristine)
    assert clone.version() == 1
    assert clone.pdf(0, 1) == pytest.approx(5.0 / 16.0)
    assert [clone.sample(u, v) for u, v in GRID] == first

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(ist.TableError) as exc:
            t.restore(broken)
        assert exc.value.code == "TABLE_SNAPSHOT_INVALID"
    assert t.version() == 1
