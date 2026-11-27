import threading

import pytest

import restir_reservoir_guard as rg

FRAME = 7
NORMAL = (0.0, 0.0, 1.0)


def guard(**kwargs):
    return rg.ReservoirGuard(**kwargs)


def update(g, sample_id, weight=1.0, *, pixel=(0, 0), depth=10.0, frame=FRAME):
    return g.update_sample(pixel, sample_id=sample_id, target_weight=weight,
                           depth=depth, normal=NORMAL, frame=frame)


def history(**overrides):
    values = dict(pixel=(0, 0), sample_id="old", weight_sum=3.0, sample_count=3,
                  depth=10.0, normal=NORMAL, frame=FRAME, history_frame=-1,
                  history_valid=False)
    values.update(overrides)
    return rg.ReservoirState(**values)


def test_first_sample_records_state_and_counters():
    g = guard()
    state = update(g, "s-1", 2.5, pixel=(3, 4), depth=12.5)
    assert state.pixel == (3, 4)
    assert state.sample_id == "s-1"
    assert state.weight_sum == pytest.approx(2.5)
    assert state.sample_count == 1
    assert state.depth == pytest.approx(12.5)
    assert state.normal == NORMAL
    assert state.frame == FRAME
    assert state.history_frame == -1
    assert state.history_valid is False
    assert g.stats() == {"pixels": 1, "updates": 1, "merged_history": 0,
                         "rejected_history": 0, "merged_neighbors": 0,
                         "resets": 0}


def test_weight_sum_accumulates_below_cap():
    g = guard()
    for index, weight in enumerate((1.0, 2.0, 3.0, 4.0)):
        update(g, "s-%d" % index, weight)
    state = g.pixel_state((0, 0))
    assert state.sample_count == 4
    assert state.weight_sum == pytest.approx(10.0)
    assert g.stats()["updates"] == 4


def test_resolve_reports_mean_weight():
    g = guard()
    for index, weight in enumerate((1.0, 2.0, 3.0, 4.0)):
        update(g, "s-%d" % index, weight)
    out = g.resolve((0, 0))
    assert out.pixel == (0, 0)
    assert out.sample_count == 4
    assert out.weight == pytest.approx(2.5)
    assert out.history_frame == -1
    assert out.history_valid is False


def test_unknown_pixel_returns_none_and_resolve_raises():
    g = guard()
    assert g.pixel_state((9, 9)) is None
    with pytest.raises(rg.ReservoirError) as exc:
        g.resolve((9, 9))
    assert exc.value.code == "RESERVOIR_UNKNOWN_PIXEL"


def test_sample_count_is_capped():
    g = guard(max_samples=8)
    for index in range(40):
        update(g, "s-%d" % index, 1.0)
    state = g.pixel_state((0, 0))
    assert state.sample_count == 8
    assert g.stats()["updates"] == 40


def test_config_rejects_non_positive_cap():
    with pytest.raises(rg.ReservoirError) as exc:
        rg.ReservoirGuard(max_samples=0)
    assert exc.value.code == "RESERVOIR_INVALID_CONFIG"


def test_update_rejects_blank_sample_id_and_bad_weight():
    g = guard()
    with pytest.raises(rg.ReservoirError) as exc:
        update(g, "   ")
    assert exc.value.code == "RESERVOIR_INVALID_SAMPLE"
    with pytest.raises(rg.ReservoirError) as exc2:
        update(g, "s-1", 0.0)
    assert exc2.value.code == "RESERVOIR_INVALID_SAMPLE"


def test_validate_history_accepts_matching_geometry():
    g = guard()
    update(g, "cur", 1.0, depth=10.0)
    assert g.validate_history((0, 0), depth=10.03, normal=(0.0, 0.0, 1.0),
                              frame=FRAME) is True


def test_validate_history_rejects_depth_and_normal_mismatch():
    g = guard()
    update(g, "cur", 1.0, depth=10.0)
    assert g.validate_history((0, 0), depth=10.5, normal=NORMAL,
                              frame=FRAME) is False
    assert g.validate_history((0, 0), depth=10.0, normal=(1.0, 0.0, 0.0),
                              frame=FRAME) is False


def test_merge_history_records_frame_when_within_threshold():
    g = guard()
    update(g, "cur", 1.0, depth=10.0)
    state = g.merge_history((0, 0), history(depth=10.02, sample_count=3,
                                            weight_sum=3.0))
    assert state.history_valid is True
    assert state.history_frame == FRAME
    assert state.sample_count == 4
    assert g.stats()["merged_history"] == 1
    assert g.stats()["rejected_history"] == 0


def test_merge_history_rejects_out_of_threshold_history():
    g = guard()
    update(g, "cur", 1.0, depth=10.0)
    state = g.merge_history((0, 0), history(depth=10.4))
    assert state.history_valid is False
    assert state.sample_count == 1
    assert state.history_frame == -1
    assert g.stats()["rejected_history"] == 1
    assert g.stats()["merged_history"] == 0


def test_merge_neighbors_keeps_pixel_and_cap():
    g = guard(max_samples=4)
    update(g, "cur", 1.0)
    near = history(sample_id="n1", pixel=(1, 1), sample_count=2)
    far = history(sample_id="n2", pixel=(0, 1), sample_count=3)
    state = g.merge_neighbors((0, 0), [near, far])
    assert state.pixel == (0, 0)
    assert state.sample_count == 4
    assert g.stats()["merged_neighbors"] == 2
    untouched = g.merge_neighbors((0, 0), [])
    assert untouched.sample_count == 4


def test_reset_clears_single_pixel_then_all():
    g = guard()
    update(g, "a", pixel=(0, 0))
    update(g, "b", pixel=(1, 1))
    g.reset((0, 0))
    assert g.pixel_state((0, 0)) is None
    assert g.pixel_state((1, 1)) is not None
    g.reset()
    assert g.pixel_state((1, 1)) is None
    assert g.stats()["pixels"] == 0
    assert g.stats()["resets"] == 2


def test_snapshot_restore_round_trip_is_isolated():
    g = guard(max_samples=8)
    for index in range(3):
        update(g, "s-%d" % index, 1.0)
    snap = g.snapshot()
    for index in range(5):
        update(g, "t-%d" % index, 2.0)
    other = guard(max_samples=8)
    other.restore(snap)
    restored = other.resolve((0, 0))
    assert restored.sample_count == 3
    assert restored.weight == pytest.approx(1.0)
    assert g.resolve((0, 0)).weight == pytest.approx(13.0 / 8.0)
    with pytest.raises(rg.ReservoirError) as exc:
        other.restore({"version": 999, "pixels": []})
    assert exc.value.code == "RESERVOIR_SNAPSHOT_INVALID"
    assert other.resolve((0, 0)).sample_count == 3


def test_concurrent_updates_are_serialized():
    g = guard(max_samples=500)
    pixel = (7, 7)
    failures = []

    def worker(index):
        try:
            for step in range(10):
                g.update_sample(pixel, sample_id="w%d-%d" % (index, step),
                                target_weight=1.0, depth=3.0, normal=NORMAL,
                                frame=FRAME)
        except BaseException as exc:  # noqa: BLE001 - collected for assertion
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    state = g.pixel_state(pixel)
    assert state.sample_count == 80
    assert state.weight_sum == pytest.approx(80.0)
    assert g.stats()["updates"] == 80
