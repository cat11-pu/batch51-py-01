import copy
import threading

import pytest

import ray_instance_ledger as rl


def ledger(**kwargs):
    return rl.RayInstanceLedger(**kwargs)


def with_blas(name="geo", **kwargs):
    instance = ledger(**kwargs)
    instance.ref_blas(name)
    return instance


def code_of(call):
    with pytest.raises(rl.InstanceLedgerError) as exc:
        call()
    return exc.value.code


def test_auto_ids_start_at_one_and_buffer_is_sorted():
    instance = with_blas()
    assert instance.add_instance(blas="geo") == 1
    assert instance.add_instance(blas="geo") == 2
    records = instance.instance_buffer()
    assert [record.instance_id for record in records] == [1, 2]
    assert records[0] == rl.InstanceRecord(1, "geo", (0.0, 0.0, 0.0), 1, True)
    assert instance.allocated_ids() == (1, 2)
    assert instance.free_ids() == ()
    assert instance.stats()["instances"] == 2


def test_explicit_duplicate_id_is_rejected():
    instance = with_blas()
    assert instance.add_instance(blas="geo", instance_id=5) == 5
    assert code_of(lambda: instance.add_instance(
        blas="geo", instance_id=5)) == "LEDGER_DUPLICATE_ID"
    assert instance.allocated_ids() == (5,)
    assert instance.stats()["instances"] == 1


def test_capacity_limit_refuses_new_instances():
    instance = with_blas(max_instances=2)
    instance.add_instance(blas="geo")
    instance.add_instance(blas="geo")
    assert code_of(lambda: instance.add_instance(
        blas="geo")) == "LEDGER_CAPACITY_EXCEEDED"
    assert len(instance.instance_buffer()) == 2
    assert instance.allocated_ids() == (1, 2)


def test_removed_ids_are_reused_lowest_first():
    instance = with_blas()
    for _ in range(3):
        instance.add_instance(blas="geo")
    assert instance.remove_instance(2) == 2
    assert instance.free_ids() == (2,)
    assert instance.add_instance(blas="geo") == 2
    assert instance.free_ids() == ()

    instance.remove_instance(1)
    instance.remove_instance(3)
    assert instance.free_ids() == (1, 3)
    assert instance.add_instance(blas="geo") == 1
    assert instance.add_instance(blas="geo") == 3
    assert instance.allocated_ids() == (1, 2, 3)


def test_remove_unknown_instance_raises_key_error():
    instance = with_blas()
    instance.add_instance(blas="geo")
    with pytest.raises(KeyError):
        instance.remove_instance(9)
    with pytest.raises(KeyError):
        instance.set_mask(9, 1)
    with pytest.raises(KeyError):
        instance.mark_transform(9, (1.0, 2.0, 3.0))
    assert instance.allocated_ids() == (1,)


def test_blas_refcount_counts_instances():
    instance = ledger()
    assert instance.ref_blas("geo") == 1
    instance.add_instance(blas="geo")
    instance.add_instance(blas="geo")
    assert instance.blas_refcount("geo") == 3
    instance.remove_instance(1)
    assert instance.blas_refcount("geo") == 2
    instance.remove_instance(2)
    assert instance.blas_refcount("geo") == 1


def test_manual_reference_lifecycle():
    instance = ledger()
    assert instance.ref_blas("geo") == 1
    assert instance.ref_blas("geo") == 2
    assert instance.release_blas("geo") == 1
    assert instance.release_blas("geo") == 0
    with pytest.raises(KeyError):
        instance.blas_refcount("geo")


def test_set_mask_updates_record_and_visibility():
    instance = with_blas()
    instance.add_instance(blas="geo")
    instance.add_instance(blas="geo")

    record = instance.set_mask(1, 0b0100)
    assert record == rl.InstanceRecord(1, "geo", (0.0, 0.0, 0.0), 0b0100, True)
    assert instance.instance_buffer()[0].mask == 0b0100
    assert instance.visible_instances(0b0010) == (2,)
    assert instance.visible_instances(0b0100) == (1,)
    assert instance.visible_instances() == (1, 2)


def test_set_mask_validates_the_range():
    instance = with_blas()
    instance.add_instance(blas="geo")
    for bad in (-1, 0x10000, 1.5, "1"):
        assert code_of(lambda: instance.set_mask(1, bad)) == \
            "LEDGER_INVALID_MASK"
    assert instance.instance_buffer()[0].mask == 1


def test_mark_transform_marks_dirty_and_rebuild_clears_it():
    instance = with_blas()
    instance.add_instance(blas="geo")
    first = instance.rebuild_buffer()
    assert (first.written, first.dirty, first.high_water) == (1, 1, 2)
    assert instance.instance_buffer()[0].dirty is False
    assert instance.stats()["dirty"] == 0

    record = instance.mark_transform(1, (1.0, 2.0, 3.0))
    assert record == rl.InstanceRecord(1, "geo", (1.0, 2.0, 3.0), 1, True)
    assert instance.stats()["dirty"] == 1

    second = instance.rebuild_buffer()
    assert (second.written, second.dirty) == (1, 1)
    assert instance.instance_buffer()[0].dirty is False
    assert instance.stats()["rebuilds"] == 2


def test_instance_buffer_is_a_snapshot_copy():
    instance = with_blas()
    instance.add_instance(blas="geo")
    before = instance.instance_buffer()
    instance.add_instance(blas="geo")
    assert len(before) == 1
    assert len(instance.instance_buffer()) == 2
    assert before[0].instance_id == 1


def test_add_instance_requires_a_referenced_blas():
    instance = ledger()
    with pytest.raises(KeyError):
        instance.add_instance(blas="missing")
    assert instance.allocated_ids() == ()
    assert instance.stats()["instances"] == 0


def test_concurrent_adds_keep_ids_unique_and_dense():
    instance = with_blas(max_instances=64)
    errors = []
    ids = []
    guard = threading.Lock()
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            for _ in range(4):
                allocated = instance.add_instance(blas="geo")
                with guard:
                    ids.append(allocated)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(ids) == list(range(1, 33))
    assert instance.allocated_ids() == tuple(range(1, 33))
    assert instance.blas_refcount("geo") == 33


def test_snapshot_restore_roundtrip():
    instance = with_blas()
    instance.add_instance(blas="geo", mask=0b0011)
    instance.mark_transform(1, (1.0, 2.0, 3.0))

    state = instance.snapshot()
    assert set(state) == {"version", "instances", "free", "blas",
                          "next_id", "stats"}
    pristine = copy.deepcopy(state)
    state["instances"].clear()
    state["stats"]["rebuilds"] = 99
    assert instance.stats()["rebuilds"] == 0
    assert instance.allocated_ids() == (1,)

    clone = ledger()
    clone.restore(pristine)
    assert clone.allocated_ids() == (1,)
    assert clone.instance_buffer() == instance.instance_buffer()
    assert clone.blas_refcount("geo") == 2
    assert clone.add_instance(blas="geo") == 2


def test_restore_rejects_malformed_state():
    instance = with_blas()
    instance.add_instance(blas="geo")
    for broken in (None, {}, {"version": 1}):
        assert code_of(lambda: instance.restore(broken)) == \
            "LEDGER_SNAPSHOT_INVALID"
    assert instance.allocated_ids() == (1,)
    assert instance.blas_refcount("geo") == 2
