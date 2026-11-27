import copy

import pytest

import convolution_reverb_scheduler as rv


def scheduler(**kwargs):
    return rv.ReverbScheduler(**kwargs)


def bus_with_ir(**kwargs):
    taps = kwargs.pop("taps", 300)
    engine = scheduler(**kwargs)
    engine.create_bus("bus")
    engine.load_ir("bus", "ir-room", taps=taps)
    return engine


def test_create_bus_strips_name_and_rejects_duplicate_and_blank():
    engine = scheduler()
    assert engine.create_bus("  mains ") == "mains"
    assert engine.stats()["buses"] == 1

    with pytest.raises(rv.ReverbError) as exc:
        engine.create_bus("mains")
    assert exc.value.code == "REVERB_BUS_EXISTS"

    for bad in ("", "   ", None):
        with pytest.raises(rv.ReverbError) as exc:
            engine.create_bus(bad)
        assert exc.value.code == "REVERB_INVALID_NAME"

    assert engine.stats()["buses"] == 1


def test_create_bus_capacity_is_hard():
    engine = scheduler(max_buses=2)
    engine.create_bus("a")
    engine.create_bus("b")
    with pytest.raises(rv.ReverbError) as exc:
        engine.create_bus("c")
    assert exc.value.code == "REVERB_CAPACITY"
    assert engine.stats()["buses"] == 2

    assert engine.release_bus("a") == 0
    assert engine.create_bus("c") == "c"
    assert engine.stats()["buses"] == 2


def test_load_ir_reports_partition_split_and_enforces_limit():
    engine = scheduler(head_samples=64, block_size=128, max_partitions=2)
    engine.create_bus("bus")
    binding = engine.load_ir("bus", "ir-room", taps=320)
    assert binding == rv.IrBinding(bus="bus", ir_id="ir-room", version=1,
                                   taps=320, head_samples=64, partitions=2)
    assert engine.partition_count("bus") == 2
    assert engine.stats()["loads"] == 1

    with pytest.raises(rv.ReverbError) as exc:
        engine.swap_ir("bus", "ir-long", taps=321)
    assert exc.value.code == "REVERB_PARTITION_LIMIT"
    assert engine.partition_count("bus") == 2
    assert engine.stats()["swaps"] == 0


def test_load_ir_rejects_unknown_bus_and_bad_ir():
    engine = scheduler()
    engine.create_bus("bus")
    cases = [
        ("ghost", "ir", 100, "REVERB_BUS_UNKNOWN"),
        ("bus", "   ", 100, "REVERB_IR_INVALID"),
        ("bus", "ir", 0, "REVERB_IR_INVALID"),
        ("bus", "ir", -5, "REVERB_IR_INVALID"),
    ]
    for bus, ir_id, taps, code in cases:
        with pytest.raises(rv.ReverbError) as exc:
            engine.load_ir(bus, ir_id, taps=taps)
        assert exc.value.code == code
    assert engine.stats()["loads"] == 0
    assert engine.stats()["buses"] == 1


def test_load_ir_twice_reports_ir_present():
    engine = scheduler()
    engine.create_bus("bus")
    engine.load_ir("bus", "ir-a", taps=200)
    with pytest.raises(rv.ReverbError) as exc:
        engine.load_ir("bus", "ir-b", taps=200)
    assert exc.value.code == "REVERB_IR_PRESENT"
    assert engine.stats()["loads"] == 1
    assert engine.bus_state("bus")["ir_id"] == "ir-a"


def test_swap_ir_bumps_version_and_resets_tail():
    engine = scheduler(head_samples=64, block_size=128)
    engine.create_bus("bus")
    engine.load_ir("bus", "ir-a", taps=200)
    assert engine.tail_of("bus") == 200

    binding = engine.swap_ir("bus", "ir-b", taps=100)
    assert (binding.bus, binding.ir_id, binding.version) == ("bus", "ir-b", 2)
    assert binding.partitions == 1
    assert engine.tail_of("bus") == 100
    assert engine.bus_state("bus")["version"] == 2
    assert engine.stats()["swaps"] == 1


def test_swap_ir_rejections():
    engine = scheduler()
    engine.create_bus("bus")
    with pytest.raises(rv.ReverbError) as exc:
        engine.swap_ir("ghost", "ir", taps=50)
    assert exc.value.code == "REVERB_BUS_UNKNOWN"

    with pytest.raises(rv.ReverbError) as exc:
        engine.swap_ir("bus", "ir", taps=50)
    assert exc.value.code == "REVERB_NO_IR"

    engine.load_ir("bus", "ir-1", taps=50)
    with pytest.raises(rv.ReverbError) as exc:
        engine.swap_ir("bus", "ir-1", taps=80)
    assert exc.value.code == "REVERB_IR_UNCHANGED"

    with pytest.raises(rv.ReverbError) as exc:
        engine.swap_ir("bus", "ir-2", taps=0)
    assert exc.value.code == "REVERB_IR_INVALID"

    assert engine.stats()["swaps"] == 0
    assert engine.bus_state("bus")["version"] == 1


def test_set_mix_range_and_bus_lookup():
    engine = scheduler()
    engine.create_bus("bus")
    assert engine.set_mix("bus", wet=0.0) == 0.0
    assert engine.set_mix("bus", wet=1) == 1.0
    assert engine.set_mix("bus", wet=0.25) == 0.25
    assert engine.bus_state("bus")["wet"] == 0.25

    for bad in (1.01, -0.01, 2):
        with pytest.raises(rv.ReverbError) as exc:
            engine.set_mix("bus", wet=bad)
        assert exc.value.code == "REVERB_MIX_OUT_OF_RANGE"

    with pytest.raises(rv.ReverbError) as exc:
        engine.set_mix("ghost", wet=0.5)
    assert exc.value.code == "REVERB_BUS_UNKNOWN"
    assert engine.bus_state("bus")["wet"] == 0.25


def test_process_block_requires_ir_and_valid_block_size():
    engine = scheduler(block_size=128)
    engine.create_bus("bus")
    with pytest.raises(rv.ReverbError) as exc:
        engine.process_block("bus", seq=1, samples=64)
    assert exc.value.code == "REVERB_NO_IR"

    engine.load_ir("bus", "ir", taps=512)
    for bad in (0, -1):
        with pytest.raises(rv.ReverbError) as exc:
            engine.process_block("bus", seq=1, samples=bad)
        assert exc.value.code == "REVERB_BLOCK_INVALID"

    with pytest.raises(rv.ReverbError) as exc:
        engine.process_block("bus", seq=1, samples=129)
    assert exc.value.code == "REVERB_BLOCK_TOO_LARGE"

    assert engine.stats()["blocks"] == 0
    assert engine.stats()["samples"] == 0


def test_process_block_enforces_strict_sequence():
    engine = bus_with_ir(taps=512)
    first = engine.process_block("bus", seq=1, samples=128)
    assert (first.bus, first.seq, first.samples) == ("bus", 1, 128)

    for bad in (1, 3, 0):
        with pytest.raises(rv.ReverbError) as exc:
            engine.process_block("bus", seq=bad, samples=128)
        assert exc.value.code == "REVERB_SEQ_MISMATCH"

    second = engine.process_block("bus", seq=2, samples=128)
    assert second.seq == 2
    assert engine.stats()["blocks"] == 2
    assert engine.stats()["samples"] == 256
    assert engine.bus_state("bus")["last_seq"] == 2


def test_tail_remaining_counts_down_and_clamps():
    engine = bus_with_ir(head_samples=64, block_size=128, taps=300)
    assert engine.tail_of("bus") == 300

    first = engine.process_block("bus", seq=1, samples=128)
    assert first.tail_remaining == 172
    assert engine.tail_of("bus") == 172

    second = engine.process_block("bus", seq=2, samples=128)
    assert second.tail_remaining == 44

    third = engine.process_block("bus", seq=3, samples=40)
    assert third.tail_remaining == 4

    fourth = engine.process_block("bus", seq=4, samples=40)
    assert fourth.tail_remaining == 0
    assert engine.tail_of("bus") == 0


def test_fade_window_progress_and_remaining():
    engine = bus_with_ir(block_size=128, fade_blocks=4, taps=600)
    assert engine.fade_progress("bus") == 0.0

    engine.swap_ir("bus", "ir-b", taps=600)
    assert engine.fade_progress("bus") == 0.0

    block = engine.process_block("bus", seq=1, samples=128)
    assert block.fade_remaining == 384
    assert engine.fade_progress("bus") == pytest.approx(0.25)

    engine.process_block("bus", seq=2, samples=128)
    assert engine.fade_progress("bus") == pytest.approx(0.5)

    engine.process_block("bus", seq=3, samples=128)
    engine.process_block("bus", seq=4, samples=128)
    assert engine.fade_progress("bus") == pytest.approx(1.0)

    tail = engine.process_block("bus", seq=5, samples=64)
    assert tail.fade_remaining == 0
    assert engine.fade_progress("bus") == pytest.approx(1.0)


def test_release_bus_returns_released_refs():
    engine = scheduler()
    engine.create_bus("dry")
    assert engine.release_bus("dry") == 0

    engine.create_bus("wet")
    engine.load_ir("wet", "ir", taps=100)
    assert engine.release_bus("wet") == 1

    with pytest.raises(rv.ReverbError) as exc:
        engine.tail_of("wet")
    assert exc.value.code == "REVERB_BUS_UNKNOWN"

    with pytest.raises(rv.ReverbError) as exc:
        engine.release_bus("wet")
    assert exc.value.code == "REVERB_BUS_UNKNOWN"

    assert engine.stats() == {"buses": 0, "loads": 1, "swaps": 0,
                              "blocks": 0, "samples": 0, "released": 1}


def test_snapshot_is_detached_and_restore_roundtrips():
    engine = scheduler(head_samples=64, block_size=128, fade_blocks=2)
    engine.create_bus("bus")
    engine.load_ir("bus", "ir-a", taps=300)
    engine.set_mix("bus", wet=0.4)
    engine.process_block("bus", seq=1, samples=128)
    engine.swap_ir("bus", "ir-b", taps=200)
    engine.process_block("bus", seq=2, samples=128)

    state = engine.snapshot()
    pristine = copy.deepcopy(state)
    state["buses"].clear()
    state["stats"]["blocks"] = 99

    assert engine.stats()["blocks"] == 2
    assert engine.tail_of("bus") == 72

    clone = scheduler(head_samples=64, block_size=128, fade_blocks=2)
    clone.restore(pristine)
    assert clone.stats() == engine.stats()
    assert clone.tail_of("bus") == 72
    assert clone.partition_count("bus") == 2
    assert clone.bus_state("bus")["wet"] == 0.4
    assert clone.bus_state("bus")["version"] == 2

    resumed = clone.process_block("bus", seq=3, samples=64)
    assert resumed.seq == 3
    assert resumed.tail_remaining == 8


def test_restore_rejects_malformed_state_without_mutating():
    engine = bus_with_ir(taps=300)
    bad_states = [
        None,
        {},
        {"version": 2, "buses": [], "stats": {}},
        {"version": 1, "buses": "nope", "stats": {}},
        {"version": 1, "buses": [{"bus": "x"}], "stats": {}},
        {"version": 1, "buses": [{"bus": "x", "ir_id": "ir", "ir_taps": 10,
                                  "version": 1, "partitions": 0, "wet": 0.0,
                                  "processed": 0, "last_seq": 0,
                                  "fade_remaining": 0,
                                  "retiring": "many"}], "stats": {}},
    ]
    for state in bad_states:
        with pytest.raises(rv.ReverbError) as exc:
            engine.restore(state)
        assert exc.value.code == "REVERB_SNAPSHOT_INVALID"

    assert engine.stats()["buses"] == 1
    assert engine.tail_of("bus") == 300
    assert engine.bus_state("bus")["ir_id"] == "ir-room"
