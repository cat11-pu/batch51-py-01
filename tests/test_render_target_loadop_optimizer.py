import threading

import pytest

import render_target_loadop_optimizer as lo


def optimizer(**kwargs):
    return lo.LoadOpOptimizer(**kwargs)


def test_declare_target_validates_and_caps():
    opt = optimizer()
    state = opt.declare_target("hdr", bytes_per_frame=1024, samples=4)
    assert state == lo.TargetState("hdr", 1024, 4, False, False)
    with pytest.raises(lo.LoadOpError) as exc:
        opt.declare_target("hdr", bytes_per_frame=512)
    assert exc.value.code == "LOADOP_TARGET_EXISTS"
    for name, kwargs in (("", {"bytes_per_frame": 16}),
                         ("bad", {"bytes_per_frame": 0}),
                         ("msaa", {"bytes_per_frame": 16, "samples": 3})):
        with pytest.raises(lo.LoadOpError) as exc:
            opt.declare_target(name, **kwargs)
        assert exc.value.code == "LOADOP_INVALID_TARGET"

    capped = optimizer(max_targets=2)
    capped.declare_target("a", bytes_per_frame=16)
    capped.declare_target("b", bytes_per_frame=16)
    with pytest.raises(lo.LoadOpError) as exc:
        capped.declare_target("c", bytes_per_frame=16)
    assert exc.value.code == "LOADOP_CAPACITY_EXCEEDED"


def test_declare_use_validates_target_kind_and_pass():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024)
    with pytest.raises(lo.LoadOpError) as exc:
        opt.declare_use("ghost", 1, "write")
    assert exc.value.code == "LOADOP_NO_SUCH_TARGET"
    with pytest.raises(lo.LoadOpError) as exc:
        opt.declare_use("hdr", 1, "readwrite")
    assert exc.value.code == "LOADOP_INVALID_USE"
    with pytest.raises(lo.LoadOpError) as exc:
        opt.declare_use("hdr", -1, "write")
    assert exc.value.code == "LOADOP_INVALID_USE"
    opt.declare_use("hdr", 1, "write")
    with pytest.raises(lo.LoadOpError) as exc:
        opt.declare_use("hdr", 1, "read")
    assert exc.value.code == "LOADOP_PASS_CONFLICT"


def test_plan_is_deterministic_and_sorted():
    opt = optimizer()
    opt.declare_target("z-shadow", bytes_per_frame=16)
    opt.declare_target("albedo", bytes_per_frame=16)
    opt.declare_use("z-shadow", 2, "write")
    opt.declare_use("albedo", 3, "write")
    opt.declare_use("albedo", 1, "write")
    first = opt.plan()
    assert [(item.target, item.pass_index) for item in first] == [
        ("albedo", 1), ("albedo", 3), ("z-shadow", 2)]
    assert opt.plan() == first


def test_single_write_use_clears_and_discards():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024)
    opt.declare_use("hdr", 1, "write")
    plan = opt.plan()
    assert len(plan) == 1
    assert plan[0].load_op == "clear"
    assert plan[0].store_op == "discard"
    assert opt.bandwidth_saved() == {"baseline_bytes": 2048,
                                     "planned_bytes": 0,
                                     "saved_bytes": 2048,
                                     "per_target": {"hdr": 2048}}


def test_pure_write_chain_elides_the_intermediate_store():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024)
    opt.declare_use("hdr", 1, "write")
    opt.declare_use("hdr", 3, "write")
    assert opt.load_op_of("hdr", 3) == "discard"
    assert opt.store_op_of("hdr", 1) == "discard"
    assert opt.store_op_of("hdr", 3) == "discard"
    assert opt.bandwidth_saved()["saved_bytes"] == 4096


def test_write_then_read_keeps_content_between_passes():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024)
    opt.declare_use("hdr", 1, "write")
    opt.declare_use("hdr", 2, "read")
    assert opt.load_op_of("hdr", 2) == "load"
    assert opt.store_op_of("hdr", 2) == "discard"
    assert opt.bandwidth_saved()["saved_bytes"] == 2048


def test_first_use_read_loads_existing_content():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024)
    opt.declare_use("hdr", 2, "read")
    assert opt.load_op_of("hdr", 2) == "load"
    assert opt.store_op_of("hdr", 2) == "discard"
    assert opt.bandwidth_saved()["saved_bytes"] == 1024


def test_resolve_use_stores_the_resolved_surface():
    opt = optimizer()
    opt.declare_target("msaa-color", bytes_per_frame=1024, samples=4)
    opt.declare_use("msaa-color", 1, "write")
    opt.declare_use("msaa-color", 2, "read_write", resolve=True)
    assert opt.load_op_of("msaa-color", 2) == "load"
    assert opt.store_op_of("msaa-color", 2) == "resolve"
    plan = opt.plan()
    assert plan[1].resolve is True
    assert opt.bandwidth_saved()["saved_bytes"] == 1024


def test_resolve_requires_multisampled_target():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024, samples=1)
    opt.declare_use("hdr", 1, "write")
    opt.declare_use("hdr", 2, "read_write", resolve=True)
    with pytest.raises(lo.LoadOpError) as exc:
        opt.plan()
    assert exc.value.code == "LOADOP_RESOLVE_NOT_MSAA"


def test_use_limit_per_target_is_enforced():
    opt = optimizer(max_uses_per_target=2)
    opt.declare_target("hdr", bytes_per_frame=1024)
    opt.declare_use("hdr", 1, "write")
    opt.declare_use("hdr", 2, "read")
    with pytest.raises(lo.LoadOpError) as exc:
        opt.declare_use("hdr", 3, "write")
    assert exc.value.code == "LOADOP_USE_LIMIT"
    assert len(opt.uses_of("hdr")) == 2


def test_bandwidth_breakdown_per_target():
    opt = optimizer()
    opt.declare_target("albedo", bytes_per_frame=1024)
    opt.declare_target("depth", bytes_per_frame=512)
    opt.declare_use("albedo", 1, "write")
    opt.declare_use("depth", 1, "write")
    opt.declare_use("depth", 2, "read")
    saved = opt.bandwidth_saved()
    assert saved["baseline_bytes"] == 4096
    assert saved["planned_bytes"] == 1024
    assert saved["saved_bytes"] == 3072
    assert saved["per_target"] == {"albedo": 2048, "depth": 1024}


def test_snapshot_restore_roundtrip_and_malformed():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024, samples=2)
    opt.declare_use("hdr", 1, "write")
    opt.declare_external_read("hdr")
    state = opt.snapshot()
    assert set(state) == {"version", "targets", "uses", "counters"}

    state["uses"].clear()
    state["targets"].clear()
    assert len(opt.uses_of("hdr")) == 1
    assert opt.target_state("hdr").external_read is True

    pristine = opt.snapshot()
    clone = optimizer()
    clone.restore(pristine)
    assert clone.plan() == opt.plan()
    assert clone.target_state("hdr") == opt.target_state("hdr")
    assert clone.bandwidth_saved() == opt.bandwidth_saved()

    for bad in (None, {},
                {"version": 2, "targets": {}, "uses": {}, "counters": {}},
                {"version": 1, "targets": {}, "uses": {}}):
        with pytest.raises(lo.LoadOpError) as exc:
            clone.restore(bad)
        assert exc.value.code == "LOADOP_SNAPSHOT_INVALID"
    assert len(clone.uses_of("hdr")) == 1


def test_stats_track_targets_uses_and_plans():
    opt = optimizer()
    opt.declare_target("albedo", bytes_per_frame=1024)
    opt.declare_target("depth", bytes_per_frame=512)
    opt.declare_use("albedo", 1, "write")
    opt.declare_use("depth", 1, "write")
    opt.declare_use("depth", 2, "read")
    opt.plan()
    opt.plan()
    with pytest.raises(lo.LoadOpError):
        opt.declare_use("ghost", 1, "write")
    assert opt.stats() == {"targets": 2, "uses": 3, "plans": 2, "rejected": 1}


def test_concurrent_declares_keep_every_pass():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024)
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            opt.declare_use("hdr", index + 1, "write")
        except Exception as exc:  # pragma: no cover - surfaced through assertions
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(opt.uses_of("hdr")) == 8
    plan = opt.plan()
    assert [item.pass_index for item in plan] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert opt.bandwidth_saved()["saved_bytes"] == 16384


def test_target_state_reports_declaration():
    opt = optimizer()
    opt.declare_target("hdr", bytes_per_frame=1024, samples=2, persistent=True)
    state = opt.target_state("hdr")
    assert state.name == "hdr"
    assert state.bytes_per_frame == 1024
    assert state.samples == 2
    assert state.persistent is True
    assert state.external_read is False
    assert opt.declare_external_read("hdr").external_read is True
    with pytest.raises(lo.LoadOpError) as exc:
        opt.target_state("ghost")
    assert exc.value.code == "LOADOP_NO_SUCH_TARGET"
