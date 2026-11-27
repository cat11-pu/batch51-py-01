import copy
import threading

import pytest

import transient_attachment_aliaser as ta

SIZE_256 = 1024


def aliaser(**kwargs):
    return ta.TransientAttachmentAliaser(**kwargs)


def attach(planner, name, *, width=16, height=16, bytes_per_pixel=4,
           kind="color", external=False, backbuffer=False):
    return planner.declare_attachment(
        name, width=width, height=height, bytes_per_pixel=bytes_per_pixel,
        kind=kind, external=external, backbuffer=backbuffer)


def frame(planner, count=4):
    for index in range(count):
        planner.declare_pass(index, f"pass-{index}")


def test_declare_attachment_validates_and_returns_record():
    planner = aliaser()
    planner.declare_pass(0, "gbuffer")
    record = attach(planner, "hdr")
    assert record == ta.AttachmentRecord("hdr", 16, 16, 4, "color", False, False)
    assert planner.attachment_state("hdr") == record

    for broken in (dict(width=0), dict(height=-2), dict(bytes_per_pixel=0)):
        with pytest.raises(ValueError):
            attach(planner, "broken", **broken)
    with pytest.raises(ValueError):
        attach(planner, "hdr")
    with pytest.raises(ValueError):
        attach(planner, "storage", kind="storage")
    assert planner.stats()["attachments"] == 1


def test_declare_pass_rejects_duplicate_and_negative_index():
    planner = aliaser()
    assert planner.declare_pass(3, "lighting") == ta.PassRecord(3, "lighting")
    with pytest.raises(ValueError):
        planner.declare_pass(3, "other")
    with pytest.raises(ValueError):
        planner.declare_pass(-1, "broken")
    assert planner.stats()["passes"] == 1


def test_declare_use_requires_declared_pass_and_attachment():
    planner = aliaser()
    frame(planner, 3)
    attach(planner, "hdr")
    planner.declare_use("hdr", 1, "write")
    planner.declare_use("hdr", 0, "read")
    assert planner.uses_of("hdr") == ((0, "read"), (1, "write"))

    with pytest.raises(KeyError):
        planner.declare_use("ghost", 0, "read")
    with pytest.raises(KeyError):
        planner.declare_use("hdr", 9, "read")
    with pytest.raises(ValueError):
        planner.declare_use("hdr", 0, "sample")
    with pytest.raises(ValueError):
        planner.declare_use("hdr", -1, "read")
    assert planner.stats()["uses"] == 2


def test_unknown_handle_queries_raise_key_error():
    planner = aliaser()
    with pytest.raises(KeyError):
        planner.offset_of("ghost")
    with pytest.raises(KeyError):
        planner.attachment_state("ghost")
    with pytest.raises(KeyError):
        planner.uses_of("ghost")


def test_disjoint_lifetimes_share_the_same_offset():
    planner = aliaser()
    frame(planner)
    attach(planner, "albedo")
    attach(planner, "normal")
    planner.declare_use("albedo", 0, "write")
    planner.declare_use("albedo", 1, "read")
    planner.declare_use("normal", 2, "write")
    planner.declare_use("normal", 3, "read")

    offsets = planner.plan()
    assert offsets == {"albedo": 0, "normal": 0}
    assert planner.offset_of("normal") == 0
    assert planner.heap_usage() == SIZE_256
    assert planner.stats()["plans"] == 1


def test_overlapping_lifetimes_get_separate_offsets():
    planner = aliaser()
    frame(planner)
    attach(planner, "albedo")
    attach(planner, "normal")
    planner.declare_use("albedo", 0, "write")
    planner.declare_use("albedo", 2, "read")
    planner.declare_use("normal", 2, "read")

    assert planner.plan() == {"albedo": 0, "normal": SIZE_256}
    assert planner.heap_usage() == 2 * SIZE_256


def test_freed_slot_is_reused_by_a_later_lifetime():
    planner = aliaser()
    frame(planner)
    for name in ("a", "b", "c"):
        attach(planner, name)
    planner.declare_use("a", 0, "write")
    planner.declare_use("b", 0, "write")
    planner.declare_use("c", 1, "write")

    assert planner.plan() == {"a": 0, "b": SIZE_256, "c": 0}
    assert planner.heap_usage() == 2 * SIZE_256


def test_offset_is_unavailable_before_planning():
    planner = aliaser()
    frame(planner)
    attach(planner, "hdr")
    planner.declare_use("hdr", 0, "write")

    with pytest.raises(KeyError):
        planner.offset_of("hdr")
    planner.plan()
    assert planner.offset_of("hdr") == 0


def test_heap_usage_pads_each_attachment_to_the_heap_alignment():
    planner = aliaser(alignment=512)
    frame(planner)
    attach(planner, "small", width=8, height=8, bytes_per_pixel=1)
    attach(planner, "other", width=8, height=8, bytes_per_pixel=1)
    planner.declare_use("small", 0, "write")
    planner.declare_use("other", 0, "write")

    assert planner.plan() == {"small": 0, "other": 512}
    assert planner.heap_usage() == 1024


def test_dedicated_attachments_never_alias():
    planner = aliaser()
    frame(planner)
    attach(planner, "hdr")
    attach(planner, "capture", external=True)
    attach(planner, "back", backbuffer=True)
    planner.declare_use("hdr", 2, "write")
    for index in range(4):
        planner.declare_use("capture", index, "write")
    planner.declare_use("back", 1, "read")

    assert planner.plan() == {"hdr": 0, "back": SIZE_256, "capture": 2 * SIZE_256}
    assert planner.heap_usage() == 3 * SIZE_256


def test_heap_limit_rejects_the_whole_plan():
    planner = aliaser(heap_bytes=SIZE_256)
    frame(planner)
    attach(planner, "a")
    attach(planner, "b")
    planner.declare_use("a", 0, "write")
    planner.declare_use("b", 0, "write")

    with pytest.raises(ValueError):
        planner.plan()
    with pytest.raises(KeyError):
        planner.offset_of("a")
    assert planner.stats()["rejected"] == 1
    assert planner.stats()["plans"] == 0


def test_plan_does_not_depend_on_declaration_order():
    def build(names, use_order):
        planner = aliaser()
        frame(planner)
        for name in names:
            attach(planner, name)
        for name, index in use_order:
            planner.declare_use(name, index, "write")
        return planner.plan()

    first = build(["alpha", "beta", "gamma"],
                  [("alpha", 0), ("alpha", 1), ("beta", 1), ("beta", 2),
                   ("gamma", 2), ("gamma", 3)])
    second = build(["gamma", "beta", "alpha"],
                   [("gamma", 3), ("gamma", 2), ("beta", 2), ("beta", 1),
                    ("alpha", 1), ("alpha", 0)])
    assert first == second == {"alpha": 0, "beta": SIZE_256, "gamma": 0}


def test_snapshot_is_detached_and_restore_roundtrips():
    planner = aliaser()
    frame(planner)
    attach(planner, "hdr")
    planner.declare_use("hdr", 0, "write")
    planner.plan()

    state = planner.snapshot()
    assert set(state) == {"version", "passes", "attachments", "uses", "plan",
                          "stats"}
    pristine = copy.deepcopy(state)
    state["attachments"].clear()
    state["stats"]["plans"] = 99
    assert planner.stats()["plans"] == 1
    assert planner.offset_of("hdr") == 0

    clone = aliaser()
    clone.restore(pristine)
    assert clone.plan() == {"hdr": 0}
    assert clone.heap_usage() == SIZE_256
    assert clone.stats()["attachments"] == 1


def test_restore_rejects_malformed_state_and_keeps_live_data():
    planner = aliaser()
    frame(planner)
    attach(planner, "hdr")
    planner.declare_use("hdr", 0, "write")
    planner.plan()

    for broken in (None, {}, {"version": 1}):
        with pytest.raises(ValueError):
            planner.restore(broken)
    assert planner.offset_of("hdr") == 0
    assert planner.stats()["attachments"] == 1


def test_concurrent_plan_and_queries_stay_consistent():
    planner = aliaser()
    frame(planner)
    names = ["a", "b", "c", "d"]
    for name in names:
        attach(planner, name)
    planner.declare_use("a", 0, "write")
    planner.declare_use("b", 0, "write")
    planner.declare_use("c", 1, "write")
    planner.declare_use("d", 2, "write")
    expected = planner.plan()
    errors = []
    seen = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            for _ in range(20):
                offsets = tuple(planner.offset_of(name) for name in names)
                seen.append((offsets, planner.heap_usage()))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(seen) == 160
    assert set(seen) == {(tuple(expected[name] for name in names), 2 * SIZE_256)}
