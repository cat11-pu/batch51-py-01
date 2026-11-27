import copy
import threading

import pytest

import loop_device_lifecycle_guard as lg

IMG_A = "/srv/images/rootfs-a.img"
IMG_B = "/srv/images/data-b.img"


def guard(**kwargs):
    return lg.LoopDeviceGuard(**kwargs)


def observe(g, path, *, dev=8, inode=1000, mtime_ns=10, size=4096):
    return g.observe_file(path, dev=dev, inode=inode, mtime_ns=mtime_ns, size=size)


def test_attach_assigns_monotonic_numbers_and_records_signature():
    g = guard()
    observe(g, IMG_A, inode=1001, size=8192)
    observe(g, IMG_B, inode=1002, size=4096)
    first = g.attach(IMG_A)
    second = g.attach(IMG_B)
    assert first.loop == "loop0"
    assert second.loop == "loop1"
    assert (first.dev, first.inode, first.size) == (8, 1001, 8192)
    assert (first.offset, first.size_limit) == (0, 8192)
    assert first.read_only is False
    assert first.autoclear is False
    assert first.generation == 1
    status = g.status("loop1")
    assert status.attached is True
    assert status.path == IMG_B
    assert status.holders == ()
    assert g.stats()["attaches"] == 2


def test_attach_rejects_unknown_backing_and_out_of_range_requests():
    g = guard()
    with pytest.raises(lg.LoopError) as exc:
        g.attach("/srv/images/absent.img")
    assert exc.value.code == "LOOP_BACKING_UNKNOWN"
    assert exc.value.detail["path"] == "/srv/images/absent.img"

    observe(g, IMG_A, size=4096)
    bad_requests = [
        dict(offset=-1),
        dict(offset=4096),
        dict(offset=1024, sizelimit=4096),
        dict(offset=0, sizelimit=0),
    ]
    for request in bad_requests:
        with pytest.raises(lg.LoopError) as exc:
            g.attach(IMG_A, **request)
        assert exc.value.code == "LOOP_RANGE_INVALID"
        assert exc.value.detail["offset"] == request.get("offset", 0)
        assert "size_limit" in exc.value.detail
        assert exc.value.detail["size"] == 4096

    ok = g.attach(IMG_A, offset=1024, sizelimit=1024)
    assert (ok.offset, ok.size_limit) == (1024, 1024)
    assert g.stats()["attaches"] == 1


def test_device_cap_refuses_new_attach_without_side_effects():
    g = guard(max_devices=2)
    observe(g, IMG_A, inode=1)
    observe(g, IMG_B, inode=2)
    observe(g, "/srv/images/third.img", inode=3)
    g.attach(IMG_A)
    g.attach(IMG_B)
    with pytest.raises(lg.LoopError) as exc:
        g.attach("/srv/images/third.img")
    assert exc.value.code == "LOOP_DEVICE_EXHAUSTED"
    assert exc.value.detail["max_devices"] == 2
    assert g.status("loop2").attached is False
    assert g.stats()["attaches"] == 2


def test_duplicate_binding_reuses_read_only_and_refuses_writable():
    g = guard()
    observe(g, IMG_A)
    first = g.attach(IMG_A, read_only=True)
    second = g.attach(IMG_A, read_only=True)
    assert first.loop == second.loop == "loop0"
    assert len(g.bindings_for(IMG_A)) == 1
    assert g.stats()["attaches"] == 1
    assert g.stats()["reused"] == 1

    other = guard()
    observe(other, IMG_A)
    binding = other.attach(IMG_A)
    assert binding.read_only is False
    with pytest.raises(lg.LoopError) as exc:
        other.attach(IMG_A)
    assert exc.value.code == "LOOP_SHARED_CONFLICT"
    assert exc.value.detail["loop"] == "loop0"
    with pytest.raises(lg.LoopError) as exc:
        other.attach(IMG_A, read_only=True)
    assert exc.value.code == "LOOP_SHARED_CONFLICT"


def test_per_file_binding_cap_counts_distinct_ranges():
    g = guard(max_bindings_per_file=2)
    observe(g, IMG_A, size=4096)
    g.attach(IMG_A, offset=0, sizelimit=1024, read_only=True)
    g.attach(IMG_A, offset=1024, sizelimit=1024, read_only=True)
    with pytest.raises(lg.LoopError) as exc:
        g.attach(IMG_A, offset=2048, sizelimit=1024, read_only=True)
    assert exc.value.code == "LOOP_BACKING_LIMIT"
    assert exc.value.detail["path"] == IMG_A
    assert exc.value.detail["limit"] == 2
    assert len(g.bindings_for(IMG_A)) == 2


def test_manual_device_detach_refused_while_held():
    g = guard()
    observe(g, IMG_A)
    binding = g.attach(IMG_A, autoclear=False)
    assert binding.autoclear is False
    g.open_device("loop0", holder="pid-42")
    with pytest.raises(lg.LoopError) as exc:
        g.detach("loop0")
    assert exc.value.code == "LOOP_HELD"
    assert exc.value.detail["holders"] == ("pid-42",)
    assert g.status("loop0").attached is True
    assert g.close_device("loop0", holder="pid-42") == 0
    assert g.detach("loop0") is True
    assert g.status("loop0").attached is False
    assert g.stats()["detaches"] == 1


def test_holders_are_sorted_and_device_numbers_are_not_recycled():
    g = guard()
    observe(g, IMG_A)
    observe(g, IMG_B, inode=1002)
    g.attach(IMG_A)
    g.open_device("loop0", holder="tty-holder")
    g.open_device("loop0", holder="cron-holder")
    assert g.holders("loop0") == ("cron-holder", "tty-holder")
    with pytest.raises(lg.LoopError) as exc:
        g.close_device("loop0", holder="ghost")
    assert exc.value.code == "LOOP_NOT_HELD"
    assert g.close_device("loop0", holder="tty-holder") == 1
    assert g.status("loop0").holders == ("cron-holder",)
    assert g.close_device("loop0", holder="cron-holder") == 0
    assert g.detach("loop0") is True
    assert g.attach(IMG_B).loop == "loop1"


def test_reconfigure_is_busy_while_held_and_revalidates_range():
    g = guard()
    observe(g, IMG_A, size=8192)
    g.attach(IMG_A)
    g.open_device("loop0", holder="mount-holder")
    with pytest.raises(lg.LoopError) as exc:
        g.reconfigure("loop0", offset=512)
    assert exc.value.code == "LOOP_BUSY"
    assert exc.value.detail["holders"] == ("mount-holder",)
    assert g.close_device("loop0", holder="mount-holder") == 0

    with pytest.raises(lg.LoopError) as exc:
        g.reconfigure("loop0", offset=4096, sizelimit=8192)
    assert exc.value.code == "LOOP_RANGE_INVALID"

    changed = g.reconfigure("loop0", offset=1024, sizelimit=2048)
    assert (changed.offset, changed.size_limit) == (1024, 2048)
    assert changed.generation == 2
    assert changed.size == 8192
    assert g.status("loop0").generation == 2


def test_partition_scan_is_invalidated_by_reconfigure():
    g = guard()
    observe(g, IMG_A, size=8192)
    g.attach(IMG_A)
    assert g.scan_partitions("loop0") == ()
    g.record_partitions("loop0", ("loop0p1", "loop0p2"))
    assert g.scan_partitions("loop0") == ("loop0p1", "loop0p2")
    g.reconfigure("loop0", sizelimit=4096)
    assert g.scan_partitions("loop0") == ()
    assert g.stats()["scans"] == 3


def test_replaced_backing_file_is_refused_on_next_open():
    g = guard()
    observe(g, IMG_A, inode=1001, size=4096)
    g.attach(IMG_A)
    observe(g, IMG_A, inode=2002, size=4096)
    with pytest.raises(lg.LoopError) as exc:
        g.open_device("loop0", holder="writer")
    assert exc.value.code == "LOOP_BACKING_DRIFT"
    assert exc.value.detail["reason"] == "replaced"
    assert g.stats()["drift_refused"] == 1
    assert g.status("loop0").holders == ()


def test_modified_time_only_touch_is_allowed_and_counted():
    g = guard()
    observe(g, IMG_A, mtime_ns=10, size=4096)
    g.attach(IMG_A)
    observe(g, IMG_A, mtime_ns=99, size=4096)
    status = g.open_device("loop0", holder="writer")
    assert status.holders == ("writer",)
    assert status.touched is True
    assert g.stats()["touched"] == 1
    assert g.stats()["drift_refused"] == 0


def test_reclaim_frees_only_unheld_autoclear_devices():
    g = guard()
    observe(g, IMG_A)
    observe(g, IMG_B, inode=1002)
    g.attach(IMG_A, autoclear=True)
    g.attach(IMG_B, autoclear=False)
    assert g.reclaim() == 1
    assert g.status("loop0").attached is False
    assert g.status("loop1").attached is True
    assert g.reclaim() == 0
    assert g.stats()["reclaimed"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    observe(g, IMG_A, inode=1001, size=8192)
    g.attach(IMG_A, offset=512, sizelimit=4096, read_only=True)
    g.open_device("loop0", holder="writer")
    g.record_partitions("loop0", ("loop0p1",))
    state = g.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "next_index", "devices",
                             "observations", "stats"}

    state["devices"].clear()
    state["stats"]["attaches"] = 999
    assert g.status("loop0").attached is True
    assert g.stats()["attaches"] == 1

    clone = guard()
    clone.restore(pristine)
    restored = clone.status("loop0")
    assert restored.attached is True
    assert (restored.offset, restored.size_limit) == (512, 4096)
    assert restored.read_only is True
    assert restored.holders == ("writer",)
    assert restored.partitions == ("loop0p1",)
    assert clone.stats()["attaches"] == 1
    assert clone.attach(IMG_A, offset=0, sizelimit=512, read_only=True).loop == "loop1"


def test_restore_rejects_malformed_state_without_touching_live_data():
    g = guard()
    observe(g, IMG_A)
    g.attach(IMG_A)
    bad_states = [
        None,
        {},
        {"version": 2, "next_index": 1, "devices": [], "observations": {},
         "stats": dict(g.stats())},
        {"version": 1, "next_index": "one", "devices": [], "observations": {},
         "stats": dict(g.stats())},
        {"version": 1, "next_index": 1, "devices": {}, "observations": {},
         "stats": dict(g.stats())},
        {"version": 1, "next_index": 1, "devices": [], "observations": {},
         "stats": {"attaches": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(lg.LoopError) as exc:
            g.restore(bad)
        assert exc.value.code == "LOOP_SNAPSHOT_INVALID"

    assert g.status("loop0").attached is True
    assert g.stats()["attaches"] == 1


def test_concurrent_attach_of_distinct_files_keeps_numbers_unique():
    g = guard(max_devices=16)
    paths = [f"/srv/images/disk-{index:02d}.img" for index in range(12)]
    for index, path in enumerate(paths):
        observe(g, path, inode=5000 + index)
    errors = []
    barrier = threading.Barrier(len(paths))

    def worker(path):
        try:
            barrier.wait(timeout=5)
            g.attach(path)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(path,)) for path in paths]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    loops = sorted(binding.loop for binding in
                   (g.bindings_for(path)[0] for path in paths))
    assert loops == sorted(f"loop{index}" for index in range(12))
    assert g.stats()["attaches"] == 12
