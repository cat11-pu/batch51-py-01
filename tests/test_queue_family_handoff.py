import copy
import threading

import pytest

import queue_family_handoff as qh


def code_of(call):
    with pytest.raises(qh.HandoffError) as exc:
        call()
    return exc.value.code


def test_register_validates_kind_duplicate_and_capacity():
    tracker = qh.QueueFamilyHandoff()
    record = tracker.register_resource("tex", kind="image", size=1024)
    assert record == qh.ResourceRecord("tex", "image", 1024, "graphics", 1, 0)
    assert code_of(lambda: tracker.register_resource("tex")) == \
        "HANDOFF_DUPLICATE_RESOURCE"
    assert code_of(lambda: tracker.register_resource("bad", kind="sampler")) == \
        "HANDOFF_INVALID_RESOURCE"
    assert code_of(lambda: tracker.register_resource("bad2", size=0)) == \
        "HANDOFF_INVALID_RESOURCE"

    capped = qh.QueueFamilyHandoff(max_resources=1)
    capped.register_resource("one")
    assert code_of(lambda: capped.register_resource("two")) == \
        "HANDOFF_CAPACITY_EXCEEDED"
    assert capped.stats()["resources"] == 1


def test_register_rejects_illegal_owner_and_unknown_handles():
    tracker = qh.QueueFamilyHandoff()
    assert code_of(lambda: tracker.register_resource(
        "img", kind="image", owner="transfer")) == "HANDOFF_INVALID_FAMILY"
    assert tracker.register_resource(
        "img", kind="image", owner="compute").owner == "compute"
    assert tracker.register_resource(
        "buf", kind="buffer", owner="transfer").owner == "transfer"

    for call in (lambda: tracker.owner_of("ghost"),
                 lambda: tracker.version_of("ghost"),
                 lambda: tracker.pending_owner("ghost")):
        with pytest.raises(KeyError):
            call()


def test_release_validates_family_type_and_sequence():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("buf")
    tracker.register_resource("img", kind="image")
    tracker.register_resource("late", sequence=5)

    assert code_of(lambda: tracker.release_to(
        "buf", "audio", sequence=1)) == "HANDOFF_INVALID_FAMILY"
    assert code_of(lambda: tracker.release_to(
        "img", "transfer", sequence=1)) == "HANDOFF_INVALID_FAMILY"
    assert code_of(lambda: tracker.release_to(
        "late", "compute", sequence=4)) == "HANDOFF_SEQUENCE_REGRESS"
    assert tracker.pending_owner("late") is None


def test_release_and_acquire_move_ownership_and_bump_version():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("tex", kind="image", size=2048)

    pending = tracker.release_to("tex", "compute", sequence=3)
    assert pending == qh.PendingHandoff("tex", "graphics", "compute", 3)
    assert tracker.owner_of("tex") == "graphics"
    assert tracker.pending_owner("tex") == pending

    record = tracker.acquire_from("tex", "compute", sequence=4)
    assert record == qh.ResourceRecord("tex", "image", 2048, "compute", 2, 4)
    assert tracker.owner_of("tex") == "compute"
    assert tracker.version_of("tex") == 2
    assert tracker.pending_owner("tex") is None
    assert len(tracker.handoff_barriers()) == 2


def test_write_requires_a_completed_acquire():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("buf")
    assert code_of(lambda: tracker.write_begin(
        "buf", "compute", sequence=1)) == "HANDOFF_NOT_ACQUIRED"

    tracker.release_to("buf", "compute", sequence=2)
    assert code_of(lambda: tracker.write_begin(
        "buf", "compute", sequence=3)) == "HANDOFF_NOT_ACQUIRED"

    tracker.acquire_from("buf", "compute", sequence=4)
    assert tracker.write_begin("buf", "compute", sequence=5).owner == "compute"
    assert code_of(lambda: tracker.write_begin(
        "buf", "graphics", sequence=6)) == "HANDOFF_NOT_ACQUIRED"


def test_acquire_without_matching_release_is_refused():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("buf")
    assert code_of(lambda: tracker.acquire_from(
        "buf", "compute", sequence=1)) == "HANDOFF_NOT_PENDING"

    tracker.release_to("buf", "compute", sequence=2)
    assert code_of(lambda: tracker.acquire_from(
        "buf", "graphics", sequence=3)) == "HANDOFF_FAMILY_MISMATCH"
    assert code_of(lambda: tracker.acquire_from(
        "buf", "compute", sequence=2)) == "HANDOFF_SEQUENCE_REGRESS"
    assert tracker.owner_of("buf") == "graphics"
    assert tracker.version_of("buf") == 1


def test_second_release_while_pending_is_refused():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("buf")
    tracker.release_to("buf", "compute", sequence=2)
    assert code_of(lambda: tracker.release_to(
        "buf", "transfer", sequence=3)) == "HANDOFF_ALREADY_PENDING"
    assert tracker.pending_owner("buf") == qh.PendingHandoff(
        "buf", "graphics", "compute", 2)


def test_barriers_are_ordered_and_paired():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("a")
    tracker.register_resource("b")
    tracker.release_to("a", "compute", sequence=5)
    tracker.acquire_from("a", "compute", sequence=6)
    tracker.release_to("b", "transfer", sequence=2)
    tracker.acquire_from("b", "transfer", sequence=3)

    barriers = tracker.handoff_barriers()
    assert [(item.handle, item.phase, item.sequence) for item in barriers] == [
        ("b", "release", 2), ("b", "acquire", 3),
        ("a", "release", 5), ("a", "acquire", 6)]
    assert barriers[0] == qh.Barrier("b", "release", "graphics", "transfer", 2)
    assert barriers[3] == qh.Barrier("a", "acquire", "graphics", "compute", 6)


def test_submit_commits_only_complete_batches():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("a")
    tracker.register_resource("b")
    tracker.release_to("a", "compute", sequence=2)
    tracker.release_to("b", "compute", sequence=1)
    tracker.acquire_from("b", "compute", sequence=2)

    assert tracker.submit(5) == 2
    assert [(item.handle, item.phase) for item in tracker.handoff_barriers()] == \
        [("a", "release")]

    tracker.acquire_from("a", "compute", sequence=6)
    assert tracker.submit(6) == 2
    assert tracker.handoff_barriers() == ()
    assert tracker.stats()["submitted"] == 4


def test_submit_rejects_a_regressing_sequence():
    tracker = qh.QueueFamilyHandoff()
    assert tracker.submit(4) == 0
    assert code_of(lambda: tracker.submit(4)) == "HANDOFF_SEQUENCE_REGRESS"
    assert code_of(lambda: tracker.submit(3)) == "HANDOFF_SEQUENCE_REGRESS"
    assert tracker.submit(5) == 0


def test_pending_owner_reports_the_waiting_handoff():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("buf")
    tracker.release_to("buf", "compute", sequence=7)
    pending = tracker.pending_owner("buf")
    assert pending == qh.PendingHandoff("buf", "graphics", "compute", 7)
    assert (pending.source, pending.target, pending.release_sequence) == \
        ("graphics", "compute", 7)
    assert tracker.owner_of("buf") == "graphics"


def test_snapshot_is_detached_and_restore_roundtrips():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("tex", kind="image", size=2048)
    tracker.release_to("tex", "compute", sequence=3)

    state = tracker.snapshot()
    assert set(state) == {"version", "resources", "pending", "barriers",
                          "last_submit", "stats"}
    pristine = copy.deepcopy(state)
    state["resources"].clear()
    state["stats"]["handoffs"] = 99
    assert tracker.stats()["handoffs"] == 0
    assert tracker.owner_of("tex") == "graphics"

    clone = qh.QueueFamilyHandoff()
    clone.restore(pristine)
    assert clone.owner_of("tex") == "graphics"
    assert clone.pending_owner("tex") == qh.PendingHandoff(
        "tex", "graphics", "compute", 3)
    assert clone.acquire_from("tex", "compute", sequence=4).owner == "compute"
    assert len(clone.handoff_barriers()) == 2


def test_restore_rejects_malformed_state_and_keeps_live_data():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("tex", kind="image", size=2048)
    tracker.release_to("tex", "compute", sequence=3)

    for broken in (None, {}, {"version": 1}):
        assert code_of(lambda: tracker.restore(broken)) == \
            "HANDOFF_SNAPSHOT_INVALID"
    assert tracker.owner_of("tex") == "graphics"
    assert tracker.pending_owner("tex") is not None


def test_concurrent_handoffs_keep_owners_and_barriers_consistent():
    tracker = qh.QueueFamilyHandoff()
    handles = [f"res-{index}" for index in range(8)]
    for handle in handles:
        tracker.register_resource(handle)
    errors = []
    barrier = threading.Barrier(len(handles))

    def worker(handle, index):
        target = "compute" if index % 2 == 0 else "transfer"
        try:
            barrier.wait(timeout=5)
            tracker.release_to(handle, target, sequence=index + 1)
            tracker.acquire_from(handle, target, sequence=index + 2)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(handle, index))
               for index, handle in enumerate(handles)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert [tracker.owner_of(handle) for handle in handles] == \
        ["compute", "transfer"] * 4
    assert len(tracker.handoff_barriers()) == 16
    assert tracker.stats()["handoffs"] == 8


def test_stats_counts_each_operation():
    tracker = qh.QueueFamilyHandoff()
    tracker.register_resource("a")
    tracker.register_resource("b")
    tracker.release_to("a", "compute", sequence=2)
    tracker.acquire_from("a", "compute", sequence=3)
    tracker.submit(3)
    tracker.release_to("b", "transfer", sequence=1)

    assert tracker.stats() == {"resources": 2, "handoffs": 1, "barriers": 3,
                               "submitted": 2, "rejected": 0}
    assert code_of(lambda: tracker.acquire_from(
        "b", "compute", sequence=2)) == "HANDOFF_FAMILY_MISMATCH"
    assert tracker.stats()["rejected"] == 1
    assert tracker.stats()["handoffs"] == 1
