import threading

import pytest

import frame_capture_scheduler as fc

NOW = "2026-11-27T11:00:00+00:00"
LATER = "2026-11-27T11:00:05+00:00"


def scheduler(**kwargs):
    return fc.FrameCaptureScheduler(**kwargs)


def feed(sched, start, end, *, payload=1000, now=NOW):
    metas = []
    for frame_no in range(start, end + 1):
        metas.append(sched.on_frame(frame_no, payload_size=payload, now=now))
    return metas


def test_default_config_and_arm_validation():
    sched = scheduler()
    config = sched.arm(pre_frames=5, post_frames=2, ring_size=32)
    assert config == {"ring_size": 32, "pre_frames": 5, "post_frames": 2,
                      "max_active": 2, "min_interval_frames": 0,
                      "max_bytes": 8_000_000}
    for bad in ({"pre_frames": -1}, {"post_frames": -3}, {"ring_size": 0}):
        with pytest.raises(fc.CaptureError) as exc:
            sched.arm(**bad)
        assert exc.value.code == "CAPTURE_INVALID_ARGUMENT"
    assert sched.arm() == config


def test_on_frame_validates_order_and_payload():
    sched = scheduler(ring_size=8)
    sched.on_frame(10, payload_size=100, now=NOW)
    sched.on_frame(11, payload_size=100, now=NOW)
    with pytest.raises(fc.CaptureError) as exc:
        sched.on_frame(11, payload_size=100, now=NOW)
    assert exc.value.code == "CAPTURE_FRAME_ORDER"
    with pytest.raises(fc.CaptureError) as exc:
        sched.on_frame(9, payload_size=100, now=NOW)
    assert exc.value.code == "CAPTURE_FRAME_ORDER"
    with pytest.raises(fc.CaptureError) as exc:
        sched.on_frame("12", payload_size=100, now=NOW)
    assert exc.value.code == "CAPTURE_INVALID_ARGUMENT"
    with pytest.raises(fc.CaptureError) as exc:
        sched.on_frame(12, payload_size=-1, now=NOW)
    assert exc.value.code == "CAPTURE_INVALID_ARGUMENT"


def test_ring_buffer_keeps_only_recent_frames():
    sched = scheduler(ring_size=4)
    feed(sched, 0, 9)
    assert sched.ring_frames() == (6, 7, 8, 9)
    assert sched.stats()["frames"] == 10
    assert sched.stats()["dropped_frames"] == 6


def test_trigger_claims_pre_roll_window():
    sched = scheduler(ring_size=32, pre_frames=3, post_frames=2)
    feed(sched, 90, 100)
    ticket = sched.trigger("gpu-hang", now=NOW)
    assert ticket.capture_id == "cap-1"
    assert ticket.reason == "gpu-hang"
    assert ticket.trigger_frame == 100
    assert ticket.first_frame == 97
    assert ticket.last_frame == 102
    assert ticket.status == "recording"
    assert sched.capture_of("cap-1") == ticket
    assert sched.active_captures() == (ticket,)


def test_capture_becomes_ready_after_post_frames():
    sched = scheduler(ring_size=32, pre_frames=3, post_frames=2)
    feed(sched, 90, 100)
    sched.trigger("gpu-hang", now=NOW)
    sched.on_frame(101, payload_size=1000, now=NOW)
    assert sched.capture_of("cap-1").status == "recording"
    sched.on_frame(102, payload_size=1000, now=NOW)
    assert sched.capture_of("cap-1").status == "ready"
    record = sched.finalize("cap-1", now=LATER)
    assert record.capture_id == "cap-1"
    assert record.first_frame == 97
    assert record.last_frame == 102
    assert record.frame_count == 6
    assert record.finalized_at == LATER


def test_second_trigger_skips_frames_claimed_by_first():
    sched = scheduler(ring_size=32, pre_frames=2, post_frames=1,
                      max_active=3, min_interval_frames=0)
    feed(sched, 95, 100)
    first = sched.trigger("gpu-hang", now=NOW)
    assert (first.first_frame, first.last_frame) == (98, 101)
    sched.on_frame(101, payload_size=1000, now=NOW)
    sched.on_frame(102, payload_size=1000, now=NOW)
    second = sched.trigger("shader-stall", now=NOW)
    assert (second.first_frame, second.last_frame) == (102, 103)
    sched.on_frame(103, payload_size=1000, now=NOW)
    record = sched.finalize("cap-2", now=LATER)
    assert record.frame_count == 2
    assert record.first_frame == 102


def test_duplicate_trigger_on_same_frame_is_rejected():
    sched = scheduler(ring_size=16, pre_frames=1, post_frames=2, max_active=4)
    feed(sched, 40, 42)
    sched.trigger("first", now=NOW)
    with pytest.raises(fc.CaptureError) as exc:
        sched.trigger("second", now=NOW)
    assert exc.value.code == "CAPTURE_FRAME_CLAIMED"
    assert len(sched.captures()) == 1


def test_finalize_requires_ready_and_runs_once():
    sched = scheduler(ring_size=16, pre_frames=1, post_frames=2)
    feed(sched, 10, 12)
    sched.trigger("gpu-hang", now=NOW)
    with pytest.raises(fc.CaptureError) as exc:
        sched.finalize("cap-1", now=NOW)
    assert exc.value.code == "CAPTURE_NOT_READY"
    feed(sched, 13, 14)
    record = sched.finalize("cap-1", now=LATER)
    assert record.frame_count == 4
    with pytest.raises(fc.CaptureError) as exc:
        sched.finalize("cap-1", now=LATER)
    assert exc.value.code == "CAPTURE_ALREADY_FINALIZED"
    assert sched.stats()["finalized"] == 1


def test_finalize_sums_included_frame_bytes():
    sched = scheduler(ring_size=16, pre_frames=1, post_frames=1)
    sched.on_frame(100, payload_size=111, now=NOW)
    sched.on_frame(101, payload_size=222, now=NOW)
    sched.trigger("gpu-hang", now=NOW)
    sched.on_frame(102, payload_size=333, now=NOW)
    record = sched.finalize("cap-1", now=LATER)
    assert record.frame_count == 3
    assert record.bytes_total == 666


def test_mask_regions_are_reported_on_export():
    sched = scheduler(ring_size=16, pre_frames=1, post_frames=0)
    feed(sched, 20, 21)
    assert sched.mask_region(x=0, y=0, width=100, height=50) == 1
    assert sched.mask_region(x=10, y=10, width=20, height=20) == 2
    with pytest.raises(fc.CaptureError) as exc:
        sched.mask_region(x=0, y=0, width=0, height=50)
    assert exc.value.code == "CAPTURE_INVALID_ARGUMENT"
    sched.trigger("privacy-report", now=NOW)
    record = sched.finalize("cap-1", now=LATER)
    assert record.masks_applied == 2
    assert record.masked_regions == ((0, 0, 100, 50), (10, 10, 20, 20))


def test_pre_roll_is_clipped_to_the_ring():
    sched = scheduler(ring_size=8, pre_frames=20, post_frames=0)
    feed(sched, 90, 100)
    ticket = sched.trigger("gpu-hang", now=NOW)
    assert ticket.first_frame == 93
    assert ticket.last_frame == 100
    record = sched.finalize("cap-1", now=LATER)
    assert record.frame_count == 8


def test_byte_budget_rejects_oversized_capture():
    sched = scheduler(ring_size=16, pre_frames=2, post_frames=2,
                      max_bytes=10_000)
    feed(sched, 100, 105, payload=4000)
    with pytest.raises(fc.CaptureError) as exc:
        sched.trigger("gpu-hang", now=NOW)
    assert exc.value.code == "CAPTURE_QUOTA_EXCEEDED"
    assert sched.active_captures() == ()
    assert sched.ring_frames() == (100, 101, 102, 103, 104, 105)
    assert sched.stats()["rejected"] == 1


def test_snapshot_restore_roundtrip_and_malformed():
    sched = scheduler(ring_size=16, pre_frames=2, post_frames=1)
    feed(sched, 10, 12)
    sched.trigger("gpu-hang", now=NOW)
    sched.mask_region(x=1, y=2, width=3, height=4)
    state = sched.snapshot()
    assert set(state) == {"version", "config", "ring", "captures",
                          "claimed", "masks", "counters"}

    state["ring"].clear()
    state["captures"].clear()
    assert sched.ring_frames() == (10, 11, 12)
    assert sched.capture_of("cap-1").status == "recording"

    pristine = sched.snapshot()
    clone = scheduler()
    clone.restore(pristine)
    assert clone.capture_of("cap-1").status == "recording"
    assert clone.ring_frames() == (10, 11, 12)
    clone.on_frame(13, payload_size=1000, now=NOW)
    assert clone.capture_of("cap-1").status == "ready"
    record = clone.finalize("cap-1", now=LATER)
    assert record.frame_count == 4
    assert record.masks_applied == 1

    for bad in (None, {},
                {"version": 2, "config": {}, "ring": {}, "captures": {},
                 "claimed": [], "masks": [], "counters": {}},
                {"version": 1, "config": {}, "ring": {}, "captures": {},
                 "claimed": [], "masks": []}):
        with pytest.raises(fc.CaptureError) as exc:
            clone.restore(bad)
        assert exc.value.code == "CAPTURE_SNAPSHOT_INVALID"
    assert clone.capture_of("cap-1").status == "ready"


def test_stats_track_frames_captures_and_rejections():
    sched = scheduler(ring_size=16, pre_frames=1, post_frames=1)
    feed(sched, 0, 2)
    sched.trigger("gpu-hang", now=NOW)
    sched.mask_region(x=0, y=0, width=8, height=8)
    with pytest.raises(fc.CaptureError):
        sched.trigger("again", now=NOW)
    sched.on_frame(3, payload_size=1000, now=NOW)
    sched.finalize("cap-1", now=LATER)
    assert sched.stats() == {"frames": 3, "captures": 1, "finalized": 1,
                             "rejected": 1, "dropped_frames": 0, "merged": 0,
                             "masks": 1}


def test_concurrent_triggers_claim_a_frame_once():
    sched = scheduler(ring_size=16, pre_frames=1, post_frames=0, max_active=8)
    feed(sched, 0, 5)
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(sched.trigger("gpu-hang", now=NOW))
        except fc.CaptureError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 1
    assert errors == ["CAPTURE_FRAME_CLAIMED"] * 7
    assert len(sched.captures()) == 1
    assert sched.stats()["captures"] == 1
    assert sched.stats()["rejected"] == 7
