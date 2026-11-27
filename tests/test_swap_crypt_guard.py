import copy
import threading

import pytest

import swap_crypt_guard as sg

CIPHER = "aes-xts-plain64"
OTHER_CIPHER = "aes-cbc-essiv:sha256"


def guard(**kwargs):
    return sg.SwapCryptGuard(**kwargs)


def test_enable_creates_active_device_record():
    g = guard()
    state = g.enable("sda2", size_pages=1024, key_id="k1",
                     cipher=CIPHER, resume_offset=512, now=1000)
    assert state.device == "sda2"
    assert state.state == "enabled"
    assert state.key_id == "k1"
    assert state.cipher == CIPHER
    assert state.size_pages == 1024
    assert state.resume_offset == 512
    assert state.generation == 1
    assert state.dirty_pages == 0
    assert g.devices() == ("sda2",)
    assert g.stats()["enables"] == 1


def test_enable_rejects_invalid_parameters():
    g = guard()
    bad_calls = [
        dict(size_pages=0, key_id="k1", cipher=CIPHER, resume_offset=0),
        dict(size_pages=16, key_id="", cipher=CIPHER, resume_offset=0),
        dict(size_pages=16, key_id="k1", cipher="", resume_offset=0),
        dict(size_pages=16, key_id="k1", cipher=CIPHER, resume_offset=16),
        dict(size_pages=16, key_id="k1", cipher=CIPHER, resume_offset=-1),
    ]
    for kwargs in bad_calls:
        with pytest.raises(sg.SwapError) as exc:
            g.enable("sda2", now=1000, **kwargs)
        assert exc.value.code == "SWAP_INVALID_REQUEST"
    assert g.devices() == ()
    assert g.stats()["enables"] == 0


def test_devices_are_sorted_and_status_rejects_unknown_device():
    g = guard()
    g.enable("sdb1", size_pages=2048, key_id="k2",
             cipher=OTHER_CIPHER, resume_offset=0, now=1000)
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1001)
    assert g.devices() == ("sda2", "sdb1")
    assert g.status("sda2").key_id == "k1"
    assert g.status("sdb1").cipher == OTHER_CIPHER

    with pytest.raises(sg.SwapError) as exc:
        g.status("sdz9")
    assert exc.value.code == "SWAP_DEVICE_UNKNOWN"


def test_disable_clears_key_and_is_idempotent():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)

    state = g.disable("sda2", now=1100)
    assert state.state == "disabled"
    assert state.key_id is None
    assert state.cipher is None
    assert state.generation == 2
    assert g.stats()["zeroized"] == 1
    assert g.stats()["disables"] == 1
    assert g.pending_writeback() == {}

    again = g.disable("sda2", now=1200)
    assert again.state == "disabled"
    assert again.generation == 2
    assert g.stats()["disables"] == 1
    assert g.stats()["zeroized"] == 1


def test_disable_unknown_device_is_refused():
    g = guard()
    with pytest.raises(sg.SwapError) as exc:
        g.disable("sdz9", now=1000)
    assert exc.value.code == "SWAP_DEVICE_UNKNOWN"
    assert g.stats()["disables"] == 0


def test_rotate_key_swaps_after_drain_when_clean():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)

    state = g.rotate_key("sda2", new_key_id="k2", now=1100)
    assert state.state == "enabled"
    assert state.key_id == "k2"
    assert state.cipher == CIPHER
    assert state.generation == 2
    assert g.stats()["rotations"] == 1


def test_rotate_to_key_used_elsewhere_is_refused():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    g.enable("sdb1", size_pages=1024, key_id="k2",
             cipher=CIPHER, resume_offset=0, now=1000)

    with pytest.raises(sg.SwapError) as exc:
        g.rotate_key("sda2", new_key_id="k2", now=1100)
    assert exc.value.code == "SWAP_KEY_CONFLICT"
    assert g.status("sda2").key_id == "k1"
    assert g.stats()["rotations"] == 0


def test_enable_with_key_bound_to_another_device_is_refused():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    with pytest.raises(sg.SwapError) as exc:
        g.enable("sdb1", size_pages=1024, key_id="k1",
                 cipher=CIPHER, resume_offset=0, now=1000)
    assert exc.value.code == "SWAP_KEY_CONFLICT"
    assert g.devices() == ("sda2",)


def test_resume_with_matching_image_succeeds():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    assert g.resume("sda2", image_device="sda2", image_offset=512) is True
    assert g.stats()["resumes"] == 1
    assert g.status("sda2").state == "enabled"


def test_resume_requires_known_enabled_device():
    g = guard()
    with pytest.raises(sg.SwapError) as exc:
        g.resume("sdz9", image_device="sdz9", image_offset=0)
    assert exc.value.code == "SWAP_DEVICE_UNKNOWN"

    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    g.disable("sda2", now=1100)
    with pytest.raises(sg.SwapError) as exc:
        g.resume("sda2", image_device="sda2", image_offset=512)
    assert exc.value.code == "SWAP_NOT_ENABLED"
    assert g.stats()["resumes"] == 0


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    g.enable("sdb1", size_pages=2048, key_id="k2",
             cipher=OTHER_CIPHER, resume_offset=0, now=1000)

    state = g.snapshot()
    assert set(state) == {"version", "devices", "counters"}
    pristine = copy.deepcopy(state)
    state["devices"].clear()
    state["counters"]["enables"] = 99
    assert g.devices() == ("sda2", "sdb1")
    assert g.stats()["enables"] == 2

    before = g.stats()
    clone = guard()
    clone.restore(copy.deepcopy(pristine))
    assert clone.devices() == ("sda2", "sdb1")
    assert clone.status("sda2").key_id == "k1"
    assert clone.status("sdb1").resume_offset == 0
    assert clone.stats() == before
    assert clone.resume("sda2", image_device="sda2", image_offset=512) is True


def test_restore_rejects_malformed_state_without_touching_live_data():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    bad_states = [
        None,
        {},
        {"version": 1, "devices": [], "counters": g.stats()},
        {"version": 1, "devices": {}, "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(sg.SwapError) as exc:
            g.restore(bad)
        assert exc.value.code == "SWAP_SNAPSHOT_INVALID"

    assert g.devices() == ("sda2",)
    assert g.status("sda2").key_id == "k1"


def test_recover_leaves_clean_snapshot_untouched():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    clone = guard()
    clone.restore(copy.deepcopy(g.snapshot()))

    assert clone.recover() == ()
    assert clone.stats()["recovered"] == 0
    assert clone.status("sda2").state == "enabled"
    assert clone.status("sda2").key_id == "k1"


def test_stats_track_each_lifecycle_operation():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=0, now=1000)
    g.enable("sdb1", size_pages=2048, key_id="k2",
             cipher=OTHER_CIPHER, resume_offset=0, now=1000)
    g.disable("sdb1", now=1100)
    assert g.stats() == {"enables": 2, "disables": 1, "rotations": 0,
                         "resumes": 0, "idempotent": 0, "deferred": 0,
                         "zeroized": 1, "recovered": 0}


def test_concurrent_disable_has_single_winner():
    g = guard()
    g.enable("sda2", size_pages=1024, key_id="k1",
             cipher=CIPHER, resume_offset=512, now=1000)
    workers = 8
    results = []
    errors = []
    barrier = threading.Barrier(workers)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(g.disable("sda2", now=1100))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == workers
    assert {row.state for row in results} == {"disabled"}
    assert {row.generation for row in results} == {2}
    assert g.stats()["disables"] == 1
    assert g.stats()["zeroized"] == 1
