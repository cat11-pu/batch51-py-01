import threading

import pytest

import modbus_write_guard as mw

NOW = 1000


def guard(**kwargs):
    return mw.ModbusWriteGuard(**kwargs)


def add_device(g, device_id="dev-1", slave_id=1, readable=(0, 99),
               writable=(100, 199), function_codes=(5, 6, 16)):
    return g.register_device(device_id, slave_id=slave_id, tenant="t1",
                             readable=readable, writable=writable,
                             function_codes=function_codes)


def request(**overrides):
    base = {
        "client_id": "c1",
        "request_id": "r1",
        "seq": 1,
        "device_id": "dev-1",
        "function_code": 16,
        "address": 100,
        "count": 2,
        "values": [7, 8],
    }
    base.update(overrides)
    return base


def test_register_device_normalizes_and_rejects_duplicate():
    g = guard()
    record = add_device(g, function_codes=(16, 6))
    assert record.function_codes == (6, 16)
    assert record.readable == (0, 99)
    assert record.writable == (100, 199)
    assert record.tenant == "t1"
    assert g.device_record("dev-1") == record

    with pytest.raises(mw.ModbusError) as dup:
        add_device(g)
    assert dup.value.code == "MODBUS_DEVICE_EXISTS"

    with pytest.raises(mw.ModbusError) as bad:
        add_device(g, device_id="dev-2", readable=(50, 10))
    assert bad.value.code == "MODBUS_DEVICE_INVALID"
    assert g.device_record("dev-2") is None


def test_admit_on_unknown_device_raises():
    g = guard()
    with pytest.raises(mw.ModbusError) as exc:
        g.admit(request(device_id="ghost"), now=NOW)
    assert exc.value.code == "MODBUS_UNKNOWN_DEVICE"
    assert g.stats()["denied"] == 0
    assert g.stats()["admitted"] == 0


def test_write_function_outside_whitelist_gets_illegal_function():
    g = guard()
    add_device(g, function_codes=(16,))
    out = g.admit(request(function_code=6, count=1, values=[1]), now=NOW)
    assert out.allowed is False
    assert out.exception_code == 1
    assert out.registers == ()
    assert g.pending_for("c1") == ()
    assert g.stats()["denied"] == 1
    assert g.stats()["admitted"] == 0


def test_admit_allowed_returns_register_window_and_frame():
    g = guard()
    add_device(g)
    out = g.admit(request(count=3, values=[1, 2, 3]), now=NOW)
    assert out.allowed is True
    assert out.exception_code == 0
    assert out.registers == (100, 101, 102)
    assert out.replayed is False
    assert out.values == (1, 2, 3)
    assert g.pending_for("c1") == ("r1",)
    assert g.translate("r1") == {
        "slave_id": 1,
        "function_code": 16,
        "address": 100,
        "count": 3,
        "values": (1, 2, 3),
        "exception_code": 0,
    }


def test_write_count_over_limit_is_denied():
    g = guard(max_registers_per_write=2)
    add_device(g)
    out = g.admit(request(count=3, values=[1, 2, 3]), now=NOW)
    assert out.allowed is False
    assert out.exception_code == 3
    assert out.registers == ()
    assert g.stats()["denied"] == 1
    assert g.pending_for("c1") == ()


def test_value_shape_errors_use_illegal_data_value():
    g = guard()
    add_device(g)
    short = g.admit(request(count=2, values=[1]), now=NOW)
    wide = g.admit(request(request_id="r2", seq=2, count=1, values=[70000]), now=NOW)
    assert short.allowed is False and short.exception_code == 3
    assert wide.allowed is False and wide.exception_code == 3
    assert g.stats()["denied"] == 2
    assert g.stats()["admitted"] == 0
    assert g.pending_for("c1") == ()


def test_commit_writes_values_and_runs_only_once():
    g = guard()
    add_device(g)
    g.admit(request(count=3, values=[11, 12, 13]), now=NOW)
    assert g.commit("r1", now=NOW) == 3
    assert g.device_values("dev-1") == {100: 11, 101: 12, 102: 13}
    assert g.pending_for("c1") == ()
    with pytest.raises(mw.ModbusError) as exc:
        g.commit("r1", now=NOW)
    assert exc.value.code == "MODBUS_REQUEST_COMMITTED"
    assert g.stats()["committed"] == 1
    assert g.stats()["registers_written"] == 3


def test_commit_of_denied_or_unknown_request_raises():
    g = guard()
    add_device(g, function_codes=(16,))
    g.admit(request(function_code=6, count=1, values=[1]), now=NOW)
    with pytest.raises(mw.ModbusError) as denied:
        g.commit("r1", now=NOW)
    assert denied.value.code == "MODBUS_REQUEST_DENIED"
    with pytest.raises(mw.ModbusError) as unknown:
        g.commit("r404", now=NOW)
    assert unknown.value.code == "MODBUS_UNKNOWN_REQUEST"
    assert g.stats()["committed"] == 0
    assert g.device_values("dev-1") == {}


def test_commit_with_older_sequence_is_rejected():
    g = guard()
    add_device(g)
    g.admit(request(request_id="new", seq=5, count=1, values=[11]), now=NOW)
    g.admit(request(request_id="old", seq=3, address=100, count=1, values=[22]), now=NOW)
    assert g.commit("new", now=NOW) == 1
    with pytest.raises(mw.ModbusError) as exc:
        g.commit("old", now=NOW)
    assert exc.value.code == "MODBUS_STALE_SEQUENCE"
    assert g.device_values("dev-1") == {100: 11}
    assert g.stats()["registers_written"] == 1


def test_rollback_restores_previous_values_and_is_idempotent():
    g = guard()
    add_device(g)
    g.admit(request(seq=1, count=2, values=[5, 6]), now=NOW)
    g.commit("r1", now=NOW)
    assert g.rollback("r1", now=NOW) is True
    assert g.device_values("dev-1") == {}
    assert g.rollback("r1", now=NOW) is False
    assert g.stats()["rolled_back"] == 1
    assert g.stats()["registers_written"] == 2


def test_exception_log_is_per_device_and_ordered_by_sequence():
    g = guard()
    add_device(g, function_codes=(16,))
    add_device(g, device_id="dev-2", slave_id=2, readable=(0, 9),
               writable=(10, 19), function_codes=(16,))
    g.admit(request(request_id="r5", seq=5, count=99, values=[1]), now=NOW)
    g.admit(request(request_id="r3", seq=3, function_code=6, count=1, values=[1]), now=NOW)
    g.admit(request(request_id="r7", seq=7, count=1, values=[70000]), now=NOW)
    g.admit(request(request_id="d1", seq=1, device_id="dev-2",
                     function_code=6, address=10, count=1, values=[1]), now=NOW)
    assert g.exception_log("dev-1") == (("r3", 1), ("r5", 3), ("r7", 3))
    assert g.exception_log("dev-2") == (("d1", 1),)
    assert g.exception_log("dev-9") == ()


def test_stats_count_each_operation():
    g = guard()
    add_device(g, function_codes=(16,))
    g.admit(request(count=2, values=[1, 2]), now=NOW)
    g.admit(request(request_id="r2", seq=2, function_code=6, count=1, values=[1]), now=NOW)
    g.commit("r1", now=NOW)
    g.rollback("r1", now=NOW)
    assert g.stats() == {
        "admitted": 1,
        "denied": 1,
        "committed": 1,
        "rolled_back": 1,
        "registers_written": 2,
        "replayed": 0,
        "expired": 0,
    }


def test_snapshot_restore_resumes_pending_admission():
    g = guard()
    add_device(g)
    g.admit(request(count=2, values=[4, 5]), now=NOW)
    state = g.snapshot()
    assert set(state) == {"version", "devices", "admissions", "values",
                          "seq_marks", "stats"}
    state["admissions"].clear()
    assert g.pending_for("c1") == ("r1",)

    clone = guard()
    clone.restore(g.snapshot())
    assert clone.stats() == g.stats()
    assert clone.device_values("dev-1") == {}
    assert clone.device_record("dev-1").writable == (100, 199)
    assert clone.commit("r1", now=NOW) == 2
    assert clone.device_values("dev-1") == {100: 4, 101: 5}


def test_restore_rejects_malformed_state_without_touching_live_data():
    g = guard()
    add_device(g)
    g.admit(request(count=1, values=[9]), now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "devices": {}, "admissions": {}, "values": {},
         "seq_marks": {}, "stats": {}},
        {"version": 1, "devices": [], "admissions": {}, "values": {},
         "seq_marks": {}, "stats": {}},
        {"version": 1, "devices": {}, "admissions": [], "values": {},
         "seq_marks": {}, "stats": {}},
        {"version": 1, "devices": {}, "admissions": {}, "values": {},
         "seq_marks": {}},
    ]
    for bad in bad_states:
        with pytest.raises(mw.ModbusError) as exc:
            g.restore(bad)
        assert exc.value.code == "MODBUS_SNAPSHOT_INVALID"
    assert g.pending_for("c1") == ("r1",)
    assert g.stats()["admitted"] == 1


def test_concurrent_commits_keep_every_register():
    g = guard()
    add_device(g, writable=(100, 199))
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            g.admit(request(request_id=f"r{index}", seq=index + 1,
                            address=100 + index, count=1, values=[index]),
                    now=NOW)
            g.commit(f"r{index}", now=NOW)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.device_values("dev-1") == {100 + index: index for index in range(12)}
    assert g.stats()["committed"] == 12
    assert g.stats()["registers_written"] == 12
