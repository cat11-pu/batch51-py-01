import pytest

import proc_identity_pinner as pi


def row(pid, start, *, ns="ns-a", state="running",
        exe="/bin/app", cwd="/srv/app"):
    return {"pid": pid, "start_time": start, "namespace": ns, "state": state,
            "exe": exe, "cwd": cwd}


def loaded(*rows, **kwargs):
    pn = pi.ProcIdentityPinner(**kwargs)
    pn.ingest_proc_table(list(rows))
    return pn


def test_pin_builds_handle_with_identity_triple():
    pn = loaded(row(4100, 9001), row(4101, 9002, exe="/bin/other", cwd="/srv/other"))
    first = pn.pin(4100, owner="ops-a", now=100)
    second = pn.pin(4101, owner="ops-a", now=100)
    assert first.handle_id == "h-1"
    assert second.handle_id == "h-2"
    assert (first.pid, first.start_time, first.namespace) == (4100, 9001, "ns-a")
    assert first.owner == "ops-a"
    assert first.state == "live"


def test_pin_unknown_pid_is_refused():
    pn = loaded(row(4100, 9001))
    with pytest.raises(pi.ProcError) as excinfo:
        pn.pin(9999)
    assert excinfo.value.code == "PROC_UNKNOWN_PID"
    assert pn.stats()["pins"] == 0
    assert pn.handles_for("default") == []


def test_resolve_returns_paths_for_matching_triple():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    out = pn.resolve(handle.handle_id, now=120)
    assert out.handle_id == "h-1"
    assert (out.pid, out.start_time, out.namespace) == (4100, 9001, "ns-a")
    assert out.exe == "/bin/app"
    assert out.cwd == "/srv/app"
    assert out.available is True


def test_pid_reuse_marks_handle_stale():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    pn.ingest_proc_table([row(4100, 7777)])
    with pytest.raises(pi.ProcError) as excinfo:
        pn.resolve(handle.handle_id)
    assert excinfo.value.code == "PROC_HANDLE_STALE"
    assert excinfo.value.detail == "pid_reused"
    assert pn.invalid_reason(handle.handle_id) == "pid_reused"
    assert pn.still_alive(handle.handle_id) is False
    assert pn.stats()["stale"] == 1


def test_pid_gone_from_table_is_not_alive():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    pn.ingest_proc_table([row(4101, 9100)])
    assert pn.still_alive(handle.handle_id) is False
    assert pn.invalid_reason(handle.handle_id) == "process_gone"
    with pytest.raises(pi.ProcError) as excinfo:
        pn.resolve(handle.handle_id)
    assert excinfo.value.detail == "process_gone"


def test_release_reports_second_call_false():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    assert pn.release(handle.handle_id) is True
    assert pn.release(handle.handle_id) is False
    assert pn.invalid_reason(handle.handle_id) == "released"
    with pytest.raises(pi.ProcError) as excinfo:
        pn.resolve(handle.handle_id)
    assert excinfo.value.code == "PROC_HANDLE_STALE"
    assert excinfo.value.detail == "released"


def test_release_owner_keeps_other_owners():
    pn = loaded(row(4100, 9001), row(4101, 9002))
    first = pn.pin(4100, owner="scan")
    second = pn.pin(4101, owner="audit")
    assert pn.release_owner("scan") == 1
    assert pn.still_alive(first.handle_id) is False
    assert pn.still_alive(second.handle_id) is True
    assert pn.handles_for("scan") == []
    assert pn.handles_for("audit") == [second.handle_id]


def test_handle_cap_evicts_oldest_idle_handle():
    pn = loaded(row(4100, 9001), row(4101, 9002), row(4102, 9003),
                max_handles=2)
    first = pn.pin(4100, now=10)
    second = pn.pin(4101, now=20)
    pn.resolve(first.handle_id, now=30)
    third = pn.pin(4102, now=40)
    assert third.handle_id == "h-3"
    assert pn.invalid_reason(second.handle_id) == "evicted"
    assert pn.still_alive(first.handle_id) is True
    assert pn.stats()["evictions"] == 1
    assert len(pn.handles_for("default")) == 2


def test_reap_idle_uses_last_use():
    pn = loaded(row(4100, 9001), row(4101, 9002), idle_timeout=30)
    first = pn.pin(4100, now=0)
    second = pn.pin(4101, now=0)
    pn.resolve(second.handle_id, now=20)
    assert pn.reap_idle(now=31) == 1
    assert pn.invalid_reason(first.handle_id) == "idle_reaped"
    assert pn.still_alive(second.handle_id) is True
    assert pn.stats()["reaped"] == 1


def test_invalid_reason_is_none_while_live():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    assert pn.invalid_reason(handle.handle_id) is None
    with pytest.raises(pi.ProcError) as excinfo:
        pn.invalid_reason("h-404")
    assert excinfo.value.code == "PROC_HANDLE_UNKNOWN"


def test_reingest_same_triple_refreshes_paths():
    pn = loaded(row(4100, 9001, exe="/bin/old", cwd="/srv/old"))
    handle = pn.pin(4100)
    pn.ingest_proc_table([row(4100, 9001, exe="/bin/new", cwd="/srv/new")])
    out = pn.resolve(handle.handle_id)
    assert out.exe == "/bin/new"
    assert out.cwd == "/srv/new"
    assert pn.still_alive(handle.handle_id) is True


def test_stats_track_operations():
    pn = loaded(row(4100, 9001), row(4101, 9002))
    first = pn.pin(4100, now=5)
    second = pn.pin(4101, now=5)
    pn.resolve(first.handle_id, now=6)
    pn.release(second.handle_id, now=7)
    stats = pn.stats()
    assert stats["pins"] == 2
    assert stats["releases"] == 1
    assert stats["stale"] == 0
    assert stats["pids_ingested"] == 2
    assert stats["live_handles"] == 1


def test_snapshot_restore_round_trip_is_deep():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100, owner="audit", now=50)
    pn.resolve(handle.handle_id, now=55)
    state = pn.snapshot()
    pn.release(handle.handle_id)
    assert pn.still_alive(handle.handle_id) is False
    pn.restore(state)
    assert pn.still_alive(handle.handle_id) is True
    assert pn.stats()["releases"] == 0
    state["stats"]["pins"] = 999
    assert pn.stats()["pins"] == 1


def test_restore_rejects_broken_state_and_keeps_current():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    with pytest.raises(pi.ProcError) as excinfo:
        pn.restore({"processes": [], "handles": [{"handle_id": "h-1"}]})
    assert excinfo.value.code == "PROC_SNAPSHOT_INVALID"
    assert pn.still_alive(handle.handle_id) is True


def test_ingest_rejects_malformed_table_without_touching_state():
    pn = loaded(row(4100, 9001))
    handle = pn.pin(4100)
    with pytest.raises(pi.ProcError) as excinfo:
        pn.ingest_proc_table([{"pid": "x", "start_time": 1, "namespace": "ns-a",
                               "state": "running", "exe": "/bin/app",
                               "cwd": "/"}])
    assert excinfo.value.code == "PROC_TABLE_INVALID"
    assert pn.still_alive(handle.handle_id) is True
