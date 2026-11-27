import copy
import threading

import pytest

import unix_peer_cred_gate as gate_mod

CRED = dict(pid=4242, uid=1000, gid=1000, start_time=9000,
            user_ns="user-ns:7", pid_ns="pid-ns:7")


def new_gate(**kwargs):
    return gate_mod.UnixPeerCredGate(**kwargs)


def tenant(gate, name="t1", *, uids=(1000,), user_ns="user-ns:7",
           pid_ns="pid-ns:7", processes=((4242, 9000),)):
    gate.register_tenant(name, uids=uids, user_ns=user_ns, pid_ns=pid_ns,
                         processes=processes)


def accept(gate, connection_id="c1", **overrides):
    connection_id = overrides.pop("connection_id", connection_id)
    payload = dict(CRED)
    payload.update(overrides)
    return gate.accept_connection(connection_id, **payload)


def test_register_tenant_normalizes_and_rejects_duplicates():
    gate = new_gate()
    tenant(gate, uids=(1002, 1001, 1001), processes=((20, 2000), (10, 1000)))
    assert gate.tenant_config("t1") is not None
    assert gate.tenant_config("t9") is None

    bad_calls = [
        dict(tenant="", uids=(1000,), user_ns="user-ns:7", pid_ns="pid-ns:7"),
        dict(tenant="t2", uids=(), user_ns="user-ns:7", pid_ns="pid-ns:7"),
        dict(tenant="t2", uids=(1000, -1), user_ns="user-ns:7",
             pid_ns="pid-ns:7"),
        dict(tenant="t2", uids=(1000,), user_ns="", pid_ns="pid-ns:7"),
        dict(tenant="t2", uids=(1000,), user_ns="user-ns:7", pid_ns="  "),
        dict(tenant="t2", uids=(1000,), user_ns="user-ns:7",
             pid_ns="pid-ns:7", processes=((0, 10),)),
    ]
    for kwargs in bad_calls:
        name = kwargs.pop("tenant")
        with pytest.raises(gate_mod.PeerCredError) as exc:
            gate.register_tenant(name, **kwargs)
        assert exc.value.code == "PEER_INVALID_REQUEST"

    with pytest.raises(gate_mod.PeerCredError) as exc:
        tenant(gate)
    assert exc.value.code == "PEER_TENANT_EXISTS"
    assert gate.stats()["refused"] == 7
    assert gate.stats()["accepted"] == 0


def test_accept_connection_freezes_credential_fields():
    gate = new_gate()
    cred = accept(gate)
    assert isinstance(cred, gate_mod.PeerCredential)
    assert (cred.connection_id, cred.pid, cred.uid, cred.gid, cred.start_time,
            cred.user_ns, cred.pid_ns) == ("c1", 4242, 1000, 1000, 9000,
                                           "user-ns:7", "pid-ns:7")
    assert gate.snapshot_cred("c1") == cred
    assert gate.snapshot_cred("missing") is None
    assert gate.open_connections() == ("c1",)
    assert gate.stats()["accepted"] == 1


def test_accept_connection_rejects_duplicate_and_capacity():
    gate = new_gate(max_connections=1)
    accept(gate)
    with pytest.raises(gate_mod.PeerCredError) as exc:
        accept(gate)
    assert exc.value.code == "PEER_CONNECTION_EXISTS"
    with pytest.raises(gate_mod.PeerCredError) as exc:
        accept(gate, connection_id="c2")
    assert exc.value.code == "PEER_CAPACITY_EXCEEDED"
    assert gate.open_connections() == ("c1",)
    assert gate.stats()["accepted"] == 1
    assert gate.stats()["refused"] == 2


def test_accept_connection_validates_credential_fields():
    gate = new_gate()
    bad_overrides = [
        dict(connection_id=""),
        dict(pid=0),
        dict(uid=-1),
        dict(gid=-5),
        dict(start_time=0),
        dict(user_ns=""),
        dict(pid_ns=""),
    ]
    for overrides in bad_overrides:
        with pytest.raises(gate_mod.PeerCredError) as exc:
            accept(gate, **overrides)
        assert exc.value.code == "PEER_INVALID_REQUEST"
    assert gate.open_connections() == ()
    assert gate.stats()["accepted"] == 0
    assert gate.stats()["refused"] == len(bad_overrides)


def test_verify_allows_trusted_peer_with_mapping():
    gate = new_gate()
    tenant(gate)
    gate.add_id_mapping(pid_ns="pid-ns:7", inner_pid=7, outer_pid=4242)
    accept(gate)
    out = gate.verify_peer("c1", tenant="t1")
    assert out.status == "allowed"
    assert out.reason == "PEER_TRUSTED"
    assert out.mapped_pid == 7
    assert out.credential == gate.snapshot_cred("c1")
    again = gate.verify_peer("c1", tenant="t1")
    assert (again.status, again.reason, again.mapped_pid) == (
        "allowed", "PEER_TRUSTED", 7)
    assert gate.stats()["allowed"] == 2
    assert gate.stats()["rejected"] == 0


def test_verify_rejects_uid_mismatch():
    gate = new_gate()
    tenant(gate)
    gate.add_id_mapping(pid_ns="pid-ns:7", inner_pid=7, outer_pid=4242)
    accept(gate, uid=1001)
    out = gate.verify_peer("c1", tenant="t1")
    assert out.status == "rejected"
    assert out.reason == "PEER_UID_MISMATCH"
    assert out.mapped_pid is None
    assert out.credential.uid == 1001
    assert gate.stats()["rejected"] == 1


def test_verify_rejects_user_namespace_mismatch():
    gate = new_gate()
    tenant(gate)
    accept(gate, user_ns="user-ns:8")
    out = gate.verify_peer("c1", tenant="t1")
    assert out.status == "rejected"
    assert out.reason == "PEER_USER_NS_MISMATCH"
    assert gate.stats()["rejected"] == 1
    assert gate.stats()["allowed"] == 0


def test_verify_rejects_pid_namespace_and_process_start_mismatch():
    gate = new_gate()
    tenant(gate)
    accept(gate, connection_id="c1", pid_ns="pid-ns:8")
    accept(gate, connection_id="c2", start_time=9001)
    first = gate.verify_peer("c1", tenant="t1")
    second = gate.verify_peer("c2", tenant="t1")
    assert (first.status, first.reason) == ("rejected", "PEER_PID_NS_MISMATCH")
    assert (second.status, second.reason) == ("rejected",
                                              "PEER_PROCESS_MISMATCH")
    assert gate.stats()["rejected"] == 2


def test_verify_rejects_unknown_connection_and_unknown_tenant():
    gate = new_gate()
    tenant(gate)
    unknown = gate.verify_peer("ghost", tenant="t1")
    assert unknown.status == "rejected"
    assert unknown.reason == "PEER_UNKNOWN_CONNECTION"
    assert unknown.credential is None
    assert unknown.mapped_pid is None
    accept(gate)
    other = gate.verify_peer("c1", tenant="no-such-tenant")
    assert (other.status, other.reason) == ("rejected", "PEER_UNKNOWN_TENANT")
    assert gate.stats()["rejected"] == 2
    assert gate.stats()["allowed"] == 0


def test_close_connection_is_idempotent_and_keeps_frozen_record():
    gate = new_gate()
    tenant(gate)
    cred = accept(gate)
    assert gate.close_connection("c1") is True
    assert gate.close_connection("c1") is False
    assert gate.close_connection("ghost") is False
    assert gate.snapshot_cred("c1") == cred
    assert gate.open_connections() == ()
    out = gate.verify_peer("c1", tenant="t1")
    assert (out.status, out.reason) == ("rejected", "PEER_CONNECTION_CLOSED")
    assert gate.stats()["closed"] == 1


def test_id_mapping_is_per_namespace_and_rejects_conflicts():
    gate = new_gate()
    gate.add_id_mapping(pid_ns="pid-ns:9", inner_pid=5, outer_pid=500)
    assert gate.map_ids(pid_ns="pid-ns:9", outer_pid=500) == 5
    gate.add_id_mapping(pid_ns="pid-ns:9", inner_pid=5, outer_pid=500)
    with pytest.raises(gate_mod.PeerCredError) as exc:
        gate.add_id_mapping(pid_ns="pid-ns:9", inner_pid=6, outer_pid=500)
    assert exc.value.code == "PEER_MAPPING_CONFLICT"
    assert gate.map_ids(pid_ns="pid-ns:9", outer_pid=500) == 5
    gate.add_id_mapping(pid_ns="pid-ns:10", inner_pid=55, outer_pid=500)
    assert gate.map_ids(pid_ns="pid-ns:10", outer_pid=500) == 55
    assert gate.stats()["refused"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    gate = new_gate()
    tenant(gate)
    gate.add_id_mapping(pid_ns="pid-ns:7", inner_pid=7, outer_pid=4242)
    accept(gate, connection_id="c1")
    accept(gate, connection_id="c2", uid=1000, start_time=9000)
    gate.close_connection("c2")
    state = gate.snapshot()
    assert set(state) == {"version", "tenants", "connections", "mappings",
                          "stats"}
    pristine = copy.deepcopy(state)
    state["connections"].clear()
    state["stats"]["accepted"] = 99
    assert gate.snapshot_cred("c1").pid == 4242
    assert gate.stats()["accepted"] == 2

    clone = new_gate()
    clone.restore(pristine)
    assert clone.snapshot_cred("c1").start_time == 9000
    assert clone.open_connections() == ("c1",)
    assert clone.verify_peer("c1", tenant="t1").status == "allowed"
    assert clone.snapshot_cred("c2") is not None
    assert clone.map_ids(pid_ns="pid-ns:7", outer_pid=4242) == 7
    assert clone.stats()["accepted"] == 2
    assert clone.stats()["closed"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    gate = new_gate()
    tenant(gate)
    accept(gate)
    good = gate.snapshot()

    bad_states = [None, {}]
    case = copy.deepcopy(good)
    case["version"] = 3
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["tenants"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["connections"] = {"c1": {"pid": 1}}
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["mappings"] = {"pid-ns:7": [[1, 2]]}
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["stats"].pop("allowed")
    bad_states.append(case)

    for bad in bad_states:
        with pytest.raises(gate_mod.PeerCredError) as exc:
            gate.restore(bad)
        assert exc.value.code == "PEER_SNAPSHOT_INVALID"

    assert gate.snapshot_cred("c1").pid == 4242
    assert gate.open_connections() == ("c1",)
    assert gate.stats()["accepted"] == 1


def test_concurrent_accepts_are_unique():
    gate = new_gate(max_connections=16)
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            accept(gate, connection_id=f"c{index:02d}")
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert gate.open_connections() == tuple(f"c{index:02d}"
                                            for index in range(12))
    assert gate.stats()["accepted"] == 12


def test_stats_track_each_verification_outcome():
    gate = new_gate()
    tenant(gate)
    gate.add_id_mapping(pid_ns="pid-ns:7", inner_pid=7, outer_pid=4242)
    accept(gate, connection_id="c1")
    accept(gate, connection_id="c2", uid=1001)
    assert gate.verify_peer("c1", tenant="t1").status == "allowed"
    assert gate.verify_peer("c2", tenant="t1").status == "rejected"
    assert gate.close_connection("c1") is True
    assert gate.verify_peer("c1", tenant="t1").status == "rejected"
    with pytest.raises(gate_mod.PeerCredError):
        accept(gate, connection_id="c2")
    assert gate.stats() == {"accepted": 2, "closed": 1, "allowed": 1,
                            "rejected": 2, "unverifiable": 0, "refused": 1}
