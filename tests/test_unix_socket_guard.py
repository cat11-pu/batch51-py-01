import copy
import threading

import pytest

import unix_socket_guard as ug

NAME = "com.example.svc"


def guard(**kwargs):
    return ug.UnixSocketGuard(**kwargs)


def register(g, binding_id="svc-1", *, abstract=NAME, namespace="ns1",
             owner_uid=1000, owner_pid=4242, mode=0o600, dir_mode=0o755,
             path=None, now=100):
    return g.register(binding_id, namespace=namespace, owner_uid=owner_uid,
                      owner_pid=owner_pid, mode=mode, dir_mode=dir_mode,
                      abstract=abstract, path=path, now=now)


def peer(uid=1000, pid=5000, exe="/usr/bin/client"):
    return ug.PeerCred(pid=pid, uid=uid, gid=uid, exe=exe)


def test_register_abstract_binding_records_owner_and_lookup():
    g = guard()
    rec = register(g)
    assert (rec.binding_id, rec.namespace, rec.kind, rec.name) == (
        "svc-1", "ns1", "abstract", NAME)
    assert (rec.owner_uid, rec.owner_pid, rec.mode) == (1000, 4242, 0o600)
    assert rec.state == "registered"
    assert rec.bound_at is None and rec.expires_at is None
    assert g.lookup("ns1", NAME) == rec
    assert [row.binding_id for row in g.bindings()] == ["svc-1"]
    assert g.stats()["registered"] == 1


def test_register_requires_exactly_one_name():
    g = guard()
    with pytest.raises(ug.SocketError) as exc:
        register(g, "both", path="/run/svc.sock")
    assert exc.value.code == "SOCKET_INVALID_REQUEST"

    with pytest.raises(ug.SocketError) as exc:
        register(g, "neither", abstract=None, path=None)
    assert exc.value.code == "SOCKET_INVALID_REQUEST"
    assert g.bindings() == ()


def test_register_same_name_in_same_namespace_is_refused():
    g = guard()
    register(g, "svc-1")
    with pytest.raises(ug.SocketError) as exc:
        register(g, "svc-2")
    assert exc.value.code == "SOCKET_NAME_TAKEN"
    assert [row.binding_id for row in g.bindings()] == ["svc-1"]


def test_register_rejects_invalid_namespace_uid_and_mode():
    g = guard()
    with pytest.raises(ug.SocketError) as exc:
        register(g, "bad-ns", namespace="")
    assert exc.value.code == "SOCKET_INVALID_REQUEST"

    with pytest.raises(ug.SocketError) as exc:
        register(g, "bad-uid", owner_uid=-1)
    assert exc.value.code == "SOCKET_INVALID_REQUEST"

    with pytest.raises(ug.SocketError) as exc:
        register(g, "bad-mode", mode=0o666)
    assert exc.value.code == "SOCKET_MODE_INSECURE"

    with pytest.raises(ug.SocketError) as exc:
        register(g, "bad-path", abstract=None, path="run/svc.sock")
    assert exc.value.code == "SOCKET_INVALID_REQUEST"
    assert g.bindings() == ()


def test_bind_attaches_lease_to_registered_entry():
    g = guard(lease_ttl=30)
    register(g)
    rec = g.bind("svc-1", now=100)
    assert rec.state == "bound"
    assert rec.bound_at == 100
    assert rec.expires_at == 130
    assert g.stats()["binds"] == 1
    assert g.lookup("ns1", NAME).state == "bound"


def test_bind_twice_and_unknown_binding_are_refused():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    with pytest.raises(ug.SocketError) as exc:
        g.bind("svc-1", now=101)
    assert exc.value.code == "SOCKET_ALREADY_BOUND"

    with pytest.raises(ug.SocketError) as exc:
        g.bind("ghost", now=101)
    assert exc.value.code == "SOCKET_BINDING_UNKNOWN"
    assert g.stats()["binds"] == 1


def test_authorize_same_uid_is_allowed():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    decision = g.authorize("svc-1", peer(), now=110)
    assert (decision.status, decision.code) == ("allow", "")
    assert decision.binding_id == "svc-1"
    assert decision.peer_uid == 1000
    assert g.stats()["allowed"] == 1


def test_authorize_other_uid_is_denied():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    decision = g.authorize("svc-1", peer(uid=1001), now=110)
    assert (decision.status, decision.code) == ("deny", "PEER_NOT_PERMITTED")
    assert g.stats()["denied"] == 1
    assert g.stats()["allowed"] == 0


def test_authorize_unknown_binding_is_denied():
    g = guard()
    decision = g.authorize("ghost", peer(), now=110)
    assert (decision.status, decision.code) == ("deny", "BINDING_UNKNOWN")
    assert decision.peer_uid == 1000


def test_connect_opens_connection_and_verify_accepts_same_peer():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    client = peer()
    conn = g.connect("svc-1", client, now=110)
    assert conn.binding_id == "svc-1"
    assert conn.state == "open"
    assert conn.peer == client
    assert conn.opened_at == 110
    assert [row.conn_id for row in g.connections()] == [conn.conn_id]
    assert g.verify(conn.conn_id, client) == "open"
    assert g.stats()["connections"] == 1


def test_connect_with_foreign_uid_raises_and_creates_nothing():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    with pytest.raises(ug.SocketError) as exc:
        g.connect("svc-1", peer(uid=1001), now=110)
    assert exc.value.code == "PEER_NOT_PERMITTED"
    assert g.connections() == ()


def test_heartbeat_extends_lease_and_expire_reclaims_it():
    g = guard(lease_ttl=60)
    register(g)
    g.bind("svc-1", now=100)
    refreshed = g.heartbeat("svc-1", now=140)
    assert refreshed.expires_at == 200

    assert g.expire(199) == 0
    assert g.expire(200) == 1
    assert g.lookup("ns1", NAME) is None
    assert g.bindings() == ()
    assert g.stats()["expired"] == 1


def test_release_frees_name_for_reuse():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    assert g.release("svc-1") is True
    assert g.release("svc-1") is False
    assert g.lookup("ns1", NAME) is None
    assert g.stats()["released"] == 1

    again = register(g, "svc-2")
    assert again.state == "registered"
    assert [row.binding_id for row in g.bindings()] == ["svc-2"]


def test_snapshot_is_detached_restore_roundtrips_and_rejects_malformed():
    g = guard()
    register(g)
    g.bind("svc-1", now=100)
    client = peer()
    conn = g.connect("svc-1", client, now=110)

    state = g.snapshot()
    assert set(state) == {"version", "bindings", "connections", "counters"}
    pristine = copy.deepcopy(state)
    state["bindings"].clear()
    state["counters"]["registered"] = 99
    assert [row.binding_id for row in g.bindings()] == ["svc-1"]
    assert g.stats()["registered"] == 1

    before = g.stats()
    clone = guard()
    clone.restore(copy.deepcopy(pristine))
    assert clone.lookup("ns1", NAME).state == "bound"
    assert [row.conn_id for row in clone.connections()] == [conn.conn_id]
    assert clone.verify(conn.conn_id, client) == "open"
    assert clone.stats() == before

    bad_states = [
        None,
        {},
        {"version": 1, "bindings": [], "connections": {}, "counters": before},
        {"version": 1, "bindings": {}, "connections": {}, "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ug.SocketError) as exc:
            g.restore(bad)
        assert exc.value.code == "SOCKET_SNAPSHOT_INVALID"
    assert g.lookup("ns1", NAME) is not None


def test_concurrent_bind_has_single_winner():
    g = guard()
    register(g)
    workers = 8
    results = []
    errors = []
    barrier = threading.Barrier(workers)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(g.bind("svc-1", now=100))
        except ug.SocketError as exc:
            errors.append(exc.code)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 1
    assert results[0].state == "bound"
    assert errors == ["SOCKET_ALREADY_BOUND"] * (workers - 1)
    assert g.stats()["binds"] == 1
    assert g.lookup("ns1", NAME).expires_at == 160
