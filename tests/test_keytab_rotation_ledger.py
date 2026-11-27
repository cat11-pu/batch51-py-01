import copy
import threading

import pytest

import keytab_rotation_ledger as kt

T0 = "2026-11-27T10:00:00+00:00"
T1 = "2026-11-27T10:01:00+00:00"
T2 = "2026-11-27T10:02:00+00:00"
T5 = "2026-11-27T10:05:00+00:00"


def ledger(**kwargs):
    return kt.KeytabRotationLedger(**kwargs)


def seeded(**kwargs):
    instance = ledger(**kwargs)
    instance.register_principal(principal="HTTP/app", replicas=["r1", "r2"])
    return instance


def activate(instance, *, now=T0, request_id=None):
    rotation = instance.rotate(principal="HTTP/app", request_id=request_id, now=now)
    instance.distribute(principal="HTTP/app", version=rotation.version, now=now)
    for replica in ("r1", "r2"):
        instance.confirm(principal="HTTP/app", version=rotation.version,
                         replica_id=replica, now=now)
    return rotation


def test_register_principal_validates_and_rejects_duplicate():
    instance = seeded()
    with pytest.raises(kt.KeytabError) as exc:
        instance.register_principal(principal="HTTP/app", replicas=["r3"])
    assert exc.value.code == "KEYTAB_PRINCIPAL_EXISTS"

    with pytest.raises(kt.KeytabError) as exc:
        instance.register_principal(principal="HTTP/other", replicas=[])
    assert exc.value.code == "KEYTAB_REQUEST_INVALID"

    with pytest.raises(kt.KeytabError) as exc:
        instance.rotate(principal="HTTP/ghost", now=T0)
    assert exc.value.code == "KEYTAB_PRINCIPAL_UNKNOWN"


def test_rotate_creates_first_version_with_pending_replicas():
    instance = seeded()
    rotation = instance.rotate(principal="HTTP/app", now=T0)
    assert (rotation.principal, rotation.version, rotation.state) == (
        "HTTP/app", 1, "distributing")
    assert [row.replica_id for row in rotation.replicas] == ["r1", "r2"]
    assert {row.status for row in rotation.replicas} == {"pending"}
    assert rotation.created_at == T0
    assert instance.active_version("HTTP/app") is None
    assert instance.issuable_versions("HTTP/app") == ()
    assert instance.stats()["rotations"] == 1


def test_second_rotation_waits_for_first_activation():
    instance = seeded()
    instance.rotate(principal="HTTP/app", now=T0)
    with pytest.raises(kt.KeytabError) as exc:
        instance.rotate(principal="HTTP/app", now=T0)
    assert exc.value.code == "KEYTAB_ROTATION_IN_FLIGHT"

    activate(instance)
    second = instance.rotate(principal="HTTP/app", now=T2)
    assert second.version == 2
    assert instance.stats()["rotations"] == 2


def test_distribute_marks_replicas_and_is_single_shot():
    instance = seeded()
    rotation = instance.rotate(principal="HTTP/app", now=T0)
    rows = instance.distribute(principal="HTTP/app", version=1, now=T0)
    assert [(row.replica_id, row.status) for row in rows] == [
        ("r1", "distributed"), ("r2", "distributed")]

    with pytest.raises(kt.KeytabError) as exc:
        instance.distribute(principal="HTTP/app", version=1, now=T0)
    assert exc.value.code == "KEYTAB_STATE_INVALID"
    assert rotation.version == 1


def test_confirm_before_distribute_and_unknown_replica():
    instance = seeded()
    instance.rotate(principal="HTTP/app", now=T0)
    with pytest.raises(kt.KeytabError) as exc:
        instance.confirm(principal="HTTP/app", version=1, replica_id="r1", now=T0)
    assert exc.value.code == "KEYTAB_NOT_DISTRIBUTED"

    instance.distribute(principal="HTTP/app", version=1, now=T0)
    with pytest.raises(kt.KeytabError) as exc:
        instance.confirm(principal="HTTP/app", version=1,
                         replica_id="r9", now=T0)
    assert exc.value.code == "KEYTAB_REPLICA_UNKNOWN"
    assert instance.active_version("HTTP/app") is None


def test_all_confirmations_activate_version():
    instance = seeded()
    instance.rotate(principal="HTTP/app", now=T0)
    instance.distribute(principal="HTTP/app", version=1, now=T0)

    halfway = instance.confirm(principal="HTTP/app", version=1,
                              replica_id="r1", now=T1)
    assert halfway.state == "distributed"
    assert instance.active_version("HTTP/app") is None

    done = instance.confirm(principal="HTTP/app", version=1,
                            replica_id="r2", now=T1)
    assert done.state == "active"
    assert instance.active_version("HTTP/app") == 1
    assert instance.issuable_versions("HTTP/app") == (1,)
    assert instance.verifiable_versions("HTTP/app") == (1,)
    assert instance.stats()["activations"] == 1


def test_version_numbers_advance_across_activations():
    instance = seeded()
    activate(instance, now=T0)
    activate(instance, now=T2, request_id="req-second")
    assert instance.stats()["rotations"] == 2
    assert instance.active_version("HTTP/app") == 2
    assert instance.issuable_versions("HTTP/app") == (2,)


def test_duplicate_request_id_returns_same_version():
    instance = seeded()
    first = instance.rotate(principal="HTTP/app", request_id="req-1", now=T0)
    again = instance.rotate(principal="HTTP/app", request_id="req-1", now=T1)
    assert again.version == first.version == 1
    assert again.replicas == first.replicas
    assert instance.stats()["rotations"] == 1
    assert instance.stats()["idempotent_hits"] == 1


def test_concurrent_same_request_yields_single_version():
    instance = seeded()
    versions = []
    errors = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            rotation = instance.rotate(principal="HTTP/app",
                                       request_id="req-parallel", now=T0)
            versions.append(rotation.version)
        except kt.KeytabError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert set(versions) == {1}
    assert instance.stats()["rotations"] == 1
    assert instance.stats()["idempotent_hits"] == 9


def test_retire_drops_retained_version_at_retention_boundary():
    instance = seeded(retention=600)
    activate(instance, now=T0)
    activate(instance, now=T2, request_id="req-second")
    assert instance.active_version("HTTP/app") == 2

    assert instance.retire(principal="HTTP/app",
                           now="2026-11-27T10:09:59+00:00") == 0
    assert instance.retire(principal="HTTP/app",
                           now="2026-11-27T10:10:00+00:00") == 1
    assert instance.verifiable_versions("HTTP/app") == (2,)
    assert instance.stats()["retired"] == 1


def test_retire_refuses_active_and_non_retained_versions():
    instance = seeded()
    activate(instance, now=T0)
    with pytest.raises(kt.KeytabError) as exc:
        instance.retire(principal="HTTP/app", version=1, now=T1)
    assert exc.value.code == "KEYTAB_ACTIVE_RETIRE"

    instance.rotate(principal="HTTP/app", now=T2, request_id="req-next")
    with pytest.raises(kt.KeytabError) as exc:
        instance.retire(principal="HTTP/app", version=2, now=T2)
    assert exc.value.code == "KEYTAB_STATE_INVALID"

    with pytest.raises(kt.KeytabError) as exc:
        instance.retire(principal="HTTP/app", version=99, now=T2)
    assert exc.value.code == "KEYTAB_VERSION_UNKNOWN"


def test_snapshot_restore_preserves_rotation_state():
    instance = seeded()
    activate(instance, now=T0)
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "principals", "stats"}
    state["stats"]["rotations"] = 99

    clone = ledger()
    clone.restore(pristine)
    assert clone.active_version("HTTP/app") == 1
    assert clone.issuable_versions("HTTP/app") == (1,)
    follow_up = clone.rotate(principal="HTTP/app", now=T5)
    assert follow_up.version == 2
    assert follow_up.state == "distributing"
    assert clone.stats()["rotations"] == 2


def test_snapshot_is_detached_from_live_state():
    instance = seeded()
    activate(instance, now=T0)
    state = instance.snapshot()
    state["principals"].clear()
    state["stats"]["activations"] = 99
    assert instance.active_version("HTTP/app") == 1
    assert instance.stats()["activations"] == 1


def test_restore_rejects_malformed_state_without_mutating_live_data():
    instance = seeded()
    activate(instance, now=T0)
    bad_states = [
        None,
        {},
        {"version": 2, "principals": {}, "stats": {}},
        {"version": 1, "principals": [], "stats": {}},
        {"version": 1, "principals": {}, "stats": {"rotations": 1}},
        {"version": 1, "principals": {"HTTP/app": []}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(kt.KeytabError) as exc:
            instance.restore(bad)
        assert exc.value.code == "KEYTAB_SNAPSHOT_INVALID"

    assert instance.active_version("HTTP/app") == 1
    assert instance.stats()["activations"] == 1


def test_stats_track_rotation_lifecycle():
    instance = seeded()
    first = instance.rotate(principal="HTTP/app", request_id="req-1", now=T0)
    instance.rotate(principal="HTTP/app", request_id="req-1", now=T0)
    instance.distribute(principal="HTTP/app", version=first.version, now=T0)
    instance.confirm(principal="HTTP/app", version=first.version,
                     replica_id="r1", now=T1)
    instance.confirm(principal="HTTP/app", version=first.version,
                     replica_id="r2", now=T1)
    instance.rotate(principal="HTTP/app", now=T2)
    assert instance.stats() == {"rotations": 2, "activations": 1,
                               "retired": 0, "idempotent_hits": 1,
                               "confirm_failures": 0}
