import copy
import threading

import pytest

import guardian_recovery_quorum as gq

T0 = 1_800_000_000
HOUR = 3600
DAY = 86400


def quorum(**kwargs):
    return gq.GuardianRecoveryQuorum(**kwargs)


def seeded(account="acct-1", names=("g1", "g2", "g3"), **kwargs):
    q = quorum(**kwargs)
    for name in names:
        q.add_guardian(account, name)
    return q


def test_guardian_registry_keeps_sorted_unique_members():
    q = quorum()
    assert q.add_guardian("acct-1", "g2") is True
    assert q.add_guardian("acct-1", "g1") is True
    assert q.add_guardian("acct-1", "g2") is False
    assert q.guardians("acct-1") == ("g1", "g2")
    assert q.remove_guardian("acct-1", "g1") is True
    assert q.remove_guardian("acct-1", "g1") is False
    assert q.guardians("acct-1") == ("g2",)
    assert q.guardians("acct-unknown") == ()


def test_case_needs_enough_guardians_and_starts_wait_window():
    q = seeded(names=("g1", "g2"), threshold=3)
    with pytest.raises(gq.GuardianError) as exc:
        q.open_case("acct-1", case_id="case-1", at=T0)
    assert exc.value.code == "GUARD_INSUFFICIENT_GUARDIANS"
    q.add_guardian("acct-1", "g3")
    view = q.open_case("acct-1", case_id="case-1", at=T0, requested_by="acct-1")
    assert view.status == "collecting"
    assert view.opened_at == T0
    assert view.waiting_until == T0 + DAY
    assert view.approvals == 0
    assert view.settled_at is None
    assert q.stats()["cases_opened"] == 1


def test_open_case_rejects_possible_conflicts():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    with pytest.raises(gq.GuardianError) as exc:
        q.open_case("acct-1", case_id="case-2", at=T0 + 10)
    assert exc.value.code == "GUARD_CASE_CONFLICT"
    q.add_guardian("acct-2", "g5")
    q.add_guardian("acct-2", "g6")
    with pytest.raises(gq.GuardianError) as exc:
        q.open_case("acct-2", case_id="case-1", at=T0 + 10)
    assert exc.value.code == "GUARD_CASE_EXISTS"


def test_approval_from_non_guardian_is_refused():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    out = q.cast_approval("case-1", guardian="intruder", ticket_id="tk-1",
                          device_id="dev-a", at=T0 + 60)
    assert out.accepted is False
    assert out.code == "GUARD_NOT_GUARDIAN"
    assert out.approvals == 0
    assert q.case_state("case-1").approvals == 0


def test_approvals_accumulate_until_quorum():
    q = seeded(names=("g1", "g2", "g3"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    first = q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                            device_id="dev-a", at=T0 + 60)
    assert first.accepted is True
    assert first.code == "GUARD_TICKET_ACCEPTED"
    assert first.approvals == 1
    assert first.threshold == 2
    assert first.quorum_met is False
    second = q.cast_approval("case-1", guardian="g2", ticket_id="tk-2",
                             device_id="dev-b", at=T0 + 120)
    assert second.approvals == 2
    assert second.quorum_met is True
    view = q.case_state("case-1")
    assert view.approvals == 2
    assert view.status == "collecting"
    assert q.stats()["approvals"] == 2


def test_finalize_before_window_keeps_case_open():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                    device_id="dev-a", at=T0 + 60)
    q.cast_approval("case-1", guardian="g2", ticket_id="tk-2",
                    device_id="dev-b", at=T0 + 120)
    early = q.finalize_case("case-1", at=T0 + DAY - 1)
    assert early.status == "collecting"
    assert early.reason == "GUARD_WAIT_PENDING"
    assert early.settled_at is None
    assert q.recovery_epoch("acct-1") == 0
    assert q.stats()["settled"] == 0


def test_finalize_after_window_approves_and_bumps_epoch():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                    device_id="dev-a", at=T0 + 60)
    q.cast_approval("case-1", guardian="g2", ticket_id="tk-2",
                    device_id="dev-b", at=T0 + 120)
    settled = q.finalize_case("case-1", at=T0 + DAY)
    assert settled.status == "approved"
    assert settled.reason == "GUARD_QUORUM_MET"
    assert settled.approvals == 2
    assert settled.settled_at == T0 + DAY
    assert q.recovery_epoch("acct-1") == 1
    assert q.login_frozen("acct-1", at=T0 + DAY + 1) is False
    assert q.stats()["approved"] == 1
    assert q.stats()["settled"] == 1


def test_finalize_after_window_without_quorum_rejects():
    q = seeded(names=("g1", "g2", "g3"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                    device_id="dev-a", at=T0 + 60)
    settled = q.finalize_case("case-1", at=T0 + DAY)
    assert settled.status == "rejected"
    assert settled.reason == "GUARD_QUORUM_SHORT"
    assert q.recovery_epoch("acct-1") == 0
    assert q.login_frozen("acct-1", at=T0 + DAY + 1) is False
    assert q.stats()["rejected"] == 1


def test_objection_voids_case_and_tickets():
    q = seeded(names=("g1", "g2", "g3"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                    device_id="dev-a", at=T0 + 60)
    q.cast_approval("case-1", guardian="g2", ticket_id="tk-2",
                    device_id="dev-b", at=T0 + 120)
    view = q.cast_objection("case-1", guardian="g3", at=T0 + 180,
                            note="call back first")
    assert view.status == "voided"
    assert view.objections == 1
    assert view.approvals == 0
    assert q.login_frozen("acct-1", at=T0 + 181) is False
    settled = q.finalize_case("case-1", at=T0 + DAY)
    assert settled.status == "rejected"
    assert settled.reason == "GUARD_OBJECTED"
    assert q.recovery_epoch("acct-1") == 0
    assert q.stats()["objections"] == 1


def test_login_freeze_follows_case_lifecycle():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0, requested_by="acct-1")
    assert q.login_frozen("acct-1", at=T0 + HOUR) is True
    assert q.login_frozen("acct-other", at=T0 + HOUR) is False
    with pytest.raises(gq.GuardianError) as exc:
        q.cancel_case("case-1", actor="someone-else", at=T0 + 600)
    assert exc.value.code == "GUARD_NOT_APPLICANT"
    cancelled = q.cancel_case("case-1", actor="acct-1", at=T0 + 900)
    assert cancelled.status == "cancelled"
    assert cancelled.settled_at == T0 + 900
    assert q.login_frozen("acct-1", at=T0 + 901) is False
    assert q.stats()["cancelled"] == 1


def test_unknown_case_is_refused():
    q = seeded(names=("g1", "g2"))
    with pytest.raises(gq.GuardianError) as exc:
        q.cast_approval("case-x", guardian="g1", ticket_id="tk-1",
                        device_id="dev-a", at=T0)
    assert exc.value.code == "GUARD_UNKNOWN_CASE"
    with pytest.raises(gq.GuardianError) as exc:
        q.case_state("case-x")
    assert exc.value.code == "GUARD_UNKNOWN_CASE"
    with pytest.raises(gq.GuardianError) as exc:
        q.finalize_case("case-x", at=T0)
    assert exc.value.code == "GUARD_UNKNOWN_CASE"


def test_ticket_value_cannot_be_reused_across_cases():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    assert q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                           device_id="dev-a", at=T0 + 60).accepted
    q.cancel_case("case-1", actor="acct-1", at=T0 + 120)
    q.open_case("acct-1", case_id="case-2", at=T0 + 200)
    out = q.cast_approval("case-2", guardian="g1", ticket_id="tk-1",
                          device_id="dev-a", at=T0 + 260)
    assert out.accepted is False
    assert out.code == "GUARD_TICKET_REUSED"
    assert out.approvals == 0


def test_snapshot_is_detached_and_restore_roundtrips():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                    device_id="dev-a", at=T0 + 60)
    state = q.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "guardians", "cases", "tickets",
                             "epochs", "stats"}
    state["guardians"].clear()
    state["cases"].clear()
    state["stats"]["approvals"] = 99
    assert q.stats()["approvals"] == 1
    assert q.guardians("acct-1") == ("g1", "g2")
    clone = quorum()
    clone.restore(pristine)
    assert clone.stats() == q.stats()
    assert clone.guardians("acct-1") == ("g1", "g2")
    assert clone.case_state("case-1").approvals == 1
    assert clone.login_frozen("acct-1", at=T0 + 100) is True
    assert clone.cast_approval("case-1", guardian="g2", ticket_id="tk-2",
                               device_id="dev-b", at=T0 + 200).accepted is True


def test_restore_rejects_malformed_state():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    bad_states = [
        None,
        {},
        {"version": 2, "guardians": {}, "cases": {}, "tickets": [],
         "epochs": {}, "stats": {}},
        {"version": 1, "guardians": [], "cases": {}, "tickets": [],
         "epochs": {}, "stats": {}},
        {"version": 1, "guardians": {}, "cases": [], "tickets": [],
         "epochs": {}, "stats": {}},
        {"version": 1, "guardians": {}, "cases": {}, "tickets": {},
         "epochs": {}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(gq.GuardianError) as exc:
            q.restore(bad)
        assert exc.value.code == "GUARD_SNAPSHOT_INVALID"
    assert q.guardians("acct-1") == ("g1", "g2")
    assert q.case_state("case-1").status == "collecting"


def test_concurrent_finalize_settles_case_once():
    q = seeded(names=("g1", "g2"))
    q.open_case("acct-1", case_id="case-1", at=T0)
    q.cast_approval("case-1", guardian="g1", ticket_id="tk-1",
                    device_id="dev-a", at=T0 + 60)
    q.cast_approval("case-1", guardian="g2", ticket_id="tk-2",
                    device_id="dev-b", at=T0 + 120)
    results = []
    errors = []
    barrier = threading.Barrier(4)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(q.finalize_case("case-1", at=T0 + DAY).status)
        except gq.GuardianError as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count("approved") == 1
    assert errors == ["GUARD_CASE_CLOSED"] * 3
    assert q.recovery_epoch("acct-1") == 1
    assert q.stats()["settled"] == 1
    assert q.stats()["approved"] == 1
