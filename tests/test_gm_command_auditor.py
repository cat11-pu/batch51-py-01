import pytest

import gm_command_auditor as gm


def auditor(**kwargs):
    obj = gm.GmCommandAuditor(**kwargs)
    obj.grant_role("alice", "gm_operator")
    obj.grant_role("bob", "gm_approver")
    obj.register_command("give-item", required_role="gm_operator",
                         kind="grant_item", max_targets=3)
    return obj


def submitted(obj, request_id="r1", **overrides):
    kwargs = dict(operator="alice", reviewer="bob",
                  params={"item": "sword", "count": 1},
                  targets=("t1", "t2", "t3"), reason="活动补偿", at_ms=1_000)
    kwargs.update(overrides)
    return obj.submit(request_id, "give-item", **kwargs)


def approved(obj, request_id="r1"):
    submitted(obj, request_id=request_id)
    obj.authorize(request_id, at_ms=2_000)
    return request_id


def test_register_command_validates_and_rejects_duplicate():
    obj = gm.GmCommandAuditor()
    spec = obj.register_command("give-item", required_role="gm_operator",
                                kind="grant_item", max_targets=3)
    assert (spec.command_id, spec.kind, spec.max_targets) == ("give-item", "grant_item", 3)
    with pytest.raises(gm.GmError) as exc:
        obj.register_command("give-item", required_role="gm_operator", kind="grant_item")
    assert exc.value.code == "GM_COMMAND_EXISTS"
    with pytest.raises(gm.GmError) as exc:
        obj.register_command("bad", required_role="gm_operator", kind="teleport")
    assert exc.value.code == "GM_INVALID_COMMAND"
    with pytest.raises(gm.GmError) as exc:
        obj.register_command("bad", required_role="nobody", kind="grant_item")
    assert exc.value.code == "GM_INVALID_COMMAND"


def test_submit_rejects_unknown_command():
    obj = auditor()
    with pytest.raises(gm.GmError) as exc:
        obj.submit("r1", "no-such-command", operator="alice", reviewer="bob",
                   params={}, targets=("t1",), reason="x", at_ms=1_000)
    assert exc.value.code == "GM_UNKNOWN_COMMAND"
    assert obj.pending_approvals() == ()


def test_submit_requires_reason():
    obj = auditor()
    with pytest.raises(gm.GmError) as exc:
        submitted(obj, reason="   ")
    assert exc.value.code == "GM_REASON_REQUIRED"
    assert obj.stats()["requests"] == 0


def test_submit_requires_operator_role():
    obj = auditor()
    with pytest.raises(gm.GmPermissionError) as exc:
        submitted(obj, operator="mallory")
    assert exc.value.code == "GM_FORBIDDEN"
    assert obj.stats()["requests"] == 0
    assert obj.stats()["denied"] == 1


def test_submit_is_idempotent_by_request_id():
    obj = auditor()
    first = submitted(obj)
    assert first["status"] == "pending_approval"
    second = submitted(obj, targets=("t9",))
    assert second["status"] == "duplicate"
    assert obj.stats()["requests"] == 1
    assert obj.pending_approvals() == ("r1",)
    assert obj.request_of("r1").targets == ("t1", "t2", "t3")


def test_authorize_requires_reviewer():
    obj = auditor()
    with pytest.raises(gm.GmPermissionError) as exc:
        submitted(obj, reviewer="")
    assert exc.value.code == "GM_REVIEWER_REQUIRED"
    assert obj.pending_approvals() == ()


def test_authorize_requires_qualified_reviewer():
    obj = auditor()
    obj.grant_role("carol", "gm_operator")
    with pytest.raises(gm.GmPermissionError) as exc:
        submitted(obj, reviewer="carol")
    assert exc.value.code == "GM_REVIEWER_NOT_QUALIFIED"
    assert obj.pending_approvals() == ()


def test_authorize_approves_and_clears_pending():
    obj = auditor()
    submitted(obj)
    out = obj.authorize("r1", at_ms=2_000)
    assert out["status"] == "approved"
    assert out["reviewer"] == "bob"
    assert obj.pending_approvals() == ()
    assert obj.request_of("r1").status == "approved"
    assert obj.stats()["approved"] == 1
    with pytest.raises(gm.GmError) as exc:
        obj.authorize("r1", at_ms=2_500)
    assert exc.value.code == "GM_ALREADY_AUTHORIZED"


def test_dry_run_requires_approval():
    obj = auditor()
    submitted(obj)
    with pytest.raises(gm.GmPermissionError) as exc:
        obj.dry_run("r1", at_ms=2_000)
    assert exc.value.code == "GM_NOT_APPROVED"
    assert obj.stats()["executed"] == 0


def test_dry_run_is_read_only_and_reports_targets():
    obj = auditor()
    approved(obj)
    preview = obj.dry_run("r1", at_ms=3_000)
    assert preview["command_id"] == "give-item"
    assert preview["targets"] == ("t1", "t2", "t3")
    assert preview["count"] == 3
    assert isinstance(preview["digest"], str) and preview["digest"]
    again = obj.dry_run("r1", at_ms=3_500)
    assert again["digest"] == preview["digest"]
    assert obj.request_of("r1").status == "approved"
    assert obj.stats()["executed"] == 0
    assert obj.stats()["applied"] == 0


def test_execute_applies_every_target_in_submit_order():
    obj = auditor()
    approved(obj)
    out = obj.execute("r1", at_ms=3_000)
    assert out["status"] == "executed"
    assert out["applied"] == ("t1", "t2", "t3")
    assert out["failed"] == ()
    assert obj.request_of("r1").status == "executed"
    assert obj.stats()["executed"] == 1
    assert obj.stats()["applied"] == 3


def test_execute_is_idempotent_by_request_id():
    obj = auditor()
    approved(obj)
    first = obj.execute("r1", at_ms=3_000)
    second = obj.execute("r1", at_ms=4_000)
    assert second["status"] == "duplicate"
    assert second["applied"] == first["applied"]
    assert obj.stats()["executed"] == 1
    assert obj.stats()["applied"] == 3


def test_rollback_plan_reverts_applied_targets_in_reverse():
    obj = auditor()
    submitted(obj)
    with pytest.raises(gm.GmError) as exc:
        obj.rollback_plan("r1")
    assert exc.value.code == "GM_NOT_EXECUTED"
    obj.authorize("r1", at_ms=2_000)
    obj.execute("r1", at_ms=3_000)
    plan = obj.rollback_plan("r1")
    assert tuple(op["target"] for op in plan) == ("t3", "t2", "t1")
    assert all(op["op"] == "revert" for op in plan)
    assert all(op["command_id"] == "give-item" for op in plan)


def test_audit_log_is_capped_and_ordered():
    obj = auditor(max_log=3)
    approved(obj)
    obj.dry_run("r1", at_ms=3_000)
    obj.execute("r1", at_ms=4_000)
    entries = obj.audit_log()
    assert len(entries) == 3
    assert tuple(entry["phase"] for entry in entries) == ("authorized", "dry_run", "executed")
    assert tuple(entry["seq"] for entry in entries) == (2, 3, 4)
    assert list(obj.audit_log(limit=1)) == [entries[-1]]
    assert obj.audit_log(request_id="r1") == entries
    assert obj.stats()["log_entries"] == 3


def test_snapshot_restore_roundtrip_and_malformed_rejection():
    obj = auditor()
    approved(obj)
    obj.dry_run("r1", at_ms=3_000)
    state = obj.snapshot()

    clone = gm.GmCommandAuditor()
    clone.restore(state)
    assert clone.request_of("r1").status == "approved"
    assert clone.stats() == obj.stats()
    assert len(clone.audit_log()) == 3
    assert clone.audit_log()[0]["phase"] == "submitted"
    assert clone.pending_approvals() == ()

    with pytest.raises(gm.GmError) as exc:
        clone.restore({"version": 1})
    assert exc.value.code == "GM_SNAPSHOT_INVALID"
    assert clone.request_of("r1").status == "approved"
