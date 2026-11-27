import copy
import threading

import pytest

import access_review_campaign as ar

NOW = 1000
LATER = 1200


def campaign(**kwargs):
    return ar.AccessReviewCampaign(**kwargs)


def seed_subject(camp, subject, resources, *, now=NOW):
    rows = []
    for resource in resources:
        rows.append(camp.add_entitlement(subject, resource, now=now))
    return rows


def open_review(camp, *, campaign_id="cmp-1", subjects=("alice",),
                reviewers=("r1", "r2"), now=NOW):
    return camp.open_campaign(campaign_id, subjects=list(subjects),
                              reviewers=list(reviewers), now=now)


def assign_all(camp, *, campaign_id="cmp-1", reviewer="r1", now=NOW):
    ids = list(camp.campaign(campaign_id).entitlement_ids)
    return camp.assign(campaign_id, reviewer=reviewer,
                       entitlement_ids=ids, now=now)


def test_add_entitlement_uses_sequential_ids_and_filters_by_subject():
    camp = campaign()
    first = camp.add_entitlement("alice", "s3://fin", now=NOW)
    second = camp.add_entitlement("bob", "db:payroll", now=NOW)
    assert first.entitlement_id == "ent-0001"
    assert second.entitlement_id == "ent-0002"
    assert first.active is True
    assert [(row.entitlement_id, row.subject) for row in camp.entitlements()] == [
        ("ent-0001", "alice"),
        ("ent-0002", "bob"),
    ]
    assert camp.entitlements("alice") == [first]
    assert camp.entitlements("carol") == []
    assert camp.stats()["entitlements_added"] == 2


def test_duplicate_or_blank_entitlement_is_rejected():
    camp = campaign()
    camp.add_entitlement("alice", "s3://fin", now=NOW)
    with pytest.raises(ar.CampaignError) as exc:
        camp.add_entitlement("alice", "s3://fin", now=NOW)
    assert exc.value.code == "CAMPAIGN_ENTITLEMENT_EXISTS"
    with pytest.raises(ar.CampaignError) as exc:
        camp.add_entitlement("  ", "s3://fin", now=NOW)
    assert exc.value.code == "CAMPAIGN_INVALID_REQUEST"
    with pytest.raises(ar.CampaignError) as exc:
        camp.add_entitlement("alice", "", now=NOW)
    assert exc.value.code == "CAMPAIGN_INVALID_REQUEST"
    assert len(camp.entitlements()) == 1


def test_open_campaign_freezes_matching_entitlements():
    camp = campaign()
    camp.add_entitlement("alice", "repo:read", now=NOW)
    camp.add_entitlement("alice", "repo:write", now=NOW)
    camp.add_entitlement("bob", "repo:read", now=NOW)
    view = open_review(camp)
    assert view.status == "open"
    assert view.snapshot_version == 1
    assert view.entitlement_ids == ("ent-0001", "ent-0002")
    assert view.opened_at == NOW
    assert view.closed_at is None
    assert view.pending_count == 2
    assert view.decided_count == 0
    assert camp.stats()["campaigns_opened"] == 1


def test_entitlement_added_after_open_stays_out_of_the_round():
    camp = campaign()
    camp.add_entitlement("alice", "repo:read", now=NOW)
    first = open_review(camp)
    camp.add_entitlement("alice", "repo:write", now=NOW)
    assert camp.campaign("cmp-1").entitlement_ids == ("ent-0001",)
    assert [row.entitlement_id for row in camp.items("cmp-1")] == ["ent-0001"]
    second = open_review(camp, campaign_id="cmp-2", now=LATER)
    assert first.snapshot_version == 1
    assert second.snapshot_version == 2
    assert second.entitlement_ids == ("ent-0001", "ent-0002")


def test_assign_requires_registered_reviewer_and_sets_due_time():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read", "repo:write"])
    open_review(camp)
    assigned = assign_all(camp)
    assert assigned == 2
    rows = camp.items("cmp-1", reviewer="r1")
    assert [row.entitlement_id for row in rows] == ["ent-0001", "ent-0002"]
    assert all(row.due_at == NOW + 100 for row in rows)
    assert all(row.state == "pending" for row in rows)
    with pytest.raises(ar.CampaignError) as exc:
        camp.assign("cmp-1", reviewer="outsider",
                    entitlement_ids=["ent-0001"], now=NOW)
    assert exc.value.code == "CAMPAIGN_UNKNOWN_REVIEWER"
    with pytest.raises(ar.CampaignError) as exc:
        camp.assign("cmp-missing", reviewer="r1",
                    entitlement_ids=["ent-0001"], now=NOW)
    assert exc.value.code == "CAMPAIGN_NOT_FOUND"


def test_decide_records_first_decision_and_ignores_duplicates():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read"])
    open_review(camp)
    assign_all(camp)
    first = camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                        decision="keep", now=NOW)
    assert first.decision == "keep"
    assert first.state == "kept"
    assert first.decided_at == NOW
    again = camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                        decision="revoke", now=LATER)
    assert again.decision == "keep"
    assert again.state == "kept"
    assert again.decided_at == NOW
    assert camp.stats()["decisions_recorded"] == 1
    assert camp.stats()["duplicates_ignored"] == 1


def test_decide_rejects_wrong_reviewer_and_unknown_decision():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read"])
    open_review(camp)
    camp.assign("cmp-1", reviewer="r1", entitlement_ids=["ent-0001"], now=NOW)
    with pytest.raises(ar.CampaignError) as exc:
        camp.decide("cmp-1", reviewer="r2", entitlement_id="ent-0001",
                    decision="keep", now=NOW)
    assert exc.value.code == "CAMPAIGN_NOT_REVIEWER"
    with pytest.raises(ar.CampaignError) as exc:
        camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                    decision="maybe", now=NOW)
    assert exc.value.code == "CAMPAIGN_INVALID_DECISION"
    row = camp.items("cmp-1")[0]
    assert row.decision is None
    assert row.state == "pending"


def test_close_is_refused_while_items_are_pending():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read", "repo:write"])
    open_review(camp)
    assign_all(camp)
    camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                decision="keep", now=NOW)
    with pytest.raises(ar.CampaignError) as exc:
        camp.close_campaign("cmp-1", now=LATER)
    assert exc.value.code == "CAMPAIGN_PENDING_ITEMS"
    assert exc.value.detail == 1
    assert camp.campaign("cmp-1").status == "open"


def test_close_then_reclaim_applies_revocations():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read", "repo:write"])
    open_review(camp)
    assign_all(camp)
    camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                decision="revoke", now=NOW)
    camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0002",
                decision="keep", now=NOW)
    closed = camp.close_campaign("cmp-1", now=LATER)
    assert closed.status == "closed"
    assert closed.closed_at == LATER
    result = camp.reclaim("cmp-1", now=LATER + 10)
    assert result.campaign_id == "cmp-1"
    assert result.reclaimed == ("ent-0001",)
    assert result.skipped_invalid == ()
    assert result.already_reclaimed == ()
    assert result.replayed is False
    states = {row.entitlement_id: row.state for row in camp.items("cmp-1")}
    assert states == {"ent-0001": "reclaimed", "ent-0002": "kept"}
    assert camp.stats()["items_reclaimed"] == 1


def test_reclaim_is_idempotent_and_reports_replay():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read", "repo:write"])
    open_review(camp)
    assign_all(camp)
    camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                decision="revoke", now=NOW)
    camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0002",
                decision="keep", now=NOW)
    camp.close_campaign("cmp-1", now=LATER)
    camp.reclaim("cmp-1", now=LATER + 1)
    replay = camp.reclaim("cmp-1", now=LATER + 2)
    assert replay.reclaimed == ()
    assert replay.replayed is True
    assert camp.stats()["items_reclaimed"] == 1


def test_reclaim_requires_a_closed_campaign():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read"])
    open_review(camp)
    with pytest.raises(ar.CampaignError) as exc:
        camp.reclaim("cmp-1", now=LATER)
    assert exc.value.code == "CAMPAIGN_NOT_CLOSED"


def test_concurrent_decisions_record_only_the_first_verdict():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read"])
    open_review(camp)
    camp.assign("cmp-1", reviewer="r1", entitlement_ids=["ent-0001"], now=NOW)
    verdicts = ["keep", "revoke"] * 6
    errors = []
    barrier = threading.Barrier(len(verdicts))

    def worker(decision):
        try:
            barrier.wait(timeout=5)
            camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                        decision=decision, now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(value,))
               for value in verdicts]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert camp.stats()["decisions_recorded"] == 1
    assert camp.stats()["duplicates_ignored"] == len(verdicts) - 1
    row = camp.items("cmp-1")[0]
    assert row.decision in {"keep", "revoke"}
    assert row.state in {"kept", "revoked"}


def test_snapshot_is_detached_and_restore_roundtrips():
    camp = campaign()
    seed_subject(camp, "alice", ["repo:read"])
    seed_subject(camp, "bob", ["repo:read"])
    open_review(camp)
    camp.assign("cmp-1", reviewer="r1", entitlement_ids=["ent-0001"], now=NOW)
    camp.decide("cmp-1", reviewer="r1", entitlement_id="ent-0001",
                decision="keep", now=NOW)
    state = camp.snapshot()
    assert set(state) == {"version", "next_entitlement", "next_snapshot",
                          "entitlements", "campaigns", "reclaimed", "stats"}
    pristine = copy.deepcopy(state)
    state["entitlements"].clear()
    state["stats"]["campaigns_opened"] = 999
    assert len(camp.entitlements()) == 2
    assert camp.stats()["campaigns_opened"] == 1

    clone = campaign()
    clone.restore(pristine)
    assert clone.campaign("cmp-1").status == "open"
    assert clone.items("cmp-1")[0].decision == "keep"
    assert clone.stats() == camp.stats()
    assert len(clone.entitlements()) == 2


def test_restore_rejects_malformed_state_without_touching_live_data():
    camp = campaign()
    camp.add_entitlement("alice", "repo:read", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 1, "next_entitlement": 2, "next_snapshot": 1,
         "entitlements": [], "campaigns": {}, "reclaimed": {}},
        {"version": 2, "next_entitlement": 2, "next_snapshot": 1,
         "entitlements": [], "campaigns": {}, "reclaimed": {}, "stats": {}},
        {"version": 1, "next_entitlement": 2, "next_snapshot": 1,
         "entitlements": "nope", "campaigns": {}, "reclaimed": {}, "stats": {}},
        {"version": 1, "next_entitlement": 2, "next_snapshot": 1,
         "entitlements": [], "campaigns": {}, "reclaimed": {}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ar.CampaignError) as exc:
            camp.restore(bad)
        assert exc.value.code == "CAMPAIGN_SNAPSHOT_INVALID"
    assert len(camp.entitlements()) == 1
    assert camp.stats()["entitlements_added"] == 1


def test_campaign_item_cap_blocks_oversized_round():
    camp = campaign(max_items_per_campaign=2)
    seed_subject(camp, "alice", ["repo:read", "repo:write", "repo:admin"])
    with pytest.raises(ar.CampaignError) as exc:
        open_review(camp, campaign_id="cmp-big")
    assert exc.value.code == "CAMPAIGN_TOO_LARGE"
    with pytest.raises(ar.CampaignError) as exc:
        camp.campaign("cmp-big")
    assert exc.value.code == "CAMPAIGN_NOT_FOUND"
    assert len(camp.entitlements()) == 3
