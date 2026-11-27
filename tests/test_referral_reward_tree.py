import copy
import threading

import pytest

import referral_reward_tree as rr

T0 = "2026-11-24T09:00:00+00:00"
T1 = "2026-11-24T09:10:00+00:00"
T2 = "2026-11-24T09:20:00+00:00"
T3 = "2026-11-24T09:30:00+00:00"


def tree(**kwargs):
    kwargs.setdefault("milestones", {"m1": 400, "m2": 800})
    return rr.ReferralTree(**kwargs)


def pyramid(**kwargs):
    t = tree(**kwargs)
    t.register_account("root", now=T0)
    t.bind_invite("a1", "root", now=T0)
    t.bind_invite("a2", "a1", now=T0)
    t.bind_invite("a3", "a2", now=T0)
    return t


def test_bind_assigns_level_and_records_bound_at():
    t = tree()
    t.register_account("root", now=T0)
    t.register_account("mid", now=T0)
    t.bind_invite("mid", "root", now=T1)
    t.bind_invite("leaf", "mid", now=T2)
    rows = t.tree_of("root")
    assert [(row.account, row.level, row.inviter) for row in rows] == [
        ("root", 0, None),
        ("mid", 1, "root"),
        ("leaf", 2, "mid"),
    ]
    assert [row.bound_at for row in rows] == [T0, T1, T2]
    assert t.stats()["accounts"] == 3
    assert t.stats()["bound"] == 2


def test_bind_unknown_inviter_is_rejected_before_write():
    t = tree()
    t.register_account("root", now=T0)
    with pytest.raises(rr.ReferralError) as exc:
        t.bind_invite("child", "ghost", now=T1)
    assert exc.value.code == "REFERRAL_NO_SUCH_ACCOUNT"
    assert [row.account for row in t.tree_of("root")] == ["root"]
    with pytest.raises(rr.ReferralError) as exc:
        t.tree_of("ghost")
    assert exc.value.code == "REFERRAL_NO_SUCH_ACCOUNT"
    t.bind_invite("child", "root", now=T2)
    assert [row.account for row in t.tree_of("root")] == ["root", "child"]


def test_bind_self_or_descendant_is_rejected():
    t = tree()
    t.register_account("root", now=T0)
    t.bind_invite("child", "root", now=T1)
    with pytest.raises(rr.ReferralError) as exc:
        t.bind_invite("root", "root", now=T2)
    assert exc.value.code == "REFERRAL_CYCLE"
    with pytest.raises(rr.ReferralError) as exc:
        t.bind_invite("root", "child", now=T2)
    assert exc.value.code == "REFERRAL_CYCLE"
    assert t.tree_of("root")[0].inviter is None
    assert [row.account for row in t.tree_of("root")] == ["root", "child"]


def test_milestone_pays_three_levels_by_share():
    t = pyramid()
    paid = t.record_milestone("a3", "m1", now=T3)
    assert paid == 700
    assert t.reward_state("a2")["claimable"] == 400
    assert t.reward_state("a1")["claimable"] == 200
    assert t.reward_state("root")["claimable"] == 100
    assert t.reward_state("a3")["claimable"] == 0


def test_milestone_settles_once_per_account():
    t = pyramid()
    first = t.record_milestone("a1", "m1", now=T3)
    second = t.record_milestone("a1", "m1", now=T3)
    assert (first, second) == (400, 0)
    assert [entry.kind for entry in t.ledger_of("root")] == ["credit"]
    assert t.stats()["milestones"] == 1


def test_claim_rewards_moves_claimable_to_balance():
    t = pyramid()
    t.record_milestone("a1", "m2", now=T3)
    assert t.claim_rewards("root") == 800
    assert t.claim_rewards("root") == 0
    assert t.reward_state("root") == {"balance": 800, "claimable": 0, "debt": 0}
    assert t.balance_of("root") == 800
    assert t.ledger_of("root")[-1].kind == "claim"


def test_clawback_deducts_from_ancestor_balance():
    t = pyramid()
    t.record_milestone("a3", "m1", now=T3)
    for account in ("a2", "a1", "root"):
        t.claim_rewards(account)
    taken = t.clawback("a3", "m1")
    assert taken == {"a2": 400, "a1": 200, "root": 100}
    assert t.balance_of("a2") == 0
    assert t.pending_debt("a2") == 0
    assert [entry.amount for entry in t.ledger_of("a2") if entry.kind == "reverse"] == [-400]
    assert t.stats()["reversed"] == 700


def test_clawback_rejects_unsettled_and_unknown_targets():
    t = pyramid()
    with pytest.raises(rr.ReferralError) as exc:
        t.clawback("ghost", "m1")
    assert exc.value.code == "REFERRAL_NO_SUCH_ACCOUNT"
    with pytest.raises(rr.ReferralError) as exc:
        t.clawback("a3", "nope")
    assert exc.value.code == "REFERRAL_UNKNOWN_MILESTONE"
    with pytest.raises(rr.ReferralError) as exc:
        t.clawback("a3", "m1")
    assert exc.value.code == "REFERRAL_NOT_SETTLED"
    t.record_milestone("a3", "m1", now=T3)
    for account in ("a2", "a1", "root"):
        t.claim_rewards(account)
    assert t.clawback("a3", "m1") == {"a2": 400, "a1": 200, "root": 100}
    with pytest.raises(rr.ReferralError) as exc:
        t.clawback("a3", "m1")
    assert exc.value.code == "REFERRAL_NOT_SETTLED"


def test_bind_over_children_cap_is_rejected():
    t = tree(max_children=2)
    t.register_account("root", now=T0)
    t.bind_invite("c1", "root", now=T0)
    t.bind_invite("c2", "root", now=T0)
    with pytest.raises(rr.ReferralError) as exc:
        t.bind_invite("c3", "root", now=T1)
    assert exc.value.code == "REFERRAL_NODE_LIMIT"
    assert t.stats()["accounts"] == 3
    assert [row.account for row in t.tree_of("root")] == ["root", "c1", "c2"]


def test_banned_account_cannot_settle_milestone():
    t = tree()
    t.register_account("root", now=T0)
    t.bind_invite("a1", "root", now=T0)
    t.bind_invite("a2", "a1", now=T0)
    assert t.ban_account("a1") == 2
    with pytest.raises(rr.ReferralError) as exc:
        t.record_milestone("a2", "m1", now=T3)
    assert exc.value.code == "REFERRAL_ACCOUNT_BANNED"
    with pytest.raises(rr.ReferralError) as exc:
        t.bind_invite("a3", "a1", now=T3)
    assert exc.value.code == "REFERRAL_ACCOUNT_BANNED"
    assert t.record_milestone("root", "m1", now=T3) == 0
    assert t.stats()["milestones"] == 1


def test_tree_of_is_sorted_preorder_and_scoped():
    t = tree()
    t.register_account("root", now=T0)
    t.bind_invite("c2", "root", now=T0)
    t.bind_invite("c1", "root", now=T0)
    t.bind_invite("g1", "c1", now=T0)
    assert [row.account for row in t.tree_of("root")] == ["root", "c1", "g1", "c2"]
    subtree = t.tree_of("c1")
    assert [row.account for row in subtree] == ["c1", "g1"]
    assert [row.level for row in subtree] == [1, 2]
    with pytest.raises(rr.ReferralError) as exc:
        t.tree_of("nobody")
    assert exc.value.code == "REFERRAL_NO_SUCH_ACCOUNT"


def test_snapshot_is_detached_and_restore_roundtrips():
    t = pyramid()
    t.record_milestone("a2", "m1", now=T3)
    t.claim_rewards("a1")
    state = t.snapshot()
    assert set(state) == {"version", "nodes", "milestones", "ledger", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["nodes"].clear()
    state["stats"]["paid"] = 999
    assert t.stats()["paid"] == 600
    clone = tree()
    clone.restore(pristine)
    assert clone.stats() == t.stats()
    assert clone.balance_of("a1") == 400
    assert [row.account for row in clone.tree_of("root")] == ["root", "a1", "a2", "a3"]


def test_restore_rejects_malformed_state():
    t = pyramid()
    t.record_milestone("a1", "m1", now=T3)
    bad_states = [
        None,
        {},
        {"version": 1, "nodes": [], "milestones": {}, "ledger": [],
         "counters": {}, "stats": {}},
        {"version": 1, "nodes": {}, "milestones": [], "ledger": [],
         "counters": {}, "stats": {}},
        {"version": 1, "nodes": {}, "milestones": {}, "ledger": {},
         "counters": {}, "stats": {}},
        {"version": 1, "nodes": {}, "milestones": {}, "ledger": [],
         "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(rr.ReferralError) as exc:
            t.restore(bad)
        assert exc.value.code == "REFERRAL_SNAPSHOT_INVALID"
    assert t.stats()["milestones"] == 1
    assert t.reward_state("root")["claimable"] == 400


def test_concurrent_milestones_settle_exactly_once():
    t = pyramid()
    totals = []
    failures = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            totals.append(t.record_milestone("a3", "m1", now=T3))
        except Exception as exc:  # pragma: no cover - surfaced through failures
            failures.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert sorted(totals) == [0, 0, 0, 0, 0, 0, 0, 700]
    assert t.stats()["milestones"] == 1
    assert t.stats()["paid"] == 700


def test_stats_track_accounts_milestones_and_amounts():
    t = tree()
    t.register_account("root", now=T0)
    t.bind_invite("a1", "root", now=T0)
    t.bind_invite("a2", "a1", now=T0)
    t.record_milestone("a2", "m1", now=T3)
    t.claim_rewards("a1")
    assert t.stats() == {
        "accounts": 3,
        "bound": 2,
        "milestones": 1,
        "paid": 600,
        "claimable": 200,
        "reversed": 0,
        "debt": 0,
    }
