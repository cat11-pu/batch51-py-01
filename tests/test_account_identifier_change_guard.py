import copy
import threading

import pytest

import account_identifier_change_guard as ic


def guard(**kwargs):
    return ic.IdentifierChangeGuard(**kwargs)


def make_account(g, account_id="a1", identifier="old@x", *, now=0):
    return g.create_account(account_id, identifier, now=now)


def start_change(g, account_id="a1", new_identifier="new@x", *, now=0):
    view = g.initiate_change(account_id, new_identifier, now=now)
    codes = g.challenge_codes(view.request_id)
    return view, codes


def confirm_both(g, view, codes, *, now=0):
    g.confirm_old(view.request_id, codes["old"], now=now)
    g.confirm_new(view.request_id, codes["new"], now=now)
    return g.change(view.request_id)


def test_create_account_normalizes_identifier_and_rejects_duplicates():
    g = guard()
    account = g.create_account("a1", " Alice@Corp.COM ", now=0)
    assert account.account_id == "a1"
    assert account.identifier == "alice@corp.com"
    assert account.disabled is False
    assert account.pending_request is None
    assert account.created_at == 0
    with pytest.raises(ic.IdentifierError) as exc:
        g.create_account("a2", "ALICE@corp.com", now=0)
    assert exc.value.code == "IDENTIFIER_TAKEN"
    with pytest.raises(ic.IdentifierError) as exc:
        g.create_account("", "other@x", now=0)
    assert exc.value.code == "IDENTIFIER_INVALID"
    with pytest.raises(ic.IdentifierError) as exc:
        g.create_account("a3", "   ", now=0)
    assert exc.value.code == "IDENTIFIER_INVALID"
    assert g.stats()["accounts"] == 1


def test_initiate_change_opens_request_with_codes_and_ttl():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    assert view.request_id == "chg-0001"
    assert view.account_id == "a1"
    assert view.old_identifier == "old@x"
    assert view.new_identifier == "new@x"
    assert view.state == "awaiting_old"
    assert view.old_confirmed is False
    assert view.new_confirmed is False
    assert view.created_at == 0
    assert view.expires_at == 300
    assert view.committed_at is None
    assert set(codes) == {"old", "new"}
    assert len(codes["old"]) == 6 and len(codes["new"]) == 6
    assert codes["old"] != codes["new"]
    assert g.challenge_codes(view.request_id) == codes
    assert g.stats()["requests_initiated"] == 1


def test_only_one_change_may_be_in_flight_per_account():
    g = guard()
    make_account(g)
    start_change(g)
    with pytest.raises(ic.IdentifierError) as exc:
        g.initiate_change("a1", "other@x", now=10)
    assert exc.value.code == "CHANGE_IN_FLIGHT"


def test_confirm_old_rejects_bad_code_and_advances_once():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    with pytest.raises(ic.IdentifierError) as exc:
        g.confirm_old(view.request_id, "000000", now=10)
    assert exc.value.code == "CHANGE_BAD_CODE"
    assert g.change(view.request_id).state == "awaiting_old"
    assert g.account("a1").pending_request == view.request_id
    advanced = g.confirm_old(view.request_id, codes["old"], now=20)
    assert advanced.state == "awaiting_new"
    assert advanced.old_confirmed is True
    assert advanced.new_confirmed is False
    assert g.stats()["confirmations"] == 1


def test_confirm_new_requires_old_side_first():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    with pytest.raises(ic.IdentifierError) as exc:
        g.confirm_new(view.request_id, codes["new"], now=10)
    assert exc.value.code == "CHANGE_STEP_OUT_OF_ORDER"
    g.confirm_old(view.request_id, codes["old"], now=20)
    ready = g.confirm_new(view.request_id, codes["new"], now=30)
    assert ready.state == "awaiting_commit"
    assert ready.old_confirmed is True
    assert ready.new_confirmed is True
    assert g.stats()["confirmations"] == 2


def test_commit_is_refused_before_both_confirmations():
    g = guard()
    make_account(g)
    view, _ = start_change(g)
    with pytest.raises(ic.IdentifierError) as exc:
        g.commit(view.request_id, now=50)
    assert exc.value.code == "CHANGE_INCOMPLETE"


def test_commit_switches_identifier_and_clears_pending():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    confirm_both(g, view, codes, now=100)
    committed = g.commit(view.request_id, now=200)
    assert committed.state == "committed"
    assert committed.committed_at == 200
    assert g.account("a1").identifier == "new@x"
    assert g.pending_change("a1") is None
    assert g.stats()["changes_committed"] == 1


def test_expired_request_can_be_replaced_by_a_new_one():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    with pytest.raises(ic.IdentifierError) as exc:
        g.confirm_old(view.request_id, codes["old"], now=301)
    assert exc.value.code == "CHANGE_EXPIRED"
    assert g.change(view.request_id).state == "expired"
    assert g.account("a1").identifier == "old@x"
    assert g.pending_change("a1") is None
    replacement = g.initiate_change("a1", "other@x", now=302)
    assert replacement.request_id == "chg-0002"
    assert replacement.state == "awaiting_old"


def test_rollback_restores_old_identifier_and_frees_new_one():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    confirm_both(g, view, codes, now=100)
    g.commit(view.request_id, now=200)
    rolled = g.rollback(view.request_id, now=300)
    assert rolled.state == "rolled_back"
    assert g.account("a1").identifier == "old@x"
    fresh = g.create_account("a2", "new@x", now=300)
    assert fresh.identifier == "new@x"
    assert g.stats()["changes_rolled_back"] == 1


def test_unknown_account_and_request_are_reported():
    g = guard()
    make_account(g)
    with pytest.raises(ic.IdentifierError) as exc:
        g.initiate_change("ghost", "x@y", now=0)
    assert exc.value.code == "ACCOUNT_UNKNOWN"
    with pytest.raises(ic.IdentifierError) as exc:
        g.account("ghost")
    assert exc.value.code == "ACCOUNT_UNKNOWN"
    with pytest.raises(ic.IdentifierError) as exc:
        g.change("chg-9999")
    assert exc.value.code == "CHANGE_UNKNOWN"
    with pytest.raises(ic.IdentifierError) as exc:
        g.confirm_old("chg-9999", "123456", now=0)
    assert exc.value.code == "CHANGE_UNKNOWN"


def test_release_hold_only_counts_live_expiry():
    g = guard(hold_ticks=50)
    make_account(g)
    view, codes = start_change(g)
    confirm_both(g, view, codes, now=0)
    g.commit(view.request_id, now=0)
    assert g.release_hold("old@x", now=10) == 0
    assert g.release_hold("old@x", now=49) == 0
    assert g.release_hold("old@x", now=50) == 1
    assert g.release_hold("old@x", now=60) == 0
    assert g.stats()["holds_released"] == 1


def test_concurrent_commit_on_same_new_identifier_has_one_winner():
    g = guard()
    make_account(g, "a1", "old1@x")
    make_account(g, "a2", "old2@x")
    first, first_codes = start_change(g, "a1", "shared@x")
    second, second_codes = start_change(g, "a2", "shared@x")
    confirm_both(g, first, first_codes)
    confirm_both(g, second, second_codes)
    outcomes = []
    barrier = threading.Barrier(2)

    def worker(request_id):
        try:
            barrier.wait(timeout=5)
            outcomes.append(("ok", g.commit(request_id, now=200)))
        except ic.IdentifierError as exc:
            outcomes.append(("err", exc.code))

    threads = [
        threading.Thread(target=worker, args=(first.request_id,)),
        threading.Thread(target=worker, args=(second.request_id,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    wins = [view for kind, view in outcomes if kind == "ok"]
    losses = [code for kind, code in outcomes if kind == "err"]
    assert len(wins) == 1
    assert losses == ["IDENTIFIER_RESERVED"]
    winner = wins[0].account_id
    loser = "a2" if winner == "a1" else "a1"
    assert g.account(winner).identifier == "shared@x"
    assert g.account(loser).identifier in {"old1@x", "old2@x"}
    assert g.stats()["changes_committed"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    make_account(g, "a1", "old1@x")
    make_account(g, "a2", "old2@x")
    first, first_codes = start_change(g, "a1", "new1@x")
    confirm_both(g, first, first_codes, now=0)
    g.commit(first.request_id, now=100)
    second = g.initiate_change("a2", "new2@x", now=100)
    g.confirm_old(second.request_id,
                  g.challenge_codes(second.request_id)["old"], now=110)
    state = g.snapshot()
    assert set(state) == {"version", "next_request", "accounts", "changes",
                          "holds", "stats"}
    pristine = copy.deepcopy(state)
    state["accounts"].clear()
    state["stats"]["accounts"] = 99
    assert g.account("a1").identifier == "new1@x"
    assert g.account("a2").pending_request == second.request_id
    assert g.stats()["accounts"] == 2

    clone = guard()
    clone.restore(pristine)
    assert clone.account("a1").identifier == "new1@x"
    assert clone.change(first.request_id).state == "committed"
    assert clone.account("a2").pending_request == second.request_id
    assert clone.change(second.request_id).state == "awaiting_new"
    assert clone.stats() == g.stats()


def test_restore_rejects_malformed_state_without_touching_live_data():
    g = guard()
    make_account(g, "a1", "old@x")
    bad_states = [
        None,
        {},
        {"version": 1, "next_request": 2, "accounts": {}, "changes": {},
         "stats": {}},
        {"version": 2, "next_request": 2, "accounts": {}, "changes": {},
         "holds": {}, "stats": {}},
        {"version": 1, "next_request": 2, "accounts": [], "changes": {},
         "holds": {}, "stats": {}},
        {"version": 1, "next_request": 2, "accounts": {}, "changes": [],
         "holds": {}, "stats": {}},
        {"version": 1, "next_request": 2, "accounts": {}, "changes": {},
         "holds": [], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ic.IdentifierError) as exc:
            g.restore(bad)
        assert exc.value.code == "CHANGE_SNAPSHOT_INVALID"
    assert g.account("a1").identifier == "old@x"


def test_stats_track_one_full_change_exactly():
    g = guard()
    make_account(g)
    view, codes = start_change(g)
    confirm_both(g, view, codes, now=50)
    g.commit(view.request_id, now=100)
    assert g.stats() == {"accounts": 1, "requests_initiated": 1,
                         "changes_committed": 1, "changes_rolled_back": 0,
                         "holds_released": 0, "confirmations": 2}
