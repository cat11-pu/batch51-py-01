import copy

import pytest

import map_vote_ballot as vote

NOW = 1_800_000_000


def ballot(**kwargs):
    return vote.MapVoteBallot(**kwargs)


def test_open_ballot_excludes_cooldown_maps():
    board = ballot(cooldown_matches=2)
    view = board.open_ballot("m-1", participants=("p-2", "p-1"),
                             maps=("canyon", "arena", "bastion", "dune"),
                             recently_played=("zulu", "yankee"), at=NOW)
    assert view.candidates == ("arena", "bastion", "canyon", "dune")
    assert view.excluded == ("yankee", "zulu")
    assert board.candidates("m-1") == ("arena", "bastion", "canyon", "dune")
    assert board.stats()["ballots"] == 1


def test_open_ballot_rejects_empty_candidate_set():
    board = ballot(cooldown_matches=3)
    with pytest.raises(vote.VoteError) as exc:
        board.open_ballot("m-1", participants=("p-1",),
                          maps=("arena", "bastion"),
                          recently_played=("bastion", "arena", "canyon"), at=NOW)
    assert exc.value.code == "VOTE_NO_CANDIDATES"
    assert board.stats()["ballots"] == 0


def test_open_ballot_rejects_invalid_rosters():
    board = ballot()
    bad_rosters = [
        {"participants": (), "maps": ("arena",)},
        {"participants": ("p-1", "p-1"), "maps": ("arena",)},
        {"participants": ("",), "maps": ("arena",)},
        {"participants": ("p-1",), "maps": ("arena", "")},
        {"participants": ("p-1",), "maps": ()},
    ]
    for roster in bad_rosters:
        with pytest.raises(vote.VoteError) as exc:
            board.open_ballot("m-1", participants=roster["participants"],
                              maps=roster["maps"], at=NOW)
        assert exc.value.code == "VOTE_INVALID_REQUEST"
    with pytest.raises(vote.VoteError) as exc:
        board.ballot_state("m-9")
    assert exc.value.code == "VOTE_UNKNOWN_BALLOT"


def test_ballot_view_reports_sorted_roster():
    board = ballot(cooldown_matches=1)
    view = board.open_ballot("m-1", participants=("p-3", "p-1", "p-2"),
                             maps=("bravo", "alpha"), recently_played=(), at=NOW)
    assert view.match_id == "m-1"
    assert view.participants == ("p-1", "p-2", "p-3")
    assert view.candidates == ("alpha", "bravo")
    assert view.excluded == ()
    assert view.votes == ()
    assert view.opened_at == NOW
    assert view.closed is False
    assert board.ballot_state("m-1") == view


def test_cast_vote_records_choice_and_revote():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1", "p-2"),
                      maps=("alpha", "bravo"), at=NOW)
    first = board.cast_vote("m-1", "p-1", "alpha", at=NOW + 1)
    assert first.accepted is True
    assert first.reason == "VOTE_OK"
    assert first.map_id == "alpha"
    assert first.revote_count == 0
    assert first.ballot_closed is False
    second = board.cast_vote("m-1", "p-1", "bravo", at=NOW + 2)
    assert second.accepted is True
    assert second.map_id == "bravo"
    assert second.revote_count == 1
    out = board.close_ballot("m-1", at=NOW + 10)
    assert out.tally == (("alpha", 0), ("bravo", 1))
    assert out.winner == "bravo"
    assert board.stats()["votes"] == 2


def test_same_map_revote_is_unchanged():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1",), maps=("alpha", "bravo"), at=NOW)
    board.cast_vote("m-1", "p-1", "alpha", at=NOW + 1)
    again = board.cast_vote("m-1", "p-1", "alpha", at=NOW + 2)
    assert again.accepted is False
    assert again.reason == "VOTE_UNCHANGED"
    assert again.map_id == "alpha"
    assert again.revote_count == 0
    out = board.close_ballot("m-1", at=NOW + 10)
    assert out.tally == (("alpha", 1), ("bravo", 0))
    assert out.winner == "alpha"


def test_non_participant_vote_is_refused():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1",), maps=("alpha", "bravo"), at=NOW)
    out = board.cast_vote("m-1", "ghost", "alpha", at=NOW + 1)
    assert out.accepted is False
    assert out.reason == "VOTE_NOT_PARTICIPANT"
    assert out.map_id == "alpha"
    assert out.revote_count == 0
    closed = board.close_ballot("m-1", at=NOW + 10)
    assert closed.winner is None
    assert closed.decided_by == "no_votes"


def test_vote_for_uncandidate_map_is_refused():
    board = ballot(cooldown_matches=1)
    board.open_ballot("m-1", participants=("p-1",),
                      maps=("alpha", "bravo", "canyon"),
                      recently_played=("canyon",), at=NOW)
    out = board.cast_vote("m-1", "p-1", "canyon", at=NOW + 1)
    assert out.accepted is False
    assert out.reason == "VOTE_UNKNOWN_MAP"
    assert out.map_id == "canyon"
    assert board.ballot_state("m-1").votes == ()


def test_close_ballot_is_idempotent():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1", "p-2", "p-3"),
                      maps=("alpha", "bravo"), at=NOW)
    board.cast_vote("m-1", "p-1", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-3", "alpha", at=NOW + 1)
    first = board.close_ballot("m-1", at=NOW + 10)
    assert first.winner == "bravo"
    assert first.decided_by == "votes"
    assert first.closed_at == NOW + 10
    assert first.already_closed is False
    assert first.tally == (("alpha", 1), ("bravo", 2))
    again = board.close_ballot("m-1", at=NOW + 40)
    assert again.winner == "bravo"
    assert again.closed_at == NOW + 10
    assert again.already_closed is True
    assert again.tally == first.tally
    assert board.ballot_state("m-1").closed is True
    assert board.result("m-1").winner == "bravo"
    assert board.stats()["closed"] == 1


def test_tally_uses_latest_vote_only():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1", "p-2", "p-3"),
                      maps=("alpha", "bravo", "charlie"), at=NOW)
    board.cast_vote("m-1", "p-1", "alpha", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "alpha", at=NOW + 1)
    board.cast_vote("m-1", "p-3", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-3", "alpha", at=NOW + 2)
    out = board.close_ballot("m-1", at=NOW + 10)
    assert out.tally == (("alpha", 3), ("bravo", 0), ("charlie", 0))
    assert out.winner == "alpha"
    assert out.decided_by == "votes"
    assert out.abstained == 0


def test_tie_broken_by_least_recently_played():
    board = ballot(cooldown_matches=1)
    view = board.open_ballot("m-1", participants=("p-1", "p-2", "p-3", "p-4"),
                             maps=("alpha", "bravo", "charlie", "delta"),
                             recently_played=("delta", "charlie", "bravo"), at=NOW)
    assert view.candidates == ("alpha", "bravo", "charlie")
    board.cast_vote("m-1", "p-1", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-3", "charlie", at=NOW + 1)
    board.cast_vote("m-1", "p-4", "charlie", at=NOW + 1)
    out = board.close_ballot("m-1", at=NOW + 10)
    assert out.tally == (("alpha", 0), ("bravo", 2), ("charlie", 2))
    assert out.winner == "bravo"
    assert out.decided_by == "tiebreak"


def test_tie_broken_by_map_id_when_both_unplayed():
    board = ballot(cooldown_matches=1)
    board.open_ballot("m-1", participants=("p-1", "p-2"),
                      maps=("zulu", "alpha", "delta"),
                      recently_played=("delta",), at=NOW)
    board.cast_vote("m-1", "p-1", "zulu", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "alpha", at=NOW + 1)
    out = board.close_ballot("m-1", at=NOW + 10)
    assert out.tally == (("alpha", 1), ("zulu", 1))
    assert out.winner == "alpha"
    assert out.decided_by == "tiebreak"


def test_all_abstained_produces_no_winner():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1", "p-2"),
                      maps=("alpha", "bravo"), at=NOW)
    first = board.cast_vote("m-1", "p-1", None, at=NOW + 1)
    assert first.accepted is True
    assert first.reason == "VOTE_ABSTAIN"
    assert first.map_id is None
    second = board.cast_vote("m-1", "p-2", None, at=NOW + 1)
    assert second.reason == "VOTE_ABSTAIN"
    out = board.close_ballot("m-1", at=NOW + 10)
    assert out.winner is None
    assert out.decided_by == "all_abstained"
    assert out.abstained == 2
    assert out.tally == (("alpha", 0), ("bravo", 0))

    board.open_ballot("m-2", participants=("p-1", "p-2"),
                      maps=("alpha", "bravo"), at=NOW)
    untouched = board.close_ballot("m-2", at=NOW + 10)
    assert untouched.winner is None
    assert untouched.decided_by == "no_votes"


def test_snapshot_is_detached_and_restore_roundtrips():
    board = ballot(cooldown_matches=1)
    board.open_ballot("m-1", participants=("p-1", "p-2"),
                      maps=("alpha", "bravo", "charlie"),
                      recently_played=("charlie",), at=NOW)
    board.cast_vote("m-1", "p-1", "alpha", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "alpha", at=NOW + 2)
    state = board.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "config", "ballots", "stats"}
    assert pristine["config"] == {"cooldown_matches": 1}
    state["ballots"]["m-1"]["votes"]["p-1"] = "bravo"
    state["stats"]["votes"] = 99
    assert board.ballot_state("m-1").votes == (("p-1", "alpha"), ("p-2", "alpha"))
    assert board.stats() == {"ballots": 1, "votes": 3, "rejected": 0, "closed": 0}
    clone = ballot()
    clone.restore(pristine)
    assert clone.ballot_state("m-1").votes == (("p-1", "alpha"), ("p-2", "alpha"))
    assert clone.candidates("m-1") == ("alpha", "bravo")
    assert clone.ballot_state("m-1").participants == ("p-1", "p-2")
    assert clone.stats() == board.stats()
    out = clone.close_ballot("m-1", at=NOW + 10)
    assert out.winner == "alpha"
    assert out.tally == (("alpha", 2), ("bravo", 0))


def test_restored_closed_ballot_keeps_result():
    board = ballot()
    board.open_ballot("m-1", participants=("p-1", "p-2"),
                      maps=("alpha", "bravo"), at=NOW)
    board.cast_vote("m-1", "p-1", "bravo", at=NOW + 1)
    board.cast_vote("m-1", "p-2", "bravo", at=NOW + 1)
    closed = board.close_ballot("m-1", at=NOW + 10)
    assert closed.winner == "bravo"
    clone = ballot()
    clone.restore(board.snapshot())
    restored = clone.result("m-1")
    assert restored is not None
    assert restored.winner == "bravo"
    assert restored.decided_by == "votes"
    assert restored.closed_at == NOW + 10
    assert clone.ballot_state("m-1").closed is True
    assert clone.result("m-2") is None
    late = clone.cast_vote("m-1", "p-1", "alpha", at=NOW + 50)
    assert late.accepted is False
    assert late.reason == "VOTE_BALLOT_CLOSED"
    assert late.ballot_closed is True
    assert clone.result("m-1").winner == "bravo"
