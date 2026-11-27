import copy
import threading

import pytest

import world_first_race_ledger as race

NOW = 1_800_000_000
BOSS = "ash-warden"
DIFF = "mythic"
SEASON = 4


def ledger(**kwargs):
    return race.WorldFirstLedger(**kwargs)


def test_first_claim_on_empty_ledger_is_accepted():
    board = ledger()
    out = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                      digest="aa11", claim_seq=7)
    assert out.status == "accepted"
    assert out.changed is True
    assert out.reason == "WORLD_FIRST_CLAIM"
    assert out.first_claim_id == out.claim_id
    first = board.first_of(BOSS, DIFF, SEASON)
    assert first.claim_id == out.claim_id
    assert first.server == "s-1"
    assert first.killed_at == NOW
    assert first.claim_seq == 7
    assert first.digest == "aa11"
    assert first.status == "first"
    assert first.evidence_ok is False
    assert board.stats() == {"claims": 1, "duplicates": 0, "invalidations": 0,
                             "supersessions": 0, "promotions": 1}


def test_later_kill_is_recorded_without_displacing():
    board = ledger(skew_tolerance=30)
    first = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=7)
    out = board.claim(BOSS, DIFF, SEASON, server="s-2", killed_at=NOW + 100,
                      digest="bb22", claim_seq=1)
    assert out.status == "recorded"
    assert out.changed is False
    assert out.reason == "WORLD_NOT_FASTER"
    assert out.first_claim_id == first.claim_id
    assert board.first_of(BOSS, DIFF, SEASON).claim_id == first.claim_id
    assert board.stats()["supersessions"] == 0
    assert board.stats()["claims"] == 2


def test_earlier_kill_outside_skew_displaces_and_supersedes():
    board = ledger(skew_tolerance=30)
    first = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=7)
    out = board.claim(BOSS, DIFF, SEASON, server="s-2", killed_at=NOW - 31,
                      digest="bb22", claim_seq=9)
    assert out.status == "accepted"
    assert out.changed is True
    assert out.reason == "WORLD_DISPLACED"
    current = board.first_of(BOSS, DIFF, SEASON)
    assert current.claim_id == out.claim_id
    assert current.killed_at == NOW - 31
    assert current.claim_seq == 9
    timeline = board.history(BOSS, DIFF, SEASON)
    assert [row.claim_id for row in timeline] == [out.claim_id, first.claim_id]
    assert [row.status for row in timeline] == ["first", "superseded"]
    assert board.stats()["supersessions"] == 1
    assert board.stats()["promotions"] == 2


def test_claim_seq_decides_when_kill_times_are_inside_skew():
    promoted = ledger(skew_tolerance=30)
    promoted.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                   digest="aa11", claim_seq=5)
    out = promoted.claim(BOSS, DIFF, SEASON, server="s-2", killed_at=NOW + 20,
                         digest="bb22", claim_seq=1)
    assert out.status == "accepted"
    assert out.reason == "WORLD_DISPLACED"
    assert promoted.first_of(BOSS, DIFF, SEASON).claim_seq == 1

    held = ledger(skew_tolerance=30)
    base = held.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                      digest="aa11", claim_seq=5)
    out = held.claim(BOSS, DIFF, SEASON, server="s-3", killed_at=NOW - 20,
                     digest="cc33", claim_seq=9)
    assert out.status == "recorded"
    assert held.first_of(BOSS, DIFF, SEASON).claim_id == base.claim_id


def test_duplicate_digest_returns_existing_claim():
    board = ledger()
    first = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=5)
    out = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                      digest="aa11", claim_seq=6)
    assert out.status == "duplicate"
    assert out.claim_id == first.claim_id
    assert out.changed is False
    assert out.reason == "WORLD_DUPLICATE_EVIDENCE"
    assert out.first_claim_id == first.claim_id
    assert len(board.history(BOSS, DIFF, SEASON)) == 1
    assert board.stats()["duplicates"] == 1
    assert board.stats()["claims"] == 1


def test_invalidate_first_promotes_next_valid_claim():
    board = ledger()
    early = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=1)
    later = board.claim(BOSS, DIFF, SEASON, server="s-2", killed_at=NOW + 10,
                        digest="bb22", claim_seq=2)
    out = board.invalidate(early.claim_id, "WORLD_CHEAT_CONFIRMED")
    assert out.status == "invalidated"
    assert out.changed is True
    assert out.first_claim_id == later.claim_id
    assert board.first_of(BOSS, DIFF, SEASON).claim_id == later.claim_id
    timeline = board.history(BOSS, DIFF, SEASON)
    assert [row.claim_id for row in timeline] == [early.claim_id, later.claim_id]
    assert [row.status for row in timeline] == ["invalidated", "first"]
    assert board.stats()["invalidations"] == 1
    assert board.claim_of(early.claim_id).evidence_ok is False


def test_invalidating_the_only_claim_leaves_no_first():
    board = ledger()
    only = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                       digest="aa11", claim_seq=1)
    out = board.invalidate(only.claim_id, "WORLD_CHEAT_CONFIRMED")
    assert out.first_claim_id is None
    assert board.first_of(BOSS, DIFF, SEASON) is None
    assert board.stats()["invalidations"] == 1


def test_unknown_claim_is_refused():
    board = ledger()
    with pytest.raises(race.RaceError) as exc:
        board.invalidate(404, "WORLD_CHEAT_CONFIRMED")
    assert exc.value.code == "WORLD_UNKNOWN_CLAIM"
    with pytest.raises(race.RaceError) as exc:
        board.claim_of(404)
    assert exc.value.code == "WORLD_UNKNOWN_CLAIM"
    board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                digest="aa11", claim_seq=1)
    with pytest.raises(race.RaceError) as exc:
        board.verify(999, digest="aa11", ok=True)
    assert exc.value.code == "WORLD_UNKNOWN_CLAIM"


def test_verify_marks_evidence_ok():
    board = ledger()
    first = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=1)
    out = board.verify(first.claim_id, digest="aa11", ok=True)
    assert out.status == "accepted"
    assert out.changed is False
    assert out.first_claim_id == first.claim_id
    record = board.first_of(BOSS, DIFF, SEASON)
    assert record.evidence_ok is True
    assert record.digest == "aa11"
    assert board.stats()["invalidations"] == 0


def test_verify_with_wrong_digest_is_refused():
    board = ledger()
    first = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=1)
    with pytest.raises(race.RaceError) as exc:
        board.verify(first.claim_id, digest="ff99", ok=True)
    assert exc.value.code == "WORLD_EVIDENCE_MISMATCH"
    assert board.first_of(BOSS, DIFF, SEASON).evidence_ok is False
    assert board.stats()["invalidations"] == 0


def test_invalidated_boss_can_be_claimed_again_but_record_is_kept():
    board = ledger()
    gone = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                       digest="aa11", claim_seq=1)
    board.invalidate(gone.claim_id, "WORLD_CHEAT_CONFIRMED")
    assert board.first_of(BOSS, DIFF, SEASON) is None
    out = board.claim(BOSS, DIFF, SEASON, server="s-9", killed_at=NOW + 50,
                      digest="dd44", claim_seq=2)
    assert out.status == "accepted"
    assert out.reason == "WORLD_FIRST_CLAIM"
    assert board.first_of(BOSS, DIFF, SEASON).claim_id == out.claim_id
    timeline = board.history(BOSS, DIFF, SEASON)
    assert [row.status for row in timeline] == ["invalidated", "first"]
    assert len(timeline) == 2


def test_history_keeps_all_claims_in_adjudicated_order():
    board = ledger(skew_tolerance=30)
    late_kill = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW + 20,
                            digest="aa11", claim_seq=3)
    earliest = board.claim(BOSS, DIFF, SEASON, server="s-2", killed_at=NOW,
                           digest="bb22", claim_seq=9)
    middle = board.claim(BOSS, DIFF, SEASON, server="s-3", killed_at=NOW + 10,
                         digest="cc33", claim_seq=5)
    timeline = board.history(BOSS, DIFF, SEASON)
    assert [row.claim_id for row in timeline] == [earliest.claim_id,
                                                  middle.claim_id,
                                                  late_kill.claim_id]
    assert [row.server for row in timeline] == ["s-2", "s-3", "s-1"]
    assert [row.status for row in timeline] == ["recorded", "recorded", "first"]
    assert board.first_of(BOSS, DIFF, SEASON).claim_id == late_kill.claim_id
    assert board.history("other-boss", DIFF, SEASON) == ()


def test_snapshot_is_detached_and_restore_roundtrips():
    board = ledger()
    early = board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                        digest="aa11", claim_seq=1)
    late = board.claim(BOSS, DIFF, SEASON, server="s-2", killed_at=NOW + 10,
                       digest="bb22", claim_seq=2)
    board.verify(early.claim_id, digest="aa11", ok=True)
    state = board.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "config", "claims", "first", "stats"}
    assert pristine["config"] == {"skew_tolerance": 30}
    state["claims"][0]["status"] = "invalidated"
    state["stats"]["claims"] = 99
    state["first"].clear()
    assert board.claim_of(early.claim_id).status == "first"
    assert board.stats()["claims"] == 2
    assert board.first_of(BOSS, DIFF, SEASON).claim_id == early.claim_id
    clone = ledger()
    clone.restore(pristine)
    assert clone.first_of(BOSS, DIFF, SEASON).claim_id == early.claim_id
    assert clone.first_of(BOSS, DIFF, SEASON).evidence_ok is True
    assert [row.claim_id for row in clone.history(BOSS, DIFF, SEASON)] == [
        early.claim_id, late.claim_id]
    assert clone.stats() == board.stats()
    out = clone.claim(BOSS, DIFF, SEASON, server="s-7", killed_at=NOW - 100,
                      digest="ee55", claim_seq=0)
    assert out.status == "accepted"


def test_restore_rejects_malformed_state():
    board = ledger()
    board.claim(BOSS, DIFF, SEASON, server="s-1", killed_at=NOW,
                digest="aa11", claim_seq=1)
    good = board.snapshot()
    bad_states = [
        None,
        [],
        {},
        {"version": 2, "config": good["config"], "claims": good["claims"],
         "first": good["first"], "stats": good["stats"]},
        {"version": 1, "config": {}, "claims": [], "first": {},
         "stats": good["stats"]},
        {"version": 1, "config": good["config"], "claims": good["claims"],
         "first": [], "stats": good["stats"]},
        {"version": 1, "config": good["config"], "claims": good["claims"],
         "first": good["first"], "stats": {"claims": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(race.RaceError) as exc:
            board.restore(bad)
        assert exc.value.code == "WORLD_SNAPSHOT_INVALID"
    assert board.stats() == good["stats"]
    assert len(board.history(BOSS, DIFF, SEASON)) == 1


def test_concurrent_claims_resolve_to_a_single_first():
    board = ledger(skew_tolerance=30)
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            results.append(board.claim(BOSS, DIFF, SEASON, server=f"s-{index}",
                                       killed_at=NOW, digest=f"d{index:03d}",
                                       claim_seq=index))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    timeline = board.history(BOSS, DIFF, SEASON)
    assert len(timeline) == 8
    assert [row.claim_seq for row in timeline] == [0, 1, 2, 3, 4, 5, 6, 7]
    assert sum(1 for row in timeline if row.status == "first") == 1
    assert board.first_of(BOSS, DIFF, SEASON).claim_seq == 0
    assert board.first_of(BOSS, DIFF, SEASON).server == "s-0"
    assert board.stats()["claims"] == 8
