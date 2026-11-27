"""Post-match map vote ballot: eligibility, revotes, cooldowns and tie breaks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


REASON_OK = "VOTE_OK"
REASON_ABSTAIN = "VOTE_ABSTAIN"
REASON_UNCHANGED = "VOTE_UNCHANGED"
REASON_NOT_PARTICIPANT = "VOTE_NOT_PARTICIPANT"
REASON_UNKNOWN_MAP = "VOTE_UNKNOWN_MAP"
REASON_BALLOT_CLOSED = "VOTE_BALLOT_CLOSED"

DECIDED_BY_VOTES = "votes"
DECIDED_BY_TIEBREAK = "tiebreak"
DECIDED_BY_NO_VOTES = "no_votes"
DECIDED_BY_ALL_ABSTAINED = "all_abstained"

DEFAULT_CONFIG = {"cooldown_matches": 3}

STAT_KEYS = ("ballots", "votes", "rejected", "closed")

SNAPSHOT_VERSION = 1


class VoteError(ValueError):
    """Refusal raised by the map vote ballot."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BallotView:
    match_id: str
    participants: tuple
    candidates: tuple
    excluded: tuple
    votes: tuple
    opened_at: int
    closed: bool


@dataclass(frozen=True)
class VoteOutcome:
    accepted: bool
    reason: str
    map_id: str | None
    revote_count: int
    ballot_closed: bool


@dataclass(frozen=True)
class BallotResult:
    match_id: str
    winner: str | None
    decided_by: str
    tally: tuple
    abstained: int
    closed_at: int
    already_closed: bool


@dataclass(frozen=True)
class RemoveOutcome:
    map_id: str
    removed: bool
    voided_votes: int
    reason: str


@dataclass(frozen=True)
class DepartureOutcome:
    match_id: str
    player_id: str
    keeps_vote: bool
    votes: tuple


class MapVoteBallot:
    """Collect one revotable choice per participant and pick the next map."""

    def __init__(self, *, cooldown_matches: int = 3) -> None:
        self.cooldown_matches = cooldown_matches
        self._lock = threading.RLock()

    def open_ballot(
        self,
        match_id: str,
        *,
        participants: tuple,
        maps: tuple,
        recently_played: tuple = (),
        at: int,
    ) -> BallotView:
        raise NotImplementedError

    def ballot_state(self, match_id: str) -> BallotView:
        raise NotImplementedError

    def candidates(self, match_id: str) -> tuple:
        raise NotImplementedError

    def cast_vote(self, match_id: str, player_id: str, map_id: str | None, *, at: int) -> VoteOutcome:
        raise NotImplementedError

    def close_ballot(self, match_id: str, *, at: int) -> BallotResult:
        raise NotImplementedError

    def result(self, match_id: str) -> BallotResult | None:
        raise NotImplementedError

    def remove_candidate(self, match_id: str, map_id: str, *, reason: str, at: int) -> RemoveOutcome:
        raise NotImplementedError

    def mark_departed(self, match_id: str, player_id: str, *, at: int) -> DepartureOutcome:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
