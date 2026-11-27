"""Post-match map vote ballot: eligibility, revotes, cooldowns and tie breaks."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace


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

ERR_INVALID_REQUEST = "VOTE_INVALID_REQUEST"
ERR_NO_CANDIDATES = "VOTE_NO_CANDIDATES"
ERR_UNKNOWN_BALLOT = "VOTE_UNKNOWN_BALLOT"
ERR_SNAPSHOT_INVALID = "VOTE_SNAPSHOT_INVALID"


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


@dataclass
class _BallotState:
    match_id: str
    participants: tuple
    candidates: tuple
    excluded: tuple
    opened_at: int
    votes: dict = field(default_factory=dict)
    revote_counts: dict = field(default_factory=dict)
    ranks: dict = field(default_factory=dict)
    closed: bool = False
    closed_at: int | None = None
    ever_voted: bool = False
    result: BallotResult | None = None


def _invalid(detail: object) -> None:
    raise VoteError(ERR_INVALID_REQUEST, detail)


def _snapshot_invalid(detail: object) -> None:
    raise VoteError(ERR_SNAPSHOT_INVALID, detail)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_timestamp(value: object, field_name: str) -> None:
    if not _is_int(value):
        _invalid({field_name: value})


def _require_match_id(match_id: object) -> str:
    if not isinstance(match_id, str) or not match_id:
        _invalid({"match_id": match_id})
    return match_id


def _validate_string_tuple(
    value: object,
    field_name: str,
    *,
    allow_empty: bool,
    unique: bool = True,
) -> tuple:
    if not isinstance(value, tuple):
        _invalid({field_name: value})
    if not value and not allow_empty:
        _invalid({field_name: value})

    seen = set()
    for item in value:
        if not isinstance(item, str) or not item:
            _invalid({field_name: value})
        if unique and item in seen:
            _invalid({field_name: value})
        seen.add(item)
    return value


def _sorted_votes(votes: dict) -> tuple:
    return tuple((player_id, votes[player_id]) for player_id in sorted(votes))


class MapVoteBallot:
    """Collect one revotable choice per participant and pick the next map."""

    def __init__(self, *, cooldown_matches: int = 3) -> None:
        if not _is_int(cooldown_matches) or cooldown_matches < 0:
            _invalid({"cooldown_matches": cooldown_matches})
        self.cooldown_matches = cooldown_matches
        self._lock = threading.RLock()
        self._ballots: dict[str, _BallotState] = {}
        self._stats = {key: 0 for key in STAT_KEYS}

    def _require_ballot(self, match_id: object) -> _BallotState:
        if not isinstance(match_id, str) or not match_id:
            raise VoteError(ERR_UNKNOWN_BALLOT, match_id)
        ballot = self._ballots.get(match_id)
        if ballot is None:
            raise VoteError(ERR_UNKNOWN_BALLOT, match_id)
        return ballot

    @staticmethod
    def _view(ballot: _BallotState) -> BallotView:
        return BallotView(
            match_id=ballot.match_id,
            participants=tuple(ballot.participants),
            candidates=tuple(ballot.candidates),
            excluded=tuple(ballot.excluded),
            votes=_sorted_votes(ballot.votes),
            opened_at=ballot.opened_at,
            closed=ballot.closed,
        )

    def open_ballot(
        self,
        match_id: str,
        *,
        participants: tuple,
        maps: tuple,
        recently_played: tuple = (),
        at: int,
    ) -> BallotView:
        with self._lock:
            match_id = _require_match_id(match_id)
            participants = _validate_string_tuple(
                participants, "participants", allow_empty=False
            )
            maps = _validate_string_tuple(maps, "maps", allow_empty=False)
            recently_played = _validate_string_tuple(
                recently_played, "recently_played", allow_empty=True, unique=False
            )
            _require_timestamp(at, "at")

            cooldown = min(self.cooldown_matches, len(recently_played))
            excluded_set = set(recently_played[:cooldown])
            candidates = tuple(sorted(map_id for map_id in maps if map_id not in excluded_set))
            if not candidates:
                raise VoteError(
                    ERR_NO_CANDIDATES,
                    {"maps": maps, "recently_played": recently_played},
                )
            if match_id in self._ballots:
                _invalid({"match_id": match_id, "reason": "ballot already exists"})

            excluded = tuple(sorted(excluded_set))
            ranks = {}
            for index, map_id in enumerate(recently_played):
                if map_id in candidates and map_id not in ranks:
                    ranks[map_id] = len(recently_played) - index
            for map_id in candidates:
                ranks.setdefault(map_id, 0)

            ballot = _BallotState(
                match_id=match_id,
                participants=tuple(sorted(participants)),
                candidates=candidates,
                excluded=excluded,
                opened_at=at,
                ranks={map_id: ranks[map_id] for map_id in sorted(ranks)},
            )
            self._ballots[match_id] = ballot
            self._stats["ballots"] += 1
            return self._view(ballot)

    def ballot_state(self, match_id: str) -> BallotView:
        with self._lock:
            return self._view(self._require_ballot(match_id))

    def candidates(self, match_id: str) -> tuple:
        with self._lock:
            ballot = self._require_ballot(match_id)
            return tuple(ballot.candidates)

    def cast_vote(self, match_id: str, player_id: str, map_id: str | None, *, at: int) -> VoteOutcome:
        with self._lock:
            ballot = self._require_ballot(match_id)
            _require_timestamp(at, "at")

            current_revotes = (
                ballot.revote_counts.get(player_id, 0)
                if isinstance(player_id, str)
                else 0
            )
            if ballot.closed:
                self._stats["rejected"] += 1
                return VoteOutcome(
                    False, REASON_BALLOT_CLOSED, map_id, current_revotes, True
                )

            if not isinstance(player_id, str) or player_id not in ballot.participants:
                self._stats["rejected"] += 1
                return VoteOutcome(
                    False, REASON_NOT_PARTICIPANT, map_id, current_revotes, False
                )
            if map_id is not None and map_id not in ballot.candidates:
                self._stats["rejected"] += 1
                return VoteOutcome(
                    False, REASON_UNKNOWN_MAP, map_id, current_revotes, False
                )

            has_vote = player_id in ballot.votes
            if has_vote and ballot.votes[player_id] == map_id:
                self._stats["rejected"] += 1
                return VoteOutcome(
                    False, REASON_UNCHANGED, map_id, current_revotes, False
                )

            revote_count = current_revotes + 1 if has_vote else 0
            ballot.votes[player_id] = map_id
            ballot.revote_counts[player_id] = revote_count
            ballot.ever_voted = True
            self._stats["votes"] += 1
            reason = REASON_ABSTAIN if map_id is None else REASON_OK
            return VoteOutcome(True, reason, map_id, revote_count, False)

    def close_ballot(self, match_id: str, *, at: int) -> BallotResult:
        with self._lock:
            ballot = self._require_ballot(match_id)
            _require_timestamp(at, "at")

            if ballot.closed:
                return replace(ballot.result, already_closed=True)

            result = self._settle(ballot, at)
            ballot.closed = True
            ballot.closed_at = at
            ballot.result = result
            self._stats["closed"] += 1
            return result

    def result(self, match_id: str) -> BallotResult | None:
        with self._lock:
            if not isinstance(match_id, str) or not match_id:
                return None
            ballot = self._ballots.get(match_id)
            if ballot is None or not ballot.closed:
                return None
            return ballot.result

    def remove_candidate(self, match_id: str, map_id: str, *, reason: str, at: int) -> RemoveOutcome:
        with self._lock:
            ballot = self._require_ballot(match_id)
            _require_timestamp(at, "at")
            if not isinstance(reason, str) or not reason:
                _invalid({"reason": reason})
            if ballot.closed:
                raise VoteError(REASON_BALLOT_CLOSED, match_id)

            if map_id not in ballot.candidates:
                return RemoveOutcome(map_id, False, 0, reason)

            voided_votes = sum(
                1 for choice in ballot.votes.values() if choice == map_id
            )
            for player_id in sorted(ballot.votes):
                if ballot.votes[player_id] == map_id:
                    ballot.votes[player_id] = None
            ballot.candidates = tuple(
                candidate for candidate in ballot.candidates if candidate != map_id
            )
            ballot.ranks.pop(map_id, None)
            return RemoveOutcome(map_id, True, voided_votes, reason)

    def mark_departed(self, match_id: str, player_id: str, *, at: int) -> DepartureOutcome:
        with self._lock:
            ballot = self._require_ballot(match_id)
            _require_timestamp(at, "at")
            if not isinstance(player_id, str) or player_id not in ballot.participants:
                raise VoteError(REASON_NOT_PARTICIPANT, player_id)
            return DepartureOutcome(
                match_id=ballot.match_id,
                player_id=player_id,
                keeps_vote=True,
                votes=_sorted_votes(ballot.votes),
            )

    def snapshot(self) -> dict:
        with self._lock:
            ballots = {}
            for match_id in sorted(self._ballots):
                ballot = self._ballots[match_id]
                result = None
                if ballot.result is not None:
                    result = {
                        "match_id": ballot.result.match_id,
                        "winner": ballot.result.winner,
                        "decided_by": ballot.result.decided_by,
                        "tally": tuple(ballot.result.tally),
                        "abstained": ballot.result.abstained,
                        "closed_at": ballot.result.closed_at,
                        "already_closed": ballot.result.already_closed,
                    }
                ballots[match_id] = {
                    "match_id": ballot.match_id,
                    "participants": tuple(ballot.participants),
                    "candidates": tuple(ballot.candidates),
                    "excluded": tuple(ballot.excluded),
                    "votes": {
                        player_id: ballot.votes[player_id]
                        for player_id in sorted(ballot.votes)
                    },
                    "revote_counts": {
                        player_id: ballot.revote_counts[player_id]
                        for player_id in sorted(ballot.revote_counts)
                    },
                    "ranks": {
                        map_id: ballot.ranks[map_id]
                        for map_id in sorted(ballot.ranks)
                    },
                    "opened_at": ballot.opened_at,
                    "closed": ballot.closed,
                    "closed_at": ballot.closed_at,
                    "ever_voted": ballot.ever_voted,
                    "result": result,
                }
            return {
                "version": SNAPSHOT_VERSION,
                "config": {"cooldown_matches": self.cooldown_matches},
                "ballots": ballots,
                "stats": {key: self._stats[key] for key in STAT_KEYS},
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                cooldown, ballots, stats = self._decode_snapshot(state)
            except VoteError:
                raise
            except Exception as exc:
                raise VoteError(ERR_SNAPSHOT_INVALID, exc) from exc
            self.cooldown_matches = cooldown
            self._ballots = ballots
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in STAT_KEYS}

    @staticmethod
    def _settle(ballot: _BallotState, at: int) -> BallotResult:
        candidate_set = set(ballot.candidates)
        counts = {map_id: 0 for map_id in ballot.candidates}
        valid_votes = 0
        for player_id in ballot.participants:
            choice = ballot.votes.get(player_id)
            if choice is not None and choice in candidate_set:
                counts[choice] += 1
                valid_votes += 1

        tally = tuple((map_id, counts[map_id]) for map_id in sorted(counts))
        abstained = len(ballot.participants) - valid_votes

        winner = None
        if valid_votes == 0:
            decided_by = (
                DECIDED_BY_ALL_ABSTAINED
                if ballot.ever_voted
                else DECIDED_BY_NO_VOTES
            )
        else:
            highest = max(counts.values())
            leaders = [
                map_id for map_id in ballot.candidates if counts[map_id] == highest
            ]
            if len(leaders) == 1:
                winner = leaders[0]
                decided_by = DECIDED_BY_VOTES
            else:
                winner = min(
                    leaders, key=lambda map_id: (ballot.ranks.get(map_id, 0), map_id)
                )
                decided_by = DECIDED_BY_TIEBREAK

        return BallotResult(
            match_id=ballot.match_id,
            winner=winner,
            decided_by=decided_by,
            tally=tally,
            abstained=abstained,
            closed_at=at,
            already_closed=False,
        )

    @staticmethod
    def _decode_snapshot(state: dict) -> tuple[int, dict, dict]:
        if not isinstance(state, dict):
            _snapshot_invalid("snapshot must be a dict")
        if set(state) != {"version", "config", "ballots", "stats"}:
            _snapshot_invalid("snapshot keys")
        if state["version"] != SNAPSHOT_VERSION:
            _snapshot_invalid({"version": state["version"]})

        config = state["config"]
        if not isinstance(config, dict) or set(config) != {"cooldown_matches"}:
            _snapshot_invalid("config")
        cooldown = config["cooldown_matches"]
        if not _is_int(cooldown) or cooldown < 0:
            _snapshot_invalid({"cooldown_matches": cooldown})

        raw_ballots = state["ballots"]
        if not isinstance(raw_ballots, dict):
            _snapshot_invalid("ballots")
        ballots = {}
        for match_id, raw in raw_ballots.items():
            if not isinstance(match_id, str) or not match_id:
                _snapshot_invalid({"match_id": match_id})
            ballots[match_id] = MapVoteBallot._decode_ballot(match_id, raw)

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(STAT_KEYS):
            _snapshot_invalid("stats")
        stats = {}
        for key in STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                _snapshot_invalid({"stats": key, "value": value})
            stats[key] = value

        ordered_ballots = {
            match_id: ballots[match_id] for match_id in sorted(ballots)
        }
        return cooldown, ordered_ballots, stats

    @staticmethod
    def _decode_ballot(match_id: str, raw: object) -> _BallotState:
        keys = {
            "match_id",
            "participants",
            "candidates",
            "excluded",
            "votes",
            "revote_counts",
            "ranks",
            "opened_at",
            "closed",
            "closed_at",
            "ever_voted",
            "result",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            _snapshot_invalid({"ballot": match_id, "keys": raw})
        if raw["match_id"] != match_id:
            _snapshot_invalid({"ballot": match_id, "match_id": raw["match_id"]})

        participants = MapVoteBallot._snapshot_tuple(
            raw["participants"], "participants", allow_empty=False
        )
        candidates = MapVoteBallot._snapshot_tuple(
            raw["candidates"], "candidates", allow_empty=True
        )
        excluded = MapVoteBallot._snapshot_tuple(
            raw["excluded"], "excluded", allow_empty=True
        )
        if list(participants) != sorted(participants):
            _snapshot_invalid("participants order")
        if list(candidates) != sorted(candidates):
            _snapshot_invalid("candidates order")
        if list(excluded) != sorted(excluded):
            _snapshot_invalid("excluded order")

        opened_at = raw["opened_at"]
        if not _is_int(opened_at):
            _snapshot_invalid({"opened_at": opened_at})

        votes_raw = raw["votes"]
        if not isinstance(votes_raw, dict):
            _snapshot_invalid("votes")
        candidate_set = set(candidates)
        participant_set = set(participants)
        for player_id in votes_raw:
            if not isinstance(player_id, str) or player_id not in participant_set:
                _snapshot_invalid({"votes": player_id})
        votes = {}
        for player_id in sorted(votes_raw):
            choice = votes_raw[player_id]
            if choice is not None and (
                not isinstance(choice, str) or choice not in candidate_set
            ):
                _snapshot_invalid({"vote": player_id, "map_id": choice})
            votes[player_id] = choice

        revotes_raw = raw["revote_counts"]
        if not isinstance(revotes_raw, dict):
            _snapshot_invalid("revote_counts")
        for player_id in revotes_raw:
            value = revotes_raw[player_id]
            if (
                not isinstance(player_id, str)
                or player_id not in participant_set
                or not _is_int(value)
                or value < 0
            ):
                _snapshot_invalid({"revote": player_id, "count": value})
        revote_counts = {}
        for player_id in sorted(revotes_raw):
            value = revotes_raw[player_id]
            revote_counts[player_id] = value
        if set(revote_counts) != set(votes):
            _snapshot_invalid("vote/revote mismatch")

        ranks_raw = raw["ranks"]
        if not isinstance(ranks_raw, dict):
            _snapshot_invalid("ranks")
        for map_id in ranks_raw:
            value = ranks_raw[map_id]
            if (
                not isinstance(map_id, str)
                or map_id not in candidate_set
                or not _is_int(value)
                or value < 0
            ):
                _snapshot_invalid({"rank": map_id, "value": value})
        ranks = {}
        for map_id in sorted(ranks_raw):
            value = ranks_raw[map_id]
            ranks[map_id] = value
        if set(ranks) != candidate_set:
            _snapshot_invalid("rank/candidate mismatch")

        closed = raw["closed"]
        if not isinstance(closed, bool):
            _snapshot_invalid("closed")
        closed_at = raw["closed_at"]
        ever_voted = raw["ever_voted"]
        if not isinstance(ever_voted, bool) or ever_voted != bool(votes):
            _snapshot_invalid("ever_voted")

        result = None
        if closed:
            if not _is_int(closed_at):
                _snapshot_invalid({"closed_at": closed_at})
            if raw["result"] is None:
                _snapshot_invalid("closed result missing")
            result = MapVoteBallot._decode_result(
                match_id, raw["result"], candidates, closed_at
            )
            if result.abstained + sum(count for _, count in result.tally) != len(
                participants
            ):
                _snapshot_invalid("result count")
        else:
            if closed_at is not None or raw["result"] is not None:
                _snapshot_invalid("open result")

        return _BallotState(
            match_id=match_id,
            participants=participants,
            candidates=candidates,
            excluded=excluded,
            opened_at=opened_at,
            votes=votes,
            revote_counts=revote_counts,
            ranks=ranks,
            closed=closed,
            closed_at=closed_at,
            ever_voted=ever_voted,
            result=result,
        )

    @staticmethod
    def _snapshot_tuple(value: object, field_name: str, *, allow_empty: bool) -> tuple:
        if not isinstance(value, tuple):
            _snapshot_invalid(field_name)
        if not value and not allow_empty:
            _snapshot_invalid(field_name)
        seen = set()
        for item in value:
            if not isinstance(item, str) or not item or item in seen:
                _snapshot_invalid({"field": field_name, "value": value})
            seen.add(item)
        return tuple(value)

    @staticmethod
    def _decode_result(
        match_id: str, raw: object, candidates: tuple, closed_at: int
    ) -> BallotResult:
        keys = {
            "match_id",
            "winner",
            "decided_by",
            "tally",
            "abstained",
            "closed_at",
            "already_closed",
        }
        if not isinstance(raw, dict) or set(raw) != keys:
            _snapshot_invalid({"result": match_id, "keys": raw})
        if raw["match_id"] != match_id or raw["closed_at"] != closed_at:
            _snapshot_invalid({"result": match_id})

        winner = raw["winner"]
        if winner is not None and (
            not isinstance(winner, str) or winner not in set(candidates)
        ):
            _snapshot_invalid({"winner": winner})
        decided_by = raw["decided_by"]
        if not isinstance(decided_by, str) or decided_by not in {
            DECIDED_BY_VOTES,
            DECIDED_BY_TIEBREAK,
            DECIDED_BY_NO_VOTES,
            DECIDED_BY_ALL_ABSTAINED,
        }:
            _snapshot_invalid({"decided_by": decided_by})
        if decided_by in {DECIDED_BY_VOTES, DECIDED_BY_TIEBREAK}:
            if winner is None:
                _snapshot_invalid("winner missing")
        elif winner is not None:
            _snapshot_invalid("unexpected winner")

        tally_raw = raw["tally"]
        if not isinstance(tally_raw, tuple):
            _snapshot_invalid("tally")
        tally = []
        for item in tally_raw:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not _is_int(item[1])
                or item[1] < 0
            ):
                _snapshot_invalid({"tally": item})
            tally.append((item[0], item[1]))
        tally_tuple = tuple(tally)
        if tuple(map_id for map_id, _ in tally_tuple) != tuple(candidates):
            _snapshot_invalid("tally/candidate mismatch")

        abstained = raw["abstained"]
        if not _is_int(abstained) or abstained < 0:
            _snapshot_invalid({"abstained": abstained})
        already_closed = raw["already_closed"]
        if not isinstance(already_closed, bool):
            _snapshot_invalid("already_closed")

        return BallotResult(
            match_id=match_id,
            winner=winner,
            decided_by=decided_by,
            tally=tally_tuple,
            abstained=abstained,
            closed_at=closed_at,
            already_closed=already_closed,
        )
