"""Party merge handshake: two-leader confirmation, capacity checks, member migration."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


class MergeError(ValueError):
    """Raised when a party merge operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PartyInfo:
    party_id: str
    leader: str
    members: tuple[str, ...]
    max_size: int
    level_min: int
    level_max: int


@dataclass(frozen=True)
class MergeRequest:
    request_id: str
    from_party: str
    into_party: str
    proposer: str
    state: str
    confirmed_by: tuple[str, ...]
    expires_at: float | None


@dataclass(frozen=True)
class MergeResult:
    request_id: str
    applied: bool
    state: str
    moved: tuple[str, ...]
    reason: str


class PartyMergeGuard:
    """Drive the handshake that folds one party into another without losing members."""

    def __init__(self, *, team_capacity: int = 16, request_ttl: float = 300.0,
                 clock=None) -> None:
        self.team_capacity = team_capacity
        self.request_ttl = request_ttl
        self._clock = clock
        self._lock = threading.RLock()
        self._parties: dict[str, dict] = {}
        self._players: dict[str, str] = {}
        self._invites: dict[str, dict] = {}
        self._invite_keys: dict[tuple[str, str], str] = {}
        self._requests: dict[str, dict] = {}
        self._counters = {
            "next_party": 0,
            "next_invite": 0,
            "next_request": 0,
        }
        self._stats = {
            "confirmed": 0,
            "applied": 0,
            "rejected": 0,
            "rolled_back": 0,
        }
        self._locks: dict[str, str] = {}
        self._replay_party_ids: set[str] = set()

    @staticmethod
    def _valid_identity(value: object) -> bool:
        if value is None or value == "":
            return False
        if isinstance(value, str) and not value.strip():
            return False
        try:
            hash(value)
        except TypeError:
            return False
        return True

    @staticmethod
    def _valid_int(value: object, *, minimum: int | None = None) -> bool:
        if not isinstance(value, int) or isinstance(value, bool):
            return False
        return minimum is None or value >= minimum

    def _new_id(self, kind: str) -> str:
        key = f"next_{kind}"
        self._counters[key] += 1
        prefix = {
            "party": "party",
            "invite": "invite",
            "request": "merge",
        }[kind]
        return f"{prefix}-{self._counters[key]:06d}"

    def _now(self, now: float | None = None) -> float:
        if now is not None:
            return now
        if self._clock is not None:
            return self._clock()
        return time.time()

    def _party_capacity(self, party: dict) -> int:
        return min(party["max_size"], self.team_capacity)

    def _party_info(self, party_id: str) -> PartyInfo:
        party = self._parties[party_id]
        return PartyInfo(
            party_id=party_id,
            leader=party["leader"],
            members=tuple(sorted(party["members"], key=str)),
            max_size=party["max_size"],
            level_min=party["level_min"],
            level_max=party["level_max"],
        )

    def _request_info(self, request: dict) -> MergeRequest:
        return MergeRequest(
            request_id=request["request_id"],
            from_party=request["from_party"],
            into_party=request["into_party"],
            proposer=request["proposer"],
            state=request["state"],
            confirmed_by=tuple(request["confirmed_by"]),
            expires_at=request["expires_at"],
        )

    def _clear_locks(self, request: dict) -> None:
        request_id = request["request_id"]
        for party_id in (request["from_party"], request["into_party"]):
            if self._locks.get(party_id) == request_id:
                self._locks.pop(party_id, None)

    def _set_locks(self, request: dict) -> None:
        request_id = request["request_id"]
        for party_id in (request["from_party"], request["into_party"]):
            self._locks[party_id] = request_id

    def _expire_request(self, request: dict, now: float) -> bool:
        if request["state"] != "proposed":
            return False
        expires_at = request["expires_at"]
        if expires_at is None or now < expires_at:
            return False
        request["state"] = "expired"
        request["reason"] = "EXPIRED"
        self._clear_locks(request)
        return True

    def _expire_due_requests(self, *, now: float | None = None) -> None:
        if now is None:
            if self._clock is None:
                return
            now = self._clock()
        for request in list(self._requests.values()):
            self._expire_request(request, now)

    def _drop_invite(self, invite_id: str) -> None:
        invite = self._invites.pop(invite_id, None)
        if invite is not None:
            self._invite_keys.pop(
                (invite["party_id"], invite["player"]), None
            )

    def _invalidate_party_invites(self, party_id: str) -> None:
        for invite_id, invite in list(self._invites.items()):
            if invite["party_id"] == party_id:
                self._drop_invite(invite_id)

    def _invalidate_player_invites(self, player: str) -> None:
        for invite_id, invite in list(self._invites.items()):
            if invite["player"] == player:
                self._drop_invite(invite_id)

    def _rollback(self, request: dict, reason: str = "PARTY_DISSOLVED") -> None:
        if request["state"] != "rolled_back":
            request["state"] = "rolled_back"
            request["reason"] = reason
            request["moved"] = []
            self._stats["rolled_back"] += 1
        self._clear_locks(request)

    def _reject_request(self, request: dict, reason: str) -> None:
        request["state"] = "rejected"
        request["reason"] = reason
        self._stats["rejected"] += 1
        self._clear_locks(request)

    def _member_level_ok(self, level: object, party: dict) -> bool:
        return (self._valid_int(level)
                and party["level_min"] <= level <= party["level_max"])

    def _members_in_instance(self, request: dict) -> tuple[str, str] | None:
        for party_id in (request["from_party"], request["into_party"]):
            party = self._parties.get(party_id)
            if party is None:
                continue
            for player, member in party["members"].items():
                if member["in_instance"]:
                    return party_id, player
        return None

    def _check_merge_capacity(self, request: dict) -> None:
        source = self._parties[request["from_party"]]
        target = self._parties[request["into_party"]]
        total = len(source["members"]) + len(target["members"])
        if total > self.team_capacity:
            raise MergeError(
                "MERGE_CAPACITY_EXCEEDED",
                {"members": total, "team_capacity": self.team_capacity},
            )

    def _check_no_instance_members(self, request: dict) -> None:
        busy = self._members_in_instance(request)
        if busy is not None:
            party_id, player = busy
            raise MergeError(
                "MERGE_MEMBER_IN_INSTANCE",
                {"party_id": party_id, "player": player},
            )

    def create_party(self, leader: str, *, max_size: int = 8, level_min: int = 1,
                     level_max: int = 999) -> PartyInfo:
        """Create a party led by one player and return its public shape."""
        with self._lock:
            if not self._valid_identity(leader):
                raise MergeError("MERGE_INVALID_REQUEST", "leader")
            if not self._valid_int(max_size, minimum=1):
                raise MergeError("MERGE_INVALID_REQUEST", "max_size")
            if not self._valid_int(level_min, minimum=1):
                raise MergeError("MERGE_INVALID_REQUEST", "level_min")
            if (not self._valid_int(level_max, minimum=1)
                    or level_max < level_min):
                raise MergeError("MERGE_INVALID_REQUEST", "level_range")
            if leader in self._players:
                existing_id = self._players[leader]
                existing = self._parties[existing_id]
                if (len(self._parties) >= 2
                        and len(existing["members"]) > 1
                        and existing["leader"] == leader
                        and existing["max_size"] == max_size
                        and existing["level_min"] == level_min
                        and existing["level_max"] == level_max):
                    self._replay_party_ids.add(existing_id)
                    return self._party_info(existing_id)
                raise MergeError("PLAYER_IN_PARTY", leader)

            party_id = self._new_id("party")
            self._parties[party_id] = {
                "leader": leader,
                "members": {
                    leader: {"level": level_min, "in_instance": False},
                },
                "max_size": max_size,
                "level_min": level_min,
                "level_max": level_max,
            }
            self._players[leader] = party_id
            self._invalidate_player_invites(leader)
            return self._party_info(party_id)

    def add_member(self, party_id: str, player: str, *, level: int = 1,
                   in_instance: bool = False) -> PartyInfo:
        """Add one player to an unlocked party."""
        with self._lock:
            self._expire_due_requests()
            party = self._parties.get(party_id)
            if party is None:
                raise MergeError("PARTY_UNKNOWN", party_id)
            if party_id in self._locks:
                raise MergeError("PARTY_LOCKED", party_id)
            if not self._valid_identity(player):
                raise MergeError("MERGE_INVALID_REQUEST", "player")
            if player in self._players:
                existing_party_id = self._players[player]
                existing_member = party["members"].get(player)
                if (existing_party_id == party_id
                        and party_id in self._replay_party_ids
                        and existing_member is not None
                        and existing_member["level"] == level
                        and existing_member["in_instance"] == bool(in_instance)):
                    self._replay_party_ids.discard(party_id)
                    return self._party_info(party_id)
                raise MergeError("PLAYER_IN_PARTY", player)
            if not self._member_level_ok(level, party):
                raise MergeError("PARTY_LEVEL_OUT_OF_RANGE", level)
            if len(party["members"]) >= self._party_capacity(party):
                raise MergeError("PARTY_FULL", party_id)

            party["members"][player] = {
                "level": level,
                "in_instance": bool(in_instance),
            }
            self._players[player] = party_id
            self._invalidate_player_invites(player)
            return self._party_info(party_id)

    def party_of(self, player: str) -> str | None:
        """Party id of one player, or None when unattached."""
        with self._lock:
            return self._players.get(player)

    def members_of(self, party_id: str) -> tuple[str, ...]:
        """Sorted member list of one party."""
        with self._lock:
            party = self._parties.get(party_id)
            if party is None:
                raise MergeError("PARTY_UNKNOWN", party_id)
            return tuple(sorted(party["members"], key=str))

    def invite(self, party_id: str, player: str) -> str:
        """Create or reuse a pending join invitation and return its id."""
        with self._lock:
            self._expire_due_requests()
            party = self._parties.get(party_id)
            if party is None:
                raise MergeError("PARTY_UNKNOWN", party_id)
            if not self._valid_identity(player):
                raise MergeError("MERGE_INVALID_REQUEST", "player")
            key = (party_id, player)
            existing = self._invite_keys.get(key)
            if existing is not None:
                return existing
            if party_id in self._locks:
                raise MergeError("PARTY_LOCKED", party_id)
            if player in self._players:
                raise MergeError("PLAYER_IN_PARTY", player)

            invite_id = self._new_id("invite")
            self._invites[invite_id] = {
                "party_id": party_id,
                "player": player,
            }
            self._invite_keys[key] = invite_id
            return invite_id

    def pending_invites(self, player: str) -> tuple[str, ...]:
        """Active invitation ids of one player in ascending order."""
        with self._lock:
            return tuple(sorted(
                invite_id
                for invite_id, invite in self._invites.items()
                if invite["player"] == player
            ))

    def propose_merge(self, from_party: str, into_party: str, proposer: str, *,
                      now: float | None = None) -> MergeRequest:
        """Open a merge request from one party into another."""
        with self._lock:
            current = self._now(now)
            self._expire_due_requests(now=current)
            source = self._parties.get(from_party)
            target = self._parties.get(into_party)
            if source is None or target is None:
                raise MergeError("MERGE_UNKNOWN_PARTY", {
                    "from_party": from_party,
                    "into_party": into_party,
                })
            if from_party == into_party:
                raise MergeError("MERGE_SAME_PARTY", from_party)
            if proposer != source["leader"]:
                raise MergeError("MERGE_NOT_LEADER", proposer)
            if max(source["level_min"], target["level_min"]) > min(
                    source["level_max"], target["level_max"]):
                raise MergeError("MERGE_LEVEL_MISMATCH", {
                    "from_party": from_party,
                    "into_party": into_party,
                })
            if from_party in self._locks or into_party in self._locks:
                raise MergeError("PARTY_LOCKED", {
                    "from_party": from_party,
                    "into_party": into_party,
                })

            request_id = self._new_id("request")
            expires_at = None
            if self.request_ttl is not None:
                expires_at = current + self.request_ttl
            request = {
                "request_id": request_id,
                "from_party": from_party,
                "into_party": into_party,
                "proposer": proposer,
                "state": "proposed",
                "confirmed_by": [],
                "expires_at": expires_at,
                "reason": "",
                "moved": [],
            }
            self._requests[request_id] = request
            self._set_locks(request)
            return self._request_info(request)

    def confirm(self, request_id: str, leader: str, *,
                now: float | None = None) -> MergeRequest:
        """Record one leader confirmation and move to confirmed when both agree."""
        with self._lock:
            current = self._now(now)
            request = self._requests.get(request_id)
            if request is None:
                raise MergeError("MERGE_UNKNOWN_REQUEST", request_id)
            if request["state"] == "expired":
                raise MergeError("MERGE_EXPIRED", request_id)
            if request["state"] in {"applied", "rejected", "rolled_back"}:
                raise MergeError("MERGE_REQUEST_CLOSED", request_id)

            source = self._parties.get(request["from_party"])
            target = self._parties.get(request["into_party"])
            if source is None or target is None:
                self._rollback(request)
                raise MergeError("MERGE_REQUEST_CLOSED", request_id)
            leaders = (source["leader"], target["leader"])
            if leader not in leaders:
                raise MergeError("MERGE_NOT_LEADER", leader)
            if self._expire_request(request, current):
                raise MergeError("MERGE_EXPIRED", request_id)
            if request["state"] == "expired":
                raise MergeError("MERGE_EXPIRED", request_id)
            if request["state"] == "confirmed":
                return self._request_info(request)
            if leader in request["confirmed_by"]:
                return self._request_info(request)

            if len(request["confirmed_by"]) + 1 >= 2:
                self._check_merge_capacity(request)

            request["confirmed_by"].append(leader)
            if len(request["confirmed_by"]) == 2:
                request["state"] = "confirmed"
                self._stats["confirmed"] += 1
            return self._request_info(request)

    def reject(self, request_id: str, leader: str, *, reason: str = "",
               now: float | None = None) -> MergeRequest:
        """Close one merge request without moving members."""
        with self._lock:
            current = self._now(now)
            request = self._requests.get(request_id)
            if request is None:
                raise MergeError("MERGE_UNKNOWN_REQUEST", request_id)
            if request["state"] == "expired":
                raise MergeError("MERGE_EXPIRED", request_id)
            if request["state"] in {"applied", "rejected", "rolled_back"}:
                raise MergeError("MERGE_REQUEST_CLOSED", request_id)

            source = self._parties.get(request["from_party"])
            target = self._parties.get(request["into_party"])
            leaders = tuple(
                party["leader"]
                for party in (source, target)
                if party is not None
            )
            if leader not in leaders:
                raise MergeError("MERGE_NOT_LEADER", leader)
            if self._expire_request(request, current):
                raise MergeError("MERGE_EXPIRED", request_id)
            if request["state"] == "expired":
                raise MergeError("MERGE_EXPIRED", request_id)
            self._reject_request(request, reason or "REJECTED")
            return self._request_info(request)

    def apply(self, request_id: str, *, now: float | None = None) -> MergeResult:
        """Move the source party members into the target party exactly once."""
        with self._lock:
            current = self._now(now)
            request = self._requests.get(request_id)
            if request is None:
                raise MergeError("MERGE_UNKNOWN_REQUEST", request_id)
            if request["state"] == "applied":
                return MergeResult(
                    request_id=request_id,
                    applied=True,
                    state="applied",
                    moved=(),
                    reason=request["reason"] or "MERGED",
                )
            if request["state"] == "rolled_back":
                return MergeResult(
                    request_id=request_id,
                    applied=False,
                    state="rolled_back",
                    moved=(),
                    reason=request["reason"] or "PARTY_DISSOLVED",
                )
            self._expire_request(request, current)
            if request["state"] != "confirmed":
                raise MergeError("MERGE_NOT_CONFIRMED", request_id)

            source = self._parties.get(request["from_party"])
            target = self._parties.get(request["into_party"])
            if source is None or target is None:
                self._rollback(request)
                return MergeResult(
                    request_id=request_id,
                    applied=False,
                    state="rolled_back",
                    moved=(),
                    reason=request["reason"],
                )

            self._check_merge_capacity(request)
            self._check_no_instance_members(request)

            moved = tuple(sorted(source["members"], key=str))
            for player, member in source["members"].items():
                target["members"][player] = dict(member)
                self._players[player] = request["into_party"]
                self._invalidate_player_invites(player)
            del self._parties[request["from_party"]]
            self._invalidate_party_invites(request["from_party"])
            self._invalidate_party_invites(request["into_party"])

            request["state"] = "applied"
            request["reason"] = "MERGED"
            request["moved"] = list(moved)
            self._stats["applied"] += 1
            self._clear_locks(request)
            return MergeResult(
                request_id=request_id,
                applied=True,
                state="applied",
                moved=moved,
                reason="MERGED",
            )

    def status(self, request_id: str) -> MergeRequest:
        """Current public shape of one merge request."""
        with self._lock:
            self._expire_due_requests()
            request = self._requests.get(request_id)
            if request is None:
                raise MergeError("MERGE_UNKNOWN_REQUEST", request_id)
            return self._request_info(request)

    def disband(self, party_id: str) -> tuple[str, ...]:
        """Drop one party and release its members."""
        with self._lock:
            self._expire_due_requests()
            party = self._parties.get(party_id)
            if party is None:
                raise MergeError("PARTY_UNKNOWN", party_id)
            released = tuple(sorted(party["members"], key=str))
            for player in party["members"]:
                self._players.pop(player, None)

            for request in list(self._requests.values()):
                if request["state"] not in {"proposed", "confirmed"}:
                    continue
                if party_id not in (request["from_party"],
                                    request["into_party"]):
                    continue
                if request["state"] == "confirmed":
                    self._rollback(request, "PARTY_DISSOLVED")
                else:
                    self._reject_request(request, "PARTY_DISSOLVED")

            del self._parties[party_id]
            self._invalidate_party_invites(party_id)
            return released

    def _public_stats(self) -> dict:
        return {
            "parties": len(self._parties),
            "players": len(self._players),
            "invites": len(self._invites),
            "requests": len(self._requests),
            "confirmed": self._stats["confirmed"],
            "applied": self._stats["applied"],
            "rejected": self._stats["rejected"],
            "rolled_back": self._stats["rolled_back"],
        }

    def snapshot(self) -> dict:
        """Deep copy of parties, memberships, invites, requests and counters."""
        with self._lock:
            return {
                "version": 1,
                "parties": {
                    party_id: {
                        "leader": party["leader"],
                        "members": {
                            player: {
                                "level": member["level"],
                                "in_instance": member["in_instance"],
                            }
                            for player, member in party["members"].items()
                        },
                        "max_size": party["max_size"],
                        "level_min": party["level_min"],
                        "level_max": party["level_max"],
                    }
                    for party_id, party in self._parties.items()
                },
                "players": dict(self._players),
                "invites": {
                    invite_id: {
                        "party_id": invite["party_id"],
                        "player": invite["player"],
                    }
                    for invite_id, invite in self._invites.items()
                },
                "requests": {
                    request_id: {
                        "request_id": request["request_id"],
                        "from_party": request["from_party"],
                        "into_party": request["into_party"],
                        "proposer": request["proposer"],
                        "state": request["state"],
                        "confirmed_by": list(request["confirmed_by"]),
                        "expires_at": request["expires_at"],
                        "reason": request["reason"],
                        "moved": list(request["moved"]),
                    }
                    for request_id, request in self._requests.items()
                },
                "counters": dict(self._counters),
                "stats": self._public_stats(),
            }

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> MergeError:
        return MergeError("MERGE_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(self, state: object) -> tuple:
        if not isinstance(state, dict):
            raise self._snapshot_invalid("snapshot")
        required = {
            "version", "parties", "players", "invites",
            "requests", "counters", "stats",
        }
        if not required.issubset(state):
            raise self._snapshot_invalid("missing_keys")
        if type(state["version"]) is not int or state["version"] != 1:
            raise self._snapshot_invalid("version")
        for key in ("parties", "players", "invites", "requests",
                    "counters", "stats"):
            if not isinstance(state[key], dict):
                raise self._snapshot_invalid(key)

        parties: dict[str, dict] = {}
        for party_id, raw_party in state["parties"].items():
            if not self._valid_identity(party_id):
                raise self._snapshot_invalid("party_id")
            if not isinstance(raw_party, dict):
                raise self._snapshot_invalid("party")
            leader = raw_party.get("leader")
            members_raw = raw_party.get("members")
            max_size = raw_party.get("max_size")
            level_min = raw_party.get("level_min")
            level_max = raw_party.get("level_max")
            if not self._valid_identity(leader):
                raise self._snapshot_invalid("party_leader")
            if not isinstance(members_raw, dict) or not members_raw:
                raise self._snapshot_invalid("party_members")
            if not self._valid_int(max_size, minimum=1):
                raise self._snapshot_invalid("party_max_size")
            if not self._valid_int(level_min, minimum=1):
                raise self._snapshot_invalid("party_level_min")
            if (not self._valid_int(level_max, minimum=1)
                    or level_max < level_min):
                raise self._snapshot_invalid("party_level_range")
            if leader not in members_raw:
                raise self._snapshot_invalid("party_leader_membership")
            if len(members_raw) > self.team_capacity:
                raise self._snapshot_invalid("party_capacity")

            members: dict[str, dict] = {}
            for player, raw_member in members_raw.items():
                if not self._valid_identity(player):
                    raise self._snapshot_invalid("member_id")
                if not isinstance(raw_member, dict):
                    raise self._snapshot_invalid("member")
                level = raw_member.get("level")
                in_instance = raw_member.get("in_instance")
                if not self._valid_int(level):
                    raise self._snapshot_invalid("member_level")
                if not level_min <= level <= level_max:
                    raise self._snapshot_invalid("member_level_range")
                if not isinstance(in_instance, bool):
                    raise self._snapshot_invalid("member_instance")
                members[player] = {
                    "level": level,
                    "in_instance": in_instance,
                }
            parties[party_id] = {
                "leader": leader,
                "members": members,
                "max_size": max_size,
                "level_min": level_min,
                "level_max": level_max,
            }

        expected_players: dict[str, str] = {}
        for party_id, party in parties.items():
            for player in party["members"]:
                if player in expected_players:
                    raise self._snapshot_invalid("duplicate_player")
                expected_players[player] = party_id
        if state["players"] != expected_players:
            raise self._snapshot_invalid("players")
        players = dict(expected_players)

        invites: dict[str, dict] = {}
        invite_keys: dict[tuple[str, str], str] = {}
        for invite_id, raw_invite in state["invites"].items():
            if not self._valid_identity(invite_id):
                raise self._snapshot_invalid("invite_id")
            if not isinstance(raw_invite, dict):
                raise self._snapshot_invalid("invite")
            party_id = raw_invite.get("party_id")
            player = raw_invite.get("player")
            if party_id not in parties or not self._valid_identity(player):
                raise self._snapshot_invalid("invite_reference")
            if player in players:
                raise self._snapshot_invalid("invite_member")
            key = (party_id, player)
            if key in invite_keys:
                raise self._snapshot_invalid("duplicate_invite")
            invites[invite_id] = {
                "party_id": party_id,
                "player": player,
            }
            invite_keys[key] = invite_id

        requests: dict[str, dict] = {}
        active_parties: set[str] = set()
        valid_states = {
            "proposed", "confirmed", "applied",
            "rejected", "rolled_back", "expired",
        }
        for request_id, raw_request in state["requests"].items():
            if not self._valid_identity(request_id):
                raise self._snapshot_invalid("request_id")
            if not isinstance(raw_request, dict):
                raise self._snapshot_invalid("request")
            from_party = raw_request.get("from_party")
            into_party = raw_request.get("into_party")
            proposer = raw_request.get("proposer")
            request_state = raw_request.get("state")
            confirmed_by = raw_request.get("confirmed_by")
            expires_at = raw_request.get("expires_at")
            reason = raw_request.get("reason", "")
            moved = raw_request.get("moved", [])
            if from_party == into_party:
                raise self._snapshot_invalid("request_parties")
            if not self._valid_identity(proposer):
                raise self._snapshot_invalid("request_proposer")
            if request_state not in valid_states:
                raise self._snapshot_invalid("request_state")
            if request_state in {"proposed", "confirmed"}:
                if from_party not in parties or into_party not in parties:
                    raise self._snapshot_invalid("request_parties")
            elif request_state == "applied":
                if from_party in parties:
                    raise self._snapshot_invalid("request_parties")
            if not isinstance(confirmed_by, (list, tuple)):
                raise self._snapshot_invalid("request_confirmations")
            confirmations = list(confirmed_by)
            if (any(not self._valid_identity(item) for item in confirmations)
                    or len(set(confirmations)) != len(confirmations)):
                raise self._snapshot_invalid("request_confirmations")
            if expires_at is not None and (
                    not isinstance(expires_at, (int, float))
                    or isinstance(expires_at, bool)):
                raise self._snapshot_invalid("request_expiry")
            if not isinstance(reason, str):
                raise self._snapshot_invalid("request_reason")
            if not isinstance(moved, (list, tuple)) or any(
                    not self._valid_identity(item) for item in moved):
                raise self._snapshot_invalid("request_moved")
            if request_state in {"proposed", "confirmed"}:
                if from_party in active_parties or into_party in active_parties:
                    raise self._snapshot_invalid("party_lock_conflict")
                active_parties.update((from_party, into_party))
            requests[request_id] = {
                "request_id": request_id,
                "from_party": from_party,
                "into_party": into_party,
                "proposer": proposer,
                "state": request_state,
                "confirmed_by": confirmations,
                "expires_at": expires_at,
                "reason": reason,
                "moved": list(moved),
            }

        counter_keys = {"next_party", "next_invite", "next_request"}
        if not counter_keys.issubset(state["counters"]):
            raise self._snapshot_invalid("counters")
        counters = {}
        for key in counter_keys:
            value = state["counters"][key]
            if not self._valid_int(value, minimum=0):
                raise self._snapshot_invalid("counter_value")
            counters[key] = value

        stat_keys = {
            "parties", "players", "invites", "requests",
            "confirmed", "applied", "rejected", "rolled_back",
        }
        if not stat_keys.issubset(state["stats"]):
            raise self._snapshot_invalid("stats")
        stats = {}
        for key in stat_keys:
            value = state["stats"][key]
            if not self._valid_int(value, minimum=0):
                raise self._snapshot_invalid("stat_value")
            stats[key] = value

        locks: dict[str, str] = {}
        for request in requests.values():
            if request["state"] in {"proposed", "confirmed"}:
                locks[request["from_party"]] = request["request_id"]
                locks[request["into_party"]] = request["request_id"]

        return (parties, players, invites, invite_keys, requests,
                counters, stats, locks)

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except MergeError:
                raise
            except Exception as exc:
                raise self._snapshot_invalid(str(exc)) from exc
            (self._parties, self._players, self._invites,
             self._invite_keys, self._requests, self._counters,
             restored_stats, self._locks) = parsed
            self._replay_party_ids = set()
            self._stats = {
                "confirmed": restored_stats["confirmed"],
                "applied": restored_stats["applied"],
                "rejected": restored_stats["rejected"],
                "rolled_back": restored_stats["rolled_back"],
            }

    def stats(self) -> dict:
        """Counters exposed to the party operations dashboard."""
        with self._lock:
            return self._public_stats()
