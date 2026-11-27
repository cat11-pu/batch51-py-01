"""Cross-realm world-first ledger: clock skew arbitration and invalidation."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, fields, replace


DIFFICULTIES = ("normal", "heroic", "mythic")

STATUS_FIRST = "first"
STATUS_SUPERSEDED = "superseded"
STATUS_RECORDED = "recorded"
STATUS_INVALIDATED = "invalidated"

VERDICT_ACCEPTED = "accepted"
VERDICT_RECORDED = "recorded"
VERDICT_DUPLICATE = "duplicate"
VERDICT_INVALIDATED = "invalidated"

REASON_FIRST_CLAIM = "WORLD_FIRST_CLAIM"
REASON_DISPLACED = "WORLD_DISPLACED"
REASON_NOT_FASTER = "WORLD_NOT_FASTER"
REASON_DUPLICATE = "WORLD_DUPLICATE_EVIDENCE"

DEFAULT_CONFIG = {"skew_tolerance": 30}

STAT_KEYS = (
    "claims",
    "duplicates",
    "invalidations",
    "supersessions",
    "promotions",
)

SNAPSHOT_VERSION = 1


class RaceError(ValueError):
    """Refusal raised by the world-first ledger."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Claim:
    claim_id: int
    boss_id: str
    difficulty: str
    season: int
    server: str
    killed_at: int
    digest: str
    claim_seq: int
    status: str
    evidence_ok: bool


@dataclass(frozen=True)
class Adjudication:
    claim_id: int
    status: str
    first_claim_id: int | None
    changed: bool
    reason: str


@dataclass
class _Group:
    claim_ids: list[int]
    first_id: int | None = None


CLAIM_FIELDS = frozenset(field.name for field in fields(Claim))


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or value == "":
        raise RaceError("WORLD_INVALID_REQUEST", f"{name} must be a non-empty string")
    return value


def _require_int(value: object, name: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RaceError("WORLD_INVALID_REQUEST", f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise RaceError("WORLD_INVALID_REQUEST", f"{name} must be >= {minimum}")
    return value


def _validate_boss(boss_id: object) -> str:
    return _require_text(boss_id, "boss_id")


def _validate_difficulty(difficulty: object) -> str:
    if difficulty not in DIFFICULTIES:
        raise RaceError("WORLD_INVALID_REQUEST", f"unsupported difficulty: {difficulty!r}")
    return difficulty  # type: ignore[return-value]


def _validate_season(season: object) -> int:
    return _require_int(season, "season")


def _history_key(claim: Claim) -> tuple[int, int, str, int]:
    return (claim.killed_at, claim.claim_seq, claim.server, claim.claim_id)


def _group_key(boss_id: str, difficulty: str, season: int) -> tuple[str, str, int]:
    return (boss_id, difficulty, season)


def _encode_group_key(key: tuple[str, str, int]) -> str:
    return json.dumps(key, ensure_ascii=False, separators=(",", ":"))


def _decode_group_key(key: object) -> tuple[str, str, int]:
    value: object
    if isinstance(key, str):
        try:
            value = json.loads(key)
        except (TypeError, ValueError):
            raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid first-group key") from None
    elif isinstance(key, (tuple, list)):
        value = key
    else:
        raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid first-group key")

    if not isinstance(value, (tuple, list)) or len(value) != 3:
        raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid first-group key")

    boss_id, difficulty, season = value
    try:
        return (
            _validate_boss(boss_id),
            _validate_difficulty(difficulty),
            _validate_season(season),
        )
    except RaceError:
        raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid first-group key") from None


def _claim_to_dict(claim: Claim) -> dict:
    return {
        "claim_id": claim.claim_id,
        "boss_id": claim.boss_id,
        "difficulty": claim.difficulty,
        "season": claim.season,
        "server": claim.server,
        "killed_at": claim.killed_at,
        "digest": claim.digest,
        "claim_seq": claim.claim_seq,
        "status": claim.status,
        "evidence_ok": claim.evidence_ok,
    }


class WorldFirstLedger:
    """Adjudicate cross-realm world-first claims per boss, difficulty and season."""

    def __init__(self, *, skew_tolerance: int = 30) -> None:
        self.skew_tolerance = _require_int(
            skew_tolerance, "skew_tolerance", minimum=0
        )
        self._lock = threading.RLock()
        self._claims: dict[int, Claim] = {}
        self._groups: dict[tuple[str, str, int], _Group] = {}
        self._next_claim_id = 1
        self._stats = {key: 0 for key in STAT_KEYS}

    def _claim_or_unknown(self, claim_id: object) -> Claim:
        if isinstance(claim_id, bool) or not isinstance(claim_id, int):
            raise RaceError("WORLD_UNKNOWN_CLAIM", claim_id)
        claim = self._claims.get(claim_id)
        if claim is None:
            raise RaceError("WORLD_UNKNOWN_CLAIM", claim_id)
        return claim

    def _group_claims(self, group: _Group) -> list[Claim]:
        return [self._claims[claim_id] for claim_id in group.claim_ids]

    def _is_eligible(self, claim: Claim, group_claims: list[Claim]) -> bool:
        if claim.status == STATUS_INVALIDATED:
            return False
        if claim.status in (STATUS_FIRST, STATUS_SUPERSEDED):
            return True

        first_for_server = min(
            (row.claim_id for row in group_claims if row.server == claim.server),
            default=None,
        )
        return claim.claim_id == first_for_server

    def _has_eligible_server_claim(
        self, group: _Group, server: str
    ) -> bool:
        group_claims = self._group_claims(group)
        return any(
            row.server == server
            and row.status != STATUS_INVALIDATED
            and self._is_eligible(row, group_claims)
            for row in group_claims
        )

    def _best_valid_candidate(self, group: _Group) -> int | None:
        group_claims = self._group_claims(group)
        candidates = [
            row
            for row in group_claims
            if row.status != STATUS_INVALIDATED
            and self._is_eligible(row, group_claims)
        ]
        if not candidates:
            return None
        return min(candidates, key=_history_key).claim_id

    def _promote_after_invalidation(self, group: _Group) -> None:
        candidate_id = self._best_valid_candidate(group)
        if candidate_id is None:
            group.first_id = None
            return

        candidate = replace(self._claims[candidate_id], status=STATUS_FIRST)
        self._claims[candidate_id] = candidate
        group.first_id = candidate_id
        self._stats["promotions"] += 1

    def _invalidate_locked(
        self, claim_id: int, reason: str
    ) -> Adjudication:
        claim = self._claim_or_unknown(claim_id)
        if claim.status == STATUS_INVALIDATED:
            raise RaceError("WORLD_INVALID_STATE", claim_id)

        key = _group_key(claim.boss_id, claim.difficulty, claim.season)
        group = self._groups[key]
        was_first = group.first_id == claim_id

        self._claims[claim_id] = replace(claim, status=STATUS_INVALIDATED)
        self._stats["invalidations"] += 1

        if was_first:
            self._promote_after_invalidation(group)

        return Adjudication(
            claim_id=claim_id,
            status=VERDICT_INVALIDATED,
            first_claim_id=group.first_id,
            changed=was_first,
            reason=reason,
        )

    def claim(
        self,
        boss_id: str,
        difficulty: str,
        season: int,
        *,
        server: str,
        killed_at: int,
        digest: str,
        claim_seq: int,
    ) -> Adjudication:
        boss_id = _validate_boss(boss_id)
        difficulty = _validate_difficulty(difficulty)
        season = _validate_season(season)
        server = _require_text(server, "server")
        killed_at = _require_int(killed_at, "killed_at")
        digest = _require_text(digest, "digest")
        claim_seq = _require_int(claim_seq, "claim_seq", minimum=0)
        key = _group_key(boss_id, difficulty, season)

        with self._lock:
            group = self._groups.get(key)

            if group is not None:
                for existing_id in group.claim_ids:
                    existing = self._claims[existing_id]
                    if existing.server == server and existing.digest == digest:
                        self._stats["duplicates"] += 1
                        return Adjudication(
                            claim_id=existing.claim_id,
                            status=VERDICT_DUPLICATE,
                            first_claim_id=group.first_id,
                            changed=False,
                            reason=REASON_DUPLICATE,
                        )

            if group is None:
                group = _Group(claim_ids=[])
                self._groups[key] = group
                eligible = True
            else:
                eligible = not self._has_eligible_server_claim(group, server)

            claim_id = self._next_claim_id
            self._next_claim_id += 1
            record = Claim(
                claim_id=claim_id,
                boss_id=boss_id,
                difficulty=difficulty,
                season=season,
                server=server,
                killed_at=killed_at,
                digest=digest,
                claim_seq=claim_seq,
                status=STATUS_RECORDED,
                evidence_ok=False,
            )

            first_id = group.first_id
            if first_id is None:
                record = replace(record, status=STATUS_FIRST)
                self._claims[claim_id] = record
                group.claim_ids.append(claim_id)
                group.first_id = claim_id
                self._stats["claims"] += 1
                self._stats["promotions"] += 1
                return Adjudication(
                    claim_id=claim_id,
                    status=VERDICT_ACCEPTED,
                    first_claim_id=claim_id,
                    changed=True,
                    reason=REASON_FIRST_CLAIM,
                )

            current = self._claims[first_id]
            wins = False
            if eligible:
                difference = killed_at - current.killed_at
                if difference < -self.skew_tolerance:
                    wins = True
                elif difference <= self.skew_tolerance:
                    wins = (
                        claim_seq,
                        server,
                        claim_id,
                    ) < (
                        current.claim_seq,
                        current.server,
                        current.claim_id,
                    )

            if wins:
                self._claims[first_id] = replace(
                    current, status=STATUS_SUPERSEDED
                )
                record = replace(record, status=STATUS_FIRST)
                self._claims[claim_id] = record
                group.claim_ids.append(claim_id)
                group.first_id = claim_id
                self._stats["claims"] += 1
                self._stats["supersessions"] += 1
                self._stats["promotions"] += 1
                return Adjudication(
                    claim_id=claim_id,
                    status=VERDICT_ACCEPTED,
                    first_claim_id=claim_id,
                    changed=True,
                    reason=REASON_DISPLACED,
                )

            self._claims[claim_id] = record
            group.claim_ids.append(claim_id)
            self._stats["claims"] += 1
            return Adjudication(
                claim_id=claim_id,
                status=VERDICT_RECORDED,
                first_claim_id=group.first_id,
                changed=False,
                reason=REASON_NOT_FASTER,
            )

    def verify(self, claim_id: int, *, digest: str, ok: bool, reason: str = "") -> Adjudication:
        digest = _require_text(digest, "digest")
        if not isinstance(ok, bool):
            raise RaceError("WORLD_INVALID_REQUEST", "ok must be a boolean")

        with self._lock:
            claim = self._claim_or_unknown(claim_id)
            if claim.digest != digest:
                raise RaceError("WORLD_EVIDENCE_MISMATCH", claim_id)

            if not ok:
                return self._invalidate_locked(claim_id, reason)

            if not claim.evidence_ok:
                self._claims[claim_id] = replace(claim, evidence_ok=True)

            group = self._groups[
                _group_key(claim.boss_id, claim.difficulty, claim.season)
            ]
            return Adjudication(
                claim_id=claim_id,
                status=VERDICT_ACCEPTED,
                first_claim_id=group.first_id,
                changed=False,
                reason="",
            )

    def invalidate(self, claim_id: int, reason: str) -> Adjudication:
        with self._lock:
            return self._invalidate_locked(claim_id, reason)

    def first_of(self, boss_id: str, difficulty: str, season: int) -> Claim | None:
        boss_id = _validate_boss(boss_id)
        difficulty = _validate_difficulty(difficulty)
        season = _validate_season(season)
        key = _group_key(boss_id, difficulty, season)

        with self._lock:
            group = self._groups.get(key)
            if group is None or group.first_id is None:
                return None
            return self._claims[group.first_id]

    def history(self, boss_id: str, difficulty: str, season: int) -> tuple:
        boss_id = _validate_boss(boss_id)
        difficulty = _validate_difficulty(difficulty)
        season = _validate_season(season)
        key = _group_key(boss_id, difficulty, season)

        with self._lock:
            group = self._groups.get(key)
            if group is None:
                return ()
            rows = [self._claims[claim_id] for claim_id in group.claim_ids]
            return tuple(sorted(rows, key=_history_key))

    def claim_of(self, claim_id: int) -> Claim:
        with self._lock:
            return self._claim_or_unknown(claim_id)

    def snapshot(self) -> dict:
        with self._lock:
            claims = [
                _claim_to_dict(self._claims[claim_id])
                for claim_id in sorted(self._claims)
            ]
            first = {
                _encode_group_key(key): group.first_id
                for key, group in sorted(self._groups.items())
                if group.first_id is not None
            }
            return {
                "version": SNAPSHOT_VERSION,
                "config": {"skew_tolerance": self.skew_tolerance},
                "claims": claims,
                "first": first,
                "stats": {key: self._stats[key] for key in STAT_KEYS},
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, dict):
                raise RaceError("WORLD_SNAPSHOT_INVALID", "state must be a dict")
            if set(state) != {"version", "config", "claims", "first", "stats"}:
                raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid snapshot keys")

            version = state["version"]
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version != SNAPSHOT_VERSION
            ):
                raise RaceError("WORLD_SNAPSHOT_INVALID", "unsupported version")

            config = state["config"]
            if not isinstance(config, dict) or set(config) != {"skew_tolerance"}:
                raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid config")
            try:
                skew_tolerance = _require_int(
                    config["skew_tolerance"], "skew_tolerance", minimum=0
                )
            except RaceError:
                raise RaceError(
                    "WORLD_SNAPSHOT_INVALID", "invalid config"
                ) from None

            raw_claims = state["claims"]
            if not isinstance(raw_claims, list):
                raise RaceError("WORLD_SNAPSHOT_INVALID", "claims must be a list")

            claims: dict[int, Claim] = {}
            for item in raw_claims:
                if not isinstance(item, dict) or set(item) != CLAIM_FIELDS:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "invalid claim record"
                    )
                try:
                    claim_id = _require_int(
                        item["claim_id"], "claim_id", minimum=0
                    )
                    boss_id = _validate_boss(item["boss_id"])
                    difficulty = _validate_difficulty(item["difficulty"])
                    season = _validate_season(item["season"])
                    server = _require_text(item["server"], "server")
                    killed_at = _require_int(item["killed_at"], "killed_at")
                    digest = _require_text(item["digest"], "digest")
                    claim_seq = _require_int(
                        item["claim_seq"], "claim_seq", minimum=0
                    )
                except RaceError:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "invalid claim record"
                    ) from None

                status = item["status"]
                if status not in (
                    STATUS_FIRST,
                    STATUS_SUPERSEDED,
                    STATUS_RECORDED,
                    STATUS_INVALIDATED,
                ):
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "invalid claim status"
                    )
                evidence_ok = item["evidence_ok"]
                if not isinstance(evidence_ok, bool):
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "invalid evidence flag"
                    )
                if claim_id in claims:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "duplicate claim id"
                    )
                claims[claim_id] = Claim(
                    claim_id=claim_id,
                    boss_id=boss_id,
                    difficulty=difficulty,
                    season=season,
                    server=server,
                    killed_at=killed_at,
                    digest=digest,
                    claim_seq=claim_seq,
                    status=status,
                    evidence_ok=evidence_ok,
                )

            groups: dict[tuple[str, str, int], _Group] = {}
            for claim_id in sorted(claims):
                claim = claims[claim_id]
                key = _group_key(claim.boss_id, claim.difficulty, claim.season)
                group = groups.setdefault(key, _Group(claim_ids=[]))
                group.claim_ids.append(claim_id)
                if claim.status == STATUS_FIRST:
                    if group.first_id is not None:
                        raise RaceError(
                            "WORLD_SNAPSHOT_INVALID",
                            "multiple first claims in one group",
                        )
                    group.first_id = claim_id

            raw_first = state["first"]
            if not isinstance(raw_first, dict):
                raise RaceError(
                    "WORLD_SNAPSHOT_INVALID", "first must be a dict"
                )
            seen_first_keys: set[tuple[str, str, int]] = set()
            for raw_key, raw_claim_id in raw_first.items():
                key = _decode_group_key(raw_key)
                if key in seen_first_keys:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "duplicate first group"
                    )
                seen_first_keys.add(key)
                try:
                    first_claim_id = _require_int(
                        raw_claim_id, "first claim id", minimum=0
                    )
                except RaceError:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "invalid first claim id"
                    ) from None
                claim = claims.get(first_claim_id)
                if (
                    claim is None
                    or claim.status != STATUS_FIRST
                    or _group_key(
                        claim.boss_id, claim.difficulty, claim.season
                    )
                    != key
                ):
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "first mapping mismatch"
                    )

            for key, group in groups.items():
                if group.first_id is not None and key not in seen_first_keys:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "missing first mapping"
                    )

            raw_stats = state["stats"]
            if not isinstance(raw_stats, dict) or set(raw_stats) != set(STAT_KEYS):
                raise RaceError("WORLD_SNAPSHOT_INVALID", "invalid stats")
            stats: dict[str, int] = {}
            for stat_key in STAT_KEYS:
                try:
                    stats[stat_key] = _require_int(
                        raw_stats[stat_key], stat_key, minimum=0
                    )
                except RaceError:
                    raise RaceError(
                        "WORLD_SNAPSHOT_INVALID", "invalid stats"
                    ) from None
            if stats["claims"] != len(claims):
                raise RaceError(
                    "WORLD_SNAPSHOT_INVALID", "claims counter mismatch"
                )

            next_claim_id = max(claims, default=0) + 1

            self.skew_tolerance = skew_tolerance
            self._claims = claims
            self._groups = groups
            self._next_claim_id = next_claim_id
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in STAT_KEYS}
