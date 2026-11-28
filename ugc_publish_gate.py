"""User level publishing: draft revisions, review tickets, frozen online copies."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any


_SNAPSHOT_VERSION = 1
_STATS_KEYS = {
    "levels",
    "drafts",
    "submitted",
    "approved",
    "rejected",
    "published",
    "taken_down",
    "pending",
}
_TICKET_STATES = {"pending", "approved", "rejected"}


class UgcError(ValueError):
    """Raised when a level publishing operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DraftInfo:
    level_id: str
    player: str
    version: int
    fingerprint: str
    saved_at: str | None


@dataclass(frozen=True)
class ReviewTicket:
    ticket_id: str
    level_id: str
    player: str
    version: int
    fingerprint: str
    state: str
    reviewer: str | None
    note: str


@dataclass(frozen=True)
class PublishedVersion:
    level_id: str
    version: int
    fingerprint: str
    reviewer: str
    published_at: str | None


@dataclass(frozen=True)
class LevelStatus:
    level_id: str
    state: str
    draft_version: int
    online_version: int
    review_state: str
    fingerprint: str


@dataclass
class _Draft:
    player: str
    version: int
    fingerprint: str
    content: Any
    saved_at: str | None


@dataclass
class _Online:
    version: int
    fingerprint: str
    content: Any
    reviewer: str
    published_at: str | None


@dataclass
class _Level:
    level_id: str
    draft: _Draft
    online: _Online | None = None
    online_visible: bool = False
    current_ticket_id: str | None = None


@dataclass
class _Ticket:
    ticket_id: str
    level_id: str
    player: str
    version: int
    fingerprint: str
    state: str
    reviewer: str | None
    note: str
    consumed: bool = False


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UgcError("UGC_INVALID_REQUEST", f"{field} must be a non-empty string")
    return value


def _require_now(now: object) -> str | None:
    if now is not None and not isinstance(now, str):
        raise UgcError("UGC_INVALID_REQUEST", "now must be a string or None")
    return now


def _canonical_content(content: object) -> tuple[str, Any]:
    if not isinstance(content, (dict, list)):
        raise UgcError(
            "UGC_INVALID_REQUEST",
            "content must be a JSON-serializable object or array",
        )

    def validate(value: object) -> None:
        if value is None or isinstance(value, (str, int, float, bool)):
            return
        if isinstance(value, list):
            for item in value:
                validate(item)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise UgcError(
                        "UGC_INVALID_REQUEST",
                        "content object keys must be strings",
                    )
                validate(item)
            return
        raise UgcError(
            "UGC_INVALID_REQUEST",
            "content must contain only JSON-serializable values",
        )

    try:
        validate(content)
        canonical = json.dumps(
            content,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        detached = copy.deepcopy(content)
    except UgcError:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise UgcError("UGC_INVALID_REQUEST", f"content is not serializable: {exc}") from None
    return canonical, detached


class UgcPublishGate:
    """Keep the draft, review and published copies of self-made levels apart."""

    def __init__(self, *, max_levels: int = 500, max_audit: int = 500) -> None:
        if not _is_int(max_levels) or max_levels < 0:
            raise UgcError("UGC_INVALID_REQUEST", "max_levels must be a non-negative integer")
        if not _is_int(max_audit) or max_audit < 0:
            raise UgcError("UGC_INVALID_REQUEST", "max_audit must be a non-negative integer")

        self.max_levels = max_levels
        self.max_audit = max_audit
        self._lock = threading.RLock()
        self._levels: dict[str, _Level] = {}
        self._tickets: dict[str, _Ticket] = {}
        self._audit: dict[str, list[dict]] = {}
        self._counters = {"next_ticket": 1, "next_audit": 1}
        self._stats = {key: 0 for key in _STATS_KEYS}

    @staticmethod
    def _fingerprint(content: object) -> tuple[str, Any]:
        canonical, detached = _canonical_content(content)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return digest, detached

    @staticmethod
    def _ticket_view(ticket: _Ticket) -> ReviewTicket:
        return ReviewTicket(
            ticket_id=ticket.ticket_id,
            level_id=ticket.level_id,
            player=ticket.player,
            version=ticket.version,
            fingerprint=ticket.fingerprint,
            state=ticket.state,
            reviewer=ticket.reviewer,
            note=ticket.note,
        )

    @staticmethod
    def _level_state(level: _Level) -> str:
        if level.online is None:
            return "draft"
        return "published" if level.online_visible else "taken_down"

    def _review_state(self, level: _Level) -> str:
        if level.current_ticket_id is None:
            return "none"
        ticket = self._tickets.get(level.current_ticket_id)
        return ticket.state if ticket is not None else "none"

    def _append_audit(
        self,
        level_id: str,
        kind: str,
        version: int,
        detail: dict,
    ) -> None:
        seq = self._counters["next_audit"]
        self._counters["next_audit"] = seq + 1
        if self.max_audit == 0:
            return

        rows = self._audit.setdefault(level_id, [])
        rows.append(
            {
                "seq": seq,
                "level": level_id,
                "kind": kind,
                "version": version,
                "detail": copy.deepcopy(detail),
            }
        )
        if len(rows) > self.max_audit:
            del rows[: len(rows) - self.max_audit]

    def fingerprint_of(self, content) -> str:
        """SHA-256 hex digest of the canonical JSON serialization of content."""
        return self._fingerprint(content)[0]

    def save_draft(self, level_id: str, player: str, content, *,
                   now: str | None = None) -> DraftInfo:
        """Store a new draft revision of one level and return its fingerprint."""
        level_id = _require_text(level_id, "level_id")
        player = _require_text(player, "player")
        now = _require_now(now)
        fingerprint, detached = self._fingerprint(content)

        with self._lock:
            level = self._levels.get(level_id)
            if level is None:
                if len(self._levels) >= self.max_levels:
                    raise UgcError(
                        "UGC_CAPACITY_EXCEEDED",
                        {"max_levels": self.max_levels},
                    )
                version = 1
                draft = _Draft(
                    player=player,
                    version=version,
                    fingerprint=fingerprint,
                    content=detached,
                    saved_at=now,
                )
                level = _Level(level_id=level_id, draft=draft)
                self._levels[level_id] = level
                self._stats["levels"] += 1
            else:
                version = level.draft.version + 1
                draft = _Draft(
                    player=player,
                    version=version,
                    fingerprint=fingerprint,
                    content=detached,
                    saved_at=now,
                )
                level.draft = draft

            self._stats["drafts"] += 1
            self._append_audit(
                level_id,
                "save",
                version,
                {
                    "player": player,
                    "fingerprint": fingerprint,
                    "saved_at": now,
                },
            )
            return DraftInfo(
                level_id=level_id,
                player=player,
                version=version,
                fingerprint=fingerprint,
                saved_at=now,
            )

    def submit_review(self, level_id: str, player: str, *,
                      now: str | None = None) -> ReviewTicket:
        """Open a review ticket for the current draft of one level."""
        level_id = _require_text(level_id, "level_id")
        player = _require_text(player, "player")
        now = _require_now(now)

        with self._lock:
            level = self._levels.get(level_id)
            if level is None:
                raise UgcError("UGC_UNKNOWN_LEVEL", level_id)
            if level.draft is None:
                raise UgcError("UGC_INVALID_REQUEST", "a draft is required before review")

            if level.current_ticket_id is not None:
                current = self._tickets.get(level.current_ticket_id)
                if current is not None:
                    same_content = current.fingerprint == level.draft.fingerprint
                    if current.state == "pending":
                        if same_content:
                            return self._ticket_view(current)
                        raise UgcError("UGC_REVIEW_PENDING", current.ticket_id)
                    if current.state == "approved" and not current.consumed and same_content:
                        return self._ticket_view(current)

            ticket_id = f"t-{self._counters['next_ticket']}"
            self._counters["next_ticket"] += 1
            ticket = _Ticket(
                ticket_id=ticket_id,
                level_id=level_id,
                player=player,
                version=level.draft.version,
                fingerprint=level.draft.fingerprint,
                state="pending",
                reviewer=None,
                note="",
            )
            self._tickets[ticket_id] = ticket
            level.current_ticket_id = ticket_id
            self._stats["submitted"] += 1
            self._stats["pending"] += 1
            self._append_audit(
                level_id,
                "submit",
                level.draft.version,
                {
                    "ticket_id": ticket_id,
                    "player": player,
                    "fingerprint": level.draft.fingerprint,
                    "submitted_at": now,
                },
            )
            return self._ticket_view(ticket)

    def review(self, ticket_id: str, reviewer: str, *, approved: bool,
               note: str = "", now: str | None = None) -> ReviewTicket:
        """Close one pending ticket as approved or rejected."""
        ticket_id = _require_text(ticket_id, "ticket_id")
        reviewer = _require_text(reviewer, "reviewer")
        now = _require_now(now)
        if not isinstance(approved, bool):
            raise UgcError("UGC_INVALID_REQUEST", "approved must be a boolean")
        if not isinstance(note, str):
            raise UgcError("UGC_INVALID_REQUEST", "note must be a string")

        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise UgcError("UGC_UNKNOWN_TICKET", ticket_id)
            if ticket.state != "pending":
                raise UgcError("UGC_TICKET_CLOSED", ticket_id)

            ticket.state = "approved" if approved else "rejected"
            ticket.reviewer = reviewer
            ticket.note = note
            self._stats["approved" if approved else "rejected"] += 1
            self._stats["pending"] -= 1
            self._append_audit(
                ticket.level_id,
                "review",
                ticket.version,
                {
                    "ticket_id": ticket_id,
                    "reviewer": reviewer,
                    "approved": approved,
                    "note": note,
                    "reviewed_at": now,
                },
            )
            return self._ticket_view(ticket)

    def publish(self, ticket_id: str, player: str, *,
                now: str | None = None) -> PublishedVersion:
        """Freeze the approved draft as the playable online version."""
        ticket_id = _require_text(ticket_id, "ticket_id")
        player = _require_text(player, "player")
        now = _require_now(now)

        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise UgcError("UGC_UNKNOWN_TICKET", ticket_id)

            level = self._levels.get(ticket.level_id)
            if level is None:
                raise UgcError("UGC_UNKNOWN_LEVEL", ticket.level_id)

            if ticket.state != "approved" or ticket.consumed:
                raise UgcError("UGC_NOT_APPROVED", ticket_id)
            if level.current_ticket_id != ticket.ticket_id:
                raise UgcError("UGC_NOT_APPROVED", ticket_id)
            if level.draft is None:
                raise UgcError("UGC_NOT_APPROVED", ticket_id)
            if ticket.fingerprint != level.draft.fingerprint:
                raise UgcError(
                    "UGC_NOT_APPROVED",
                    {
                        "ticket_id": ticket_id,
                        "ticket_fingerprint": ticket.fingerprint,
                        "draft_fingerprint": level.draft.fingerprint,
                    },
                )

            version = level.draft.version
            online = _Online(
                version=version,
                fingerprint=level.draft.fingerprint,
                content=copy.deepcopy(level.draft.content),
                reviewer=ticket.reviewer or "",
                published_at=now,
            )
            level.online = online
            level.online_visible = True
            ticket.consumed = True
            level.current_ticket_id = None
            self._stats["published"] += 1
            self._append_audit(
                ticket.level_id,
                "publish",
                version,
                {
                    "ticket_id": ticket_id,
                    "player": player,
                    "fingerprint": online.fingerprint,
                    "reviewer": online.reviewer,
                    "published_at": now,
                },
            )
            return PublishedVersion(
                level_id=ticket.level_id,
                version=version,
                fingerprint=online.fingerprint,
                reviewer=online.reviewer,
                published_at=now,
            )

    def takedown(self, level_id: str, actor: str, *, reason: str = "",
                 now: str | None = None) -> bool:
        """Remove one level from the playable set."""
        level_id = _require_text(level_id, "level_id")
        actor = _require_text(actor, "actor")
        now = _require_now(now)
        if not isinstance(reason, str):
            raise UgcError("UGC_INVALID_REQUEST", "reason must be a string")

        with self._lock:
            level = self._levels.get(level_id)
            if level is None:
                raise UgcError("UGC_UNKNOWN_LEVEL", level_id)
            if level.online is None or not level.online_visible:
                raise UgcError("UGC_NOT_PUBLISHED", level_id)

            level.online_visible = False
            self._stats["taken_down"] += 1
            self._append_audit(
                level_id,
                "takedown",
                level.online.version,
                {
                    "actor": actor,
                    "reason": reason,
                    "taken_down_at": now,
                },
            )
            return True

    def version_of(self, level_id: str) -> LevelStatus:
        """Draft and online revision numbers together with the current state."""
        level_id = _require_text(level_id, "level_id")
        with self._lock:
            level = self._levels.get(level_id)
            if level is None:
                raise UgcError("UGC_UNKNOWN_LEVEL", level_id)
            return LevelStatus(
                level_id=level_id,
                state=self._level_state(level),
                draft_version=level.draft.version,
                online_version=level.online.version if level.online else 0,
                review_state=self._review_state(level),
                fingerprint=level.draft.fingerprint,
            )

    def content_of(self, level_id: str):
        """Deep copy of the playable online content."""
        level_id = _require_text(level_id, "level_id")
        with self._lock:
            level = self._levels.get(level_id)
            if level is None:
                raise UgcError("UGC_UNKNOWN_LEVEL", level_id)
            if level.online is None or not level.online_visible:
                raise UgcError("UGC_NOT_PUBLISHED", level_id)
            return copy.deepcopy(level.online.content)

    def audit_of(self, level_id: str) -> list[dict]:
        """Transition log of one level in sequence order."""
        with self._lock:
            return copy.deepcopy(self._audit.get(level_id, []))

    def snapshot(self) -> dict:
        """Deep copy of levels, tickets, audit trail and counters."""
        with self._lock:
            levels = {}
            for level_id, level in self._levels.items():
                levels[level_id] = {
                    "draft": {
                        "player": level.draft.player,
                        "version": level.draft.version,
                        "fingerprint": level.draft.fingerprint,
                        "content": copy.deepcopy(level.draft.content),
                        "saved_at": level.draft.saved_at,
                    },
                    "online": (
                        None
                        if level.online is None
                        else {
                            "version": level.online.version,
                            "fingerprint": level.online.fingerprint,
                            "content": copy.deepcopy(level.online.content),
                            "reviewer": level.online.reviewer,
                            "published_at": level.online.published_at,
                        }
                    ),
                    "online_visible": level.online_visible,
                    "current_ticket_id": level.current_ticket_id,
                }

            tickets = [
                {
                    "ticket_id": ticket.ticket_id,
                    "level_id": ticket.level_id,
                    "player": ticket.player,
                    "version": ticket.version,
                    "fingerprint": ticket.fingerprint,
                    "state": ticket.state,
                    "reviewer": ticket.reviewer,
                    "note": ticket.note,
                    "consumed": ticket.consumed,
                }
                for ticket in self._tickets.values()
            ]
            audit = [
                copy.deepcopy(row)
                for rows in self._audit.values()
                for row in rows
            ]
            audit.sort(key=lambda row: row["seq"])

            return {
                "version": _SNAPSHOT_VERSION,
                "levels": levels,
                "tickets": tickets,
                "audit": audit,
                "counters": copy.deepcopy(self._counters),
                "stats": copy.deepcopy(self._stats),
            }

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> UgcError:
        return UgcError("UGC_SNAPSHOT_INVALID", detail)

    @staticmethod
    def _snapshot_fingerprint(content: object) -> str:
        try:
            return UgcPublishGate._fingerprint(content)[0]
        except UgcError as exc:
            raise UgcPublishGate._snapshot_invalid(str(exc)) from None

    @staticmethod
    def _require_fingerprint(value: object) -> str:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise UgcPublishGate._snapshot_invalid("invalid fingerprint")
        return value

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        try:
            snapshot = copy.deepcopy(state)
            if not isinstance(snapshot, dict):
                raise self._snapshot_invalid("snapshot must be an object")
            expected = {"version", "levels", "tickets", "audit", "counters", "stats"}
            if set(snapshot) != expected:
                raise self._snapshot_invalid("snapshot keys do not match schema")
            if not _is_int(snapshot["version"]) or snapshot["version"] != _SNAPSHOT_VERSION:
                raise self._snapshot_invalid("unsupported snapshot version")
            if not isinstance(snapshot["levels"], dict):
                raise self._snapshot_invalid("levels must be an object")
            if len(snapshot["levels"]) > self.max_levels:
                raise self._snapshot_invalid("snapshot exceeds max_levels")
            if not isinstance(snapshot["tickets"], list):
                raise self._snapshot_invalid("tickets must be an array")
            if not isinstance(snapshot["audit"], list):
                raise self._snapshot_invalid("audit must be an array")
            if not isinstance(snapshot["counters"], dict):
                raise self._snapshot_invalid("counters must be an object")
            if not isinstance(snapshot["stats"], dict):
                raise self._snapshot_invalid("stats must be an object")

            counters_raw = snapshot["counters"]
            if set(counters_raw) != {"next_ticket", "next_audit"}:
                raise self._snapshot_invalid("counter keys do not match schema")
            if any(
                not _is_int(value) or value < 1
                for value in counters_raw.values()
            ):
                raise self._snapshot_invalid("counters must be positive integers")
            counters = {
                "next_ticket": counters_raw["next_ticket"],
                "next_audit": counters_raw["next_audit"],
            }

            stats_raw = snapshot["stats"]
            if set(stats_raw) != _STATS_KEYS:
                raise self._snapshot_invalid("stats keys do not match schema")
            if any(not _is_int(value) or value < 0 for value in stats_raw.values()):
                raise self._snapshot_invalid("stats values must be non-negative integers")
            stats = dict(stats_raw)

            levels: dict[str, _Level] = {}
            for level_id, raw in snapshot["levels"].items():
                if not isinstance(level_id, str) or not level_id.strip():
                    raise self._snapshot_invalid("invalid level id")
                if not isinstance(raw, dict):
                    raise self._snapshot_invalid("level entry must be an object")
                if set(raw) != {
                    "draft",
                    "online",
                    "online_visible",
                    "current_ticket_id",
                }:
                    raise self._snapshot_invalid("level entry keys do not match schema")

                draft_raw = raw["draft"]
                if not isinstance(draft_raw, dict):
                    raise self._snapshot_invalid("draft must be an object")
                if set(draft_raw) != {
                    "player",
                    "version",
                    "fingerprint",
                    "content",
                    "saved_at",
                }:
                    raise self._snapshot_invalid("draft keys do not match schema")
                _require_text(draft_raw["player"], "draft.player")
                if not _is_int(draft_raw["version"]) or draft_raw["version"] < 1:
                    raise self._snapshot_invalid("draft version must be positive")
                fingerprint = self._require_fingerprint(draft_raw["fingerprint"])
                if self._snapshot_fingerprint(draft_raw["content"]) != fingerprint:
                    raise self._snapshot_invalid("draft fingerprint does not match content")
                if draft_raw["saved_at"] is not None and not isinstance(
                    draft_raw["saved_at"], str
                ):
                    raise self._snapshot_invalid("draft saved_at must be a string or None")

                online_raw = raw["online"]
                online = None
                if online_raw is not None:
                    if not isinstance(online_raw, dict):
                        raise self._snapshot_invalid("online must be an object or None")
                    if set(online_raw) != {
                        "version",
                        "fingerprint",
                        "content",
                        "reviewer",
                        "published_at",
                    }:
                        raise self._snapshot_invalid("online keys do not match schema")
                    if not _is_int(online_raw["version"]) or online_raw["version"] < 1:
                        raise self._snapshot_invalid("online version must be positive")
                    online_fingerprint = self._require_fingerprint(
                        online_raw["fingerprint"]
                    )
                    if (
                        self._snapshot_fingerprint(online_raw["content"])
                        != online_fingerprint
                    ):
                        raise self._snapshot_invalid(
                            "online fingerprint does not match content"
                        )
                    _require_text(online_raw["reviewer"], "online.reviewer")
                    if online_raw["published_at"] is not None and not isinstance(
                        online_raw["published_at"], str
                    ):
                        raise self._snapshot_invalid(
                            "online published_at must be a string or None"
                        )
                    if online_raw["version"] > draft_raw["version"]:
                        raise self._snapshot_invalid(
                            "online version is newer than draft version"
                        )
                    online = _Online(
                        version=online_raw["version"],
                        fingerprint=online_fingerprint,
                        content=online_raw["content"],
                        reviewer=online_raw["reviewer"],
                        published_at=online_raw["published_at"],
                    )

                online_visible = raw["online_visible"]
                if not isinstance(online_visible, bool):
                    raise self._snapshot_invalid("online_visible must be a boolean")
                if online_visible and online is None:
                    raise self._snapshot_invalid("visible online copy is missing")
                current_ticket_id = raw["current_ticket_id"]
                if current_ticket_id is not None and (
                    not isinstance(current_ticket_id, str) or not current_ticket_id
                ):
                    raise self._snapshot_invalid(
                        "current_ticket_id must be a string or None"
                    )

                levels[level_id] = _Level(
                    level_id=level_id,
                    draft=_Draft(
                        player=draft_raw["player"],
                        version=draft_raw["version"],
                        fingerprint=fingerprint,
                        content=draft_raw["content"],
                        saved_at=draft_raw["saved_at"],
                    ),
                    online=online,
                    online_visible=online_visible,
                    current_ticket_id=current_ticket_id,
                )

            tickets: dict[str, _Ticket] = {}
            pending_by_level: dict[str, str] = {}
            for raw in snapshot["tickets"]:
                if not isinstance(raw, dict):
                    raise self._snapshot_invalid("ticket entry must be an object")
                if set(raw) != {
                    "ticket_id",
                    "level_id",
                    "player",
                    "version",
                    "fingerprint",
                    "state",
                    "reviewer",
                    "note",
                    "consumed",
                }:
                    raise self._snapshot_invalid("ticket keys do not match schema")
                ticket_id = raw["ticket_id"]
                if not isinstance(ticket_id, str) or not ticket_id:
                    raise self._snapshot_invalid("invalid ticket id")
                if ticket_id in tickets:
                    raise self._snapshot_invalid("duplicate ticket id")
                level_id = raw["level_id"]
                if level_id not in levels:
                    raise self._snapshot_invalid("ticket refers to an unknown level")
                _require_text(raw["player"], "ticket.player")
                if not _is_int(raw["version"]) or raw["version"] < 1:
                    raise self._snapshot_invalid("ticket version must be positive")
                if raw["version"] > levels[level_id].draft.version:
                    raise self._snapshot_invalid(
                        "ticket version is newer than draft version"
                    )
                fingerprint = self._require_fingerprint(raw["fingerprint"])
                ticket_state = raw["state"]
                if ticket_state not in _TICKET_STATES:
                    raise self._snapshot_invalid("invalid ticket state")
                reviewer = raw["reviewer"]
                if ticket_state == "pending":
                    if reviewer is not None:
                        raise self._snapshot_invalid(
                            "pending ticket cannot have a reviewer"
                        )
                    if level_id in pending_by_level:
                        raise self._snapshot_invalid(
                            "level has more than one pending ticket"
                        )
                    pending_by_level[level_id] = ticket_id
                else:
                    _require_text(reviewer, "ticket.reviewer")
                if not isinstance(raw["note"], str):
                    raise self._snapshot_invalid("ticket note must be a string")
                if not isinstance(raw["consumed"], bool):
                    raise self._snapshot_invalid("ticket consumed must be a boolean")
                if raw["consumed"] and ticket_state != "approved":
                    raise self._snapshot_invalid(
                        "only approved tickets can be consumed"
                    )

                tickets[ticket_id] = _Ticket(
                    ticket_id=ticket_id,
                    level_id=level_id,
                    player=raw["player"],
                    version=raw["version"],
                    fingerprint=fingerprint,
                    state=ticket_state,
                    reviewer=reviewer,
                    note=raw["note"],
                    consumed=raw["consumed"],
                )

            for level_id, level in levels.items():
                if level.current_ticket_id is not None:
                    ticket = tickets.get(level.current_ticket_id)
                    if ticket is None or ticket.level_id != level_id:
                        raise self._snapshot_invalid(
                            "level current ticket is missing or mismatched"
                        )
                    if ticket.state == "pending" and level_id not in pending_by_level:
                        raise self._snapshot_invalid("pending ticket is not current")
                elif level_id in pending_by_level:
                    raise self._snapshot_invalid("pending ticket has no current link")

            audit: dict[str, list[dict]] = {}
            seen_seq: set[int] = set()
            for raw in snapshot["audit"]:
                if not isinstance(raw, dict):
                    raise self._snapshot_invalid("audit entry must be an object")
                if set(raw) != {"seq", "level", "kind", "version", "detail"}:
                    raise self._snapshot_invalid("audit keys do not match schema")
                seq = raw["seq"]
                if not _is_int(seq) or seq < 1:
                    raise self._snapshot_invalid("audit sequence must be positive")
                if seq in seen_seq:
                    raise self._snapshot_invalid("duplicate audit sequence")
                seen_seq.add(seq)
                if seq >= counters["next_audit"]:
                    raise self._snapshot_invalid(
                        "audit sequence is not behind the counter"
                    )
                level_id = raw["level"]
                if level_id not in levels:
                    raise self._snapshot_invalid("audit refers to an unknown level")
                if not isinstance(raw["kind"], str) or not raw["kind"]:
                    raise self._snapshot_invalid("audit kind must be a string")
                if not _is_int(raw["version"]) or raw["version"] < 1:
                    raise self._snapshot_invalid("audit version must be positive")
                audit.setdefault(level_id, []).append(
                    {
                        "seq": seq,
                        "level": level_id,
                        "kind": raw["kind"],
                        "version": raw["version"],
                        "detail": raw["detail"],
                    }
                )

            for level_id, rows in audit.items():
                rows.sort(key=lambda row: row["seq"])
                if len(rows) > self.max_audit:
                    del rows[: len(rows) - self.max_audit]

            expected_drafts = sum(level.draft.version for level in levels.values())
            approved_count = sum(
                ticket.state == "approved" for ticket in tickets.values()
            )
            rejected_count = sum(
                ticket.state == "rejected" for ticket in tickets.values()
            )
            if stats["levels"] != len(levels):
                raise self._snapshot_invalid("stats.levels does not match levels")
            if stats["drafts"] != expected_drafts:
                raise self._snapshot_invalid("stats.drafts does not match revisions")
            if stats["submitted"] != len(tickets):
                raise self._snapshot_invalid("stats.submitted does not match tickets")
            if stats["approved"] != approved_count:
                raise self._snapshot_invalid("stats.approved does not match tickets")
            if stats["rejected"] != rejected_count:
                raise self._snapshot_invalid("stats.rejected does not match tickets")
            if stats["pending"] != len(pending_by_level):
                raise self._snapshot_invalid("stats.pending does not match tickets")
            consumed_count = sum(
                ticket.consumed for ticket in tickets.values()
            )
            if stats["published"] != consumed_count:
                raise self._snapshot_invalid(
                    "stats.published does not match consumed tickets"
                )
            if stats["published"] < stats["taken_down"]:
                raise self._snapshot_invalid("takedown count exceeds published count")
            if stats["published"] > stats["approved"]:
                raise self._snapshot_invalid("published count exceeds approved count")
            if any(
                level.online is not None and not level.online_visible
                for level in levels.values()
            ) and stats["taken_down"] == 0:
                raise self._snapshot_invalid(
                    "taken-down version has no takedown counter"
                )

            next_ticket = counters["next_ticket"]
            for ticket_id in tickets:
                if ticket_id.startswith("t-") and ticket_id[2:].isdigit():
                    if int(ticket_id[2:]) >= next_ticket:
                        raise self._snapshot_invalid(
                            "ticket id is not behind the counter"
                        )

            with self._lock:
                self._levels = levels
                self._tickets = tickets
                self._audit = audit
                self._counters = counters
                self._stats = stats
        except UgcError as exc:
            if exc.code == "UGC_SNAPSHOT_INVALID":
                raise
            raise self._snapshot_invalid(str(exc)) from None
        except Exception as exc:
            raise self._snapshot_invalid(str(exc)) from None

    def stats(self) -> dict:
        """Counters exposed to the content operations dashboard."""
        with self._lock:
            return copy.deepcopy(self._stats)
