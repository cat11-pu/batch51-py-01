"""User level publishing: draft revisions, review tickets, frozen online copies."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass


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


class UgcPublishGate:
    """Keep the draft, review and published copies of self-made levels apart."""

    def __init__(self, *, max_levels: int = 500, max_audit: int = 500) -> None:
        self.max_levels = max_levels
        self.max_audit = max_audit
        self._lock = threading.RLock()

    def fingerprint_of(self, content) -> str:
        """SHA-256 hex digest of the canonical JSON serialization of content."""
        raise NotImplementedError

    def save_draft(self, level_id: str, player: str, content, *,
                   now: str | None = None) -> DraftInfo:
        """Store a new draft revision of one level and return its fingerprint."""
        raise NotImplementedError

    def submit_review(self, level_id: str, player: str, *,
                      now: str | None = None) -> ReviewTicket:
        """Open a review ticket for the current draft of one level."""
        raise NotImplementedError

    def review(self, ticket_id: str, reviewer: str, *, approved: bool,
               note: str = "", now: str | None = None) -> ReviewTicket:
        """Close one pending ticket as approved or rejected."""
        raise NotImplementedError

    def publish(self, ticket_id: str, player: str, *,
                now: str | None = None) -> PublishedVersion:
        """Freeze the approved draft as the playable online version."""
        raise NotImplementedError

    def takedown(self, level_id: str, actor: str, *, reason: str = "",
                 now: str | None = None) -> bool:
        """Remove one level from the playable set."""
        raise NotImplementedError

    def version_of(self, level_id: str) -> LevelStatus:
        """Draft and online revision numbers together with the current state."""
        raise NotImplementedError

    def content_of(self, level_id: str):
        """Deep copy of the playable online content."""
        raise NotImplementedError

    def audit_of(self, level_id: str) -> list[dict]:
        """Transition log of one level in sequence order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of levels, tickets, audit trail and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters exposed to the content operations dashboard."""
        raise NotImplementedError
