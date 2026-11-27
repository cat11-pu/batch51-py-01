"""ActivityPub inbox guard: signature coverage, activity dedupe, forward depth."""

from __future__ import annotations

import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
REQUIRED_HEADERS = ("request-target", "host", "date", "digest")
ACTOR_STATES = ("active", "blocked", "deleted", "unknown")


class FederationError(ValueError):
    """Raised when an inbox request or forwarding hop is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Actor:
    actor_id: str
    inbox: str
    key_id: str
    secret: str
    created_at: int
    state: str


@dataclass(frozen=True)
class ActorKey:
    actor_id: str
    key_id: str
    secret: str
    valid_from: int
    valid_until: int | None


@dataclass(frozen=True)
class SignedRequest:
    actor_id: str
    method: str
    target: str
    host: str
    date: int
    digest: str
    key_id: str
    signature: str
    body: str
    inbox: str
    headers: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedRequest:
    actor_id: str
    key_id: str
    digest: str
    verified_at: int


@dataclass(frozen=True)
class Delivery:
    activity_id: str
    inbox: str
    status: str
    forward_depth: int
    body: str


class ActivityPubInboxGuard:
    """Verify inbox requests, dedupe activities and bound forwarding chains."""

    def __init__(self, *, max_inbox_items: int = 16, max_dedupe: int = 64,
                 max_forward_depth: int = 3,
                 clock_skew_seconds: int = 300) -> None:
        self.max_inbox_items = max_inbox_items
        self.max_dedupe = max_dedupe
        self.max_forward_depth = max_forward_depth
        self.clock_skew_seconds = clock_skew_seconds
        self._lock = threading.RLock()

    def register_actor(self, actor_id: str, inbox: str, *, secret: str,
                       key_id: str | None = None, now: int = 0) -> Actor:
        raise NotImplementedError

    def rotate_key(self, actor_id: str, secret: str, *, key_id: str | None = None,
                   now: int = 0, grace: int = 300) -> ActorKey:
        raise NotImplementedError

    def delete_actor(self, actor_id: str, *, now: int = 0) -> Actor:
        raise NotImplementedError

    def block_actor(self, actor_id: str) -> Actor:
        raise NotImplementedError

    def unblock_actor(self, actor_id: str) -> Actor:
        raise NotImplementedError

    def actor_state(self, actor_id: str) -> str:
        raise NotImplementedError

    def fetch_actor_key(self, actor_id: str, *, key_id: str | None = None,
                        now: int = 0) -> ActorKey:
        raise NotImplementedError

    def verify_signature(self, request: SignedRequest, *, now: int) -> VerifiedRequest:
        raise NotImplementedError

    def ingest_activity(self, request: SignedRequest, *, now: int) -> Delivery:
        raise NotImplementedError

    def dedupe(self, activity_id: str) -> bool:
        raise NotImplementedError

    def delivery_status(self, activity_id: str) -> str:
        raise NotImplementedError

    def forward(self, activity_id: str, *, target_inbox: str, depth: int,
                now: int = 0) -> Delivery:
        raise NotImplementedError

    def inbox_depth(self, inbox: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
