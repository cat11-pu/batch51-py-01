"""ActivityPub inbox guard: signature coverage, activity dedupe, forward depth."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass, replace

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
    signature: str = ""
    key_id: str = ""


@dataclass(frozen=True)
class _ActivityRecord:
    request: SignedRequest
    status: str


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
        self._actors: dict[str, Actor] = {}
        self._keys: dict[str, list[ActorKey]] = {}
        self._dedupe: OrderedDict[str, None] = OrderedDict()
        self._inboxes: dict[str, OrderedDict[str, str]] = {}
        self._statuses: dict[str, str] = {}
        self._activities: dict[str, _ActivityRecord] = {}
        self._stats = {
            "delivered": 0,
            "duplicates": 0,
            "rejected": 0,
            "forwarded": 0,
        }

    @staticmethod
    def _present(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _as_int(value: object) -> int | None:
        if isinstance(value, bool):
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result

    def _fail(self, code: str, detail: object = None) -> None:
        self._stats["rejected"] += 1
        raise FederationError(code, detail)

    @staticmethod
    def _snapshot_fail(detail: object = None) -> None:
        raise FederationError("FED_SNAPSHOT_INVALID", detail)

    def _require_actor(self, actor_id: str) -> Actor:
        actor = self._actors.get(actor_id)
        if actor is None:
            self._fail("FED_ACTOR_UNKNOWN", {"actor_id": actor_id})
        return actor

    def _require_active_actor(self, actor_id: str) -> Actor:
        actor = self._require_actor(actor_id)
        if actor.state == "deleted":
            self._fail("FED_ACTOR_DELETED", {"actor_id": actor_id})
        if actor.state == "blocked":
            self._fail("FED_ACTOR_BLOCKED", {"actor_id": actor_id})
        return actor

    def _next_key_id(self, actor_id: str) -> str:
        used = {key.key_id for key in self._keys.get(actor_id, ())}
        suffix = 1
        while True:
            candidate = f"{actor_id}#key-{suffix}"
            if candidate not in used:
                return candidate
            suffix += 1

    def _select_key(self, actor: Actor, key_id: str | None, now: int) -> ActorKey:
        if key_id is None:
            wanted = actor.key_id
        else:
            if not self._present(key_id):
                self._fail("FED_KEY_MISMATCH",
                           {"actor_id": actor.actor_id, "key_id": key_id})
            wanted = key_id

        for key in reversed(self._keys.get(actor.actor_id, ())):
            if key.key_id != wanted:
                continue
            if key.valid_until is not None and now > key.valid_until:
                self._fail("FED_KEY_EXPIRED",
                           {"actor_id": actor.actor_id, "key_id": wanted,
                            "valid_until": key.valid_until})
            return key

        self._fail("FED_KEY_MISMATCH",
                   {"actor_id": actor.actor_id, "key_id": wanted})

    def _body_value(self, body: object) -> object:
        if isinstance(body, str):
            try:
                return json.loads(body)
            except (TypeError, ValueError, json.JSONDecodeError):
                return None
        if isinstance(body, (bytes, bytearray)):
            try:
                return json.loads(bytes(body).decode("utf-8"))
            except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
                return None
        return None

    @staticmethod
    def _snapshot_request(request: SignedRequest) -> dict:
        data = asdict(request)
        data["headers"] = list(request.headers)
        return data

    def _actor_refs(self, value: object) -> list[str]:
        refs: list[str] = []

        def walk(item: object) -> None:
            if isinstance(item, dict):
                for name in ("actor", "attributedTo"):
                    actor_ref = item.get(name)
                    if isinstance(actor_ref, str):
                        refs.append(actor_ref)
                    elif isinstance(actor_ref, dict):
                        nested_id = actor_ref.get("id")
                        if isinstance(nested_id, str):
                            refs.append(nested_id)
                for nested in item.values():
                    walk(nested)
            elif isinstance(item, list):
                for nested in item:
                    walk(nested)

        walk(value)
        return refs

    def _check_origin_allowed(self, body: object) -> None:
        parsed = self._body_value(body)
        if parsed is None:
            return
        checked: set[str] = set()
        for actor_id in self._actor_refs(parsed):
            if actor_id in checked:
                continue
            checked.add(actor_id)
            actor = self._actors.get(actor_id)
            if actor is None:
                continue
            if actor.state == "deleted":
                self._fail("FED_ACTOR_DELETED", {"actor_id": actor_id})
            if actor.state == "blocked":
                self._fail("FED_ACTOR_BLOCKED", {"actor_id": actor_id})

    def _check_activity_allowed(self, record: _ActivityRecord) -> None:
        actor = self._actors.get(record.request.actor_id)
        if actor is not None:
            if actor.state == "deleted":
                self._fail("FED_ACTOR_DELETED",
                           {"actor_id": actor.actor_id})
            if actor.state == "blocked":
                self._fail("FED_ACTOR_BLOCKED",
                           {"actor_id": actor.actor_id})
        self._check_origin_allowed(record.request.body)

    def _remember_dedupe(self, activity_id: str) -> None:
        if activity_id in self._dedupe:
            return
        if self.max_dedupe <= 0:
            return
        while len(self._dedupe) >= self.max_dedupe:
            self._dedupe.popitem(last=False)
        self._dedupe[activity_id] = None

    def _deliver_to_inbox(self, inbox: str, activity_id: str,
                          status: str, *, allow_full: bool) -> bool:
        bucket = self._inboxes.setdefault(inbox, OrderedDict())
        if activity_id in bucket:
            return False
        if len(bucket) >= self.max_inbox_items:
            if allow_full:
                return False
            self._fail("FED_INBOX_FULL",
                       {"inbox": inbox, "capacity": self.max_inbox_items})
        bucket[activity_id] = status
        return True

    def register_actor(self, actor_id: str, inbox: str, *, secret: str,
                       key_id: str | None = None, now: int = 0) -> Actor:
        with self._lock:
            if (not self._present(actor_id) or not self._present(inbox)
                    or not self._present(secret)
                    or (key_id is not None and not self._present(key_id))):
                self._fail("FED_INVALID_REQUEST")
            if actor_id in self._actors:
                self._fail("FED_ACTOR_EXISTS", {"actor_id": actor_id})

            created_at = self._as_int(now)
            if created_at is None:
                self._fail("FED_INVALID_REQUEST", {"field": "now"})
            actual_key_id = key_id if key_id is not None else self._next_key_id(actor_id)
            actor = Actor(
                actor_id=actor_id,
                inbox=inbox,
                key_id=actual_key_id,
                secret=secret,
                created_at=created_at,
                state="active",
            )
            key = ActorKey(
                actor_id=actor_id,
                key_id=actual_key_id,
                secret=secret,
                valid_from=created_at,
                valid_until=None,
            )
            self._actors[actor_id] = actor
            self._keys[actor_id] = [key]
            return actor

    def rotate_key(self, actor_id: str, secret: str, *, key_id: str | None = None,
                   now: int = 0, grace: int = 300) -> ActorKey:
        with self._lock:
            if not self._present(secret):
                self._fail("FED_INVALID_REQUEST", {"field": "secret"})
            if key_id is not None and not self._present(key_id):
                self._fail("FED_INVALID_REQUEST", {"field": "key_id"})

            actor = self._require_actor(actor_id)
            if actor.state == "deleted":
                self._fail("FED_ACTOR_DELETED", {"actor_id": actor_id})
            rotation_at = self._as_int(now)
            grace_seconds = self._as_int(grace)
            if rotation_at is None or grace_seconds is None or grace_seconds < 0:
                self._fail("FED_INVALID_REQUEST")

            keys = self._keys.setdefault(actor_id, [])
            if key_id is None:
                actual_key_id = self._next_key_id(actor_id)
            else:
                actual_key_id = key_id
                if any(key.key_id == actual_key_id for key in keys):
                    self._fail("FED_KEY_MISMATCH",
                               {"actor_id": actor_id, "key_id": actual_key_id})

            updated_keys: list[ActorKey] = []
            for old_key in keys:
                if old_key.key_id == actor.key_id and old_key.valid_until is None:
                    updated_keys.append(replace(
                        old_key,
                        valid_until=rotation_at + grace_seconds,
                    ))
                else:
                    updated_keys.append(old_key)

            new_key = ActorKey(
                actor_id=actor_id,
                key_id=actual_key_id,
                secret=secret,
                valid_from=rotation_at,
                valid_until=None,
            )
            updated_keys.append(new_key)
            self._keys[actor_id] = updated_keys
            self._actors[actor_id] = replace(
                actor,
                key_id=actual_key_id,
                secret=secret,
            )
            return new_key

    def delete_actor(self, actor_id: str, *, now: int = 0) -> Actor:
        with self._lock:
            actor = self._require_actor(actor_id)
            if actor.state == "deleted":
                return actor
            actor = replace(actor, state="deleted")
            self._actors[actor_id] = actor
            return actor

    def block_actor(self, actor_id: str) -> Actor:
        with self._lock:
            actor = self._require_actor(actor_id)
            if actor.state == "deleted":
                self._fail("FED_ACTOR_DELETED", {"actor_id": actor_id})
            if actor.state == "blocked":
                return actor
            actor = replace(actor, state="blocked")
            self._actors[actor_id] = actor
            return actor

    def unblock_actor(self, actor_id: str) -> Actor:
        with self._lock:
            actor = self._require_actor(actor_id)
            if actor.state == "deleted":
                self._fail("FED_ACTOR_DELETED", {"actor_id": actor_id})
            if actor.state == "active":
                return actor
            actor = replace(actor, state="active")
            self._actors[actor_id] = actor
            return actor

    def actor_state(self, actor_id: str) -> str:
        with self._lock:
            actor = self._actors.get(actor_id)
            return actor.state if actor is not None else "unknown"

    def fetch_actor_key(self, actor_id: str, *, key_id: str | None = None,
                        now: int = 0) -> ActorKey:
        with self._lock:
            actor = self._require_actor(actor_id)
            if actor.state == "deleted":
                self._fail("FED_ACTOR_DELETED", {"actor_id": actor_id})
            fetch_at = self._as_int(now)
            if fetch_at is None:
                self._fail("FED_INVALID_REQUEST", {"field": "now"})
            return self._select_key(actor, key_id, fetch_at)

    def verify_signature(self, request: SignedRequest, *, now: int) -> VerifiedRequest:
        with self._lock:
            try:
                headers = {
                    str(header).strip().lower()
                    for header in request.headers
                }
            except TypeError:
                headers = set()
            missing = [name for name in REQUIRED_HEADERS if name not in headers]
            if missing:
                self._fail("FED_SIGNATURE_HEADERS", {"missing": missing})

            verified_at = self._as_int(now)
            request_date = self._as_int(request.date)
            if (verified_at is None or request_date is None
                    or abs(verified_at - request_date) > self.clock_skew_seconds):
                self._fail("FED_DATE_SKEW", {
                    "date": request.date,
                    "now": now,
                    "window": self.clock_skew_seconds,
                })

            actor = self._require_active_actor(request.actor_id)
            if not isinstance(request.target, str) or not isinstance(request.host, str):
                self._fail("FED_INVALID_REQUEST")
            body = request.body
            if isinstance(body, str):
                body_bytes = body.encode("utf-8")
            elif isinstance(body, (bytes, bytearray)):
                body_bytes = bytes(body)
            else:
                self._fail("FED_DIGEST_MISMATCH")
            if (not isinstance(request.digest, str)
                    or not request.digest.isascii()):
                self._fail("FED_DIGEST_MISMATCH")
            expected_digest = "sha256=" + hashlib.sha256(body_bytes).hexdigest()
            if not hmac.compare_digest(request.digest, expected_digest):
                self._fail("FED_DIGEST_MISMATCH", {
                    "expected": expected_digest,
                    "actual": request.digest,
                })

            if not self._present(request.key_id):
                self._fail("FED_KEY_MISMATCH",
                           {"actor_id": request.actor_id,
                            "key_id": request.key_id})
            key = self._select_key(actor, request.key_id, verified_at)
            payload = "|".join((
                key.secret,
                request.target,
                request.host,
                str(request.date),
                request.digest,
            ))
            expected_signature = hashlib.sha256(
                payload.encode("utf-8")).hexdigest()
            if (not isinstance(request.signature, str)
                    or not request.signature.isascii()):
                self._fail("FED_SIGNATURE_INVALID")
            if not hmac.compare_digest(request.signature, expected_signature):
                self._fail("FED_SIGNATURE_INVALID")

            self._check_origin_allowed(request.body)
            return VerifiedRequest(
                actor_id=request.actor_id,
                key_id=key.key_id,
                digest=request.digest,
                verified_at=verified_at,
            )

    def ingest_activity(self, request: SignedRequest, *, now: int) -> Delivery:
        with self._lock:
            self.verify_signature(request, now=now)

            parsed = self._body_value(request.body)
            if not isinstance(parsed, dict):
                self._fail("FED_INVALID_REQUEST", {"field": "body"})
            activity_id = parsed.get("id")
            if not self._present(activity_id):
                self._fail("FED_INVALID_REQUEST", {"field": "id"})
            if not self._present(request.inbox):
                self._fail("FED_INVALID_REQUEST", {"field": "inbox"})

            if activity_id in self._activities:
                self._deliver_to_inbox(
                    request.inbox, activity_id, "duplicate", allow_full=True)
                self._remember_dedupe(activity_id)
                self._stats["duplicates"] += 1
                return Delivery(
                    activity_id=activity_id,
                    inbox=request.inbox,
                    status="duplicate",
                    forward_depth=0,
                    body=request.body,
                    signature=request.signature,
                    key_id=request.key_id,
                )

            self._deliver_to_inbox(
                request.inbox, activity_id, "delivered", allow_full=False)
            record = _ActivityRecord(request=request, status="delivered")
            self._activities[activity_id] = record
            self._statuses[activity_id] = "delivered"
            self._remember_dedupe(activity_id)
            self._stats["delivered"] += 1
            return Delivery(
                activity_id=activity_id,
                inbox=request.inbox,
                status="delivered",
                forward_depth=0,
                body=request.body,
                signature=request.signature,
                key_id=request.key_id,
            )

    def dedupe(self, activity_id: str) -> bool:
        with self._lock:
            return activity_id in self._dedupe

    def delivery_status(self, activity_id: str) -> str:
        with self._lock:
            return self._statuses.get(activity_id, "unknown")

    def forward(self, activity_id: str, *, target_inbox: str, depth: int,
                now: int = 0) -> Delivery:
        with self._lock:
            forward_depth = self._as_int(depth)
            if forward_depth is None or forward_depth < 0:
                self._fail("FED_INVALID_REQUEST", {"field": "depth"})
            if forward_depth > self.max_forward_depth:
                self._fail("FED_FORWARD_DEPTH", {"depth": forward_depth})
            if not self._present(target_inbox):
                self._fail("FED_INVALID_REQUEST", {"field": "target_inbox"})

            record = self._activities.get(activity_id)
            if record is None:
                self._fail("FED_ACTIVITY_UNKNOWN", {"activity_id": activity_id})
            self._check_activity_allowed(record)

            self._deliver_to_inbox(
                target_inbox, activity_id, "forwarded", allow_full=False)
            self._stats["forwarded"] += 1
            return Delivery(
                activity_id=activity_id,
                inbox=target_inbox,
                status="forwarded",
                forward_depth=forward_depth,
                body=record.request.body,
                signature=record.request.signature,
                key_id=record.request.key_id,
            )

    def inbox_depth(self, inbox: str) -> int:
        with self._lock:
            return len(self._inboxes.get(inbox, ()))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "actors": [asdict(actor) for actor in self._actors.values()],
                "keys": {
                    actor_id: [asdict(key) for key in keys]
                    for actor_id, keys in self._keys.items()
                },
                "dedupe": list(self._dedupe),
                "inboxes": {
                    inbox: [[activity_id, status]
                            for activity_id, status in items.items()]
                    for inbox, items in self._inboxes.items()
                },
                "statuses": dict(self._statuses),
                "activities": {
                    activity_id: {
                        "request": self._snapshot_request(record.request),
                        "status": record.status,
                    }
                    for activity_id, record in self._activities.items()
                },
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            required = {
                "version", "actors", "keys", "dedupe", "inboxes",
                "statuses", "activities", "stats",
            }
            if not isinstance(state, dict) or not required.issubset(state):
                self._snapshot_fail({"missing": sorted(required - set(state))
                                     if isinstance(state, dict) else None})
            if state.get("version") != SNAPSHOT_VERSION:
                self._snapshot_fail({"version": state.get("version")})

            raw_actors = state["actors"]
            raw_keys = state["keys"]
            raw_dedupe = state["dedupe"]
            raw_inboxes = state["inboxes"]
            raw_statuses = state["statuses"]
            raw_activities = state["activities"]
            raw_stats = state["stats"]
            if (not isinstance(raw_actors, list)
                    or not isinstance(raw_keys, dict)
                    or not isinstance(raw_dedupe, list)
                    or not isinstance(raw_inboxes, dict)
                    or not isinstance(raw_statuses, dict)
                    or not isinstance(raw_activities, dict)
                    or not isinstance(raw_stats, dict)):
                self._snapshot_fail()

            new_actors: dict[str, Actor] = {}
            for item in raw_actors:
                if not isinstance(item, dict):
                    self._snapshot_fail({"actors": "entry"})
                actor_id = item.get("actor_id")
                inbox = item.get("inbox")
                key_id = item.get("key_id")
                secret = item.get("secret")
                created_at = self._as_int(item.get("created_at"))
                actor_state_value = item.get("state")
                if (not self._present(actor_id) or not self._present(inbox)
                        or not self._present(key_id) or not self._present(secret)
                        or created_at is None
                        or actor_state_value not in ("active", "blocked", "deleted")
                        or actor_id in new_actors):
                    self._snapshot_fail({"actors": actor_id})
                new_actors[actor_id] = Actor(
                    actor_id=actor_id,
                    inbox=inbox,
                    key_id=key_id,
                    secret=secret,
                    created_at=created_at,
                    state=actor_state_value,
                )

            new_keys: dict[str, list[ActorKey]] = {}
            for actor_id, key_items in raw_keys.items():
                if (not isinstance(actor_id, str) or actor_id not in new_actors
                        or not isinstance(key_items, list) or not key_items):
                    self._snapshot_fail({"keys": actor_id})
                actor_keys: list[ActorKey] = []
                seen_key_ids: set[str] = set()
                for item in key_items:
                    if not isinstance(item, dict):
                        self._snapshot_fail({"keys": actor_id})
                    key_actor_id = item.get("actor_id")
                    key_id = item.get("key_id")
                    secret = item.get("secret")
                    valid_from = self._as_int(item.get("valid_from"))
                    valid_until_raw = item.get("valid_until")
                    valid_until = (None if valid_until_raw is None
                                   else self._as_int(valid_until_raw))
                    if (key_actor_id != actor_id or not self._present(key_id)
                            or not self._present(secret) or valid_from is None
                            or (valid_until_raw is not None and valid_until is None)
                            or key_id in seen_key_ids):
                        self._snapshot_fail({"keys": actor_id})
                    seen_key_ids.add(key_id)
                    actor_keys.append(ActorKey(
                        actor_id=actor_id,
                        key_id=key_id,
                        secret=secret,
                        valid_from=valid_from,
                        valid_until=valid_until,
                    ))
                actor = new_actors[actor_id]
                matching = [
                    key for key in actor_keys
                    if key.key_id == actor.key_id and key.secret == actor.secret
                ]
                if not matching:
                    self._snapshot_fail({"keys": actor_id, "reason": "current"})
                new_keys[actor_id] = actor_keys
            if set(new_keys) != set(new_actors):
                self._snapshot_fail({"keys": "actors"})

            new_statuses: dict[str, str] = {}
            for activity_id, status in raw_statuses.items():
                if (not self._present(activity_id)
                        or status not in ("delivered", "duplicate", "forwarded")):
                    self._snapshot_fail({"statuses": activity_id})
                new_statuses[activity_id] = status

            new_activities: dict[str, _ActivityRecord] = {}
            for activity_id, item in raw_activities.items():
                if (not self._present(activity_id) or not isinstance(item, dict)
                        or not isinstance(item.get("request"), dict)
                        or item.get("status") not in ("delivered", "duplicate",
                                                      "forwarded")):
                    self._snapshot_fail({"activities": activity_id})
                request_data = item["request"]
                request_fields = {
                    "actor_id", "method", "target", "host", "date", "digest",
                    "key_id", "signature", "body", "inbox", "headers",
                }
                if not request_fields.issubset(request_data):
                    self._snapshot_fail({"activities": activity_id, "request": True})
                headers = request_data.get("headers")
                request_date = self._as_int(request_data.get("date"))
                if (not isinstance(headers, (list, tuple))
                        or any(not isinstance(header, str) for header in headers)
                        or request_date is None
                        or not self._present(request_data.get("actor_id"))
                        or not self._present(request_data.get("inbox"))
                        or not isinstance(request_data.get("body"), (str, bytes))
                        or not isinstance(request_data.get("digest"), str)
                        or not isinstance(request_data.get("signature"), str)
                        or not isinstance(request_data.get("key_id"), str)):
                    self._snapshot_fail({"activities": activity_id, "request": True})
                request = SignedRequest(
                    actor_id=request_data["actor_id"],
                    method=request_data.get("method"),
                    target=request_data.get("target"),
                    host=request_data.get("host"),
                    date=request_date,
                    digest=request_data["digest"],
                    key_id=request_data["key_id"],
                    signature=request_data["signature"],
                    body=request_data["body"],
                    inbox=request_data["inbox"],
                    headers=tuple(headers),
                )
                if request.actor_id not in new_actors:
                    self._snapshot_fail({"activities": activity_id, "actor": True})
                new_activities[activity_id] = _ActivityRecord(
                    request=request,
                    status=item["status"],
                )
            if set(new_statuses) != set(new_activities):
                self._snapshot_fail({"activities": "statuses"})
            for activity_id, record in new_activities.items():
                if new_statuses[activity_id] != record.status:
                    self._snapshot_fail({"activities": activity_id, "status": True})

            new_dedupe: OrderedDict[str, None] = OrderedDict()
            if len(raw_dedupe) > self.max_dedupe:
                self._snapshot_fail({"dedupe": "capacity"})
            for activity_id in raw_dedupe:
                if (not self._present(activity_id)
                        or activity_id in new_dedupe
                        or activity_id not in new_activities):
                    self._snapshot_fail({"dedupe": activity_id})
                new_dedupe[activity_id] = None

            new_inboxes: dict[str, OrderedDict[str, str]] = {}
            for inbox, entries in raw_inboxes.items():
                if not self._present(inbox) or not isinstance(entries, list):
                    self._snapshot_fail({"inboxes": inbox})
                if len(entries) > self.max_inbox_items:
                    self._snapshot_fail({"inboxes": inbox, "capacity": True})
                bucket: OrderedDict[str, str] = OrderedDict()
                for entry in entries:
                    if (not isinstance(entry, (list, tuple)) or len(entry) != 2):
                        self._snapshot_fail({"inboxes": inbox})
                    activity_id, status = entry
                    if (not self._present(activity_id)
                            or activity_id in bucket
                            or activity_id not in new_activities
                            or status not in ("delivered", "duplicate", "forwarded")):
                        self._snapshot_fail({"inboxes": inbox})
                    bucket[activity_id] = status
                new_inboxes[inbox] = bucket

            new_stats = dict(raw_stats)
            for name in ("delivered", "duplicates", "rejected", "forwarded"):
                value = self._as_int(new_stats.get(name))
                if value is None or value < 0:
                    self._snapshot_fail({"stats": name})
                new_stats[name] = value

            self._actors = new_actors
            self._keys = new_keys
            self._dedupe = new_dedupe
            self._inboxes = new_inboxes
            self._statuses = new_statuses
            self._activities = new_activities
            self._stats = new_stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
