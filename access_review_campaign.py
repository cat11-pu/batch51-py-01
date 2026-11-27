"""Access review campaigns: frozen entitlement snapshots, decisions and reclaim ledger."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass


class CampaignError(ValueError):
    """Raised when a review campaign operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Entitlement:
    entitlement_id: str
    subject: str
    resource: str
    active: bool


@dataclass(frozen=True)
class CampaignView:
    campaign_id: str
    status: str
    snapshot_version: int
    entitlement_ids: tuple[str, ...]
    opened_at: int
    closed_at: int | None
    pending_count: int
    decided_count: int


@dataclass(frozen=True)
class ItemView:
    entitlement_id: str
    subject: str
    resource: str
    reviewer: str | None
    decision: str | None
    state: str
    due_at: int | None
    decided_at: int | None


@dataclass(frozen=True)
class ReclaimResult:
    campaign_id: str
    reclaimed: tuple[str, ...]
    skipped_invalid: tuple[str, ...]
    already_reclaimed: tuple[str, ...]
    replayed: bool


@dataclass
class _ReviewItem:
    entitlement_id: str
    subject: str
    resource: str
    reviewer: str | None = None
    decision: str | None = None
    state: str = "pending"
    due_at: int | None = None
    decided_at: int | None = None


@dataclass
class _CampaignState:
    campaign_id: str
    status: str
    snapshot_version: int
    entitlement_ids: tuple[str, ...]
    reviewers: frozenset[str]
    opened_at: int
    closed_at: int | None
    items: dict[str, _ReviewItem]
    reclaim_complete: bool = False


_SNAPSHOT_KEYS = {
    "version",
    "next_entitlement",
    "next_snapshot",
    "entitlements",
    "campaigns",
    "reclaimed",
    "stats",
}
_STATS_KEYS = (
    "entitlements_added",
    "campaigns_opened",
    "decisions_recorded",
    "duplicates_ignored",
    "items_reclaimed",
    "skipped_invalid",
    "transferred",
)
_ENTITLEMENT_KEYS = {"entitlement_id", "subject", "resource", "active"}
_CAMPAIGN_KEYS = {
    "campaign_id",
    "status",
    "snapshot_version",
    "entitlement_ids",
    "reviewers",
    "opened_at",
    "closed_at",
    "items",
    "reclaim_complete",
}
_ITEM_KEYS = {
    "entitlement_id",
    "subject",
    "resource",
    "reviewer",
    "decision",
    "state",
    "due_at",
    "decided_at",
}
_ITEM_STATES = {"pending", "kept", "revoked", "reclaimed", "invalid"}
_ENTITLEMENT_ID_RE = re.compile(r"ent-(\d{4,})\Z")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonblank_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _id_sort_key(entitlement_id: str) -> tuple[int, str]:
    match = _ENTITLEMENT_ID_RE.fullmatch(entitlement_id)
    if match is None:
        return (0, entitlement_id)
    return (int(match.group(1)), entitlement_id)


class AccessReviewCampaign:
    """Manage entitlement snapshots, reviewer decisions and reclaim of revoked grants."""

    def __init__(self, *, default_due_ticks: int = 100,
                 max_items_per_campaign: int = 5000) -> None:
        self.default_due_ticks = default_due_ticks
        self.max_items_per_campaign = max_items_per_campaign
        self._lock = threading.RLock()
        self._next_entitlement = 1
        self._next_snapshot = 1
        self._entitlements: dict[str, Entitlement] = {}
        self._entitlement_keys: set[tuple[str, str]] = set()
        self._campaigns: dict[str, _CampaignState] = {}
        self._reclaimed: dict[str, str] = {}
        self._stats = {key: 0 for key in _STATS_KEYS}

    def add_entitlement(self, subject: str, resource: str, *, now: int) -> Entitlement:
        with self._lock:
            if not _is_nonblank_string(subject):
                raise CampaignError("CAMPAIGN_INVALID_REQUEST", "subject")
            if not _is_nonblank_string(resource):
                raise CampaignError("CAMPAIGN_INVALID_REQUEST", "resource")

            key = (subject, resource)
            if key in self._entitlement_keys:
                raise CampaignError("CAMPAIGN_ENTITLEMENT_EXISTS", key)

            entitlement_id = f"ent-{self._next_entitlement:04d}"
            entitlement = Entitlement(
                entitlement_id=entitlement_id,
                subject=subject,
                resource=resource,
                active=True,
            )
            self._entitlements[entitlement_id] = entitlement
            self._entitlement_keys.add(key)
            self._next_entitlement += 1
            self._stats["entitlements_added"] += 1
            return entitlement

    def revoke_entitlement(self, entitlement_id: str, *, now: int) -> Entitlement:
        with self._lock:
            if not _is_nonblank_string(entitlement_id):
                raise CampaignError("CAMPAIGN_INVALID_REQUEST", "entitlement_id")
            entitlement = self._entitlements.get(entitlement_id)
            if entitlement is None:
                raise CampaignError("CAMPAIGN_NOT_FOUND", entitlement_id)
            if not entitlement.active:
                return entitlement

            revoked = Entitlement(
                entitlement_id=entitlement.entitlement_id,
                subject=entitlement.subject,
                resource=entitlement.resource,
                active=False,
            )
            self._entitlements[entitlement_id] = revoked
            return revoked

    def entitlements(self, subject: str | None = None) -> list[Entitlement]:
        with self._lock:
            rows = self._entitlements.values()
            if subject is not None:
                rows = (row for row in rows if row.subject == subject)
            return sorted(rows, key=lambda row: _id_sort_key(row.entitlement_id))

    def open_campaign(self, campaign_id: str, *, subjects, reviewers,
                      now: int) -> CampaignView:
        if not _is_nonblank_string(campaign_id):
            raise CampaignError("CAMPAIGN_INVALID_REQUEST", "campaign_id")
        subject_names = self._normalise_names(subjects, "subjects")
        reviewer_names = self._normalise_names(reviewers, "reviewers")

        with self._lock:
            if campaign_id in self._campaigns:
                raise CampaignError("CAMPAIGN_EXISTS", campaign_id)

            subject_set = set(subject_names)
            frozen = [
                entitlement
                for entitlement in self._entitlements.values()
                if entitlement.active and entitlement.subject in subject_set
            ]
            frozen.sort(key=lambda row: _id_sort_key(row.entitlement_id))
            if len(frozen) > self.max_items_per_campaign:
                raise CampaignError("CAMPAIGN_TOO_LARGE", len(frozen))

            entitlement_ids = tuple(row.entitlement_id for row in frozen)
            items = {
                row.entitlement_id: _ReviewItem(
                    entitlement_id=row.entitlement_id,
                    subject=row.subject,
                    resource=row.resource,
                )
                for row in frozen
            }
            campaign = _CampaignState(
                campaign_id=campaign_id,
                status="open",
                snapshot_version=self._next_snapshot,
                entitlement_ids=entitlement_ids,
                reviewers=frozenset(reviewer_names),
                opened_at=now,
                closed_at=None,
                items=items,
            )

            self._campaigns[campaign_id] = campaign
            self._next_snapshot += 1
            self._stats["campaigns_opened"] += 1
            return self._campaign_view(campaign)

    def assign(self, campaign_id: str, *, reviewer: str, entitlement_ids,
               now: int) -> int:
        if not _is_nonblank_string(reviewer):
            raise CampaignError("CAMPAIGN_INVALID_REQUEST", "reviewer")
        ids = self._normalise_entitlement_ids(entitlement_ids)

        with self._lock:
            campaign = self._find_campaign(campaign_id)
            if campaign.status != "open":
                raise CampaignError("CAMPAIGN_NOT_OPEN", campaign_id)
            if reviewer not in campaign.reviewers:
                raise CampaignError("CAMPAIGN_UNKNOWN_REVIEWER", reviewer)
            for entitlement_id in ids:
                if entitlement_id not in campaign.items:
                    raise CampaignError("CAMPAIGN_NOT_FOUND", entitlement_id)

            assigned = 0
            due_at = now + self.default_due_ticks
            for entitlement_id in ids:
                item = campaign.items[entitlement_id]
                if item.state != "pending":
                    continue
                item.reviewer = reviewer
                item.due_at = due_at
                assigned += 1
            return assigned

    def decide(self, campaign_id: str, *, reviewer: str, entitlement_id: str,
               decision: str, now: int) -> ItemView:
        if decision not in {"keep", "revoke"}:
            raise CampaignError("CAMPAIGN_INVALID_DECISION", decision)

        with self._lock:
            campaign = self._find_campaign(campaign_id)
            item = (
                campaign.items.get(entitlement_id)
                if isinstance(entitlement_id, str)
                else None
            )
            if item is None:
                raise CampaignError("CAMPAIGN_NOT_FOUND", entitlement_id)
            if item.reviewer != reviewer:
                raise CampaignError("CAMPAIGN_NOT_REVIEWER", reviewer)
            if item.decision is not None:
                self._stats["duplicates_ignored"] += 1
                return self._item_view(item)

            item.decision = decision
            item.state = "kept" if decision == "keep" else "revoked"
            item.decided_at = now
            self._stats["decisions_recorded"] += 1
            return self._item_view(item)

    def close_campaign(self, campaign_id: str, *, now: int) -> CampaignView:
        with self._lock:
            campaign = self._find_campaign(campaign_id)
            if campaign.status == "closed":
                return self._campaign_view(campaign)

            pending_count = sum(
                item.state == "pending" for item in campaign.items.values()
            )
            if pending_count:
                raise CampaignError("CAMPAIGN_PENDING_ITEMS", pending_count)

            campaign.status = "closed"
            campaign.closed_at = now
            return self._campaign_view(campaign)

    def reclaim(self, campaign_id: str, *, now: int) -> ReclaimResult:
        with self._lock:
            campaign = self._find_campaign(campaign_id)
            if campaign.status != "closed":
                raise CampaignError("CAMPAIGN_NOT_CLOSED", campaign_id)
            if campaign.reclaim_complete:
                return ReclaimResult(campaign_id, (), (), (), True)

            reclaimed: list[str] = []
            skipped_invalid: list[str] = []
            already_reclaimed: list[str] = []

            for entitlement_id in sorted(campaign.items, key=_id_sort_key):
                item = campaign.items[entitlement_id]
                if item.state != "revoked":
                    continue

                prior_campaign = self._reclaimed.get(entitlement_id)
                if prior_campaign is not None:
                    item.state = "invalid"
                    already_reclaimed.append(entitlement_id)
                    continue

                entitlement = self._entitlements.get(entitlement_id)
                if entitlement is None or not entitlement.active:
                    item.state = "invalid"
                    skipped_invalid.append(entitlement_id)
                    self._stats["skipped_invalid"] += 1
                    continue

                self._entitlements[entitlement_id] = Entitlement(
                    entitlement_id=entitlement.entitlement_id,
                    subject=entitlement.subject,
                    resource=entitlement.resource,
                    active=False,
                )
                self._reclaimed[entitlement_id] = campaign_id
                item.state = "reclaimed"
                reclaimed.append(entitlement_id)
                self._stats["items_reclaimed"] += 1

            campaign.reclaim_complete = True
            return ReclaimResult(
                campaign_id=campaign_id,
                reclaimed=tuple(reclaimed),
                skipped_invalid=tuple(skipped_invalid),
                already_reclaimed=tuple(already_reclaimed),
                replayed=False,
            )

    def transfer_reviewer(self, campaign_id: str, *, from_reviewer: str,
                          to_reviewer: str, now: int) -> int:
        if not _is_nonblank_string(from_reviewer):
            raise CampaignError("CAMPAIGN_INVALID_REQUEST", "from_reviewer")
        if not _is_nonblank_string(to_reviewer):
            raise CampaignError("CAMPAIGN_INVALID_REQUEST", "to_reviewer")

        with self._lock:
            campaign = self._find_campaign(campaign_id)
            if campaign.status != "open":
                raise CampaignError("CAMPAIGN_NOT_OPEN", campaign_id)
            if from_reviewer not in campaign.reviewers:
                raise CampaignError("CAMPAIGN_UNKNOWN_REVIEWER", from_reviewer)
            if to_reviewer not in campaign.reviewers:
                raise CampaignError("CAMPAIGN_UNKNOWN_REVIEWER", to_reviewer)
            if from_reviewer == to_reviewer:
                return 0

            transferred = 0
            due_at = now + self.default_due_ticks
            for item in campaign.items.values():
                if item.state != "pending" or item.reviewer != from_reviewer:
                    continue
                item.reviewer = to_reviewer
                item.due_at = due_at
                transferred += 1
            if transferred:
                self._stats["transferred"] += transferred
            return transferred

    def items(self, campaign_id: str, *, reviewer: str | None = None) -> list[ItemView]:
        with self._lock:
            campaign = self._find_campaign(campaign_id)
            rows = (
                campaign.items[entitlement_id]
                for entitlement_id in sorted(campaign.items, key=_id_sort_key)
            )
            if reviewer is not None:
                rows = (item for item in rows if item.reviewer == reviewer)
            return [self._item_view(item) for item in rows]

    def campaign(self, campaign_id: str) -> CampaignView:
        with self._lock:
            campaign = self._find_campaign(campaign_id)
            return self._campaign_view(campaign)

    def snapshot(self) -> dict:
        with self._lock:
            entitlements = [
                {
                    "entitlement_id": row.entitlement_id,
                    "subject": row.subject,
                    "resource": row.resource,
                    "active": row.active,
                }
                for row in sorted(
                    self._entitlements.values(),
                    key=lambda row: _id_sort_key(row.entitlement_id),
                )
            ]

            campaigns = {}
            for campaign_id, campaign in self._campaigns.items():
                campaigns[campaign_id] = {
                    "campaign_id": campaign.campaign_id,
                    "status": campaign.status,
                    "snapshot_version": campaign.snapshot_version,
                    "entitlement_ids": list(campaign.entitlement_ids),
                    "reviewers": sorted(campaign.reviewers),
                    "opened_at": campaign.opened_at,
                    "closed_at": campaign.closed_at,
                    "items": {
                        entitlement_id: {
                            "entitlement_id": item.entitlement_id,
                            "subject": item.subject,
                            "resource": item.resource,
                            "reviewer": item.reviewer,
                            "decision": item.decision,
                            "state": item.state,
                            "due_at": item.due_at,
                            "decided_at": item.decided_at,
                        }
                        for entitlement_id, item in sorted(
                            campaign.items.items(),
                            key=lambda pair: _id_sort_key(pair[0]),
                        )
                    },
                    "reclaim_complete": campaign.reclaim_complete,
                }

            return copy.deepcopy(
                {
                    "version": 1,
                    "next_entitlement": self._next_entitlement,
                    "next_snapshot": self._next_snapshot,
                    "entitlements": entitlements,
                    "campaigns": campaigns,
                    "reclaimed": dict(self._reclaimed),
                    "stats": dict(self._stats),
                }
            )

    def restore(self, state: dict) -> None:
        with self._lock:
            restored = self._decode_snapshot(state)
            (
                next_entitlement,
                next_snapshot,
                entitlements,
                entitlement_keys,
                campaigns,
                reclaimed,
                stats,
            ) = restored

            self._next_entitlement = next_entitlement
            self._next_snapshot = next_snapshot
            self._entitlements = entitlements
            self._entitlement_keys = entitlement_keys
            self._campaigns = campaigns
            self._reclaimed = reclaimed
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _find_campaign(self, campaign_id: object) -> _CampaignState:
        if not isinstance(campaign_id, str):
            raise CampaignError("CAMPAIGN_NOT_FOUND", campaign_id)
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            raise CampaignError("CAMPAIGN_NOT_FOUND", campaign_id)
        return campaign

    @staticmethod
    def _normalise_names(values, field: str) -> list[str]:
        if isinstance(values, str):
            values = [values]
        try:
            iterator = iter(values)
        except TypeError as exc:
            raise CampaignError("CAMPAIGN_INVALID_REQUEST", field) from exc

        result: list[str] = []
        seen: set[str] = set()
        for value in iterator:
            if not _is_nonblank_string(value):
                raise CampaignError("CAMPAIGN_INVALID_REQUEST", field)
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    @staticmethod
    def _normalise_entitlement_ids(values) -> list[str]:
        if isinstance(values, str):
            values = [values]
        try:
            iterator = iter(values)
        except TypeError as exc:
            raise CampaignError(
                "CAMPAIGN_INVALID_REQUEST", "entitlement_ids"
            ) from exc

        result: list[str] = []
        seen: set[str] = set()
        for value in iterator:
            if not _is_nonblank_string(value):
                raise CampaignError(
                    "CAMPAIGN_INVALID_REQUEST", "entitlement_ids"
                )
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    @staticmethod
    def _item_view(item: _ReviewItem) -> ItemView:
        return ItemView(
            entitlement_id=item.entitlement_id,
            subject=item.subject,
            resource=item.resource,
            reviewer=item.reviewer,
            decision=item.decision,
            state=item.state,
            due_at=item.due_at,
            decided_at=item.decided_at,
        )

    @staticmethod
    def _campaign_view(campaign: _CampaignState) -> CampaignView:
        pending_count = sum(
            item.state == "pending" for item in campaign.items.values()
        )
        decided_count = sum(
            item.decision is not None for item in campaign.items.values()
        )
        return CampaignView(
            campaign_id=campaign.campaign_id,
            status=campaign.status,
            snapshot_version=campaign.snapshot_version,
            entitlement_ids=tuple(campaign.entitlement_ids),
            opened_at=campaign.opened_at,
            closed_at=campaign.closed_at,
            pending_count=pending_count,
            decided_count=decided_count,
        )

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise CampaignError("CAMPAIGN_SNAPSHOT_INVALID", detail)

    @classmethod
    def _decode_snapshot(cls, state):
        if not isinstance(state, dict):
            cls._snapshot_invalid("state")
        if set(state) != _SNAPSHOT_KEYS:
            cls._snapshot_invalid("fields")
        if state["version"] != 1 or not _is_int(state["version"]):
            cls._snapshot_invalid("version")

        next_entitlement = state["next_entitlement"]
        next_snapshot = state["next_snapshot"]
        if not _is_int(next_entitlement) or next_entitlement < 1:
            cls._snapshot_invalid("next_entitlement")
        if not _is_int(next_snapshot) or next_snapshot < 1:
            cls._snapshot_invalid("next_snapshot")

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(_STATS_KEYS):
            cls._snapshot_invalid("stats")
        stats = {}
        for key in _STATS_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                cls._snapshot_invalid(f"stats.{key}")
            stats[key] = value

        raw_entitlements = state["entitlements"]
        if not isinstance(raw_entitlements, list):
            cls._snapshot_invalid("entitlements")
        entitlements: dict[str, Entitlement] = {}
        entitlement_keys: set[tuple[str, str]] = set()
        entitlement_numbers: list[int] = []
        for row in raw_entitlements:
            if not isinstance(row, dict) or set(row) != _ENTITLEMENT_KEYS:
                cls._snapshot_invalid("entitlement")
            entitlement_id = row["entitlement_id"]
            subject = row["subject"]
            resource = row["resource"]
            active = row["active"]
            if not _is_nonblank_string(entitlement_id):
                cls._snapshot_invalid("entitlement_id")
            match = _ENTITLEMENT_ID_RE.fullmatch(entitlement_id)
            if match is None:
                cls._snapshot_invalid("entitlement_id")
            number = int(match.group(1))
            if number < 1 or entitlement_id in entitlements:
                cls._snapshot_invalid("entitlement_id")
            if not _is_nonblank_string(subject):
                cls._snapshot_invalid("subject")
            if not _is_nonblank_string(resource):
                cls._snapshot_invalid("resource")
            if not isinstance(active, bool):
                cls._snapshot_invalid("active")
            key = (subject, resource)
            if key in entitlement_keys:
                cls._snapshot_invalid("entitlement_duplicate")
            entitlements[entitlement_id] = Entitlement(
                entitlement_id=entitlement_id,
                subject=subject,
                resource=resource,
                active=active,
            )
            entitlement_keys.add(key)
            entitlement_numbers.append(number)

        if len(entitlement_numbers) + 1 != next_entitlement:
            cls._snapshot_invalid("next_entitlement")
        entitlement_numbers.sort()
        if entitlement_numbers != list(range(1, next_entitlement)):
            cls._snapshot_invalid("next_entitlement")
        entitlements = {
            entitlement_id: entitlements[entitlement_id]
            for entitlement_id in sorted(entitlements, key=_id_sort_key)
        }

        raw_campaigns = state["campaigns"]
        if not isinstance(raw_campaigns, dict):
            cls._snapshot_invalid("campaigns")
        campaigns: dict[str, _CampaignState] = {}
        snapshot_versions: set[int] = set()
        for campaign_id, raw_campaign in raw_campaigns.items():
            if not _is_nonblank_string(campaign_id):
                cls._snapshot_invalid("campaign_id")
            if (
                not isinstance(raw_campaign, dict)
                or set(raw_campaign) != _CAMPAIGN_KEYS
            ):
                cls._snapshot_invalid("campaign")
            if raw_campaign["campaign_id"] != campaign_id:
                cls._snapshot_invalid("campaign_id")

            status = raw_campaign["status"]
            if status not in {"open", "closed"}:
                cls._snapshot_invalid("campaign_status")
            snapshot_version = raw_campaign["snapshot_version"]
            if (
                not _is_int(snapshot_version)
                or snapshot_version < 1
                or snapshot_version >= next_snapshot
                or snapshot_version in snapshot_versions
            ):
                cls._snapshot_invalid("snapshot_version")
            snapshot_versions.add(snapshot_version)

            raw_entitlement_ids = raw_campaign["entitlement_ids"]
            if not isinstance(raw_entitlement_ids, list):
                cls._snapshot_invalid("campaign_entitlement_ids")
            entitlement_ids: list[str] = []
            seen_entitlement_ids: set[str] = set()
            for entitlement_id in raw_entitlement_ids:
                if (
                    not isinstance(entitlement_id, str)
                    or entitlement_id not in entitlements
                    or entitlement_id in seen_entitlement_ids
                ):
                    cls._snapshot_invalid("campaign_entitlement_ids")
                seen_entitlement_ids.add(entitlement_id)
                entitlement_ids.append(entitlement_id)
            entitlement_ids.sort(key=_id_sort_key)

            raw_reviewers = raw_campaign["reviewers"]
            if not isinstance(raw_reviewers, list):
                cls._snapshot_invalid("campaign_reviewers")
            reviewers: list[str] = []
            seen_reviewers: set[str] = set()
            for reviewer in raw_reviewers:
                if (
                    not _is_nonblank_string(reviewer)
                    or reviewer in seen_reviewers
                ):
                    cls._snapshot_invalid("campaign_reviewers")
                seen_reviewers.add(reviewer)
                reviewers.append(reviewer)

            opened_at = raw_campaign["opened_at"]
            closed_at = raw_campaign["closed_at"]
            if not _is_int(opened_at):
                cls._snapshot_invalid("opened_at")
            if closed_at is not None and not _is_int(closed_at):
                cls._snapshot_invalid("closed_at")
            if status == "open":
                if closed_at is not None:
                    cls._snapshot_invalid("closed_at")
            elif closed_at is None:
                cls._snapshot_invalid("closed_at")

            reclaim_complete = raw_campaign["reclaim_complete"]
            if not isinstance(reclaim_complete, bool):
                cls._snapshot_invalid("reclaim_complete")
            if reclaim_complete and status != "closed":
                cls._snapshot_invalid("reclaim_complete")

            raw_items = raw_campaign["items"]
            if not isinstance(raw_items, dict):
                cls._snapshot_invalid("campaign_items")
            if set(raw_items) != set(entitlement_ids):
                cls._snapshot_invalid("campaign_items")

            items: dict[str, _ReviewItem] = {}
            for entitlement_id in sorted(entitlement_ids, key=_id_sort_key):
                raw_item = raw_items[entitlement_id]
                if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_KEYS:
                    cls._snapshot_invalid("item")
                if raw_item["entitlement_id"] != entitlement_id:
                    cls._snapshot_invalid("item_entitlement_id")

                entitlement = entitlements[entitlement_id]
                subject = raw_item["subject"]
                resource = raw_item["resource"]
                if subject != entitlement.subject or resource != entitlement.resource:
                    cls._snapshot_invalid("item_snapshot")

                reviewer = raw_item["reviewer"]
                if reviewer is not None:
                    if (
                        not _is_nonblank_string(reviewer)
                        or reviewer not in seen_reviewers
                    ):
                        cls._snapshot_invalid("item_reviewer")

                decision = raw_item["decision"]
                if decision not in {None, "keep", "revoke"}:
                    cls._snapshot_invalid("item_decision")
                item_state = raw_item["state"]
                if item_state not in _ITEM_STATES:
                    cls._snapshot_invalid("item_state")

                due_at = raw_item["due_at"]
                decided_at = raw_item["decided_at"]
                if due_at is not None and not _is_int(due_at):
                    cls._snapshot_invalid("due_at")
                if decided_at is not None and not _is_int(decided_at):
                    cls._snapshot_invalid("decided_at")

                if item_state == "pending":
                    if decision is not None or decided_at is not None:
                        cls._snapshot_invalid("item_state")
                else:
                    if decision is None or decided_at is None or reviewer is None:
                        cls._snapshot_invalid("item_state")
                    if item_state == "kept" and decision != "keep":
                        cls._snapshot_invalid("item_state")
                    if (
                        item_state in {"revoked", "reclaimed", "invalid"}
                        and decision != "revoke"
                    ):
                        cls._snapshot_invalid("item_state")
                    if item_state in {"reclaimed", "invalid"} and entitlement.active:
                        cls._snapshot_invalid("item_state")

                if status == "closed" and item_state == "pending":
                    cls._snapshot_invalid("pending_item_in_closed_campaign")
                if status == "open" and item_state in {"reclaimed", "invalid"}:
                    cls._snapshot_invalid("item_state")
                if reclaim_complete and item_state == "revoked":
                    cls._snapshot_invalid("unfinished_reclaim")
                if (
                    not reclaim_complete
                    and item_state in {"reclaimed", "invalid"}
                ):
                    cls._snapshot_invalid("item_state")

                items[entitlement_id] = _ReviewItem(
                    entitlement_id=entitlement_id,
                    subject=subject,
                    resource=resource,
                    reviewer=reviewer,
                    decision=decision,
                    state=item_state,
                    due_at=due_at,
                    decided_at=decided_at,
                )

            campaigns[campaign_id] = _CampaignState(
                campaign_id=campaign_id,
                status=status,
                snapshot_version=snapshot_version,
                entitlement_ids=tuple(entitlement_ids),
                reviewers=frozenset(reviewers),
                opened_at=opened_at,
                closed_at=closed_at,
                items=items,
                reclaim_complete=reclaim_complete,
            )

        if next_snapshot != len(campaigns) + 1:
            cls._snapshot_invalid("next_snapshot")
        if snapshot_versions != set(range(1, next_snapshot)):
            cls._snapshot_invalid("next_snapshot")

        raw_reclaimed = state["reclaimed"]
        if not isinstance(raw_reclaimed, dict):
            cls._snapshot_invalid("reclaimed")
        reclaimed: dict[str, str] = {}
        for entitlement_id, campaign_id in raw_reclaimed.items():
            if (
                not isinstance(entitlement_id, str)
                or entitlement_id not in entitlements
                or not isinstance(campaign_id, str)
                or campaign_id not in campaigns
            ):
                cls._snapshot_invalid("reclaimed")
            campaign = campaigns[campaign_id]
            item = campaign.items[entitlement_id]
            if (
                campaign.status != "closed"
                or not campaign.reclaim_complete
                or item.state != "reclaimed"
            ):
                cls._snapshot_invalid("reclaimed")
            reclaimed[entitlement_id] = campaign_id

        for campaign in campaigns.values():
            for entitlement_id, item in campaign.items.items():
                if (
                    item.state == "reclaimed"
                    and reclaimed.get(entitlement_id) != campaign.campaign_id
                ):
                    cls._snapshot_invalid("reclaimed")

        return (
            next_entitlement,
            next_snapshot,
            entitlements,
            entitlement_keys,
            campaigns,
            reclaimed,
            stats,
        )
