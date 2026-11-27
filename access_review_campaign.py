"""Access review campaigns: frozen entitlement snapshots, decisions and reclaim ledger."""

from __future__ import annotations

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


class AccessReviewCampaign:
    """Manage entitlement snapshots, reviewer decisions and reclaim of revoked grants."""

    def __init__(self, *, default_due_ticks: int = 100,
                 max_items_per_campaign: int = 5000) -> None:
        self.default_due_ticks = default_due_ticks
        self.max_items_per_campaign = max_items_per_campaign
        self._lock = threading.RLock()

    def add_entitlement(self, subject: str, resource: str, *, now: int) -> Entitlement:
        raise NotImplementedError

    def revoke_entitlement(self, entitlement_id: str, *, now: int) -> Entitlement:
        raise NotImplementedError

    def entitlements(self, subject: str | None = None) -> list[Entitlement]:
        raise NotImplementedError

    def open_campaign(self, campaign_id: str, *, subjects, reviewers,
                      now: int) -> CampaignView:
        raise NotImplementedError

    def assign(self, campaign_id: str, *, reviewer: str, entitlement_ids,
               now: int) -> int:
        raise NotImplementedError

    def decide(self, campaign_id: str, *, reviewer: str, entitlement_id: str,
               decision: str, now: int) -> ItemView:
        raise NotImplementedError

    def close_campaign(self, campaign_id: str, *, now: int) -> CampaignView:
        raise NotImplementedError

    def reclaim(self, campaign_id: str, *, now: int) -> ReclaimResult:
        raise NotImplementedError

    def transfer_reviewer(self, campaign_id: str, *, from_reviewer: str,
                          to_reviewer: str, now: int) -> int:
        raise NotImplementedError

    def items(self, campaign_id: str, *, reviewer: str | None = None) -> list[ItemView]:
        raise NotImplementedError

    def campaign(self, campaign_id: str) -> CampaignView:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
