"""Guest access ledger: sponsor guarantees, access windows, renewals and expiry."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GuestError(ValueError):
    """Raised when a guest access operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SponsorView:
    sponsor_id: str
    grantable: tuple[str, ...]
    guest_count: int


@dataclass(frozen=True)
class GuestView:
    guest_id: str
    sponsor_id: str | None
    state: str
    scope: tuple[str, ...]
    invited_at: int
    granted_at: int | None
    expires_at: int | None
    disabled_reason: str | None
    renewal_pending: bool


class GuestAccessLedger:
    """Track sponsorship, scoped access windows and expiry settlement for guests."""

    def __init__(self, *, default_window_ticks: int = 1000,
                 renewal_window_ticks: int = 200,
                 max_guests_per_sponsor: int = 20) -> None:
        self.default_window_ticks = default_window_ticks
        self.renewal_window_ticks = renewal_window_ticks
        self.max_guests_per_sponsor = max_guests_per_sponsor
        self._lock = threading.RLock()

    def register_sponsor(self, sponsor_id: str, grantable, *, now: int) -> SponsorView:
        raise NotImplementedError

    def update_sponsor_scope(self, sponsor_id: str, grantable, *,
                             now: int) -> SponsorView:
        raise NotImplementedError

    def invite_guest(self, guest_id: str, *, now: int) -> GuestView:
        raise NotImplementedError

    def bind_sponsor(self, guest_id: str, sponsor_id: str, scope, *,
                     now: int) -> GuestView:
        raise NotImplementedError

    def request_renewal(self, guest_id: str, *, now: int) -> GuestView:
        raise NotImplementedError

    def approve_renewal(self, guest_id: str, *, now: int) -> GuestView:
        raise NotImplementedError

    def settle_expiry(self, *, now: int) -> int:
        raise NotImplementedError

    def revoke_guest(self, guest_id: str, sponsor: str, *, now: int) -> GuestView:
        raise NotImplementedError

    def transfer_guest(self, guest_id: str, new_sponsor: str, *,
                       now: int) -> GuestView:
        raise NotImplementedError

    def reconcile(self, *, now: int) -> int:
        raise NotImplementedError

    def effective_scope(self, guest_id: str) -> tuple:
        raise NotImplementedError

    def guest(self, guest_id: str) -> GuestView:
        raise NotImplementedError

    def guests_for(self, sponsor_id: str) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
