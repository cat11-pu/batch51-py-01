"""Account identifier change guard: dual confirmation, hold window and reservation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class IdentifierError(ValueError):
    """Raised when an identifier change is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AccountView:
    account_id: str
    identifier: str
    disabled: bool
    pending_request: str | None
    created_at: int


@dataclass(frozen=True)
class ChangeView:
    request_id: str
    account_id: str
    old_identifier: str
    new_identifier: str
    state: str
    old_confirmed: bool
    new_confirmed: bool
    created_at: int
    expires_at: int
    committed_at: int | None


@dataclass(frozen=True)
class LoginResolution:
    status: str
    account_id: str | None
    redirect_to: str | None


class IdentifierChangeGuard:
    """Guard email or phone changes with two confirmations and a hold on the old value."""

    def __init__(self, *, hold_ticks: int = 500, request_ttl: int = 300) -> None:
        self.hold_ticks = hold_ticks
        self.request_ttl = request_ttl
        self._lock = threading.RLock()

    def create_account(self, account_id: str, identifier: str, *, now: int) -> AccountView:
        raise NotImplementedError

    def initiate_change(self, account_id: str, new_identifier: str, *,
                        now: int) -> ChangeView:
        raise NotImplementedError

    def challenge_codes(self, request_id: str) -> dict:
        raise NotImplementedError

    def confirm_old(self, request_id: str, code: str, *, now: int) -> ChangeView:
        raise NotImplementedError

    def confirm_new(self, request_id: str, code: str, *, now: int) -> ChangeView:
        raise NotImplementedError

    def commit(self, request_id: str, *, now: int) -> ChangeView:
        raise NotImplementedError

    def rollback(self, request_id: str, *, now: int) -> ChangeView:
        raise NotImplementedError

    def release_hold(self, identifier: str, *, now: int) -> int:
        raise NotImplementedError

    def resolve_login(self, identifier: str, *, now: int) -> LoginResolution:
        raise NotImplementedError

    def disable_account(self, account_id: str, *, now: int) -> AccountView:
        raise NotImplementedError

    def enable_account(self, account_id: str, *, now: int) -> AccountView:
        raise NotImplementedError

    def account(self, account_id: str) -> AccountView:
        raise NotImplementedError

    def change(self, request_id: str) -> ChangeView:
        raise NotImplementedError

    def pending_change(self, account_id: str) -> ChangeView | None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
