"""Password history generations, expiry grace and forced rotation state."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PasswordPolicyError(ValueError):
    """Refusal raised by the password history policy."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class HistoryEntry:
    generation: int
    digest: str
    created_at: int


@dataclass(frozen=True)
class ChangeDecision:
    status: str
    code: str
    generation: int
    history_size: int


@dataclass(frozen=True)
class LoginVerdict:
    action: str
    reason: str
    grace_remaining: int
    entry_allowed: bool


@dataclass(frozen=True)
class AccountState:
    account: str
    generation: int
    history_size: int
    must_change: bool
    expired: bool
    grace_used: int
    changed_at: int


class PasswordHistoryPolicy:
    """Track per account password generations, expiry grace and reset flags."""

    def __init__(self, *, history_depth: int = 12, max_age_days: int = 90,
                 grace_logins: int = 3) -> None:
        self.history_depth = history_depth
        self.max_age_days = max_age_days
        self.grace_logins = grace_logins
        self._lock = threading.RLock()

    def enroll_account(self, account: str, *, digest: str, now: int) -> HistoryEntry:
        raise NotImplementedError

    def submit_change(self, account: str, *, digest: str, now: int) -> ChangeDecision:
        raise NotImplementedError

    def check_login(self, account: str, *, now: int) -> LoginVerdict:
        raise NotImplementedError

    def record_login(self, account: str, *, now: int) -> int:
        raise NotImplementedError

    def admin_reset(self, account: str, *, digest: str, now: int) -> HistoryEntry:
        raise NotImplementedError

    def update_policy(self, *, history_depth: int | None = None,
                      max_age_days: int | None = None,
                      grace_logins: int | None = None) -> dict:
        raise NotImplementedError

    def history_of(self, account: str) -> tuple:
        raise NotImplementedError

    def account_state(self, account: str, *, now: int) -> AccountState:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
