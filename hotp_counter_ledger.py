"""HOTP counter ledger: look-ahead window, resync and rollback refusal."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class HotpError(ValueError):
    """Raised when a ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class UserRecord:
    user: str
    counter: int
    lookahead: int
    consumed: tuple[int, ...]


@dataclass(frozen=True)
class VerifyResult:
    user: str
    accepted: bool
    counter: int | None
    next_counter: int
    reason: str


class HotpCounterLedger:
    """Keep one moving counter and one consumption window per user."""

    def __init__(self, *, lookahead: int = 5, max_users: int = 64,
                 window_size: int = 32, clock=None) -> None:
        self.lookahead = lookahead
        self.max_users = max_users
        self.window_size = window_size
        self._clock = clock
        self._lock = threading.RLock()

    def register(self, *, user: str, secret: str, counter: int = 0) -> UserRecord:
        raise NotImplementedError

    def verify(self, *, user: str, code: str) -> VerifyResult:
        raise NotImplementedError

    def consume(self, *, user: str, counter: int) -> int:
        raise NotImplementedError

    def counter_of(self, user: str) -> int:
        raise NotImplementedError

    def resync(self, *, user: str, counter: int, code: str) -> int:
        raise NotImplementedError

    def consumed_for(self, user: str) -> tuple[int, ...]:
        raise NotImplementedError

    def lookahead_of(self, user: str) -> int:
        raise NotImplementedError

    def unregister(self, user: str) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
