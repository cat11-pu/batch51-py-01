"""HOTP counter ledger: look-ahead window, resync and rollback refusal."""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass


_CODE_LENGTH = 6
_HEX_DIGITS = frozenset("0123456789abcdef")
_STAT_KEYS = (
    "accepted",
    "replayed",
    "stale",
    "no_match",
    "consumed",
    "resync",
)
_SNAPSHOT_KEYS = frozenset({"version", "users", "stats"})
_SNAPSHOT_USER_KEYS = frozenset(
    {"user", "secret", "counter", "lookahead", "consumed"}
)


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


@dataclass
class _UserState:
    user: str
    secret: str
    counter: int
    lookahead: int
    consumed: list[int]


def _is_int(value: object) -> bool:
    return type(value) is int


def _is_non_negative_int(value: object) -> bool:
    return _is_int(value) and value >= 0


def _is_non_empty_text(value: object) -> bool:
    return type(value) is str and bool(value)


def _is_valid_code(code: object) -> bool:
    return (
        type(code) is str
        and len(code) == _CODE_LENGTH
        and all(character in _HEX_DIGITS for character in code)
    )


def _code_for(secret: str, counter: int) -> str:
    payload = f"{secret}:{counter}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:_CODE_LENGTH]


class HotpCounterLedger:
    """Keep one moving counter and one consumption window per user."""

    def __init__(self, *, lookahead: int = 5, max_users: int = 64,
                 window_size: int = 32, clock=None) -> None:
        if not _is_non_negative_int(lookahead):
            raise HotpError("HOTP_REQUEST_INVALID", "lookahead")
        if not _is_non_negative_int(max_users):
            raise HotpError("HOTP_REQUEST_INVALID", "max_users")
        if not _is_non_negative_int(window_size):
            raise HotpError("HOTP_REQUEST_INVALID", "window_size")
        if clock is not None and not callable(clock):
            raise HotpError("HOTP_REQUEST_INVALID", "clock")

        self.lookahead = lookahead
        self.max_users = max_users
        self.window_size = window_size
        self._clock = clock
        self._lock = threading.RLock()
        self._users: dict[str, _UserState] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def register(self, *, user: str, secret: str, counter: int = 0) -> UserRecord:
        if not _is_non_empty_text(user):
            raise HotpError("HOTP_REQUEST_INVALID", "user")
        if not _is_non_empty_text(secret):
            raise HotpError("HOTP_REQUEST_INVALID", "secret")
        if not _is_non_negative_int(counter):
            raise HotpError("HOTP_REQUEST_INVALID", "counter")

        with self._lock:
            if user in self._users:
                raise HotpError("HOTP_USER_EXISTS", user)
            if len(self._users) >= self.max_users:
                raise HotpError("HOTP_CAPACITY_EXCEEDED", self.max_users)

            state = _UserState(
                user=user,
                secret=secret,
                counter=counter,
                lookahead=self.lookahead,
                consumed=[],
            )
            self._users[user] = state
            return self._record_for(state)

    def verify(self, *, user: str, code: str) -> VerifyResult:
        if not _is_valid_code(code):
            raise HotpError("HOTP_REQUEST_INVALID", "code")
        self._require_user(user)

        with self._lock:
            state = self._users.get(user)
            if state is None:
                raise HotpError("HOTP_USER_UNKNOWN", user)

            current = state.counter
            for candidate in range(current, current + state.lookahead + 1):
                if not hmac.compare_digest(_code_for(state.secret, candidate), code):
                    continue
                if candidate in state.consumed:
                    self._stats["replayed"] += 1
                    return self._rejected(user, current, "replayed")
                self._append_consumed(state, candidate)
                state.counter = candidate + 1
                self._stats["accepted"] += 1
                return VerifyResult(
                    user=user,
                    accepted=True,
                    counter=candidate,
                    next_counter=state.counter,
                    reason="ok",
                )

            if self._matches_consumed(state, code):
                self._stats["replayed"] += 1
                return self._rejected(user, current, "replayed")

            if self._matches_stale(state, code):
                self._stats["stale"] += 1
                return self._rejected(user, current, "stale")

            self._stats["no_match"] += 1
            return self._rejected(user, current, "no_match")

    def consume(self, *, user: str, counter: int) -> int:
        self._require_user(user)
        if not _is_non_negative_int(counter):
            raise HotpError("HOTP_REQUEST_INVALID", "counter")

        with self._lock:
            state = self._users.get(user)
            if state is None:
                raise HotpError("HOTP_USER_UNKNOWN", user)
            if counter < state.counter:
                raise HotpError(
                    "HOTP_COUNTER_ROLLBACK",
                    {"counter": counter, "current": state.counter},
                )

            self._append_consumed(state, counter)
            state.counter = counter + 1
            self._stats["consumed"] += 1
            return state.counter

    def counter_of(self, user: str) -> int:
        self._require_user(user)
        with self._lock:
            return self._state_for(user).counter

    def resync(self, *, user: str, counter: int, code: str) -> int:
        self._require_user(user)
        if not _is_non_negative_int(counter):
            raise HotpError("HOTP_REQUEST_INVALID", "counter")
        if not _is_valid_code(code):
            raise HotpError("HOTP_REQUEST_INVALID", "code")

        with self._lock:
            state = self._users.get(user)
            if state is None:
                raise HotpError("HOTP_USER_UNKNOWN", user)
            if counter <= state.counter:
                raise HotpError(
                    "HOTP_COUNTER_ROLLBACK",
                    {"counter": counter, "current": state.counter},
                )
            if not hmac.compare_digest(_code_for(state.secret, counter), code):
                raise HotpError("HOTP_RESYNC_MISMATCH", counter)

            self._append_consumed(state, counter)
            state.counter = counter + 1
            self._stats["resync"] += 1
            return state.counter

    def consumed_for(self, user: str) -> tuple[int, ...]:
        self._require_user(user)
        with self._lock:
            return tuple(self._state_for(user).consumed)

    def lookahead_of(self, user: str) -> int:
        self._require_user(user)
        with self._lock:
            return self._state_for(user).lookahead

    def unregister(self, user: str) -> bool:
        self._require_user(user)
        with self._lock:
            return self._users.pop(user, None) is not None

    def snapshot(self) -> dict:
        with self._lock:
            users = [
                {
                    "user": state.user,
                    "secret": state.secret,
                    "counter": state.counter,
                    "lookahead": state.lookahead,
                    "consumed": list(state.consumed),
                }
                for state in self._users.values()
            ]
            return {
                "version": 1,
                "users": users,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            users, stats = self._parse_snapshot(state)
            self._users = users
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _parse_snapshot(
        self, state: object
    ) -> tuple[dict[str, _UserState], dict[str, int]]:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise HotpError("HOTP_SNAPSHOT_INVALID", "top-level")
        if not _is_int(state.get("version")) or state["version"] != 1:
            raise HotpError("HOTP_SNAPSHOT_INVALID", "version")

        raw_users = state.get("users")
        if not isinstance(raw_users, list):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "users")
        if len(raw_users) > self.max_users:
            raise HotpError("HOTP_SNAPSHOT_INVALID", "capacity")

        users: dict[str, _UserState] = {}
        for raw_user in raw_users:
            parsed = self._parse_snapshot_user(raw_user)
            if parsed.user in users:
                raise HotpError("HOTP_SNAPSHOT_INVALID", "duplicate user")
            users[parsed.user] = parsed

        raw_stats = state.get("stats")
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(_STAT_KEYS):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "stats")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats.get(key)
            if not _is_non_negative_int(value):
                raise HotpError("HOTP_SNAPSHOT_INVALID", f"stats.{key}")
            stats[key] = value

        return users, stats

    def _parse_snapshot_user(self, raw_user: object) -> _UserState:
        if not isinstance(raw_user, dict) or set(raw_user) != _SNAPSHOT_USER_KEYS:
            raise HotpError("HOTP_SNAPSHOT_INVALID", "user record")

        user = raw_user.get("user")
        secret = raw_user.get("secret")
        counter = raw_user.get("counter")
        lookahead = raw_user.get("lookahead")
        consumed = raw_user.get("consumed")

        if not _is_non_empty_text(user):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "user")
        if not _is_non_empty_text(secret):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "secret")
        if not _is_non_negative_int(counter):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "counter")
        if not _is_non_negative_int(lookahead):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "lookahead")
        if not isinstance(consumed, list):
            raise HotpError("HOTP_SNAPSHOT_INVALID", "consumed")
        if len(consumed) > self.window_size:
            raise HotpError("HOTP_SNAPSHOT_INVALID", "consumed window")

        previous: int | None = None
        for value in consumed:
            if not _is_non_negative_int(value) or value >= counter:
                raise HotpError("HOTP_SNAPSHOT_INVALID", "consumed value")
            if previous is not None and value <= previous:
                raise HotpError("HOTP_SNAPSHOT_INVALID", "consumed order")
            previous = value

        return _UserState(
            user=user,
            secret=secret,
            counter=counter,
            lookahead=lookahead,
            consumed=list(consumed),
        )

    def _require_user(self, user: object) -> None:
        if not _is_non_empty_text(user):
            raise HotpError("HOTP_REQUEST_INVALID", "user")

    def _state_for(self, user: str) -> _UserState:
        state = self._users.get(user)
        if state is None:
            raise HotpError("HOTP_USER_UNKNOWN", user)
        return state

    def _record_for(self, state: _UserState) -> UserRecord:
        return UserRecord(
            user=state.user,
            counter=state.counter,
            lookahead=state.lookahead,
            consumed=tuple(state.consumed),
        )

    @staticmethod
    def _rejected(user: str, current: int, reason: str) -> VerifyResult:
        return VerifyResult(
            user=user,
            accepted=False,
            counter=None,
            next_counter=current,
            reason=reason,
        )

    def _append_consumed(self, state: _UserState, counter: int) -> None:
        if counter in state.consumed:
            return
        state.consumed.append(counter)
        state.consumed.sort()
        if len(state.consumed) > self.window_size:
            del state.consumed[: len(state.consumed) - self.window_size]

    @staticmethod
    def _matches_consumed(state: _UserState, code: str) -> bool:
        return any(
            hmac.compare_digest(_code_for(state.secret, counter), code)
            for counter in state.consumed
        )

    @staticmethod
    def _matches_stale(state: _UserState, code: str) -> bool:
        for counter in range(state.counter - 1, -1, -1):
            if hmac.compare_digest(_code_for(state.secret, counter), code):
                return True
        return False
