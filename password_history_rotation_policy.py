"""Password history generations, expiry grace and forced rotation state."""

from __future__ import annotations

import threading
from dataclasses import dataclass


_DAY_SECONDS = 86400
_SNAPSHOT_VERSION = 1
_STATS_KEYS = (
    "enrolled",
    "changed",
    "reused",
    "resets",
    "logins",
    "trimmed",
)


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


@dataclass
class _AccountRecord:
    generation: int
    history: list[HistoryEntry]
    must_change: bool
    grace_used: int
    changed_at: int


def _is_int(value: object) -> bool:
    return type(value) is int


def _validate_policy_values(
    history_depth: object,
    max_age_days: object,
    grace_logins: object,
    code: str,
) -> None:
    if not _is_int(history_depth) or history_depth < 1:
        raise PasswordPolicyError(code, "history_depth")
    if not _is_int(max_age_days) or max_age_days < 0:
        raise PasswordPolicyError(code, "max_age_days")
    if not _is_int(grace_logins) or grace_logins < 0:
        raise PasswordPolicyError(code, "grace_logins")


def _validate_account(account: object, code: str) -> None:
    if not isinstance(account, str) or not account:
        raise PasswordPolicyError(code, "account")


def _validate_digest(digest: object, code: str = "PWD_INVALID_DIGEST") -> None:
    if (
        not isinstance(digest, str)
        or len(digest) < 8
        or any(character.isspace() for character in digest)
    ):
        raise PasswordPolicyError(code, "digest")


def _validate_now(now: object, code: str = "PWD_INVALID_TIME") -> None:
    if not _is_int(now) or now < 0:
        raise PasswordPolicyError(code, "now")


class PasswordHistoryPolicy:
    """Track per account password generations, expiry grace and reset flags."""

    def __init__(self, *, history_depth: int = 12, max_age_days: int = 90,
                 grace_logins: int = 3) -> None:
        _validate_policy_values(
            history_depth, max_age_days, grace_logins, "PWD_POLICY_INVALID"
        )
        self.history_depth = history_depth
        self.max_age_days = max_age_days
        self.grace_logins = grace_logins
        self._lock = threading.RLock()
        self._accounts: dict[str, _AccountRecord] = {}
        self._stats = {key: 0 for key in _STATS_KEYS}

    def enroll_account(self, account: str, *, digest: str, now: int) -> HistoryEntry:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        _validate_digest(digest)
        _validate_now(now)
        with self._lock:
            if account in self._accounts:
                raise PasswordPolicyError("PWD_ACCOUNT_EXISTS", account)
            entry = HistoryEntry(
                generation=1,
                digest=digest,
                created_at=now,
            )
            self._accounts[account] = _AccountRecord(
                generation=1,
                history=[entry],
                must_change=False,
                grace_used=0,
                changed_at=now,
            )
            self._stats["enrolled"] += 1
            return entry

    def submit_change(self, account: str, *, digest: str, now: int) -> ChangeDecision:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        _validate_digest(digest)
        _validate_now(now)
        with self._lock:
            record = self._require_account(account)
            if any(entry.digest == digest for entry in record.history):
                self._stats["reused"] += 1
                return ChangeDecision(
                    status="rejected",
                    code="PWD_REUSED",
                    generation=record.generation,
                    history_size=len(record.history),
                )

            generation = record.generation + 1
            record.history.append(
                HistoryEntry(
                    generation=generation,
                    digest=digest,
                    created_at=now,
                )
            )
            record.generation = generation
            record.must_change = False
            record.grace_used = 0
            record.changed_at = now
            self._stats["changed"] += 1
            self._trim(record, self.history_depth)
            return ChangeDecision(
                status="accepted",
                code="PWD_CHANGED",
                generation=generation,
                history_size=len(record.history),
            )

    def check_login(self, account: str, *, now: int) -> LoginVerdict:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        _validate_now(now)
        with self._lock:
            record = self._accounts.get(account)
            if record is None:
                return LoginVerdict(
                    action="deny",
                    reason="PWD_UNKNOWN_ACCOUNT",
                    grace_remaining=0,
                    entry_allowed=False,
                )

            grace_remaining = self._grace_remaining(record)
            if record.must_change:
                return LoginVerdict(
                    action="change_required",
                    reason="PWD_RESET_REQUIRED",
                    grace_remaining=grace_remaining,
                    entry_allowed=True,
                )

            if self._is_expired(record, now):
                if grace_remaining > 0:
                    return LoginVerdict(
                        action="allow",
                        reason="PWD_EXPIRED_GRACE",
                        grace_remaining=grace_remaining,
                        entry_allowed=True,
                    )
                return LoginVerdict(
                    action="change_required",
                    reason="PWD_GRACE_EXHAUSTED",
                    grace_remaining=0,
                    entry_allowed=True,
                )

            return LoginVerdict(
                action="allow",
                reason="PWD_FRESH",
                grace_remaining=grace_remaining,
                entry_allowed=True,
            )

    def record_login(self, account: str, *, now: int) -> int:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        _validate_now(now)
        with self._lock:
            record = self._require_account(account)
            self._stats["logins"] += 1
            if (
                self._is_expired(record, now)
                and not record.must_change
                and record.grace_used < self.grace_logins
            ):
                record.grace_used += 1
            return self._grace_remaining(record)

    def admin_reset(self, account: str, *, digest: str, now: int) -> HistoryEntry:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        _validate_digest(digest)
        _validate_now(now)
        with self._lock:
            record = self._require_account(account)
            if any(entry.digest == digest for entry in record.history):
                self._stats["reused"] += 1
                raise PasswordPolicyError("PWD_REUSED", account)

            generation = record.generation + 1
            entry = HistoryEntry(
                generation=generation,
                digest=digest,
                created_at=now,
            )
            record.history.append(entry)
            record.generation = generation
            record.must_change = True
            record.grace_used = 0
            record.changed_at = now
            self._stats["resets"] += 1
            self._trim(record, self.history_depth)
            return entry

    def update_policy(self, *, history_depth: int | None = None,
                      max_age_days: int | None = None,
                      grace_logins: int | None = None) -> dict:
        with self._lock:
            new_depth = self.history_depth if history_depth is None else history_depth
            new_age = self.max_age_days if max_age_days is None else max_age_days
            new_grace = self.grace_logins if grace_logins is None else grace_logins
            _validate_policy_values(
                new_depth, new_age, new_grace, "PWD_POLICY_INVALID"
            )

            self.history_depth = new_depth
            self.max_age_days = new_age
            self.grace_logins = new_grace
            for record in self._accounts.values():
                self._trim(record, new_depth)
            return {
                "history_depth": self.history_depth,
                "max_age_days": self.max_age_days,
                "grace_logins": self.grace_logins,
            }

    def history_of(self, account: str) -> tuple:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        with self._lock:
            return tuple(self._require_account(account).history)

    def account_state(self, account: str, *, now: int) -> AccountState:
        _validate_account(account, "PWD_INVALID_ACCOUNT")
        _validate_now(now)
        with self._lock:
            record = self._require_account(account)
            return AccountState(
                account=account,
                generation=record.generation,
                history_size=len(record.history),
                must_change=record.must_change,
                expired=self._is_expired(record, now),
                grace_used=record.grace_used,
                changed_at=record.changed_at,
            )

    def snapshot(self) -> dict:
        with self._lock:
            accounts = {}
            for account, record in self._accounts.items():
                accounts[account] = {
                    "generation": record.generation,
                    "history": [
                        {
                            "generation": entry.generation,
                            "digest": entry.digest,
                            "created_at": entry.created_at,
                        }
                        for entry in record.history
                    ],
                    "must_change": record.must_change,
                    "grace_used": record.grace_used,
                    "changed_at": record.changed_at,
                }
            return {
                "version": _SNAPSHOT_VERSION,
                "policy": {
                    "history_depth": self.history_depth,
                    "max_age_days": self.max_age_days,
                    "grace_logins": self.grace_logins,
                },
                "accounts": accounts,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                policy, accounts, stats = self._decode_snapshot(state)
            except PasswordPolicyError:
                raise
            except Exception as exc:
                raise PasswordPolicyError("PWD_SNAPSHOT_INVALID", repr(exc)) from exc

            self.history_depth = policy["history_depth"]
            self.max_age_days = policy["max_age_days"]
            self.grace_logins = policy["grace_logins"]
            self._accounts = accounts
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _require_account(self, account: str) -> _AccountRecord:
        record = self._accounts.get(account)
        if record is None:
            raise PasswordPolicyError("PWD_UNKNOWN_ACCOUNT", account)
        return record

    def _is_expired(self, record: _AccountRecord, now: int) -> bool:
        return now >= record.changed_at + self.max_age_days * _DAY_SECONDS

    def _grace_remaining(self, record: _AccountRecord) -> int:
        return max(0, self.grace_logins - record.grace_used)

    def _trim(self, record: _AccountRecord, depth: int) -> None:
        excess = len(record.history) - depth
        if excess > 0:
            del record.history[:excess]
            self._stats["trimmed"] += excess

    @staticmethod
    def _snapshot_invalid(detail: object) -> PasswordPolicyError:
        return PasswordPolicyError("PWD_SNAPSHOT_INVALID", detail)

    def _decode_snapshot(
        self, state: object
    ) -> tuple[dict[str, int], dict[str, _AccountRecord], dict[str, int]]:
        if not isinstance(state, dict):
            raise self._snapshot_invalid("state")
        if set(state) != {"version", "policy", "accounts", "stats"}:
            raise self._snapshot_invalid("top-level keys")
        if not _is_int(state["version"]) or state["version"] != _SNAPSHOT_VERSION:
            raise self._snapshot_invalid("version")

        policy_state = state["policy"]
        if not isinstance(policy_state, dict):
            raise self._snapshot_invalid("policy")
        if set(policy_state) != {"history_depth", "max_age_days", "grace_logins"}:
            raise self._snapshot_invalid("policy keys")
        try:
            _validate_policy_values(
                policy_state["history_depth"],
                policy_state["max_age_days"],
                policy_state["grace_logins"],
                "PWD_SNAPSHOT_INVALID",
            )
        except PasswordPolicyError as exc:
            raise self._snapshot_invalid(exc.detail) from exc
        policy = {
            "history_depth": policy_state["history_depth"],
            "max_age_days": policy_state["max_age_days"],
            "grace_logins": policy_state["grace_logins"],
        }

        accounts_state = state["accounts"]
        if not isinstance(accounts_state, dict):
            raise self._snapshot_invalid("accounts")
        accounts: dict[str, _AccountRecord] = {}
        retained_after_enrollment = 0
        for account, account_state in accounts_state.items():
            if not isinstance(account, str) or not account:
                raise self._snapshot_invalid("account name")
            if not isinstance(account_state, dict):
                raise self._snapshot_invalid(f"account {account}")
            expected_account_keys = {
                "generation",
                "history",
                "must_change",
                "grace_used",
                "changed_at",
            }
            if set(account_state) != expected_account_keys:
                raise self._snapshot_invalid(f"account {account} keys")

            generation = account_state["generation"]
            history_state = account_state["history"]
            must_change = account_state["must_change"]
            grace_used = account_state["grace_used"]
            changed_at = account_state["changed_at"]
            if not _is_int(generation) or generation < 1:
                raise self._snapshot_invalid(f"account {account} generation")
            if not isinstance(history_state, list) or not history_state:
                raise self._snapshot_invalid(f"account {account} history")
            if len(history_state) > policy["history_depth"]:
                raise self._snapshot_invalid(f"account {account} history depth")
            if type(must_change) is not bool:
                raise self._snapshot_invalid(f"account {account} must_change")
            if not _is_int(grace_used) or grace_used < 0:
                raise self._snapshot_invalid(f"account {account} grace_used")
            if not _is_int(changed_at) or changed_at < 0:
                raise self._snapshot_invalid(f"account {account} changed_at")

            history: list[HistoryEntry] = []
            for index, entry_state in enumerate(history_state):
                if not isinstance(entry_state, dict):
                    raise self._snapshot_invalid(
                        f"account {account} history entry {index}"
                    )
                if set(entry_state) != {"generation", "digest", "created_at"}:
                    raise self._snapshot_invalid(
                        f"account {account} history entry {index} keys"
                    )
                entry_generation = entry_state["generation"]
                entry_digest = entry_state["digest"]
                created_at = entry_state["created_at"]
                expected_generation = generation - len(history_state) + 1 + index
                if (
                    not _is_int(entry_generation)
                    or entry_generation != expected_generation
                ):
                    raise self._snapshot_invalid(
                        f"account {account} history generation {index}"
                    )
                try:
                    _validate_digest(entry_digest, "PWD_SNAPSHOT_INVALID")
                except PasswordPolicyError as exc:
                    raise self._snapshot_invalid(exc.detail) from exc
                if not _is_int(created_at) or created_at < 0:
                    raise self._snapshot_invalid(
                        f"account {account} history time {index}"
                    )
                history.append(
                    HistoryEntry(
                        generation=entry_generation,
                        digest=entry_digest,
                        created_at=created_at,
                    )
                )

            if history[-1].generation != generation:
                raise self._snapshot_invalid(f"account {account} current generation")
            if changed_at != history[-1].created_at:
                raise self._snapshot_invalid(f"account {account} changed_at")
            if len({entry.digest for entry in history}) != len(history):
                raise self._snapshot_invalid(f"account {account} duplicate digest")

            accounts[account] = _AccountRecord(
                generation=generation,
                history=history,
                must_change=must_change,
                grace_used=grace_used,
                changed_at=changed_at,
            )
            retained_after_enrollment += len(history) - 1

        stats_state = state["stats"]
        if not isinstance(stats_state, dict):
            raise self._snapshot_invalid("stats")
        if set(stats_state) != set(_STATS_KEYS):
            raise self._snapshot_invalid("stats keys")
        stats = {}
        for key in _STATS_KEYS:
            value = stats_state[key]
            if not _is_int(value) or value < 0:
                raise self._snapshot_invalid(f"stats {key}")
            stats[key] = value

        if stats["enrolled"] != len(accounts):
            raise self._snapshot_invalid("enrolled count")
        if stats["changed"] + stats["resets"] != (
            retained_after_enrollment + stats["trimmed"]
        ):
            raise self._snapshot_invalid("history counters")

        return policy, accounts, stats
