"""Account identifier change guard: dual confirmation, hold window and reservation."""

from __future__ import annotations

import copy
import re
import secrets
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

    _SNAPSHOT_VERSION = 1
    _STAT_KEYS = (
        "accounts",
        "requests_initiated",
        "changes_committed",
        "changes_rolled_back",
        "holds_released",
        "confirmations",
    )
    _SNAPSHOT_KEYS = {
        "version",
        "next_request",
        "accounts",
        "changes",
        "holds",
        "stats",
    }
    _ACCOUNT_FIELDS = {
        "account_id",
        "identifier",
        "disabled",
        "pending_request",
        "created_at",
    }
    _CHANGE_FIELDS = {
        "request_id",
        "account_id",
        "old_identifier",
        "new_identifier",
        "state",
        "old_confirmed",
        "new_confirmed",
        "created_at",
        "expires_at",
        "committed_at",
        "codes",
    }
    _HOLD_FIELDS = {
        "identifier",
        "account_id",
        "request_id",
        "new_identifier",
        "created_at",
        "expires_at",
    }
    _IN_FLIGHT_STATES = {"awaiting_old", "awaiting_new", "awaiting_commit"}
    _TERMINAL_STATES = {"committed", "rolled_back", "expired"}
    _ALL_STATES = _IN_FLIGHT_STATES | _TERMINAL_STATES
    _REQUEST_ID_RE = re.compile(r"^chg-(\d+)$")

    def __init__(self, *, hold_ticks: int = 500, request_ttl: int = 300) -> None:
        self.hold_ticks = hold_ticks
        self.request_ttl = request_ttl
        self._lock = threading.RLock()
        self._accounts: dict[str, dict] = {}
        self._changes: dict[str, dict] = {}
        self._holds: dict[str, dict] = {}
        self._next_request = 1
        self._stats = {
            "requests_initiated": 0,
            "changes_committed": 0,
            "changes_rolled_back": 0,
            "holds_released": 0,
            "confirmations": 0,
        }

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _normalize_identifier(identifier: object) -> str:
        if not isinstance(identifier, str):
            raise IdentifierError("IDENTIFIER_INVALID", {"identifier": identifier})
        normalized = identifier.strip().lower()
        if not normalized:
            raise IdentifierError("IDENTIFIER_INVALID", {"identifier": identifier})
        return normalized

    @staticmethod
    def _validate_account_id(account_id: object) -> str:
        if not isinstance(account_id, str) or not account_id.strip():
            raise IdentifierError("IDENTIFIER_INVALID", {"account_id": account_id})
        return account_id

    @staticmethod
    def _account_view(record: dict) -> AccountView:
        return AccountView(
            account_id=record["account_id"],
            identifier=record["identifier"],
            disabled=record["disabled"],
            pending_request=record["pending_request"],
            created_at=record["created_at"],
        )

    @staticmethod
    def _change_view(record: dict) -> ChangeView:
        return ChangeView(
            request_id=record["request_id"],
            account_id=record["account_id"],
            old_identifier=record["old_identifier"],
            new_identifier=record["new_identifier"],
            state=record["state"],
            old_confirmed=record["old_confirmed"],
            new_confirmed=record["new_confirmed"],
            created_at=record["created_at"],
            expires_at=record["expires_at"],
            committed_at=record["committed_at"],
        )

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> IdentifierError:
        return IdentifierError("CHANGE_SNAPSHOT_INVALID", detail)

    def _require_account_locked(self, account_id: str) -> dict:
        record = (
            self._accounts.get(account_id)
            if isinstance(account_id, str)
            else None
        )
        if record is None:
            raise IdentifierError("ACCOUNT_UNKNOWN", {"account_id": account_id})
        return record

    def _require_change_locked(self, request_id: str) -> dict:
        record = (
            self._changes.get(request_id)
            if isinstance(request_id, str)
            else None
        )
        if record is None:
            raise IdentifierError("CHANGE_UNKNOWN", {"request_id": request_id})
        return record

    def _expire_change_locked(self, change: dict) -> None:
        if change["state"] not in self._IN_FLIGHT_STATES:
            return
        change["state"] = "expired"
        account = self._accounts.get(change["account_id"])
        if account is not None and account["pending_request"] == change["request_id"]:
            account["pending_request"] = None

    def _expire_if_due_locked(self, change: dict, now: int) -> bool:
        if change["state"] in self._IN_FLIGHT_STATES and now >= change["expires_at"]:
            self._expire_change_locked(change)
            return True
        return change["state"] == "expired"

    def _discard_expired_hold_locked(self, identifier: str, now: int) -> None:
        hold = self._holds.get(identifier)
        if hold is not None and now >= hold["expires_at"]:
            del self._holds[identifier]

    def _identifier_owned_locked(self, identifier: str) -> str | None:
        for account_id, account in self._accounts.items():
            if account["identifier"] == identifier:
                return account_id
        return None

    def _identifier_in_use_locked(self, identifier: str, now: int) -> bool:
        if self._identifier_owned_locked(identifier) is not None:
            return True
        self._discard_expired_hold_locked(identifier, now)
        return identifier in self._holds

    @staticmethod
    def _make_code(other: str | None = None) -> str:
        while True:
            code = f"{secrets.randbelow(900000) + 100000:06d}"
            if code != other:
                return code

    @staticmethod
    def _codes_equal(candidate: object, expected: str) -> bool:
        if not isinstance(candidate, str):
            return False
        return secrets.compare_digest(
            candidate.encode("utf-8"), expected.encode("utf-8")
        )

    def create_account(self, account_id: str, identifier: str, *, now: int) -> AccountView:
        with self._lock:
            account_id = self._validate_account_id(account_id)
            normalized = self._normalize_identifier(identifier)
            if account_id in self._accounts:
                raise IdentifierError(
                    "IDENTIFIER_TAKEN", {"account_id": account_id}
                )
            self._discard_expired_hold_locked(normalized, now)
            if normalized in self._holds or self._identifier_owned_locked(normalized):
                raise IdentifierError(
                    "IDENTIFIER_TAKEN", {"identifier": normalized}
                )
            record = {
                "account_id": account_id,
                "identifier": normalized,
                "disabled": False,
                "pending_request": None,
                "created_at": now,
            }
            self._accounts[account_id] = record
            return self._account_view(record)

    def initiate_change(self, account_id: str, new_identifier: str, *,
                        now: int) -> ChangeView:
        with self._lock:
            account = self._require_account_locked(account_id)
            normalized = self._normalize_identifier(new_identifier)

            pending_id = account["pending_request"]
            if pending_id is not None:
                pending = self._changes.get(pending_id)
                if pending is None:
                    account["pending_request"] = None
                elif self._expire_if_due_locked(pending, now):
                    account["pending_request"] = None
                elif pending["state"] in self._IN_FLIGHT_STATES:
                    raise IdentifierError(
                        "CHANGE_IN_FLIGHT",
                        {"account_id": account_id, "request_id": pending_id},
                    )
                else:
                    account["pending_request"] = None

            if account["disabled"]:
                raise IdentifierError(
                    "ACCOUNT_DISABLED", {"account_id": account_id}
                )

            if normalized == account["identifier"]:
                raise IdentifierError(
                    "IDENTIFIER_TAKEN", {"identifier": normalized}
                )

            old_code = self._make_code()
            new_code = self._make_code(old_code)
            request_id = f"chg-{self._next_request:04d}"
            change = {
                "request_id": request_id,
                "account_id": account_id,
                "old_identifier": account["identifier"],
                "new_identifier": normalized,
                "state": "awaiting_old",
                "old_confirmed": False,
                "new_confirmed": False,
                "created_at": now,
                "expires_at": now + self.request_ttl,
                "committed_at": None,
                "codes": {"old": old_code, "new": new_code},
            }
            self._changes[request_id] = change
            self._next_request += 1
            account["pending_request"] = request_id
            self._stats["requests_initiated"] += 1
            return self._change_view(change)

    def challenge_codes(self, request_id: str) -> dict:
        with self._lock:
            change = self._require_change_locked(request_id)
            return dict(change["codes"])

    def confirm_old(self, request_id: str, code: str, *, now: int) -> ChangeView:
        with self._lock:
            change = self._require_change_locked(request_id)
            if self._expire_if_due_locked(change, now):
                raise IdentifierError(
                    "CHANGE_EXPIRED", {"request_id": request_id}
                )

            state = change["state"]
            if state == "awaiting_old":
                if not self._codes_equal(code, change["codes"]["old"]):
                    raise IdentifierError(
                        "CHANGE_BAD_CODE",
                        {"request_id": request_id, "side": "old"},
                    )
                change["old_confirmed"] = True
                change["state"] = "awaiting_new"
                self._stats["confirmations"] += 1
                return self._change_view(change)

            if state in {"awaiting_new", "awaiting_commit"} and change["old_confirmed"]:
                if not self._codes_equal(code, change["codes"]["old"]):
                    raise IdentifierError(
                        "CHANGE_BAD_CODE",
                        {"request_id": request_id, "side": "old"},
                    )
                return self._change_view(change)

            raise IdentifierError(
                "CHANGE_STEP_OUT_OF_ORDER", {"request_id": request_id}
            )

    def confirm_new(self, request_id: str, code: str, *, now: int) -> ChangeView:
        with self._lock:
            change = self._require_change_locked(request_id)
            if self._expire_if_due_locked(change, now):
                raise IdentifierError(
                    "CHANGE_EXPIRED", {"request_id": request_id}
                )

            if change["state"] == "awaiting_old":
                raise IdentifierError(
                    "CHANGE_STEP_OUT_OF_ORDER", {"request_id": request_id}
                )
            if not change["old_confirmed"]:
                raise IdentifierError(
                    "CHANGE_STEP_OUT_OF_ORDER", {"request_id": request_id}
                )

            if change["state"] == "awaiting_new":
                if not self._codes_equal(code, change["codes"]["new"]):
                    raise IdentifierError(
                        "CHANGE_BAD_CODE",
                        {"request_id": request_id, "side": "new"},
                    )
                change["new_confirmed"] = True
                change["state"] = "awaiting_commit"
                self._stats["confirmations"] += 1
                return self._change_view(change)

            if change["state"] == "awaiting_commit" and change["new_confirmed"]:
                if not self._codes_equal(code, change["codes"]["new"]):
                    raise IdentifierError(
                        "CHANGE_BAD_CODE",
                        {"request_id": request_id, "side": "new"},
                    )
                return self._change_view(change)

            raise IdentifierError(
                "CHANGE_STEP_OUT_OF_ORDER", {"request_id": request_id}
            )

    def commit(self, request_id: str, *, now: int) -> ChangeView:
        with self._lock:
            change = self._require_change_locked(request_id)
            if self._expire_if_due_locked(change, now):
                raise IdentifierError(
                    "CHANGE_EXPIRED", {"request_id": request_id}
                )
            if (
                change["state"] != "awaiting_commit"
                or not change["old_confirmed"]
                or not change["new_confirmed"]
            ):
                raise IdentifierError(
                    "CHANGE_INCOMPLETE", {"request_id": request_id}
                )

            account = self._require_account_locked(change["account_id"])
            if account["disabled"]:
                raise IdentifierError(
                    "ACCOUNT_DISABLED", {"account_id": account["account_id"]}
                )

            new_identifier = change["new_identifier"]
            if self._identifier_in_use_locked(new_identifier, now):
                raise IdentifierError(
                    "IDENTIFIER_RESERVED", {"identifier": new_identifier}
                )

            old_identifier = change["old_identifier"]
            account["identifier"] = new_identifier
            account["pending_request"] = None
            change["state"] = "committed"
            change["committed_at"] = now
            self._holds[old_identifier] = {
                "identifier": old_identifier,
                "account_id": account["account_id"],
                "request_id": request_id,
                "new_identifier": new_identifier,
                "created_at": now,
                "expires_at": now + self.hold_ticks,
            }
            self._stats["changes_committed"] += 1
            return self._change_view(change)

    def rollback(self, request_id: str, *, now: int) -> ChangeView:
        with self._lock:
            change = self._require_change_locked(request_id)
            if change["state"] != "committed":
                raise IdentifierError(
                    "CHANGE_NOT_COMMITTED", {"request_id": request_id}
                )

            account = self._require_account_locked(change["account_id"])
            old_identifier = change["old_identifier"]
            old_hold = self._holds.get(old_identifier)
            if old_hold is not None and old_hold["request_id"] == request_id:
                del self._holds[old_identifier]

            owner = self._identifier_owned_locked(old_identifier)
            if owner is not None and owner != account["account_id"]:
                raise IdentifierError(
                    "IDENTIFIER_RESERVED", {"identifier": old_identifier}
                )
            if old_identifier in self._holds:
                raise IdentifierError(
                    "IDENTIFIER_RESERVED", {"identifier": old_identifier}
                )

            account["identifier"] = old_identifier
            account["pending_request"] = None
            change["state"] = "rolled_back"
            self._stats["changes_rolled_back"] += 1
            return self._change_view(change)

    def release_hold(self, identifier: str, *, now: int) -> int:
        with self._lock:
            try:
                normalized = self._normalize_identifier(identifier)
            except IdentifierError:
                return 0
            hold = self._holds.get(normalized)
            if hold is None or now < hold["expires_at"]:
                return 0
            del self._holds[normalized]
            self._stats["holds_released"] += 1
            return 1

    def resolve_login(self, identifier: str, *, now: int) -> LoginResolution:
        with self._lock:
            try:
                normalized = self._normalize_identifier(identifier)
            except IdentifierError:
                return LoginResolution("unknown", None, None)

            account_id = self._identifier_owned_locked(normalized)
            if account_id is not None:
                account = self._accounts[account_id]
                status = "disabled" if account["disabled"] else "ok"
                return LoginResolution(status, account_id, None)

            hold = self._holds.get(normalized)
            if hold is not None:
                if now >= hold["expires_at"]:
                    del self._holds[normalized]
                else:
                    account = self._accounts.get(hold["account_id"])
                    if account is not None:
                        if account["disabled"]:
                            return LoginResolution(
                                "disabled", account["account_id"], None
                            )
                        return LoginResolution(
                            "redirect",
                            account["account_id"],
                            account["identifier"],
                        )
            return LoginResolution("unknown", None, None)

    def disable_account(self, account_id: str, *, now: int) -> AccountView:
        with self._lock:
            account = self._require_account_locked(account_id)
            account["disabled"] = True
            return self._account_view(account)

    def enable_account(self, account_id: str, *, now: int) -> AccountView:
        with self._lock:
            account = self._require_account_locked(account_id)
            if account["disabled"]:
                pending_id = account["pending_request"]
                if pending_id is not None:
                    pending = self._changes.get(pending_id)
                    if pending is not None:
                        self._expire_change_locked(pending)
                    account["pending_request"] = None
            account["disabled"] = False
            return self._account_view(account)

    def account(self, account_id: str) -> AccountView:
        with self._lock:
            return self._account_view(self._require_account_locked(account_id))

    def change(self, request_id: str) -> ChangeView:
        with self._lock:
            return self._change_view(self._require_change_locked(request_id))

    def pending_change(self, account_id: str) -> ChangeView | None:
        with self._lock:
            account = self._require_account_locked(account_id)
            pending_id = account["pending_request"]
            if pending_id is None:
                return None
            pending = self._changes.get(pending_id)
            if pending is None or pending["state"] not in self._IN_FLIGHT_STATES:
                account["pending_request"] = None
                return None
            return self._change_view(pending)

    def snapshot(self) -> dict:
        with self._lock:
            stats = {key: 0 for key in self._STAT_KEYS}
            stats["accounts"] = len(self._accounts)
            for key in self._STAT_KEYS:
                if key != "accounts":
                    stats[key] = self._stats[key]
            return copy.deepcopy(
                {
                    "version": self._SNAPSHOT_VERSION,
                    "next_request": self._next_request,
                    "accounts": self._accounts,
                    "changes": self._changes,
                    "holds": self._holds,
                    "stats": stats,
                }
            )

    def _restore_locked(self, state: dict) -> None:
        with self._lock:
            try:
                incoming = copy.deepcopy(state)
            except Exception as exc:
                raise self._snapshot_invalid({"reason": "state is not copyable"}) from exc

            if not isinstance(incoming, dict):
                raise self._snapshot_invalid({"reason": "state must be a dict"})
            if set(incoming) != self._SNAPSHOT_KEYS:
                raise self._snapshot_invalid({"reason": "snapshot keys are invalid"})
            if (
                not self._is_int(incoming.get("version"))
                or incoming["version"] != self._SNAPSHOT_VERSION
            ):
                raise self._snapshot_invalid({"reason": "version is invalid"})
            if (
                not self._is_int(incoming.get("next_request"))
                or incoming["next_request"] < 1
            ):
                raise self._snapshot_invalid({"reason": "next_request is invalid"})
            if not isinstance(incoming.get("accounts"), dict):
                raise self._snapshot_invalid({"reason": "accounts must be a dict"})
            if not isinstance(incoming.get("changes"), dict):
                raise self._snapshot_invalid({"reason": "changes must be a dict"})
            if not isinstance(incoming.get("holds"), dict):
                raise self._snapshot_invalid({"reason": "holds must be a dict"})
            if not isinstance(incoming.get("stats"), dict):
                raise self._snapshot_invalid({"reason": "stats must be a dict"})
            if set(incoming["stats"]) != set(self._STAT_KEYS):
                raise self._snapshot_invalid({"reason": "stats keys are invalid"})

            accounts: dict[str, dict] = {}
            identifiers: set[str] = set()
            for account_id, raw in incoming["accounts"].items():
                if not isinstance(account_id, str) or not account_id.strip():
                    raise self._snapshot_invalid({"reason": "account id is invalid"})
                if not isinstance(raw, dict) or set(raw) != self._ACCOUNT_FIELDS:
                    raise self._snapshot_invalid(
                        {"reason": "account record is invalid", "account_id": account_id}
                    )
                if raw["account_id"] != account_id:
                    raise self._snapshot_invalid(
                        {"reason": "account id mismatch", "account_id": account_id}
                    )
                identifier = raw["identifier"]
                try:
                    normalized = self._normalize_identifier(identifier)
                except IdentifierError as exc:
                    raise self._snapshot_invalid(
                        {"reason": "account identifier is invalid", "account_id": account_id}
                    ) from exc
                if normalized != identifier or identifier in identifiers:
                    raise self._snapshot_invalid(
                        {"reason": "account identifier is not unique", "account_id": account_id}
                    )
                identifiers.add(identifier)
                if not isinstance(raw["disabled"], bool):
                    raise self._snapshot_invalid(
                        {"reason": "disabled must be boolean", "account_id": account_id}
                    )
                pending_request = raw["pending_request"]
                if pending_request is not None and not isinstance(pending_request, str):
                    raise self._snapshot_invalid(
                        {"reason": "pending_request is invalid", "account_id": account_id}
                    )
                if not self._is_int(raw["created_at"]):
                    raise self._snapshot_invalid(
                        {"reason": "created_at is invalid", "account_id": account_id}
                    )
                accounts[account_id] = {
                    "account_id": account_id,
                    "identifier": identifier,
                    "disabled": raw["disabled"],
                    "pending_request": pending_request,
                    "created_at": raw["created_at"],
                }

            changes: dict[str, dict] = {}
            max_request_number = 0
            expected_flags = {
                "awaiting_old": (False, False),
                "awaiting_new": (True, False),
                "awaiting_commit": (True, True),
                "committed": (True, True),
                "rolled_back": (True, True),
            }
            for request_id, raw in incoming["changes"].items():
                if not isinstance(request_id, str):
                    raise self._snapshot_invalid({"reason": "request id is invalid"})
                match = self._REQUEST_ID_RE.match(request_id)
                if match is None:
                    raise self._snapshot_invalid(
                        {"reason": "request id is invalid", "request_id": request_id}
                    )
                if not isinstance(raw, dict) or set(raw) != self._CHANGE_FIELDS:
                    raise self._snapshot_invalid(
                        {"reason": "change record is invalid", "request_id": request_id}
                    )
                if raw["request_id"] != request_id:
                    raise self._snapshot_invalid(
                        {"reason": "request id mismatch", "request_id": request_id}
                    )
                account_id = raw["account_id"]
                if account_id not in accounts:
                    raise self._snapshot_invalid(
                        {"reason": "change account is unknown", "request_id": request_id}
                    )
                old_identifier = raw["old_identifier"]
                new_identifier = raw["new_identifier"]
                try:
                    old_normalized = self._normalize_identifier(old_identifier)
                    new_normalized = self._normalize_identifier(new_identifier)
                except IdentifierError as exc:
                    raise self._snapshot_invalid(
                        {"reason": "change identifier is invalid", "request_id": request_id}
                    ) from exc
                if (
                    old_normalized != old_identifier
                    or new_normalized != new_identifier
                    or old_identifier == new_identifier
                ):
                    raise self._snapshot_invalid(
                        {"reason": "change identifiers are invalid", "request_id": request_id}
                    )
                change_state = raw["state"]
                if change_state not in self._ALL_STATES:
                    raise self._snapshot_invalid(
                        {"reason": "change state is invalid", "request_id": request_id}
                    )
                if not isinstance(raw["old_confirmed"], bool) or not isinstance(
                    raw["new_confirmed"], bool
                ):
                    raise self._snapshot_invalid(
                        {"reason": "confirmation flags are invalid", "request_id": request_id}
                    )
                if change_state in expected_flags:
                    if (raw["old_confirmed"], raw["new_confirmed"]) != expected_flags[
                        change_state
                    ]:
                        raise self._snapshot_invalid(
                            {"reason": "confirmation flags do not match state",
                             "request_id": request_id}
                        )
                if not self._is_int(raw["created_at"]) or not self._is_int(
                    raw["expires_at"]
                ):
                    raise self._snapshot_invalid(
                        {"reason": "change times are invalid", "request_id": request_id}
                    )
                if raw["expires_at"] < raw["created_at"]:
                    raise self._snapshot_invalid(
                        {"reason": "change expiry is invalid", "request_id": request_id}
                    )
                committed_at = raw["committed_at"]
                if committed_at is not None and not self._is_int(committed_at):
                    raise self._snapshot_invalid(
                        {"reason": "committed_at is invalid", "request_id": request_id}
                    )
                if change_state in {"committed", "rolled_back"}:
                    if committed_at is None:
                        raise self._snapshot_invalid(
                            {"reason": "committed_at is required", "request_id": request_id}
                        )
                elif committed_at is not None:
                    raise self._snapshot_invalid(
                        {"reason": "committed_at is unexpected", "request_id": request_id}
                    )
                codes = raw["codes"]
                if not isinstance(codes, dict) or set(codes) != {"old", "new"}:
                    raise self._snapshot_invalid(
                        {"reason": "codes are invalid", "request_id": request_id}
                    )
                old_code = codes["old"]
                new_code = codes["new"]
                if (
                    not isinstance(old_code, str)
                    or not isinstance(new_code, str)
                    or len(old_code) != 6
                    or len(new_code) != 6
                    or not old_code.isdigit()
                    or not new_code.isdigit()
                    or old_code == new_code
                ):
                    raise self._snapshot_invalid(
                        {"reason": "codes are invalid", "request_id": request_id}
                    )
                max_request_number = max(max_request_number, int(match.group(1)))
                changes[request_id] = {
                    "request_id": request_id,
                    "account_id": account_id,
                    "old_identifier": old_identifier,
                    "new_identifier": new_identifier,
                    "state": change_state,
                    "old_confirmed": raw["old_confirmed"],
                    "new_confirmed": raw["new_confirmed"],
                    "created_at": raw["created_at"],
                    "expires_at": raw["expires_at"],
                    "committed_at": committed_at,
                    "codes": {"old": old_code, "new": new_code},
                }

            if incoming["next_request"] <= max_request_number:
                raise self._snapshot_invalid(
                    {"reason": "next_request would reuse a request id"}
                )

            for account_id, account in accounts.items():
                pending_id = account["pending_request"]
                if pending_id is None:
                    continue
                pending = changes.get(pending_id)
                if (
                    pending is None
                    or pending["account_id"] != account_id
                    or pending["state"] not in self._IN_FLIGHT_STATES
                ):
                    raise self._snapshot_invalid(
                        {"reason": "pending request is invalid", "account_id": account_id}
                    )
            for request_id, change in changes.items():
                if change["state"] in self._IN_FLIGHT_STATES:
                    account = accounts[change["account_id"]]
                    if account["pending_request"] != request_id:
                        raise self._snapshot_invalid(
                            {"reason": "in-flight request is not pending",
                             "request_id": request_id}
                        )

            holds: dict[str, dict] = {}
            held_requests: set[str] = set()
            for identifier, raw in incoming["holds"].items():
                try:
                    normalized = self._normalize_identifier(identifier)
                except IdentifierError as exc:
                    raise self._snapshot_invalid(
                        {"reason": "hold identifier is invalid"}
                    ) from exc
                if normalized != identifier:
                    raise self._snapshot_invalid(
                        {"reason": "hold identifier is not normalized"}
                    )
                if not isinstance(raw, dict) or set(raw) != self._HOLD_FIELDS:
                    raise self._snapshot_invalid(
                        {"reason": "hold record is invalid", "identifier": identifier}
                    )
                if raw["identifier"] != identifier:
                    raise self._snapshot_invalid(
                        {"reason": "hold identifier mismatch", "identifier": identifier}
                    )
                account_id = raw["account_id"]
                request_id = raw["request_id"]
                if account_id not in accounts or request_id not in changes:
                    raise self._snapshot_invalid(
                        {"reason": "hold reference is unknown", "identifier": identifier}
                    )
                request = changes[request_id]
                if (
                    request["account_id"] != account_id
                    or request["old_identifier"] != identifier
                    or request["state"] != "committed"
                    or request_id in held_requests
                ):
                    raise self._snapshot_invalid(
                        {"reason": "hold does not match its request",
                         "identifier": identifier}
                    )
                try:
                    hold_new = self._normalize_identifier(raw["new_identifier"])
                except IdentifierError as exc:
                    raise self._snapshot_invalid(
                        {"reason": "hold new identifier is invalid",
                         "identifier": identifier}
                    ) from exc
                if hold_new != raw["new_identifier"] or request["new_identifier"] != hold_new:
                    raise self._snapshot_invalid(
                        {"reason": "hold new identifier is invalid",
                         "identifier": identifier}
                    )
                if not self._is_int(raw["created_at"]) or not self._is_int(
                    raw["expires_at"]
                ):
                    raise self._snapshot_invalid(
                        {"reason": "hold times are invalid", "identifier": identifier}
                    )
                if raw["expires_at"] < raw["created_at"]:
                    raise self._snapshot_invalid(
                        {"reason": "hold expiry is invalid", "identifier": identifier}
                    )
                if identifier in identifiers:
                    raise self._snapshot_invalid(
                        {"reason": "hold identifier is still owned",
                         "identifier": identifier}
                    )
                held_requests.add(request_id)
                holds[identifier] = {
                    "identifier": identifier,
                    "account_id": account_id,
                    "request_id": request_id,
                    "new_identifier": hold_new,
                    "created_at": raw["created_at"],
                    "expires_at": raw["expires_at"],
                }

            stats: dict[str, int] = {}
            for key in self._STAT_KEYS:
                value = incoming["stats"][key]
                if not self._is_int(value) or value < 0:
                    raise self._snapshot_invalid(
                        {"reason": "stat is invalid", "stat": key}
                    )
                stats[key] = value
            if stats["accounts"] != len(accounts):
                raise self._snapshot_invalid(
                    {"reason": "account count is inconsistent"}
                )

            self._accounts = accounts
            self._changes = changes
            self._holds = holds
            self._next_request = incoming["next_request"]
            self._stats = {
                key: stats[key] for key in self._STAT_KEYS if key != "accounts"
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                self._restore_locked(state)
            except IdentifierError as exc:
                if exc.code == "CHANGE_SNAPSHOT_INVALID":
                    raise
                raise self._snapshot_invalid({"reason": "state is invalid"}) from exc
            except Exception as exc:
                raise self._snapshot_invalid({"reason": "state is invalid"}) from exc

    def stats(self) -> dict:
        with self._lock:
            return {
                "accounts": len(self._accounts),
                "requests_initiated": self._stats["requests_initiated"],
                "changes_committed": self._stats["changes_committed"],
                "changes_rolled_back": self._stats["changes_rolled_back"],
                "holds_released": self._stats["holds_released"],
                "confirmations": self._stats["confirmations"],
            }
