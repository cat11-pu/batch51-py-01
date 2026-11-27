"""Guardian recovery quorum with objection veto and login freeze."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


class GuardianError(ValueError):
    """Refusal raised by the guardian recovery quorum."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CaseView:
    case_id: str
    account: str
    status: str
    reason: str
    opened_at: int
    waiting_until: int
    approvals: int
    objections: int
    settled_at: int | None


@dataclass(frozen=True)
class ApprovalResult:
    accepted: bool
    code: str
    approvals: int
    threshold: int
    quorum_met: bool


@dataclass
class _Case:
    case_id: str
    account: str
    status: str
    reason: str
    opened_at: int
    waiting_until: int
    requested_by: str
    approvals: set[str] = field(default_factory=set)
    objections: int = 0
    objection_guardian: str | None = None
    objection_note: str = ""
    objection_at: int | None = None
    settled_at: int | None = None


@dataclass
class _Ticket:
    ticket_id: str
    case_id: str
    account: str
    guardian: str
    device_id: str
    at: int
    accepted: bool
    counted: bool
    valid: bool
    code: str


_STAT_KEYS = (
    "cases_opened",
    "approvals",
    "objections",
    "settled",
    "approved",
    "rejected",
    "cancelled",
)
_CASE_STATUSES = {"collecting", "voided", "approved", "rejected", "cancelled"}


class GuardianRecoveryQuorum:
    """Collect guardian countersignatures and settle account recovery cases."""

    def __init__(self, *, threshold: int = 2, wait_seconds: int = 86400,
                 max_guardians: int = 8) -> None:
        self.threshold = threshold
        self.wait_seconds = wait_seconds
        self.max_guardians = max_guardians
        self._lock = threading.RLock()
        self._guardians: dict[str, set[str]] = {}
        self._cases: dict[str, _Case] = {}
        self._tickets: dict[str, _Ticket] = {}
        self._epochs: dict[str, int] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def add_guardian(self, account: str, guardian: str) -> bool:
        with self._lock:
            members = self._guardians.setdefault(account, set())
            if guardian in members:
                return False
            if len(members) >= self.max_guardians:
                return False
            members.add(guardian)
            return True

    def remove_guardian(self, account: str, guardian: str) -> bool:
        with self._lock:
            members = self._guardians.get(account)
            if not members or guardian not in members:
                return False

            members.remove(guardian)
            if not members:
                self._guardians.pop(account, None)

            for case in self._cases.values():
                if case.account != account or case.status != "collecting":
                    continue
                if guardian not in case.approvals:
                    continue
                case.approvals.remove(guardian)
                for ticket in self._tickets.values():
                    if (ticket.case_id == case.case_id
                            and ticket.guardian == guardian
                            and ticket.counted):
                        ticket.valid = False
                        ticket.code = "GUARD_GUARDIAN_REMOVED"
            return True

    def guardians(self, account: str) -> tuple:
        with self._lock:
            return tuple(sorted(self._guardians.get(account, ())))

    def open_case(self, account: str, *, case_id: str, at: int,
                  requested_by: str | None = None) -> CaseView:
        with self._lock:
            if any(case.account == account and case.status == "collecting"
                   for case in self._cases.values()):
                raise GuardianError("GUARD_CASE_CONFLICT")
            if case_id in self._cases:
                raise GuardianError("GUARD_CASE_EXISTS")
            if len(self._guardians.get(account, ())) < self.threshold:
                raise GuardianError("GUARD_INSUFFICIENT_GUARDIANS")

            case = _Case(
                case_id=case_id,
                account=account,
                status="collecting",
                reason="",
                opened_at=at,
                waiting_until=at + self.wait_seconds,
                requested_by=account if requested_by is None else requested_by,
            )
            self._cases[case_id] = case
            self._stats["cases_opened"] += 1
            return self._view(case)

    def cast_approval(self, case_id: str, *, guardian: str, ticket_id: str,
                      device_id: str, at: int) -> ApprovalResult:
        with self._lock:
            case = self._require_case(case_id)

            if case.status != "collecting":
                code = ("GUARD_OBJECTED" if case.status == "voided"
                        else "GUARD_CASE_CLOSED")
                return self._approval_result(case, False, code)
            if guardian not in self._guardians.get(case.account, ()):
                return self._approval_result(case, False, "GUARD_NOT_GUARDIAN")
            if at >= case.waiting_until:
                return self._approval_result(case, False, "GUARD_WINDOW_CLOSED")
            if ticket_id in self._tickets:
                return self._approval_result(case, False, "GUARD_TICKET_REUSED")

            duplicate = guardian in case.approvals
            if not duplicate:
                case.approvals.add(guardian)
                self._stats["approvals"] += 1

            self._tickets[ticket_id] = _Ticket(
                ticket_id=ticket_id,
                case_id=case.case_id,
                account=case.account,
                guardian=guardian,
                device_id=device_id,
                at=at,
                accepted=True,
                counted=not duplicate,
                valid=not duplicate,
                code="GUARD_TICKET_ACCEPTED",
            )
            return self._approval_result(case, True, "GUARD_TICKET_ACCEPTED")

    def cast_objection(self, case_id: str, *, guardian: str, at: int,
                       note: str = "") -> CaseView:
        with self._lock:
            case = self._require_case(case_id)
            if case.status != "collecting":
                raise GuardianError(
                    "GUARD_OBJECTED" if case.status == "voided"
                    else "GUARD_CASE_CLOSED"
                )
            if guardian not in self._guardians.get(case.account, ()):
                raise GuardianError("GUARD_NOT_GUARDIAN")
            if at >= case.waiting_until:
                raise GuardianError("GUARD_WINDOW_CLOSED")

            case.status = "voided"
            case.reason = "GUARD_OBJECTED"
            case.approvals.clear()
            case.objections += 1
            case.objection_guardian = guardian
            case.objection_note = note
            case.objection_at = at
            self._stats["objections"] += 1
            for ticket in self._tickets.values():
                if ticket.case_id == case.case_id:
                    ticket.valid = False
            return self._view(case)

    def finalize_case(self, case_id: str, *, at: int) -> CaseView:
        with self._lock:
            case = self._require_case(case_id)

            if case.status == "voided":
                self._close(case, "rejected", "GUARD_OBJECTED", at)
                self._stats["settled"] += 1
                self._stats["rejected"] += 1
                return self._view(case)
            if case.status != "collecting":
                raise GuardianError("GUARD_CASE_CLOSED")
            if at < case.waiting_until:
                return self._view(case, reason="GUARD_WAIT_PENDING")

            self._discard_removed_approvals(case)
            if len(case.approvals) >= self.threshold:
                self._close(case, "approved", "GUARD_QUORUM_MET", at)
                self._stats["settled"] += 1
                self._epochs[case.account] = self.recovery_epoch(case.account) + 1
                self._stats["approved"] += 1
            else:
                self._close(case, "rejected", "GUARD_QUORUM_SHORT", at)
                self._stats["settled"] += 1
                self._stats["rejected"] += 1
            return self._view(case)

    def cancel_case(self, case_id: str, *, actor: str, at: int) -> CaseView:
        with self._lock:
            case = self._require_case(case_id)
            if actor != case.requested_by:
                raise GuardianError("GUARD_NOT_APPLICANT")
            if case.status != "collecting":
                raise GuardianError("GUARD_CASE_CLOSED")

            case.approvals.clear()
            for ticket in self._tickets.values():
                if ticket.case_id == case.case_id:
                    ticket.valid = False
            self._close(case, "cancelled", "GUARD_CANCELLED", at)
            self._stats["cancelled"] += 1
            return self._view(case)

    def case_state(self, case_id: str) -> CaseView:
        with self._lock:
            return self._view(self._require_case(case_id))

    def login_frozen(self, account: str, *, at: int) -> bool:
        with self._lock:
            return any(
                case.account == account
                and case.status == "collecting"
                and at >= case.opened_at
                for case in self._cases.values()
            )

    def recovery_epoch(self, account: str) -> int:
        with self._lock:
            return self._epochs.get(account, 0)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "guardians": {
                    account: sorted(members)
                    for account, members in self._guardians.items()
                },
                "cases": {
                    case_id: {
                        "case_id": case.case_id,
                        "account": case.account,
                        "status": case.status,
                        "reason": case.reason,
                        "opened_at": case.opened_at,
                        "waiting_until": case.waiting_until,
                        "requested_by": case.requested_by,
                        "approvals": sorted(case.approvals),
                        "objections": case.objections,
                        "objection_guardian": case.objection_guardian,
                        "objection_note": case.objection_note,
                        "objection_at": case.objection_at,
                        "settled_at": case.settled_at,
                    }
                    for case_id, case in self._cases.items()
                },
                "tickets": {
                    ticket_id: {
                        "ticket_id": ticket.ticket_id,
                        "case_id": ticket.case_id,
                        "account": ticket.account,
                        "guardian": ticket.guardian,
                        "device_id": ticket.device_id,
                        "at": ticket.at,
                        "accepted": ticket.accepted,
                        "counted": ticket.counted,
                        "valid": ticket.valid,
                        "code": ticket.code,
                    }
                    for ticket_id, ticket in self._tickets.items()
                },
                "epochs": dict(self._epochs),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                guardians, cases, tickets, epochs, stats = (
                    self._parse_snapshot(state)
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise GuardianError("GUARD_SNAPSHOT_INVALID", detail=str(exc))

            self._guardians = guardians
            self._cases = cases
            self._tickets = tickets
            self._epochs = epochs
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _require_case(self, case_id: str) -> _Case:
        case = self._cases.get(case_id)
        if case is None:
            raise GuardianError("GUARD_UNKNOWN_CASE")
        return case

    def _view(self, case: _Case, *, reason: str | None = None) -> CaseView:
        return CaseView(
            case_id=case.case_id,
            account=case.account,
            status=case.status,
            reason=case.reason if reason is None else reason,
            opened_at=case.opened_at,
            waiting_until=case.waiting_until,
            approvals=len(case.approvals),
            objections=case.objections,
            settled_at=case.settled_at,
        )

    def _approval_result(self, case: _Case, accepted: bool,
                         code: str) -> ApprovalResult:
        approvals = len(case.approvals)
        return ApprovalResult(
            accepted=accepted,
            code=code,
            approvals=approvals,
            threshold=self.threshold,
            quorum_met=approvals >= self.threshold,
        )

    def _close(self, case: _Case, status: str, reason: str, at: int) -> None:
        case.status = status
        case.reason = reason
        case.settled_at = at

    def _discard_removed_approvals(self, case: _Case) -> None:
        members = self._guardians.get(case.account, set())
        removed = case.approvals - members
        if not removed:
            return
        case.approvals.difference_update(removed)
        for ticket in self._tickets.values():
            if (ticket.case_id == case.case_id
                    and ticket.guardian in removed
                    and ticket.counted):
                ticket.valid = False
                ticket.code = "GUARD_GUARDIAN_REMOVED"

    def _parse_snapshot(self, state: dict):
        if not isinstance(state, dict):
            raise TypeError("snapshot must be a mapping")
        required = {"version", "guardians", "cases", "tickets", "epochs", "stats"}
        if set(state) != required:
            raise ValueError("snapshot keys do not match")
        if not _is_int(state["version"]) or state["version"] != 1:
            raise ValueError("unsupported snapshot version")

        raw_guardians = state["guardians"]
        if not isinstance(raw_guardians, dict):
            raise TypeError("guardians must be a mapping")
        guardians: dict[str, set[str]] = {}
        for account, names in raw_guardians.items():
            if not isinstance(account, str) or not isinstance(names, list):
                raise TypeError("invalid guardian registry entry")
            if len(names) > self.max_guardians:
                raise ValueError("too many guardians")
            if any(not isinstance(name, str) for name in names):
                raise TypeError("guardian names must be strings")
            if len(set(names)) != len(names):
                raise ValueError("duplicate guardian")
            guardians[account] = set(names)

        raw_cases = state["cases"]
        if not isinstance(raw_cases, dict):
            raise TypeError("cases must be a mapping")
        cases: dict[str, _Case] = {}
        open_accounts: set[str] = set()
        for key, raw in raw_cases.items():
            if not isinstance(key, str) or not isinstance(raw, dict):
                raise TypeError("invalid case entry")
            case_id = _required_str(raw, "case_id")
            if key != case_id:
                raise ValueError("case key does not match case_id")
            account = _required_str(raw, "account")
            status = _required_str(raw, "status")
            reason = _required_str(raw, "reason", allow_empty=True)
            if status not in _CASE_STATUSES:
                raise ValueError("invalid case status")
            opened_at = _required_int(raw, "opened_at")
            waiting_until = _required_int(raw, "waiting_until")
            if waiting_until < opened_at:
                raise ValueError("invalid waiting window")
            requested_by = _required_str(raw, "requested_by")
            approvals_raw = raw["approvals"]
            if not isinstance(approvals_raw, list):
                raise TypeError("case approvals must be a list")
            if any(not isinstance(name, str) for name in approvals_raw):
                raise TypeError("approval names must be strings")
            if len(set(approvals_raw)) != len(approvals_raw):
                raise ValueError("duplicate approval")
            objections = _required_int(raw, "objections")
            if objections < 0:
                raise ValueError("invalid objection count")
            objection_guardian = _optional_str(raw, "objection_guardian")
            objection_note = _required_str(raw, "objection_note", allow_empty=True)
            objection_at = _optional_int(raw, "objection_at")
            settled_at = _optional_int(raw, "settled_at")
            if status == "collecting":
                if account in open_accounts:
                    raise ValueError("multiple open cases for account")
                open_accounts.add(account)
                if not set(approvals_raw) <= guardians.get(account, set()):
                    raise ValueError("approval from non-guardian")
                if objections or objection_at is not None:
                    raise ValueError("collecting case has objection")
                if settled_at is not None:
                    raise ValueError("collecting case is settled")
            elif status != "voided" and settled_at is None:
                raise ValueError("closed case lacks settled_at")
            if status == "voided":
                if reason != "GUARD_OBJECTED" or objections != 1:
                    raise ValueError("invalid voided case")
                if objection_at is None or settled_at is not None:
                    raise ValueError("invalid voided case timestamps")
            elif status == "rejected" and reason == "GUARD_OBJECTED":
                if objections != 1 or objection_at is None:
                    raise ValueError("invalid objected case")
            elif objections or objection_at is not None:
                raise ValueError("unexpected objection data")
            cases[case_id] = _Case(
                case_id=case_id,
                account=account,
                status=status,
                reason=reason,
                opened_at=opened_at,
                waiting_until=waiting_until,
                requested_by=requested_by,
                approvals=set(approvals_raw),
                objections=objections,
                objection_guardian=objection_guardian,
                objection_note=objection_note,
                objection_at=objection_at,
                settled_at=settled_at,
            )

        raw_tickets = state["tickets"]
        if not isinstance(raw_tickets, dict):
            raise TypeError("tickets must be a mapping")
        tickets: dict[str, _Ticket] = {}
        valid_by_case: dict[str, set[str]] = {}
        for key, raw in raw_tickets.items():
            if not isinstance(key, str) or not isinstance(raw, dict):
                raise TypeError("invalid ticket entry")
            ticket_id = _required_str(raw, "ticket_id")
            if key != ticket_id:
                raise ValueError("ticket key does not match ticket_id")
            case_id = _required_str(raw, "case_id")
            case = cases.get(case_id)
            if case is None:
                raise ValueError("ticket references unknown case")
            account = _required_str(raw, "account")
            if account != case.account:
                raise ValueError("ticket account does not match case")
            guardian = _required_str(raw, "guardian")
            device_id = _required_str(raw, "device_id")
            at = _required_int(raw, "at")
            accepted = raw["accepted"]
            counted = raw["counted"]
            valid = raw["valid"]
            if not all(isinstance(value, bool)
                       for value in (accepted, counted, valid)):
                raise TypeError("ticket flags must be booleans")
            code = _required_str(raw, "code")
            if valid and not counted:
                raise ValueError("invalid ticket flags")
            if counted:
                if not accepted or at >= case.waiting_until:
                    raise ValueError("invalid counted ticket")
                if valid:
                    if (case.status in {"voided", "cancelled"}
                            or (case.status == "rejected"
                                and case.reason == "GUARD_OBJECTED")):
                        raise ValueError("valid ticket on closed case")
                    if (case.status == "collecting"
                            and guardian not in guardians.get(account, set())):
                        raise ValueError("valid ticket from removed guardian")
                    valid_by_case.setdefault(case_id, set()).add(guardian)
            tickets[ticket_id] = _Ticket(
                ticket_id=ticket_id,
                case_id=case_id,
                account=account,
                guardian=guardian,
                device_id=device_id,
                at=at,
                accepted=accepted,
                counted=counted,
                valid=valid,
                code=code,
            )

        for case_id, case in cases.items():
            if valid_by_case.get(case_id, set()) != case.approvals:
                raise ValueError("case approvals do not match tickets")

        raw_epochs = state["epochs"]
        if not isinstance(raw_epochs, dict):
            raise TypeError("epochs must be a mapping")
        epochs: dict[str, int] = {}
        for account, epoch in raw_epochs.items():
            if not isinstance(account, str) or not _is_int(epoch) or epoch < 0:
                raise ValueError("invalid recovery epoch")
            epochs[account] = epoch

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict):
            raise TypeError("stats must be a mapping")
        if not set(_STAT_KEYS) <= set(raw_stats):
            raise ValueError("missing stats counter")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                raise ValueError("invalid stats counter")
            stats[key] = value

        return guardians, cases, tickets, epochs, stats


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _required_int(mapping: dict, key: str) -> int:
    value = mapping[key]
    if not _is_int(value):
        raise TypeError(f"{key} must be an integer")
    return value


def _optional_int(mapping: dict, key: str) -> int | None:
    value = mapping[key]
    if value is not None and not _is_int(value):
        raise TypeError(f"{key} must be an integer or null")
    return value


def _required_str(mapping: dict, key: str, *, allow_empty: bool = True) -> str:
    value = mapping[key]
    if not isinstance(value, str) or (not allow_empty and not value):
        raise TypeError(f"{key} must be a string")
    return value


def _optional_str(mapping: dict, key: str) -> str | None:
    value = mapping[key]
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{key} must be a string or null")
    return value
