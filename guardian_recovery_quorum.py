"""Guardian recovery quorum with objection veto and login freeze."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class GuardianRecoveryQuorum:
    """Collect guardian countersignatures and settle account recovery cases."""

    def __init__(self, *, threshold: int = 2, wait_seconds: int = 86400,
                 max_guardians: int = 8) -> None:
        self.threshold = threshold
        self.wait_seconds = wait_seconds
        self.max_guardians = max_guardians
        self._lock = threading.RLock()

    def add_guardian(self, account: str, guardian: str) -> bool:
        raise NotImplementedError

    def remove_guardian(self, account: str, guardian: str) -> bool:
        raise NotImplementedError

    def guardians(self, account: str) -> tuple:
        raise NotImplementedError

    def open_case(self, account: str, *, case_id: str, at: int,
                  requested_by: str | None = None) -> CaseView:
        raise NotImplementedError

    def cast_approval(self, case_id: str, *, guardian: str, ticket_id: str,
                      device_id: str, at: int) -> ApprovalResult:
        raise NotImplementedError

    def cast_objection(self, case_id: str, *, guardian: str, at: int,
                       note: str = "") -> CaseView:
        raise NotImplementedError

    def finalize_case(self, case_id: str, *, at: int) -> CaseView:
        raise NotImplementedError

    def cancel_case(self, case_id: str, *, actor: str, at: int) -> CaseView:
        raise NotImplementedError

    def case_state(self, case_id: str) -> CaseView:
        raise NotImplementedError

    def login_frozen(self, account: str, *, at: int) -> bool:
        raise NotImplementedError

    def recovery_epoch(self, account: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
