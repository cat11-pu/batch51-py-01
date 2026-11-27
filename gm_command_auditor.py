"""GM command auditor: role gate, two-person approval, dry run, rollback plan."""

from __future__ import annotations

import threading
from dataclasses import dataclass

COMMAND_KINDS = ("grant_item", "ban_account", "mail_batch", "reset_quest")
ROLES = ("gm_operator", "gm_approver")
MAX_LOG = 1000
RETENTION_MS = 86_400_000


class GmError(ValueError):
    """Raised when a command request is malformed or out of order."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class GmPermissionError(PermissionError):
    """Raised when the operator or the reviewer is not allowed to proceed."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CommandSpec:
    """The registered shape of one privileged command."""

    command_id: str
    required_role: str
    kind: str
    max_targets: int


@dataclass(frozen=True)
class CommandRequest:
    """One submitted command request and its approval state."""

    request_id: str
    command_id: str
    operator: str
    reviewer: str
    params: tuple
    targets: tuple
    reason: str
    status: str
    at_ms: int


class GmCommandAuditor:
    """Gate, rehearse, execute and roll back privileged backend commands."""

    def __init__(self, *, max_log: int = MAX_LOG,
                 retention_ms: int = RETENTION_MS) -> None:
        self.max_log = max_log
        self.retention_ms = retention_ms
        self._lock = threading.RLock()

    def register_command(self, command_id, *, required_role, kind, max_targets=1):
        """Register one privileged command and return its normalised spec."""
        raise NotImplementedError

    def grant_role(self, principal, role):
        """Give one principal an operator or approver role."""
        raise NotImplementedError

    def submit(self, request_id, command_id, *, operator, reviewer, params,
               targets, reason, at_ms):
        """Submit a command request and return its initial state."""
        raise NotImplementedError

    def authorize(self, request_id, *, at_ms):
        """Approve a pending request after the second-person check."""
        raise NotImplementedError

    def dry_run(self, request_id, *, at_ms):
        """Rehearse an approved request and report what it would change."""
        raise NotImplementedError

    def execute(self, request_id, *, at_ms):
        """Execute an approved request once and return applied and failed targets."""
        raise NotImplementedError

    def rollback_plan(self, request_id):
        """Return the compensation operations for the targets that did take effect."""
        raise NotImplementedError

    def audit_log(self, *, request_id=None, limit=None):
        """Return audit entries oldest first, optionally filtered and truncated."""
        raise NotImplementedError

    def request_of(self, request_id):
        """Return the stored request record."""
        raise NotImplementedError

    def pending_approvals(self):
        """Return the request ids still waiting for a reviewer."""
        raise NotImplementedError

    def snapshot(self):
        """Return a detached state dictionary for the whole auditor."""
        raise NotImplementedError

    def restore(self, state):
        """Replace the auditor with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self):
        """Return request, execution and log counters."""
        raise NotImplementedError
