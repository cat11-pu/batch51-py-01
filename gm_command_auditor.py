"""GM command auditor: role gate, two-person approval, dry run, rollback plan."""

from __future__ import annotations

import copy
import hashlib
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace

COMMAND_KINDS = ("grant_item", "ban_account", "mail_batch", "reset_quest")
ROLES = ("gm_operator", "gm_approver")
MAX_LOG = 1000
RETENTION_MS = 86_400_000

_REQUEST_STATUSES = ("pending_approval", "approved", "executed")
_LOG_PHASES = ("submitted", "authorized", "dry_run", "executed")
_STAT_KEYS = (
    "requests",
    "approved",
    "executed",
    "applied",
    "failed",
    "denied",
    "log_entries",
)
_SNAPSHOT_VERSION = 1


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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _freeze(value):
    """Take an immutable, detached copy of request parameters."""
    if isinstance(value, Mapping):
        return tuple((key, _freeze(item)) for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        items = [_freeze(item) for item in value]
        return tuple(sorted(items, key=repr))
    if isinstance(value, (str, bytes, int, float, bool, type(None))):
        return value
    try:
        return copy.deepcopy(value)
    except Exception:
        return repr(value)


def _canonical(value):
    """Create a stable value used for digests and target lock keys."""
    if isinstance(value, Mapping):
        items = [(_canonical(key), _canonical(item))
                 for key, item in value.items()]
        items.sort(key=repr)
        return ("map", tuple(items))
    if isinstance(value, (list, tuple)):
        return ("seq", tuple(_canonical(item) for item in value))
    if isinstance(value, (set, frozenset)):
        items = [_canonical(item) for item in value]
        items.sort(key=repr)
        return ("set", tuple(items))
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, (str, int, float, bool, type(None))):
        return (type(value).__name__, value)
    try:
        return ("object", type(value).__module__, type(value).__qualname__,
                repr(value))
    except Exception:
        return ("object", type(value).__module__, type(value).__qualname__)


def _fingerprint(command_id: str, params: object, targets: object) -> str:
    payload = _canonical(("gm-command", command_id, params, targets))
    return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()


def _targets_equal(left: object, right: object) -> bool:
    try:
        return bool(left == right)
    except Exception:
        return _canonical(left) == _canonical(right)


class GmCommandAuditor:
    """Gate, rehearse, execute and roll back privileged backend commands."""

    def __init__(self, *, max_log: int = MAX_LOG,
                 retention_ms: int = RETENTION_MS) -> None:
        if not _is_int(max_log) or max_log < 0:
            raise ValueError("max_log must be a non-negative integer")
        if not _is_int(retention_ms) or retention_ms < 0:
            raise ValueError("retention_ms must be a non-negative integer")
        self.max_log = max_log
        self.retention_ms = retention_ms
        self._lock = threading.RLock()
        self._commands: dict[str, CommandSpec] = {}
        self._roles: dict[str, set[str]] = {}
        self._requests: dict[str, CommandRequest] = {}
        self._logs: list[dict] = []
        self._next_seq = 1
        self._counters = {key: 0 for key in _STAT_KEYS}
        self._execution_results: dict[str, tuple[tuple, tuple]] = {}
        self._dry_run_digests: dict[str, str] = {}
        self._submitted_fingerprints: dict[str, str] = {}
        self._target_locks: dict[object, threading.RLock] = {}

    def register_command(self, command_id, *, required_role, kind, max_targets=1):
        """Register one privileged command and return its normalised spec."""
        with self._lock:
            if command_id in self._commands:
                raise GmError("GM_COMMAND_EXISTS", command_id)
            if (not isinstance(command_id, str) or not command_id.strip()
                    or kind not in COMMAND_KINDS
                    or required_role not in ROLES
                    or not _is_int(max_targets) or max_targets < 1):
                raise GmError(
                    "GM_INVALID_COMMAND",
                    {
                        "command_id": command_id,
                        "required_role": required_role,
                        "kind": kind,
                        "max_targets": max_targets,
                    },
                )
            spec = CommandSpec(command_id, required_role, kind, max_targets)
            self._commands[command_id] = spec
            return spec

    def grant_role(self, principal, role):
        """Give one principal an operator or approver role."""
        if not isinstance(principal, str) or not principal.strip():
            raise GmError("GM_INVALID_PRINCIPAL", principal)
        if role not in ROLES:
            raise GmError("GM_INVALID_ROLE", role)
        with self._lock:
            self._roles.setdefault(principal, set()).add(role)
        return None

    def submit(self, request_id, command_id, *, operator, reviewer, params,
               targets, reason, at_ms):
        """Submit a command request and return its initial state."""
        with self._lock:
            if request_id in self._requests:
                return {"request_id": request_id, "status": "duplicate"}

            spec = self._commands.get(command_id)
            if spec is None:
                raise GmError("GM_UNKNOWN_COMMAND", command_id)
            if not isinstance(reason, str) or not reason.strip():
                raise GmError("GM_REASON_REQUIRED", request_id)
            if not self._has_role(operator, spec.required_role):
                self._counters["denied"] += 1
                raise GmPermissionError(
                    "GM_FORBIDDEN",
                    {"operator": operator, "required_role": spec.required_role},
                )
            if not isinstance(reviewer, str) or not reviewer.strip():
                raise GmPermissionError("GM_REVIEWER_REQUIRED", request_id)
            if not self._has_role(reviewer, "gm_approver"):
                raise GmPermissionError(
                    "GM_REVIEWER_NOT_QUALIFIED", reviewer
                )

            if isinstance(targets, (str, bytes)):
                target_tuple = (copy.deepcopy(targets),)
            else:
                try:
                    target_tuple = tuple(copy.deepcopy(target) for target in targets)
                except TypeError as exc:
                    raise GmError("GM_INVALID_TARGETS", request_id) from exc
            if len(target_tuple) > spec.max_targets:
                raise GmError(
                    "GM_TARGET_LIMIT_EXCEEDED",
                    {"max_targets": spec.max_targets, "count": len(target_tuple)},
                )

            try:
                frozen_params = _freeze(params)
            except Exception as exc:
                raise GmError("GM_INVALID_PARAMS", request_id) from exc

            request = CommandRequest(
                request_id=request_id,
                command_id=command_id,
                operator=operator,
                reviewer=reviewer,
                params=frozen_params,
                targets=target_tuple,
                reason=reason,
                status="pending_approval",
                at_ms=at_ms,
            )
            fingerprint = _fingerprint(
                request.command_id, request.params, request.targets
            )
            try:
                self._requests[request_id] = request
                self._submitted_fingerprints[request_id] = fingerprint
                self._append_log_locked("submitted", request, request.targets, at_ms)
            except Exception:
                self._requests.pop(request_id, None)
                self._submitted_fingerprints.pop(request_id, None)
                raise
            self._counters["requests"] += 1
            return {"request_id": request_id, "status": request.status}

    def authorize(self, request_id, *, at_ms):
        """Approve a pending request after the second-person check."""
        with self._lock:
            request = self._get_request_locked(request_id)
            if request.status != "pending_approval":
                raise GmError("GM_ALREADY_AUTHORIZED", request_id)
            if not request.reviewer:
                raise GmPermissionError("GM_REVIEWER_REQUIRED", request_id)
            if request.reviewer == request.operator:
                raise GmPermissionError(
                    "GM_REVIEWER_NOT_QUALIFIED",
                    {"request_id": request_id, "reason": "self_review"},
                )
            if not self._has_role(request.reviewer, "gm_approver"):
                raise GmPermissionError(
                    "GM_REVIEWER_NOT_QUALIFIED", request.reviewer
                )

            approved = replace(request, status="approved")
            try:
                self._requests[request_id] = approved
                self._append_log_locked("authorized", approved,
                                        approved.targets, at_ms)
            except Exception:
                self._requests[request_id] = request
                raise
            self._counters["approved"] += 1
            return {
                "request_id": request_id,
                "status": approved.status,
                "reviewer": approved.reviewer,
            }

    def dry_run(self, request_id, *, at_ms):
        """Rehearse an approved request and report what it would change."""
        with self._lock:
            request = self._get_request_locked(request_id)
            if request.status != "approved":
                raise GmPermissionError("GM_NOT_APPROVED", request_id)
            self._verify_request_unchanged_locked(request)

            digest = _fingerprint(
                request.command_id, request.params, request.targets
            )
            previous = self._dry_run_digests.get(request_id)
            try:
                self._dry_run_digests[request_id] = digest
                self._append_log_locked("dry_run", request,
                                        request.targets, at_ms)
            except Exception:
                if previous is None:
                    self._dry_run_digests.pop(request_id, None)
                else:
                    self._dry_run_digests[request_id] = previous
                raise
            return {
                "command_id": request.command_id,
                "targets": copy.deepcopy(request.targets),
                "count": len(request.targets),
                "digest": digest,
            }

    def execute(self, request_id, *, at_ms):
        """Execute an approved request once and return applied and failed targets."""
        with self._lock:
            request = self._get_request_locked(request_id)
            if request_id in self._execution_results:
                applied, failed = self._execution_results[request_id]
                return {
                    "status": "duplicate",
                    "applied": copy.deepcopy(applied),
                    "failed": copy.deepcopy(failed),
                }
            if request.status != "approved":
                raise GmPermissionError("GM_NOT_APPROVED", request_id)
            self._verify_request_unchanged_locked(request)

            spec = self._commands.get(request.command_id)
            if spec is None:
                raise GmError("GM_UNKNOWN_COMMAND", request.command_id)
            if not self._has_role(request.operator, spec.required_role):
                raise GmPermissionError(
                    "GM_FORBIDDEN",
                    {"operator": request.operator,
                     "required_role": spec.required_role},
                )
            if request.reviewer == request.operator:
                raise GmPermissionError(
                    "GM_REVIEWER_NOT_QUALIFIED",
                    {"request_id": request_id, "reason": "self_review"},
                )
            if not self._has_role(request.reviewer, "gm_approver"):
                raise GmPermissionError(
                    "GM_REVIEWER_NOT_QUALIFIED", request.reviewer
                )
            if len(request.targets) > spec.max_targets:
                raise GmError(
                    "GM_TARGET_LIMIT_EXCEEDED",
                    {"max_targets": spec.max_targets,
                     "count": len(request.targets)},
                )

            applied: list = []
            failed: list = []
            for target in request.targets:
                target_lock = self._lock_for_target_locked(target)
                with target_lock:
                    try:
                        outcome = self._apply_target(request, target)
                        succeeded = self._outcome_succeeded(outcome)
                    except Exception:
                        succeeded = False
                if succeeded:
                    applied.append(copy.deepcopy(target))
                else:
                    failed.append(copy.deepcopy(target))

            applied_tuple = tuple(applied)
            failed_tuple = tuple(failed)
            executed = replace(request, status="executed")
            old_logs = list(self._logs)
            old_next_seq = self._next_seq
            old_counters = dict(self._counters)
            old_results = self._execution_results.get(request_id)
            try:
                self._execution_results[request_id] = (
                    applied_tuple, failed_tuple
                )
                self._requests[request_id] = executed
                self._counters["executed"] += 1
                self._counters["applied"] += len(applied_tuple)
                self._counters["failed"] += len(failed_tuple)
                self._append_log_locked("executed", executed,
                                        executed.targets, at_ms)
            except Exception:
                self._logs[:] = old_logs
                self._next_seq = old_next_seq
                self._counters = old_counters
                if old_results is None:
                    self._execution_results.pop(request_id, None)
                else:
                    self._execution_results[request_id] = old_results
                self._requests[request_id] = request
                raise
            return {
                "status": "executed",
                "applied": copy.deepcopy(applied_tuple),
                "failed": copy.deepcopy(failed_tuple),
            }

    def rollback_plan(self, request_id):
        """Return the compensation operations for the targets that did take effect."""
        with self._lock:
            request = self._get_request_locked(request_id)
            if request.status != "executed":
                raise GmError("GM_NOT_EXECUTED", request_id)
            applied, _ = self._execution_results.get(
                request_id, ((), ())
            )
            return [
                {
                    "op": "revert",
                    "target": copy.deepcopy(target),
                    "command_id": request.command_id,
                }
                for target in reversed(applied)
            ]

    def audit_log(self, *, request_id=None, limit=None):
        """Return audit entries oldest first, optionally filtered and truncated."""
        with self._lock:
            entries = [
                copy.deepcopy(entry) for entry in self._logs
                if request_id is None or entry["request_id"] == request_id
            ]
            if limit is not None:
                if not _is_int(limit):
                    raise GmError("GM_INVALID_LIMIT", limit)
                if limit < 0:
                    limit = 0
                if limit == 0:
                    entries = []
                else:
                    entries = entries[-limit:]
            return tuple(entries)

    def request_of(self, request_id):
        """Return the stored request record."""
        with self._lock:
            return copy.deepcopy(self._get_request_locked(request_id))

    def pending_approvals(self):
        """Return the request ids still waiting for a reviewer."""
        with self._lock:
            return tuple(
                request_id
                for request_id, request in self._requests.items()
                if request.status == "pending_approval"
            )

    def snapshot(self):
        """Return a detached state dictionary for the whole auditor."""
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "max_log": self.max_log,
                "retention_ms": self.retention_ms,
                "commands": {
                    command_id: {
                        "command_id": spec.command_id,
                        "required_role": spec.required_role,
                        "kind": spec.kind,
                        "max_targets": spec.max_targets,
                    }
                    for command_id, spec in self._commands.items()
                },
                "roles": {
                    principal: sorted(roles)
                    for principal, roles in self._roles.items()
                },
                "requests": {
                    request_id: {
                        "request_id": request.request_id,
                        "command_id": request.command_id,
                        "operator": request.operator,
                        "reviewer": request.reviewer,
                        "params": copy.deepcopy(request.params),
                        "targets": copy.deepcopy(request.targets),
                        "reason": request.reason,
                        "status": request.status,
                        "at_ms": request.at_ms,
                    }
                    for request_id, request in self._requests.items()
                },
                "logs": copy.deepcopy(self._logs),
                "stats": {
                    **{
                        key: self._counters.get(key, 0)
                        for key in _STAT_KEYS if key != "log_entries"
                    },
                    "log_entries": len(self._logs),
                },
                "next_seq": self._next_seq,
                "execution_results": {
                    request_id: {
                        "applied": copy.deepcopy(applied),
                        "failed": copy.deepcopy(failed),
                    }
                    for request_id, (applied, failed)
                    in self._execution_results.items()
                },
                "dry_run_digests": copy.deepcopy(self._dry_run_digests),
                "submitted_fingerprints": copy.deepcopy(
                    self._submitted_fingerprints
                ),
            }

    def restore(self, state):
        """Replace the auditor with a previously taken snapshot."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except GmError:
                raise
            except Exception as exc:
                raise GmError("GM_SNAPSHOT_INVALID", str(exc)) from exc

            (max_log, retention_ms, commands, roles, requests, logs,
             counters, next_seq, execution_results, dry_run_digests,
             submitted_fingerprints) = parsed
            self.max_log = max_log
            self.retention_ms = retention_ms
            self._commands = commands
            self._roles = roles
            self._requests = requests
            self._logs = logs
            self._counters = counters
            self._next_seq = next_seq
            self._execution_results = execution_results
            self._dry_run_digests = dry_run_digests
            self._submitted_fingerprints = submitted_fingerprints
            return None

    def stats(self):
        """Return request, execution and log counters."""
        with self._lock:
            result = {
                key: self._counters.get(key, 0) for key in _STAT_KEYS
            }
            result["log_entries"] = len(self._logs)
            return result

    def _has_role(self, principal: object, role: str) -> bool:
        if not isinstance(principal, str):
            return False
        return role in self._roles.get(principal, ())

    def _get_request_locked(self, request_id) -> CommandRequest:
        try:
            return self._requests[request_id]
        except (KeyError, TypeError) as exc:
            raise GmError("GM_UNKNOWN_REQUEST", request_id) from exc

    def _verify_request_unchanged_locked(self, request: CommandRequest) -> None:
        expected = self._submitted_fingerprints.get(request.request_id)
        actual = _fingerprint(
            request.command_id, request.params, request.targets
        )
        if expected is None or expected != actual:
            raise GmError(
                "GM_PARAMS_MISMATCH",
                {"request_id": request.request_id},
            )
        dry_run_digest = self._dry_run_digests.get(request.request_id)
        if dry_run_digest is not None and dry_run_digest != actual:
            raise GmError(
                "GM_PARAMS_MISMATCH",
                {"request_id": request.request_id},
            )

    def _append_log_locked(self, phase: str, request: CommandRequest,
                           targets: tuple, at_ms: int) -> None:
        entry = {
            "seq": self._next_seq,
            "phase": phase,
            "request_id": request.request_id,
            "operator": request.operator,
            "reviewer": request.reviewer,
            "targets": copy.deepcopy(tuple(targets)),
            "at_ms": at_ms,
        }
        self._next_seq += 1

        cutoff = at_ms - self.retention_ms
        self._logs[:] = [
            old for old in self._logs
            if not (_is_int(old.get("at_ms")) and old["at_ms"] < cutoff)
        ]
        self._logs.append(entry)
        if len(self._logs) > self.max_log:
            del self._logs[:len(self._logs) - self.max_log]

    def _lock_for_target_locked(self, target) -> threading.RLock:
        key = _canonical(target)
        try:
            return self._target_locks[key]
        except KeyError:
            lock = threading.RLock()
            self._target_locks[key] = lock
            return lock

    def _apply_target(self, request: CommandRequest, target) -> bool:
        """Apply one target atomically.

        The in-memory auditor has no game backend, so the default is a
        successful atomic application.  A subclass may override this method
        to exercise backend failures; returning ``False`` or raising marks
        that one target as failed without failing the rest of the batch.
        """
        return not self._configured_target_failure(request, target)

    def _configured_target_failure(self, request: CommandRequest,
                                   target) -> bool:
        """Recognise optional failure fixtures supplied with a request."""
        params = self._params_mapping(request.params)

        for key in ("failed_targets", "fail_targets", "failures",
                    "failed_target_ids"):
            if key in params and self._contains_target(params[key], target):
                return True

        if "fail" in params:
            value = params["fail"]
            if value is True:
                return True
            if self._contains_target(value, target):
                return True

        for key in ("target_results", "results", "target_status"):
            if key not in params:
                continue
            outcomes = self._params_mapping(params[key])
            for candidate, outcome in outcomes.items():
                if _targets_equal(candidate, target):
                    if outcome is False:
                        return True
                    if isinstance(outcome, str) and outcome.lower() in {
                        "fail", "failed", "error", "false"
                    }:
                        return True

        flags = target if isinstance(target, Mapping) else None
        if flags is not None:
            if flags.get("ok") is False or flags.get("success") is False:
                return True
            if flags.get("failed") is True or flags.get("fail") is True:
                return True
            if flags.get("error"):
                return True

        if not isinstance(target, (str, bytes, int, float, bool,
                                   type(None), Mapping, tuple, list, set,
                                   frozenset)):
            if getattr(target, "ok", True) is False:
                return True
            if getattr(target, "success", True) is False:
                return True
            if getattr(target, "failed", False) is True:
                return True
            if getattr(target, "fail", False) is True:
                return True
        return False

    @staticmethod
    def _params_mapping(value) -> dict:
        if isinstance(value, Mapping):
            return value
        if isinstance(value, (tuple, list)):
            result = {}
            for item in value:
                if isinstance(item, (tuple, list)) and len(item) == 2:
                    result[item[0]] = item[1]
            return result
        return {}

    @staticmethod
    def _contains_target(values, target) -> bool:
        if isinstance(values, (str, bytes)):
            return _targets_equal(values, target)
        if isinstance(values, Mapping):
            for candidate in values:
                if _targets_equal(candidate, target):
                    return True
            return False
        if isinstance(values, (tuple, list, set, frozenset)):
            for candidate in values:
                if _targets_equal(candidate, target):
                    return True
        return False

    @staticmethod
    def _outcome_succeeded(outcome) -> bool:
        if outcome is None:
            return True
        if isinstance(outcome, Mapping):
            if outcome.get("ok") is False or outcome.get("success") is False:
                return False
            if outcome.get("failed") is True or outcome.get("fail") is True:
                return False
            return True
        return bool(outcome)

    def _parse_snapshot(self, state):
        if not isinstance(state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "state must be a mapping")
        if state.get("version") != _SNAPSHOT_VERSION:
            raise GmError("GM_SNAPSHOT_INVALID", "unsupported version")

        required = {
            "max_log", "retention_ms", "commands", "roles", "requests",
            "logs", "stats", "next_seq", "execution_results",
            "dry_run_digests", "submitted_fingerprints",
        }
        if not required.issubset(state):
            raise GmError(
                "GM_SNAPSHOT_INVALID",
                {"missing": sorted(required.difference(state))},
            )

        max_log = state["max_log"]
        retention_ms = state["retention_ms"]
        if not _is_int(max_log) or max_log < 0:
            raise GmError("GM_SNAPSHOT_INVALID", "max_log")
        if not _is_int(retention_ms) or retention_ms < 0:
            raise GmError("GM_SNAPSHOT_INVALID", "retention_ms")

        commands_state = state["commands"]
        if not isinstance(commands_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "commands")
        commands: dict[str, CommandSpec] = {}
        for command_id, raw in commands_state.items():
            if not isinstance(command_id, str) or not command_id.strip():
                raise GmError("GM_SNAPSHOT_INVALID", "command id")
            if not isinstance(raw, Mapping):
                raise GmError("GM_SNAPSHOT_INVALID", command_id)
            if (raw.get("command_id") != command_id
                    or raw.get("kind") not in COMMAND_KINDS
                    or raw.get("required_role") not in ROLES
                    or not _is_int(raw.get("max_targets"))
                    or raw["max_targets"] < 1):
                raise GmError("GM_SNAPSHOT_INVALID", command_id)
            commands[command_id] = CommandSpec(
                command_id=command_id,
                required_role=raw["required_role"],
                kind=raw["kind"],
                max_targets=raw["max_targets"],
            )

        roles_state = state["roles"]
        if not isinstance(roles_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "roles")
        roles: dict[str, set[str]] = {}
        for principal, raw_roles in roles_state.items():
            if not isinstance(principal, str) or not principal.strip():
                raise GmError("GM_SNAPSHOT_INVALID", "principal")
            if not isinstance(raw_roles, (list, tuple, set, frozenset)):
                raise GmError("GM_SNAPSHOT_INVALID", principal)
            role_set = set()
            for role in raw_roles:
                if role not in ROLES:
                    raise GmError("GM_SNAPSHOT_INVALID", role)
                role_set.add(role)
            roles[principal] = role_set

        requests_state = state["requests"]
        if not isinstance(requests_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "requests")
        requests: dict[str, CommandRequest] = {}
        for request_id, raw in requests_state.items():
            if not isinstance(request_id, str) or not request_id.strip():
                raise GmError("GM_SNAPSHOT_INVALID", "request id")
            if not isinstance(raw, Mapping):
                raise GmError("GM_SNAPSHOT_INVALID", request_id)
            if raw.get("request_id") != request_id:
                raise GmError("GM_SNAPSHOT_INVALID", request_id)
            command_id = raw.get("command_id")
            if command_id not in commands:
                raise GmError("GM_SNAPSHOT_INVALID", command_id)
            operator = raw.get("operator")
            reviewer = raw.get("reviewer")
            reason = raw.get("reason")
            status = raw.get("status")
            at_ms = raw.get("at_ms")
            if not isinstance(operator, str) or not operator.strip():
                raise GmError("GM_SNAPSHOT_INVALID", "operator")
            if not isinstance(reviewer, str) or not reviewer.strip():
                raise GmError("GM_SNAPSHOT_INVALID", "reviewer")
            if not isinstance(reason, str) or not reason.strip():
                raise GmError("GM_SNAPSHOT_INVALID", "reason")
            if status not in _REQUEST_STATUSES:
                raise GmError("GM_SNAPSHOT_INVALID", "status")
            if not _is_int(at_ms):
                raise GmError("GM_SNAPSHOT_INVALID", "at_ms")
            raw_targets = raw.get("targets")
            if not isinstance(raw_targets, (tuple, list)):
                raise GmError("GM_SNAPSHOT_INVALID", "targets")
            targets = tuple(copy.deepcopy(target) for target in raw_targets)
            if len(targets) > commands[command_id].max_targets:
                raise GmError("GM_SNAPSHOT_INVALID", "target count")
            params = _freeze(raw.get("params"))
            requests[request_id] = CommandRequest(
                request_id=request_id,
                command_id=command_id,
                operator=operator,
                reviewer=reviewer,
                params=params,
                targets=targets,
                reason=reason,
                status=status,
                at_ms=at_ms,
            )

        logs_state = state["logs"]
        if not isinstance(logs_state, (list, tuple)):
            raise GmError("GM_SNAPSHOT_INVALID", "logs")
        if len(logs_state) > max_log:
            raise GmError("GM_SNAPSHOT_INVALID", "too many logs")
        logs: list[dict] = []
        last_seq = 0
        for raw in logs_state:
            if not isinstance(raw, Mapping):
                raise GmError("GM_SNAPSHOT_INVALID", "log entry")
            seq = raw.get("seq")
            phase = raw.get("phase")
            request_id = raw.get("request_id")
            operator = raw.get("operator")
            reviewer = raw.get("reviewer")
            targets = raw.get("targets")
            at_ms = raw.get("at_ms")
            if not _is_int(seq) or seq <= last_seq:
                raise GmError("GM_SNAPSHOT_INVALID", "log seq")
            if phase not in _LOG_PHASES:
                raise GmError("GM_SNAPSHOT_INVALID", "log phase")
            if request_id not in requests:
                raise GmError("GM_SNAPSHOT_INVALID", "log request")
            if not isinstance(operator, str) or not isinstance(reviewer, str):
                raise GmError("GM_SNAPSHOT_INVALID", "log principal")
            if not isinstance(targets, (tuple, list)):
                raise GmError("GM_SNAPSHOT_INVALID", "log targets")
            if not _is_int(at_ms):
                raise GmError("GM_SNAPSHOT_INVALID", "log at_ms")
            logs.append({
                "seq": seq,
                "phase": phase,
                "request_id": request_id,
                "operator": operator,
                "reviewer": reviewer,
                "targets": tuple(copy.deepcopy(target) for target in targets),
                "at_ms": at_ms,
            })
            last_seq = seq

        stats_state = state["stats"]
        if not isinstance(stats_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "stats")
        counters = {}
        for key in _STAT_KEYS:
            value = stats_state.get(key)
            if not _is_int(value) or value < 0:
                raise GmError("GM_SNAPSHOT_INVALID", key)
            counters[key] = value
        if counters["log_entries"] != len(logs):
            raise GmError("GM_SNAPSHOT_INVALID", "log_entries")

        next_seq = state["next_seq"]
        if not _is_int(next_seq) or next_seq < 1 or next_seq <= last_seq:
            raise GmError("GM_SNAPSHOT_INVALID", "next_seq")

        execution_state = state["execution_results"]
        if not isinstance(execution_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "execution_results")
        execution_results: dict[str, tuple[tuple, tuple]] = {}
        for request_id, raw in execution_state.items():
            request = requests.get(request_id)
            if request is None or not isinstance(raw, Mapping):
                raise GmError("GM_SNAPSHOT_INVALID", "execution result")
            applied = raw.get("applied")
            failed = raw.get("failed")
            if (not isinstance(applied, (tuple, list))
                    or not isinstance(failed, (tuple, list))):
                raise GmError("GM_SNAPSHOT_INVALID", "execution result")
            applied_tuple = tuple(copy.deepcopy(item) for item in applied)
            failed_tuple = tuple(copy.deepcopy(item) for item in failed)
            if len(applied_tuple) + len(failed_tuple) != len(request.targets):
                raise GmError("GM_SNAPSHOT_INVALID", "execution count")
            execution_results[request_id] = (applied_tuple, failed_tuple)
        for request_id, request in requests.items():
            if request.status == "executed":
                if request_id not in execution_results:
                    raise GmError("GM_SNAPSHOT_INVALID", "missing execution")
            elif request_id in execution_results:
                raise GmError("GM_SNAPSHOT_INVALID", "unexpected execution")

        dry_runs_state = state["dry_run_digests"]
        if not isinstance(dry_runs_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "dry_run_digests")
        dry_run_digests = {}
        for request_id, digest in dry_runs_state.items():
            if (request_id not in requests
                    or not isinstance(digest, str) or not digest):
                raise GmError("GM_SNAPSHOT_INVALID", "dry run digest")
            dry_run_digests[request_id] = digest

        fingerprints_state = state["submitted_fingerprints"]
        if not isinstance(fingerprints_state, Mapping):
            raise GmError("GM_SNAPSHOT_INVALID", "submitted_fingerprints")
        submitted_fingerprints = {}
        for request_id, fingerprint in fingerprints_state.items():
            if (request_id not in requests
                    or not isinstance(fingerprint, str) or not fingerprint):
                raise GmError("GM_SNAPSHOT_INVALID", "fingerprint")
            submitted_fingerprints[request_id] = fingerprint
        if set(submitted_fingerprints) != set(requests):
            raise GmError("GM_SNAPSHOT_INVALID", "missing fingerprint")
        for request_id, request in requests.items():
            actual = _fingerprint(
                request.command_id, request.params, request.targets
            )
            if submitted_fingerprints[request_id] != actual:
                raise GmError("GM_SNAPSHOT_INVALID", "fingerprint mismatch")
            if (request_id in dry_run_digests
                    and dry_run_digests[request_id] != actual):
                raise GmError("GM_SNAPSHOT_INVALID", "dry run mismatch")

        return (
            max_log,
            retention_ms,
            commands,
            roles,
            requests,
            logs,
            counters,
            next_seq,
            execution_results,
            dry_run_digests,
            submitted_fingerprints,
        )
