"""符号执行状态预算：路径分叉配额、状态合并与求解超时后的未探索标记。"""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass, replace

MAX_STATES = 64
MAX_CONSTRAINTS = 8
MAX_CONSTRAINT_CHARS = 64
MAX_ITERATIONS = 3

OPS = ("==", "!=", "<", "<=", ">", ">=")

NEGATED_OPS = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}

STATUSES = ("queued", "solved", "unexplored", "merged", "expired", "infeasible")

_INTEGER_RE = re.compile(r"[+-]?\d+\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class SymExecError(ValueError):
    """状态队列、预算或求解被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class State:
    state_id: int
    function: str
    constraints: tuple
    status: str
    reachable: bool
    iterations: int
    deadline_ms: int
    proven_safe: bool


@dataclass(frozen=True)
class Fork:
    parent_id: int
    taken_id: int
    skipped_id: int
    remaining: int
    exhausted: bool


@dataclass(frozen=True)
class SolverResult:
    state_id: int
    status: str
    cached: bool


def negate_condition(condition):
    """把条件里的运算符换成取反后的运算符，两侧原文保留。"""
    left, operator, right = _parse_constraint(condition)
    return f"{left} {NEGATED_OPS[operator]} {right}"


def _parse_constraint(condition):
    if not isinstance(condition, str):
        raise SymExecError("SYMEXEC_CONSTRAINT_INVALID", condition)
    if len(condition) > MAX_CONSTRAINT_CHARS:
        raise SymExecError("SYMEXEC_CONSTRAINT_TOO_LONG", condition)

    parts = condition.split()
    if len(parts) != 3:
        raise SymExecError("SYMEXEC_CONSTRAINT_INVALID", condition)

    left, operator, right = parts
    if operator not in OPS:
        raise SymExecError("SYMEXEC_CONSTRAINT_INVALID", condition)
    if not _is_operand(left) or not _is_operand(right):
        raise SymExecError("SYMEXEC_CONSTRAINT_INVALID", condition)
    return left, operator, right


def _is_integer(value):
    return _INTEGER_RE.fullmatch(value) is not None


def _is_operand(value):
    return _is_integer(value) or _IDENTIFIER_RE.fullmatch(value) is not None


def _constant_is_true(left, operator, right):
    lhs = int(left)
    rhs = int(right)
    if operator == "==":
        return lhs == rhs
    if operator == "!=":
        return lhs != rhs
    if operator == "<":
        return lhs < rhs
    if operator == "<=":
        return lhs <= rhs
    if operator == ">":
        return lhs > rhs
    return lhs >= rhs


def _require_nonnegative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class SymExecBudgetGuard:
    """管理符号执行的状态队列、分叉与求解预算。"""

    def __init__(self, *, max_states=MAX_STATES, max_forks_per_function=4,
                 max_solves_per_function=8, max_constraints=MAX_CONSTRAINTS,
                 max_iterations=MAX_ITERATIONS, solver=None):
        self.max_states = max_states
        self.max_forks_per_function = max_forks_per_function
        self.max_solves_per_function = max_solves_per_function
        self.max_constraints = max_constraints
        self.max_iterations = max_iterations
        self.solver = solver
        self._states = {}
        self._budget = {}
        self._cache = {}
        self._counters = {"forks": 0, "cache_hits": 0, "timeouts": 0}
        self._next_id = 1
        self._lock = threading.RLock()

    def enqueue(self, function, constraints=(), *, deadline_ms=0):
        with self._lock:
            normalized, feasible = self._normalize_constraints(constraints)
            if len(self._states) >= self.max_states:
                raise SymExecError("SYMEXEC_STATE_LIMIT", function)

            state_id = self._next_id
            self._next_id += 1
            self._ensure_budget(function)
            state = State(
                state_id=state_id,
                function=function,
                constraints=normalized,
                status="queued" if feasible else "infeasible",
                reachable=feasible,
                iterations=0,
                deadline_ms=deadline_ms,
                proven_safe=False,
            )
            self._states[state_id] = state
            return state

    def state(self, state_id):
        with self._lock:
            return self._get_state(state_id)

    def states(self):
        with self._lock:
            return tuple(self._states[key] for key in sorted(self._states))

    def fork_state(self, state_id, condition, *, loop=False):
        with self._lock:
            parent = self._get_state(state_id)
            left, operator, right = _parse_constraint(condition)
            negated = f"{left} {NEGATED_OPS[operator]} {right}"

            if len(self._states) + 2 > self.max_states:
                raise SymExecError("SYMEXEC_STATE_LIMIT", parent.function)

            taken_constraints, taken_feasible = self._normalize_constraints(
                (*parent.constraints, condition)
            )
            skipped_constraints, skipped_feasible = self._normalize_constraints(
                (*parent.constraints, negated)
            )
            if parent.status == "infeasible" or not parent.reachable:
                taken_feasible = False
                skipped_feasible = False

            budget = self._ensure_budget(parent.function)
            child_iterations = parent.iterations + (1 if loop else 0)
            iteration_capped = loop and child_iterations > self.max_iterations

            if iteration_capped:
                remaining = budget["forks_remaining"]
                exhausted = False
            elif budget["forks_remaining"] > 0:
                budget["forks_remaining"] -= 1
                remaining = budget["forks_remaining"]
                exhausted = False
            else:
                remaining = 0
                exhausted = True

            taken_id = self._next_id
            skipped_id = self._next_id + 1
            self._next_id += 2

            taken = State(
                state_id=taken_id,
                function=parent.function,
                constraints=taken_constraints,
                status=self._fork_child_status(
                    taken_feasible, iteration_capped, exhausted
                ),
                reachable=taken_feasible,
                iterations=child_iterations,
                deadline_ms=parent.deadline_ms,
                proven_safe=False,
            )
            skipped = State(
                state_id=skipped_id,
                function=parent.function,
                constraints=skipped_constraints,
                status=self._fork_child_status(
                    skipped_feasible, iteration_capped, exhausted
                ),
                reachable=skipped_feasible,
                iterations=child_iterations,
                deadline_ms=parent.deadline_ms,
                proven_safe=False,
            )
            self._states[taken_id] = taken
            self._states[skipped_id] = skipped
            self._counters["forks"] += 1

            return Fork(
                parent_id=parent.state_id,
                taken_id=taken_id,
                skipped_id=skipped_id,
                remaining=remaining,
                exhausted=exhausted,
            )

    def merge_states(self, state_ids):
        with self._lock:
            ids = list(state_ids)
            if not ids:
                raise SymExecError("SYMEXEC_MERGE_MISMATCH", ids)

            branches = [self._get_state(item) for item in ids]
            function = branches[0].function
            if any(branch.function != function for branch in branches[1:]):
                raise SymExecError("SYMEXEC_MERGE_MISMATCH", function)

            constraints = []
            seen = set()
            for branch in branches:
                for constraint in branch.constraints:
                    if constraint not in seen:
                        seen.add(constraint)
                        constraints.append(constraint)

            proven_safe = all(
                branch.status == "solved"
                or (branch.status == "merged" and branch.proven_safe)
                for branch in branches
            )
            reachable = any(branch.reachable for branch in branches)
            iterations = max(branch.iterations for branch in branches)
            deadlines = [
                branch.deadline_ms
                for branch in branches
                if branch.deadline_ms != 0
            ]
            deadline_ms = min(deadlines) if deadlines else 0

            merged_id = branches[0].state_id
            merged = State(
                state_id=merged_id,
                function=function,
                constraints=tuple(constraints),
                status="merged",
                reachable=reachable,
                iterations=iterations,
                deadline_ms=deadline_ms,
                proven_safe=proven_safe,
            )

            for branch in branches:
                self._states[branch.state_id] = replace(branch, status="merged")
            self._states[merged_id] = merged
            return merged

    def solve(self, state_id):
        with self._lock:
            state = self._get_state(state_id)
            if state.status == "expired":
                raise SymExecError("SYMEXEC_STATE_EXPIRED", state.state_id)

            cached = self._cache.get(state.state_id)
            if cached is not None:
                self._counters["cache_hits"] += 1
                return SolverResult(state.state_id, cached, True)

            if state.status == "solved":
                inferred = "unsat" if not state.reachable else "sat"
                self._cache[state.state_id] = inferred
                self._counters["cache_hits"] += 1
                return SolverResult(state.state_id, inferred, True)

            budget = self._ensure_budget(state.function)
            if budget["solves_remaining"] <= 0:
                raise SymExecError(
                    "SYMEXEC_SOLVE_BUDGET_EXHAUSTED", state.function
                )
            budget["solves_remaining"] -= 1

            try:
                if self.solver is None:
                    result = "sat"
                else:
                    result = self.solver(state.constraints)
            except TimeoutError:
                self._counters["timeouts"] += 1
                return SolverResult(state.state_id, "unknown", False)

            if result not in ("sat", "unsat"):
                raise SymExecError("SYMEXEC_SOLVER_RESULT_INVALID", result)

            self._cache[state.state_id] = result
            reachable = state.reachable
            if result == "unsat":
                reachable = False
            self._states[state.state_id] = replace(
                state, status="solved", reachable=reachable
            )
            return SolverResult(state.state_id, result, False)

    def expire(self, now_ms):
        with self._lock:
            expired = 0
            for state_id, state in tuple(self._states.items()):
                if (
                    state.status == "queued"
                    and state.deadline_ms != 0
                    and state.deadline_ms <= now_ms
                ):
                    self._states[state_id] = replace(state, status="expired")
                    expired += 1
            return expired

    def report(self):
        with self._lock:
            counts = {status: 0 for status in STATUSES}
            for state in self._states.values():
                counts[state.status] += 1

            budget = {
                function: {
                    "forks_remaining": values["forks_remaining"],
                    "solves_remaining": values["solves_remaining"],
                }
                for function, values in sorted(self._budget.items())
            }
            return {
                "total_states": len(self._states),
                "queued": counts["queued"],
                "solved": counts["solved"],
                "unexplored": counts["unexplored"],
                "merged": counts["merged"],
                "expired": counts["expired"],
                "infeasible": counts["infeasible"],
                "forks": self._counters["forks"],
                "cache_hits": self._counters["cache_hits"],
                "timeouts": self._counters["timeouts"],
                "budget": budget,
            }

    def snapshot(self):
        with self._lock:
            states = {
                str(state_id): {
                    "state_id": state.state_id,
                    "function": state.function,
                    "constraints": list(state.constraints),
                    "status": state.status,
                    "reachable": state.reachable,
                    "iterations": state.iterations,
                    "deadline_ms": state.deadline_ms,
                    "proven_safe": state.proven_safe,
                }
                for state_id, state in sorted(self._states.items())
            }
            budget = {
                function: {
                    "forks_remaining": values["forks_remaining"],
                    "solves_remaining": values["solves_remaining"],
                }
                for function, values in sorted(self._budget.items())
            }
            cache = {
                str(state_id): status
                for state_id, status in sorted(self._cache.items())
            }
            return {
                "states": states,
                "budget": budget,
                "counters": dict(self._counters),
                "cache": cache,
                "next_id": self._next_id,
            }

    def restore(self, state):
        try:
            snapshot = copy.deepcopy(state)
        except Exception as exc:
            raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", str(exc)) from exc

        with self._lock:
            restored = self._validate_snapshot(snapshot)
            states, budget, cache, counters, next_id = restored
            self._states = states
            self._budget = budget
            self._cache = cache
            self._counters = counters
            self._next_id = next_id

    def _normalize_constraints(self, constraints):
        if isinstance(constraints, str):
            constraints = (constraints,)
        try:
            raw_constraints = list(constraints)
        except TypeError as exc:
            raise SymExecError("SYMEXEC_CONSTRAINT_INVALID", constraints) from exc

        names = {}
        normalized = []
        feasible = True
        for raw in raw_constraints:
            left, operator, right = _parse_constraint(raw)
            left_is_integer = _is_integer(left)
            right_is_integer = _is_integer(right)

            if left_is_integer and right_is_integer:
                if not _constant_is_true(left, operator, right):
                    feasible = False
                continue

            if not left_is_integer:
                if left not in names:
                    names[left] = f"v{len(names)}"
                left = names[left]
            if not right_is_integer:
                if right not in names:
                    names[right] = f"v{len(names)}"
                right = names[right]
            normalized.append(f"{left} {operator} {right}")

        if len(normalized) > self.max_constraints:
            raise SymExecError("SYMEXEC_CONSTRAINT_LIMIT", len(normalized))
        return tuple(normalized), feasible

    def _get_state(self, state_id):
        if not isinstance(state_id, int) or isinstance(state_id, bool):
            raise SymExecError("SYMEXEC_STATE_UNKNOWN", state_id)
        try:
            return self._states[state_id]
        except KeyError as exc:
            raise SymExecError("SYMEXEC_STATE_UNKNOWN", state_id) from exc

    def _ensure_budget(self, function):
        return self._budget.setdefault(
            function,
            {
                "forks_remaining": self.max_forks_per_function,
                "solves_remaining": self.max_solves_per_function,
            },
        )

    @staticmethod
    def _fork_child_status(feasible, iteration_capped, exhausted):
        if not feasible:
            return "infeasible"
        if iteration_capped or exhausted:
            return "unexplored"
        return "queued"

    def _validate_snapshot(self, snapshot):
        if not isinstance(snapshot, dict):
            raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", "snapshot")
        raw_states = snapshot.get("states")
        raw_budget = snapshot.get("budget")
        if not isinstance(raw_states, dict) or not isinstance(raw_budget, dict):
            raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", "states/budget")

        states = {}
        for key, raw in raw_states.items():
            if not isinstance(key, str) or not key.isdigit():
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", key)
            state_id = int(key)
            if str(state_id) != key or state_id <= 0:
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", key)
            states[state_id] = self._state_from_snapshot(raw, state_id)

        budget = {}
        for function, raw in raw_budget.items():
            if not isinstance(function, str) or not isinstance(raw, dict):
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", function)
            forks_remaining = raw.get("forks_remaining")
            solves_remaining = raw.get("solves_remaining")
            if not _require_nonnegative_int(forks_remaining):
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", function)
            if not _require_nonnegative_int(solves_remaining):
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", function)
            budget[function] = {
                "forks_remaining": forks_remaining,
                "solves_remaining": solves_remaining,
            }

        for state in states.values():
            if state.function not in budget:
                raise SymExecError(
                    "SYMEXEC_SNAPSHOT_INVALID", state.function
                )

        raw_counters = snapshot.get("counters", {})
        if not isinstance(raw_counters, dict):
            raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", "counters")
        counters = {"forks": 0, "cache_hits": 0, "timeouts": 0}
        for name in counters:
            value = raw_counters.get(name, 0)
            if not _require_nonnegative_int(value):
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", name)
            counters[name] = value

        raw_cache = snapshot.get("cache", None)
        cache = {}
        if raw_cache is not None:
            if not isinstance(raw_cache, dict):
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", "cache")
            for key, value in raw_cache.items():
                if not isinstance(key, str) or not key.isdigit():
                    raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", key)
                state_id = int(key)
                if str(state_id) != key or state_id not in states:
                    raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", key)
                if value not in ("sat", "unsat"):
                    raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", value)
                cache[state_id] = value
        else:
            for state_id, state in states.items():
                if state.status == "solved":
                    cache[state_id] = "unsat" if not state.reachable else "sat"

        raw_next_id = snapshot.get("next_id", None)
        minimum_next_id = max(states, default=0) + 1
        if raw_next_id is None:
            next_id = minimum_next_id
        else:
            if (
                not isinstance(raw_next_id, int)
                or isinstance(raw_next_id, bool)
                or raw_next_id < minimum_next_id
            ):
                raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", "next_id")
            next_id = raw_next_id

        return states, budget, cache, counters, next_id

    @staticmethod
    def _state_from_snapshot(raw, expected_id):
        if not isinstance(raw, dict):
            raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", expected_id)

        state_id = raw.get("state_id")
        function = raw.get("function")
        constraints = raw.get("constraints")
        status = raw.get("status")
        reachable = raw.get("reachable")
        iterations = raw.get("iterations")
        deadline_ms = raw.get("deadline_ms")
        proven_safe = raw.get("proven_safe")

        if (
            not isinstance(state_id, int)
            or isinstance(state_id, bool)
            or state_id != expected_id
            or not isinstance(function, str)
            or not isinstance(constraints, (list, tuple))
            or any(not isinstance(item, str) for item in constraints)
            or status not in STATUSES
            or not isinstance(reachable, bool)
            or not _require_nonnegative_int(iterations)
            or not _require_nonnegative_int(deadline_ms)
            or not isinstance(proven_safe, bool)
        ):
            raise SymExecError("SYMEXEC_SNAPSHOT_INVALID", expected_id)

        return State(
            state_id=state_id,
            function=function,
            constraints=tuple(constraints),
            status=status,
            reachable=reachable,
            iterations=iterations,
            deadline_ms=deadline_ms,
            proven_safe=proven_safe,
        )
