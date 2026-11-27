"""符号执行状态预算：路径分叉配额、状态合并与求解超时后的未探索标记。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

MAX_STATES = 64
MAX_CONSTRAINTS = 8
MAX_CONSTRAINT_CHARS = 64
MAX_ITERATIONS = 3

OPS = ("==", "!=", "<", "<=", ">", ">=")

NEGATED_OPS = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}

STATUSES = ("queued", "solved", "unexplored", "merged", "expired", "infeasible")


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
    raise NotImplementedError


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
        raise NotImplementedError

    def state(self, state_id):
        raise NotImplementedError

    def states(self):
        raise NotImplementedError

    def fork_state(self, state_id, condition, *, loop=False):
        raise NotImplementedError

    def merge_states(self, state_ids):
        raise NotImplementedError

    def solve(self, state_id):
        raise NotImplementedError

    def expire(self, now_ms):
        raise NotImplementedError

    def report(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
