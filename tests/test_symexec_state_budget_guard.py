import copy
import threading

import pytest

import symexec_state_budget_guard as sym


def guard(**kwargs):
    return sym.SymExecBudgetGuard(**kwargs)


def test_enqueue_normalizes_variable_names_in_first_appearance_order():
    g = guard()
    state = g.enqueue("parse", ["a > 3", "b == a", "  a   !=   7 "])
    assert state.state_id == 1
    assert state.function == "parse"
    assert state.constraints == ("v0 > 3", "v1 == v0", "v0 != 7")
    assert state.status == "queued"
    assert state.reachable is True
    assert state.iterations == 0
    assert state.deadline_ms == 0
    assert state.proven_safe is False


def test_enqueue_folds_constant_constraints():
    g = guard()
    kept = g.enqueue("f", ["3 < 5", "x > 1"])
    assert kept.constraints == ("v0 > 1",)
    assert kept.status == "queued"

    folded = g.enqueue("f", ["4 < 3", "x > 1"])
    assert folded.constraints == ("v0 > 1",)
    assert folded.status == "infeasible"
    assert folded.reachable is False
    assert [row.status for row in g.states()] == ["queued", "infeasible"]


def test_enqueue_rejects_invalid_and_oversized_constraints():
    g = guard()
    for bad, code in (
        ("x 1", "SYMEXEC_CONSTRAINT_INVALID"),
        ("x = 1", "SYMEXEC_CONSTRAINT_INVALID"),
        ("1 <=", "SYMEXEC_CONSTRAINT_INVALID"),
        ("x > 1 2", "SYMEXEC_CONSTRAINT_INVALID"),
        (42, "SYMEXEC_CONSTRAINT_INVALID"),
        ("y > " + "9" * 70, "SYMEXEC_CONSTRAINT_TOO_LONG"),
    ):
        with pytest.raises(sym.SymExecError) as exc:
            g.enqueue("f", [bad])
        assert exc.value.code == code
    assert g.states() == ()


def test_enqueue_enforces_state_and_constraint_limits():
    small = guard(max_states=2)
    small.enqueue("f")
    small.enqueue("f")
    with pytest.raises(sym.SymExecError) as exc:
        small.enqueue("f")
    assert exc.value.code == "SYMEXEC_STATE_LIMIT"
    assert len(small.states()) == 2

    narrow = guard(max_constraints=2)
    with pytest.raises(sym.SymExecError) as exc:
        narrow.enqueue("f", ["a > 1", "b > 2", "c > 3"])
    assert exc.value.code == "SYMEXEC_CONSTRAINT_LIMIT"
    folded = narrow.enqueue("f", ["1 < 2", "3 < 4", "x > 1"])
    assert folded.constraints == ("v0 > 1",)


def test_fork_state_creates_two_children_with_negated_condition():
    g = guard()
    root = g.enqueue("f", ["x > 1"])
    fork = g.fork_state(root.state_id, "y == 2")
    assert (fork.parent_id, fork.taken_id, fork.skipped_id) == (1, 2, 3)
    assert fork.remaining == 3
    assert fork.exhausted is False

    taken = g.state(fork.taken_id)
    skipped = g.state(fork.skipped_id)
    assert taken.constraints == ("v0 > 1", "v1 == 2")
    assert skipped.constraints == ("v0 > 1", "v1 != 2")
    assert (taken.status, skipped.status) == ("queued", "queued")
    assert sym.negate_condition("x < 3") == "x >= 3"
    assert sym.negate_condition("v0 <= 1") == "v0 > 1"
    assert sym.negate_condition("a != b") == "a == b"


def test_fork_budget_exhaustion_marks_children_unexplored():
    g = guard(max_forks_per_function=1)
    root = g.enqueue("f")
    first = g.fork_state(root.state_id, "x > 0")
    assert (first.remaining, first.exhausted) == (0, False)

    second = g.fork_state(root.state_id, "y > 0")
    assert (second.remaining, second.exhausted) == (0, True)
    assert [row.status for row in g.states()] == ["queued", "queued", "queued",
                                                  "unexplored", "unexplored"]
    assert g.state(second.taken_id).reachable is True


def test_loop_backedge_is_truncated_by_iteration_cap():
    g = guard(max_iterations=2)
    root = g.enqueue("loop")
    first = g.fork_state(root.state_id, "i < 3", loop=True)
    assert g.state(first.taken_id).iterations == 1
    second = g.fork_state(first.taken_id, "i < 4", loop=True)
    assert g.state(second.taken_id).iterations == 2
    assert (second.remaining, second.exhausted) == (2, False)

    third = g.fork_state(second.taken_id, "i < 5", loop=True)
    capped = g.state(third.taken_id)
    assert capped.iterations == 3
    assert capped.status == "unexplored"
    assert (third.remaining, third.exhausted) == (second.remaining, False)


def test_solve_sat_unsat_and_cache_hit():
    def solver(constraints):
        return "unsat" if "v0 == 1" in constraints else "sat"

    g = guard(solver=solver)
    unsat_state = g.enqueue("f", ["x == 1"])
    sat_state = g.enqueue("f", ["x == 2"])

    unsat = g.solve(unsat_state.state_id)
    assert (unsat.state_id, unsat.status, unsat.cached) == (1, "unsat", False)
    assert g.state(1).status == "solved"
    assert g.state(1).reachable is False

    sat = g.solve(sat_state.state_id)
    assert (sat.status, sat.cached) == ("sat", False)
    assert g.state(2).status == "solved"
    assert g.state(2).reachable is True

    again = g.solve(sat_state.state_id)
    assert (again.status, again.cached) == ("sat", True)
    assert g.report()["cache_hits"] == 1


def test_solve_timeout_keeps_state_queued_and_counts():
    def slow(constraints):
        raise TimeoutError("solver timed out")

    g = guard(solver=slow)
    state = g.enqueue("f", ["x > 0"])
    result = g.solve(state.state_id)
    assert (result.status, result.cached) == ("unknown", False)
    kept = g.state(state.state_id)
    assert kept.status == "queued"
    assert kept.reachable is True
    assert g.report()["timeouts"] == 1


def test_merge_states_unions_constraints_and_marks_safe():
    g = guard()
    first = g.enqueue("f", ["x > 1"])
    second = g.enqueue("f", ["x > 1", "y == 2"])
    other = g.enqueue("g", ["x > 1"])
    g.solve(first.state_id)
    g.solve(second.state_id)

    merged = g.merge_states([first.state_id, second.state_id])
    assert merged.constraints == ("v0 > 1", "v1 == 2")
    assert merged.status == "merged"
    assert merged.proven_safe is True
    assert g.state(first.state_id).status == "merged"
    assert g.state(second.state_id).status == "merged"

    with pytest.raises(sym.SymExecError) as exc:
        g.merge_states([first.state_id, other.state_id])
    assert exc.value.code == "SYMEXEC_MERGE_MISMATCH"


def test_expire_marks_states_and_blocks_solve():
    g = guard()
    state = g.enqueue("f", ["x > 0"], deadline_ms=1000)
    assert g.expire(999) == 0
    assert g.expire(1000) == 1
    assert g.state(state.state_id).status == "expired"
    assert g.expire(2000) == 0
    with pytest.raises(sym.SymExecError) as exc:
        g.solve(state.state_id)
    assert exc.value.code == "SYMEXEC_STATE_EXPIRED"


def test_report_counts_states_budget_and_counters():
    g = guard(max_forks_per_function=2, max_solves_per_function=3)
    root = g.enqueue("f", ["x > 1"])
    g.fork_state(root.state_id, "y == 2")
    g.solve(root.state_id)
    assert g.report() == {
        "total_states": 3,
        "queued": 2,
        "solved": 1,
        "unexplored": 0,
        "merged": 0,
        "expired": 0,
        "infeasible": 0,
        "forks": 1,
        "cache_hits": 0,
        "timeouts": 0,
        "budget": {"f": {"forks_remaining": 1, "solves_remaining": 2}},
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard(max_forks_per_function=2)
    root = g.enqueue("f", ["x > 1"], deadline_ms=5000)
    fork = g.fork_state(root.state_id, "y == 2")
    g.solve(fork.taken_id)

    state = g.snapshot()
    pristine = copy.deepcopy(state)
    state["states"].clear()
    assert g.state(root.state_id).constraints == ("v0 > 1",)
    assert g.report()["total_states"] == 3

    clone = guard(max_forks_per_function=2)
    clone.restore(pristine)
    assert clone.report() == g.report()
    assert clone.states() == g.states()
    assert clone.state(fork.taken_id).status == "solved"

    for bad in (None, {}, {"states": [], "budget": {}}):
        with pytest.raises(sym.SymExecError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SYMEXEC_SNAPSHOT_INVALID"
    assert clone.report()["total_states"] == 3


def test_solve_budget_exhaustion_keeps_state_queued():
    g = guard(max_solves_per_function=1)
    first = g.enqueue("f", ["x > 1"])
    second = g.enqueue("f", ["x > 2"])
    g.solve(first.state_id)
    with pytest.raises(sym.SymExecError) as exc:
        g.solve(second.state_id)
    assert exc.value.code == "SYMEXEC_SOLVE_BUDGET_EXHAUSTED"
    assert g.state(second.state_id).status == "queued"
    assert g.report()["solved"] == 1
    with pytest.raises(sym.SymExecError) as exc:
        g.state(999)
    assert exc.value.code == "SYMEXEC_STATE_UNKNOWN"


def test_concurrent_enqueue_and_solve_keeps_counts():
    g = guard(max_states=64, max_solves_per_function=32)
    errors = []
    barrier = threading.Barrier(16)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            state = g.enqueue("f", [f"x{index} > {index}"])
            g.solve(state.state_id)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    report = g.report()
    assert report["total_states"] == 16
    assert report["solved"] == 16
    assert report["budget"]["f"]["solves_remaining"] == 16
    assert len({row.state_id for row in g.states()}) == 16
