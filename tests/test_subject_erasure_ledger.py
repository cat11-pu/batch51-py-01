import copy
import threading

import pytest

import subject_erasure_ledger as se

SHARDS = ("audit", "blob", "index")


def ledger(**kwargs):
    return se.SubjectErasureLedger(**kwargs)


def submit(led, subject="alice", generation=1, *, now=0):
    return led.submit_request(subject, generation, now=now)


def confirm_all(led, subject="alice", generation=1, *, now=50):
    for shard in SHARDS:
        led.confirm(subject, shard, generation=generation, now=now)


def test_submit_creates_pending_task_per_shard():
    led = ledger()
    ticket = submit(led)
    assert ticket.request_id == "era-0001"
    assert ticket.subject_id == "alice"
    assert ticket.generation == 1
    assert ticket.state == "new"
    assert ticket.submitted_at == 0
    assert ticket.closed_at is None
    assert [task.shard for task in ticket.tasks] == list(SHARDS)
    assert all(task.state == "pending" for task in ticket.tasks)
    assert all(task.attempts == 0 for task in ticket.tasks)
    assert all(task.dispatched_at is None for task in ticket.tasks)
    assert all(task.confirmed_at is None for task in ticket.tasks)
    with pytest.raises(se.ErasureError) as exc:
        led.submit_request("   ", 1, now=0)
    assert exc.value.code == "ERASURE_INVALID_REQUEST"
    with pytest.raises(se.ErasureError) as exc:
        led.submit_request("carol", 0, now=0)
    assert exc.value.code == "ERASURE_INVALID_REQUEST"


def test_repeat_submit_for_same_generation_is_idempotent():
    led = ledger()
    first = submit(led)
    second = submit(led, now=10)
    assert second.request_id == first.request_id
    assert led.stats()["submissions"] == 1
    later = submit(led, generation=2, now=20)
    assert later.request_id == "era-0002"
    assert led.stats()["submissions"] == 2


def test_dispatch_reports_created_then_existing_without_duplicates():
    led = ledger()
    submit(led)
    plan = led.dispatch("alice", 1, now=10)
    assert plan.request_id == "era-0001"
    assert plan.created == SHARDS
    assert plan.existing == ()
    again = led.dispatch("alice", 1, now=20)
    assert again.created == ()
    assert again.existing == SHARDS
    ticket = led.request("alice", 1)
    assert all(task.state == "dispatched" for task in ticket.tasks)
    assert all(task.dispatched_at == 10 for task in ticket.tasks)
    assert led.stats()["dispatches"] == 2


def test_confirm_one_shard_keeps_ticket_in_progress():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    ticket = led.confirm("alice", "blob", generation=1, now=20)
    assert ticket.state == "in_progress"
    states = {task.shard: task.state for task in ticket.tasks}
    assert states == {"audit": "dispatched", "blob": "confirmed",
                      "index": "dispatched"}
    stamped = {task.shard: task.confirmed_at for task in ticket.tasks}
    assert stamped["blob"] == 20
    assert stamped["audit"] is None


def test_duplicate_confirm_is_idempotent_and_counted_once():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    first = led.confirm("alice", "blob", generation=1, now=20)
    second = led.confirm("alice", "blob", generation=1, now=30)
    stamps = [task.confirmed_at for task in second.tasks
              if task.shard == "blob"]
    assert stamps == [20]
    assert led.stats()["confirmations"] == 1
    assert led.stats()["duplicate_confirmations"] == 1
    assert first.state == second.state == "in_progress"


def test_unknown_subject_shard_and_undispatched_confirm_are_refused():
    led = ledger()
    submit(led)
    with pytest.raises(se.ErasureError) as exc:
        led.dispatch("ghost", 1, now=10)
    assert exc.value.code == "ERASURE_UNKNOWN_SUBJECT"
    led.dispatch("alice", 1, now=10)
    with pytest.raises(se.ErasureError) as exc:
        led.confirm("alice", "cold", generation=1, now=20)
    assert exc.value.code == "ERASURE_UNKNOWN_SHARD"
    submit(led, subject="bob", now=20)
    with pytest.raises(se.ErasureError) as exc:
        led.confirm("bob", "blob", generation=1, now=30)
    assert exc.value.code == "ERASURE_NOT_DISPATCHED"


def test_close_after_every_shard_confirms():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    confirm_all(led, now=50)
    closed = led.close("alice", 1, now=60)
    assert closed.state == "closed"
    assert closed.closed_at == 60
    assert all(task.state == "confirmed" for task in closed.tasks)
    assert led.residuals() == []
    assert led.stats()["closed"] == 1


def test_close_with_unconfirmed_shards_is_refused():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    led.confirm("alice", "blob", generation=1, now=20)
    with pytest.raises(se.ErasureError) as exc:
        led.close("alice", 1, now=30)
    assert exc.value.code == "ERASURE_NOT_COMPLETE"


def test_retry_bumps_attempts_and_keeps_task_dispatchable():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    task = led.retry("alice", "blob", generation=1, now=20)
    assert task.attempts == 1
    assert task.state == "dispatched"
    ticket = led.confirm("alice", "blob", generation=1, now=30)
    blob = [row for row in ticket.tasks if row.shard == "blob"][0]
    assert blob.attempts == 1
    assert blob.confirmed_at == 30
    assert led.stats()["retries"] == 1


def test_resume_returns_only_unfinished_shards():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    led.confirm("alice", "blob", generation=1, now=20)
    pending = led.resume(now=30)
    assert pending == (("alice", "audit"), ("alice", "index"))


def test_snapshot_is_detached_from_live_ledger():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    led.confirm("alice", "blob", generation=1, now=20)
    state = led.snapshot()
    assert set(state) == {"version", "next_request", "requests", "tasks", "stats"}
    pristine = copy.deepcopy(state)
    state["tasks"].clear()
    state["stats"]["submissions"] = 9
    ticket = led.request("alice", 1)
    assert ticket.state == "in_progress"
    assert len(ticket.tasks) == 3
    assert led.stats()["submissions"] == 1
    assert len(pristine["tasks"]) == 3


def test_restore_resumes_without_redispatching_confirmed_shards():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    led.confirm("alice", "blob", generation=1, now=20)
    pristine = copy.deepcopy(led.snapshot())
    baseline = dict(led.stats())

    clone = ledger()
    clone.restore(pristine)
    assert clone.stats() == baseline
    assert clone.request("alice", 1).state == "in_progress"
    assert clone.resume(now=30) == (("alice", "audit"), ("alice", "index"))
    duplicate = clone.confirm("alice", "blob", generation=1, now=40)
    assert duplicate.state == "in_progress"
    assert clone.stats()["confirmations"] == 1
    assert clone.stats()["duplicate_confirmations"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    led = ledger()
    submit(led)
    bad_states = [
        None,
        {},
        {"version": 1, "next_request": 2, "requests": {}, "stats": {}},
        {"version": 2, "next_request": 2, "requests": {}, "tasks": {},
         "stats": {}},
        {"version": 1, "next_request": 2, "requests": [], "tasks": {},
         "stats": {}},
        {"version": 1, "next_request": 2, "requests": {}, "tasks": [],
         "stats": {}},
        {"version": 1, "next_request": 2, "requests": {}, "tasks": {},
         "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(se.ErasureError) as exc:
            led.restore(bad)
        assert exc.value.code == "ERASURE_SNAPSHOT_INVALID"
    assert led.request("alice", 1).state == "new"


def test_concurrent_confirm_of_same_shard_counts_once():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    errors = []
    barrier = threading.Barrier(12)

    def worker():
        try:
            barrier.wait(timeout=5)
            led.confirm("alice", "blob", generation=1, now=20)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert led.stats()["confirmations"] == 1
    assert led.stats()["duplicate_confirmations"] == 11
    ticket = led.request("alice", 1)
    blob = [task for task in ticket.tasks if task.shard == "blob"][0]
    assert blob.state == "confirmed"
    assert blob.confirmed_at == 20


def test_stats_track_a_complete_erasure_exactly():
    led = ledger()
    submit(led)
    led.dispatch("alice", 1, now=10)
    confirm_all(led, now=50)
    led.close("alice", 1, now=60)
    assert led.stats() == {"submissions": 1, "dispatches": 1,
                           "confirmations": 3, "duplicate_confirmations": 0,
                           "retries": 0, "reopened": 0, "escalated": 0,
                           "closed": 1}
