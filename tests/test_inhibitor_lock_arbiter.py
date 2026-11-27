import copy

import pytest

import inhibitor_lock_arbiter as ia


def arbiter(**kwargs):
    return ia.InhibitorLockArbiter(**kwargs)


def test_acquire_records_sorted_flags_and_first_lock_id():
    g = arbiter()
    lock = g.acquire("svc-agent", ["sleep", "shutdown"], reason="upgrade")
    assert lock.lock_id == "inh-1"
    assert lock.holder == "svc-agent"
    assert lock.mode == "block"
    assert lock.what == ("shutdown", "sleep")
    assert lock.delay == 0
    assert lock.priority == 0
    assert lock.acquired_at == 0
    assert g.locks() == (lock,)
    assert g.stats()["acquired"] == 1


def test_acquire_rejects_bad_mode_flags_holder_and_delay():
    g = arbiter()
    bad_calls = [
        dict(holder="", what=["sleep"]),
        dict(holder="h", what=["sleep"], mode="notify"),
        dict(holder="h", what=["sleep", "bogus"]),
        dict(holder="h", what=[]),
        dict(holder="h", what=["sleep"], mode="block", delay=5),
        dict(holder="h", what=["sleep"], mode="delay", delay=0),
    ]
    for call in bad_calls:
        with pytest.raises(ia.InhibitorError) as exc:
            g.acquire(**call)
        assert exc.value.code == "INHIBITOR_INVALID_REQUEST"
    assert g.locks() == ()
    assert g.stats()["acquired"] == 0


def test_query_without_locks_is_allowed():
    g = arbiter()
    result = g.query("shutdown", now=100)
    assert result.status == "allowed"
    assert result.blockers == ()
    assert result.delayers == ()
    assert result.delay_total == 0
    assert result.deadline is None


def test_block_vetoes_even_a_high_priority_delay():
    g = arbiter()
    block = g.acquire("svc-a", "shutdown")
    delay = g.acquire("svc-b", "shutdown", mode="delay", delay=30,
                      priority=99)
    result = g.query("shutdown")
    assert result.status == "blocked"
    assert result.blockers == (block.lock_id,)
    assert result.delayers == (delay.lock_id,)
    assert result.delay_total == 30
    assert g.stats()["blocked_queries"] == 1


def test_what_flags_intersect_instead_of_matching_the_whole_set():
    g = arbiter()
    sleep_lock = g.acquire("svc-a", ("sleep",))
    assert g.query("shutdown").status == "allowed"
    both = g.acquire("svc-b", ("shutdown", "idle"))
    assert g.query("shutdown").blockers == (both.lock_id,)
    assert g.query("idle").blockers == (both.lock_id,)
    assert g.query("sleep").blockers == (sleep_lock.lock_id,)
    assert g.query("handle-lid-switch").status == "allowed"


def test_delayers_are_ordered_by_priority_then_acquisition():
    g = arbiter()
    low = g.acquire("h1", "sleep", mode="delay", delay=10, priority=1, now=1)
    mid_first = g.acquire("h2", "sleep", mode="delay", delay=20, priority=5,
                          now=2)
    mid_second = g.acquire("h3", "sleep", mode="delay", delay=40, priority=5,
                           now=3)
    result = g.query("sleep")
    assert result.status == "delayed"
    assert result.delayers == (mid_first.lock_id, mid_second.lock_id,
                               low.lock_id)
    assert result.delay_total == 70


def test_repeated_identical_acquire_merges_into_one_lock():
    g = arbiter()
    first = g.acquire("svc-a", ["sleep", "shutdown"], mode="delay", delay=30)
    second = g.acquire("svc-a", ["shutdown", "sleep"], mode="delay", delay=30,
                       now=50)
    assert second.lock_id == first.lock_id
    assert len(g.locks()) == 1
    assert g.locks()[0] == first
    assert g.stats()["acquired"] == 1
    assert g.stats()["merged"] == 1


def test_holder_and_total_caps_refuse_new_locks():
    g = arbiter(max_locks=3, max_locks_per_holder=2)
    g.acquire("h1", "sleep")
    g.acquire("h1", "idle")
    with pytest.raises(ia.InhibitorError) as exc:
        g.acquire("h1", "shutdown")
    assert exc.value.code == "INHIBITOR_HOLDER_LIMIT"
    assert exc.value.detail["holder"] == "h1"
    assert exc.value.detail["limit"] == 2

    g.acquire("h2", "sleep")
    with pytest.raises(ia.InhibitorError) as exc:
        g.acquire("h3", "sleep")
    assert exc.value.code == "INHIBITOR_CAPACITY"
    assert exc.value.detail["limit"] == 3
    assert len(g.locks()) == 3


def test_release_unknown_returns_false_and_known_unblocks():
    g = arbiter()
    lock = g.acquire("svc-a", "shutdown")
    assert g.release("inh-99") is False
    assert g.release(lock.lock_id) is True
    assert g.locks() == ()
    assert g.query("shutdown").status == "allowed"
    assert g.stats()["released"] == 1
    assert g.release(lock.lock_id) is False


def test_gone_holder_keeps_blocking_until_expire_reclaims_it():
    g = arbiter()
    lock = g.acquire("svc-a", "shutdown", now=0)
    assert g.mark_holder_gone("svc-a") == 1
    blocked = g.query("shutdown")
    assert blocked.status == "blocked"
    assert blocked.blockers == (lock.lock_id,)
    assert g.expire(now=0) == 1
    assert g.query("shutdown").status == "allowed"
    assert g.stats()["expired"] == 1


def test_heartbeat_extends_the_lease_until_the_timeout_is_reached():
    g = arbiter(holder_ttl=10)
    g.acquire("svc-a", "shutdown", now=0)
    assert g.heartbeat("svc-a", now=5) == 1
    assert g.expire(now=14) == 0
    assert g.expire(now=15) == 1
    assert g.query("shutdown").status == "allowed"


def test_begin_shutdown_refused_while_blocked_then_uses_grace():
    g = arbiter()
    block = g.acquire("svc-a", "shutdown")
    with pytest.raises(ia.InhibitorError) as exc:
        g.begin_shutdown(now=100, grace=60)
    assert exc.value.code == "INHIBITOR_BLOCKED"
    assert exc.value.detail["blockers"] == (block.lock_id,)
    assert g.countdown()["active"] is False

    g.release(block.lock_id)
    state = g.begin_shutdown(now=100, grace=60)
    assert set(state) == {"active", "deadline", "delay_total", "blockers"}
    assert state["active"] is True
    assert state["deadline"] == 160
    assert state["delay_total"] == 0
    assert g.countdown()["deadline"] == 160
    with pytest.raises(ia.InhibitorError) as exc:
        g.begin_shutdown(now=110)
    assert exc.value.code == "INHIBITOR_ALREADY_SCHEDULED"


def test_delay_added_during_countdown_recomputes_deadline_with_cap():
    g = arbiter(delay_cap=120)
    g.acquire("svc-a", "shutdown", mode="delay", delay=30, now=0)
    g.begin_shutdown(now=0, grace=60)
    assert g.countdown()["deadline"] == 90

    g.acquire("svc-b", "shutdown", mode="delay", delay=500, now=10)
    state = g.countdown()
    assert state["deadline"] == 180
    assert state["delay_total"] == 120
    assert g.stats()["deadline_updates"] == 1


def test_block_added_during_countdown_cancels_it():
    g = arbiter()
    g.begin_shutdown(now=0, grace=60)
    assert g.countdown()["active"] is True
    lock = g.acquire("svc-a", "shutdown", now=5)
    assert lock.mode == "block"
    state = g.countdown()
    assert state["active"] is False
    assert state["deadline"] is None
    assert g.stats()["cancelled"] == 1
    assert g.query("shutdown").status == "blocked"


def test_snapshot_is_detached_and_restore_roundtrips():
    g = arbiter()
    block = g.acquire("svc-a", "sleep")
    delay = g.acquire("svc-b", ("sleep", "shutdown"), mode="delay", delay=20,
                      now=5)
    g.begin_shutdown(now=10, grace=60)
    assert g.countdown()["deadline"] == 90

    state = g.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "locks", "holders", "countdown",
                             "stats"}
    state["locks"].clear()
    state["stats"]["acquired"] = 999
    assert len(g.locks()) == 2
    assert g.stats()["acquired"] == 2

    clone = arbiter()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.locks() == g.locks()
    assert clone.countdown()["deadline"] == 90
    assert clone.query("sleep").blockers == (block.lock_id,)
    assert clone.query("sleep").delayers == (delay.lock_id,)

    bad_states = [
        None,
        {},
        {"version": 2, "locks": [], "holders": {}, "countdown": None,
         "stats": dict(g.stats())},
        {"version": 1, "locks": {}, "holders": {}, "countdown": None,
         "stats": dict(g.stats())},
        {"version": 1, "locks": [], "holders": {}, "countdown": None,
         "stats": {"acquired": 2}},
    ]
    for bad in bad_states:
        with pytest.raises(ia.InhibitorError) as exc:
            g.restore(bad)
        assert exc.value.code == "INHIBITOR_SNAPSHOT_INVALID"
    assert g.countdown()["deadline"] == 90
    assert len(g.locks()) == 2
