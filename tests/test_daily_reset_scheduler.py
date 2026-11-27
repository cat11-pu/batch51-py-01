import pytest

import daily_reset_scheduler as dr

# 2026-11-27T12:00Z == Friday 20:00 in Asia/Shanghai
BEFORE_RESET = 1_795_780_800_000
# 2026-11-28 05:00 in Asia/Shanghai == 2026-11-27T21:00Z
DAILY_RESET = 1_795_813_200_000
# 2026-11-29 05:00 in Asia/Shanghai
NEXT_DAILY_RESET = 1_795_899_600_000
# 2026-11-27T22:00Z == Saturday 06:00 in Asia/Shanghai
AFTER_RESET = 1_795_816_800_000
# 2026-11-30 05:00 in Asia/Shanghai == Monday
WEEKLY_RESET = 1_795_986_000_000


def scheduler(**kwargs):
    obj = dr.DailyResetScheduler(**kwargs)
    obj.register_server("s1", timezone="Asia/Shanghai")
    return obj


def test_register_rejects_invalid_timezone():
    obj = dr.DailyResetScheduler()
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("s1", timezone="Mars/Olympus")
    assert exc.value.code == "DR_INVALID_TIMEZONE"
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("", timezone="Asia/Shanghai")
    assert exc.value.code == "DR_INVALID_SERVER"
    assert obj.servers() == ()


def test_register_rejects_duplicate_and_lists_sorted():
    obj = dr.DailyResetScheduler()
    first = obj.register_server("s2", timezone="Asia/Shanghai", daily_hour=5)
    obj.register_server("s1", timezone="Asia/Tokyo")
    assert (first.server_id, first.timezone, first.daily_hour) == ("s2", "Asia/Shanghai", 5)
    assert obj.servers() == ("s1", "s2")
    assert obj.server_of("s1").timezone == "Asia/Tokyo"
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("s1", timezone="Asia/Tokyo")
    assert exc.value.code == "DR_SERVER_EXISTS"


def test_register_rejects_out_of_range_schedule():
    obj = dr.DailyResetScheduler()
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("s1", timezone="Asia/Shanghai", daily_hour=25)
    assert exc.value.code == "DR_INVALID_SCHEDULE"
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("s1", timezone="Asia/Shanghai", daily_minute=60)
    assert exc.value.code == "DR_INVALID_SCHEDULE"
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("s1", timezone="Asia/Shanghai", weekly_weekday=7)
    assert exc.value.code == "DR_INVALID_SCHEDULE"
    assert obj.servers() == ()


def test_server_limit_is_enforced():
    obj = dr.DailyResetScheduler(max_servers=2)
    obj.register_server("s1", timezone="Asia/Shanghai")
    obj.register_server("s2", timezone="Asia/Shanghai")
    with pytest.raises(dr.ResetError) as exc:
        obj.register_server("s3", timezone="Asia/Shanghai")
    assert exc.value.code == "DR_SERVER_LIMIT"
    assert obj.servers() == ("s1", "s2")


def test_next_daily_reset_uses_local_wall_clock():
    obj = scheduler()
    assert obj.next_reset("s1", BEFORE_RESET) == DAILY_RESET
    assert obj.next_reset("s1", BEFORE_RESET, period=dr.DAILY) == DAILY_RESET


def test_next_weekly_reset_lands_on_configured_weekday():
    obj = dr.DailyResetScheduler()
    obj.register_server("s1", timezone="Asia/Shanghai", daily_hour=5, weekly_weekday=0)
    assert obj.next_reset("s1", BEFORE_RESET, period=dr.WEEKLY) == WEEKLY_RESET


def test_next_reset_is_strictly_after():
    obj = scheduler()
    assert obj.next_reset("s1", DAILY_RESET) == NEXT_DAILY_RESET
    assert obj.next_reset("s1", DAILY_RESET - 1) == DAILY_RESET


def test_next_reset_rejects_unknown_server_and_period():
    obj = scheduler()
    with pytest.raises(dr.ResetError) as exc:
        obj.next_reset("s9", BEFORE_RESET)
    assert exc.value.code == "DR_UNKNOWN_SERVER"
    with pytest.raises(dr.ResetError) as exc:
        obj.next_reset("s1", BEFORE_RESET, period="hourly")
    assert exc.value.code == "DR_INVALID_PERIOD"


def test_run_due_materializes_single_cycle_once():
    obj = scheduler()
    assert obj.run_due("s1", BEFORE_RESET) == ()
    assert obj.run_due("s1", AFTER_RESET) == ("daily:2026-11-28",)
    assert obj.run_due("s1", AFTER_RESET) == ()
    with pytest.raises(dr.ResetError) as exc:
        obj.run_due("s1", BEFORE_RESET)
    assert exc.value.code == "DR_TIME_REWIND"
    assert obj.stats()["materialized"] == 1


def test_mark_done_is_idempotent_and_rejects_unknown_cycle():
    obj = scheduler()
    obj.run_due("s1", BEFORE_RESET)
    obj.run_due("s1", AFTER_RESET)
    assert obj.mark_done("s1", "daily:2026-11-28") is True
    assert obj.mark_done("s1", "daily:2026-11-28") is False
    assert obj.stats()["done"] == 1
    with pytest.raises(dr.ResetError) as exc:
        obj.mark_done("s1", "daily:2026-01-01")
    assert exc.value.code == "DR_UNKNOWN_CYCLE"


def test_pending_tracks_outstanding_cycles():
    obj = scheduler()
    assert obj.pending("s1") == ()
    obj.run_due("s1", BEFORE_RESET)
    obj.run_due("s1", AFTER_RESET)
    assert obj.pending("s1") == ("daily:2026-11-28",)
    obj.mark_done("s1", "daily:2026-11-28")
    assert obj.pending("s1") == ()


def test_catch_up_materializes_window_cycle():
    obj = scheduler()
    assert obj.catch_up("s1", from_ms=BEFORE_RESET, to_ms=AFTER_RESET) == ("daily:2026-11-28",)
    assert obj.pending("s1") == ("daily:2026-11-28",)
    assert obj.stats()["catchups"] == 1
    with pytest.raises(dr.ResetError) as exc:
        obj.catch_up("s1", from_ms=AFTER_RESET, to_ms=BEFORE_RESET)
    assert exc.value.code == "DR_TIME_REWIND"


def test_catch_up_does_not_duplicate_done_cycles():
    obj = scheduler()
    obj.catch_up("s1", from_ms=BEFORE_RESET, to_ms=AFTER_RESET)
    obj.mark_done("s1", "daily:2026-11-28")
    assert obj.catch_up("s1", from_ms=BEFORE_RESET, to_ms=AFTER_RESET) == ()
    assert obj.stats()["materialized"] == 1


def test_snapshot_restore_preserves_schedules_and_progress():
    obj = scheduler()
    obj.register_server("s2", timezone="Asia/Tokyo", daily_hour=6)
    obj.run_due("s1", BEFORE_RESET)
    obj.run_due("s1", AFTER_RESET)
    obj.run_due("s2", BEFORE_RESET)
    state = obj.snapshot()

    clone = dr.DailyResetScheduler()
    clone.restore(state)
    assert clone.servers() == ("s1", "s2")
    assert clone.pending("s1") == ("daily:2026-11-28",)
    assert clone.next_reset("s1", BEFORE_RESET) == DAILY_RESET
    assert clone.server_of("s2").daily_hour == 6
    assert clone.stats()["materialized"] == 1


def test_restore_rejects_malformed_state():
    obj = scheduler()
    for bad in (None, {}, {"version": 1, "servers": "nope", "counters": {}, "stats": {}}):
        with pytest.raises(dr.ResetError) as exc:
            obj.restore(bad)
        assert exc.value.code == "DR_SNAPSHOT_INVALID"
    assert obj.servers() == ("s1",)
