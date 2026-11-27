import copy
import hashlib

import pytest

import hotp_counter_ledger as hotp


def code_for(secret, counter):
    return hashlib.sha256(f"{secret}:{counter}".encode("utf-8")).hexdigest()[:6]


def ledger(**kwargs):
    return hotp.HotpCounterLedger(**kwargs)


def seeded(user="u1", secret="s1", counter=0, **kwargs):
    instance = ledger(**kwargs)
    instance.register(user=user, secret=secret, counter=counter)
    return instance


def test_register_starts_counter_and_rejects_duplicate():
    instance = ledger()
    record = instance.register(user="u1", secret="s1")
    assert (record.user, record.counter, record.lookahead) == ("u1", 0, 5)
    assert record.consumed == ()
    assert instance.counter_of("u1") == 0
    assert instance.lookahead_of("u1") == 5

    with pytest.raises(hotp.HotpError) as exc:
        instance.register(user="u1", secret="s2")
    assert exc.value.code == "HOTP_USER_EXISTS"
    assert instance.counter_of("u1") == 0


def test_register_validates_input_and_capacity():
    instance = ledger(max_users=2)
    for user, secret, counter in [("", "s1", 0), ("u1", "", 0), ("u2", "s2", -1)]:
        with pytest.raises(hotp.HotpError) as exc:
            instance.register(user=user, secret=secret, counter=counter)
        assert exc.value.code == "HOTP_REQUEST_INVALID"

    instance.register(user="u1", secret="s1")
    instance.register(user="u2", secret="s2")
    with pytest.raises(hotp.HotpError) as exc:
        instance.register(user="u3", secret="s3")
    assert exc.value.code == "HOTP_CAPACITY_EXCEEDED"

    assert instance.unregister("u1") is True
    assert instance.unregister("ghost") is False
    instance.register(user="u3", secret="s3")
    assert instance.counter_of("u3") == 0


def test_verify_accepts_current_counter_and_advances():
    instance = seeded()
    result = instance.verify(user="u1", code=code_for("s1", 0))
    assert result.accepted is True
    assert (result.counter, result.next_counter, result.reason) == (0, 1, "ok")
    assert instance.counter_of("u1") == 1
    assert instance.stats()["accepted"] == 1


def test_verify_accepts_lookahead_position_and_skips_ahead():
    instance = seeded(lookahead=5)
    result = instance.verify(user="u1", code=code_for("s1", 3))
    assert (result.accepted, result.counter, result.next_counter) == (True, 3, 4)
    assert instance.counter_of("u1") == 4
    assert instance.consumed_for("u1") == (3,)

    following = instance.verify(user="u1", code=code_for("s1", 4))
    assert (following.accepted, following.counter) == (True, 4)
    assert instance.counter_of("u1") == 5


def test_verify_beyond_lookahead_is_no_match():
    instance = seeded(lookahead=2)
    result = instance.verify(user="u1", code=code_for("s1", 3))
    assert result.accepted is False
    assert (result.counter, result.next_counter, result.reason) == (None, 0, "no_match")
    assert instance.counter_of("u1") == 0
    assert instance.stats()["no_match"] == 1


def test_replayed_code_is_refused_without_moving_counter():
    instance = seeded()
    instance.verify(user="u1", code=code_for("s1", 0))
    replay = instance.verify(user="u1", code=code_for("s1", 0))
    assert replay.accepted is False
    assert replay.reason == "replayed"
    assert replay.next_counter == 1
    assert instance.counter_of("u1") == 1
    assert instance.stats()["replayed"] == 1


def test_code_below_counter_is_stale():
    instance = seeded(counter=10)
    result = instance.verify(user="u1", code=code_for("s1", 5))
    assert result.accepted is False
    assert result.reason == "stale"
    assert instance.counter_of("u1") == 10
    assert instance.stats()["stale"] == 1


def test_verify_input_errors_are_distinguished():
    instance = seeded()
    with pytest.raises(hotp.HotpError) as exc:
        instance.verify(user="ghost", code=code_for("s1", 0))
    assert exc.value.code == "HOTP_USER_UNKNOWN"

    for bad in ["12345", "zzzzzz", ""]:
        with pytest.raises(hotp.HotpError) as exc:
            instance.verify(user="u1", code=bad)
        assert exc.value.code == "HOTP_REQUEST_INVALID"
    assert instance.counter_of("u1") == 0


def test_zero_lookahead_only_accepts_current_counter():
    instance = seeded(lookahead=0)
    ahead = instance.verify(user="u1", code=code_for("s1", 1))
    assert (ahead.accepted, ahead.reason) == (False, "no_match")

    current = instance.verify(user="u1", code=code_for("s1", 0))
    assert (current.accepted, current.counter) == (True, 0)
    assert instance.counter_of("u1") == 1


def test_consume_advances_and_refuses_rollback():
    instance = seeded()
    assert instance.consume(user="u1", counter=2) == 3
    assert instance.consumed_for("u1") == (2,)
    assert instance.counter_of("u1") == 3

    with pytest.raises(hotp.HotpError) as exc:
        instance.consume(user="u1", counter=1)
    assert exc.value.code == "HOTP_COUNTER_ROLLBACK"
    assert instance.counter_of("u1") == 3

    assert instance.consume(user="u1", counter=4) == 5
    assert instance.consumed_for("u1") == (2, 4)


def test_resync_jumps_forward_with_matching_code():
    instance = seeded()
    assert instance.resync(user="u1", counter=40, code=code_for("s1", 40)) == 41
    assert instance.counter_of("u1") == 41
    assert instance.stats()["resync"] == 1

    result = instance.verify(user="u1", code=code_for("s1", 41))
    assert (result.accepted, result.next_counter) == (True, 42)


def test_resync_with_wrong_code_keeps_counter():
    instance = seeded()
    with pytest.raises(hotp.HotpError) as exc:
        instance.resync(user="u1", counter=40, code=code_for("s1", 39))
    assert exc.value.code == "HOTP_RESYNC_MISMATCH"
    assert instance.counter_of("u1") == 0
    assert instance.stats()["resync"] == 0


def test_consumed_window_keeps_latest_entries_sorted():
    instance = seeded(window_size=3)
    for counter in (0, 2, 4, 6):
        instance.consume(user="u1", counter=counter)
    assert instance.consumed_for("u1") == (2, 4, 6)
    assert instance.counter_of("u1") == 7
    assert instance.stats()["consumed"] == 4


def test_snapshot_restore_resumes_counter_and_window():
    instance = seeded()
    instance.verify(user="u1", code=code_for("s1", 0))
    instance.verify(user="u1", code=code_for("s1", 1))
    assert instance.counter_of("u1") == 2

    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "users", "stats"}
    state["stats"]["accepted"] = 99
    state["users"][0]["counter"] = 99
    assert instance.stats()["accepted"] == 2
    assert instance.counter_of("u1") == 2

    clone = ledger()
    clone.restore(pristine)
    assert clone.counter_of("u1") == 2
    result = clone.verify(user="u1", code=code_for("s1", 2))
    assert (result.accepted, result.next_counter) == (True, 3)
    assert clone.consumed_for("u1") == (0, 1, 2)


def test_restore_rejects_malformed_state_and_unregister_drops_user():
    instance = seeded()
    instance.verify(user="u1", code=code_for("s1", 0))
    bad_states = [
        None,
        {},
        {"version": 2, "users": [], "stats": {}},
        {"version": 1, "users": {}, "stats": {}},
        {"version": 1, "users": [], "stats": {"accepted": 1}},
        {"version": 1, "users": [{"user": "u1", "counter": "x"}], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(hotp.HotpError) as exc:
            instance.restore(bad)
        assert exc.value.code == "HOTP_SNAPSHOT_INVALID"

    assert instance.counter_of("u1") == 1
    assert instance.stats()["accepted"] == 1

    assert instance.unregister("u1") is True
    with pytest.raises(hotp.HotpError) as exc:
        instance.counter_of("u1")
    assert exc.value.code == "HOTP_USER_UNKNOWN"
