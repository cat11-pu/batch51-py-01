import pytest

import survival_needs_ledger as sn


def ledger(**kwargs):
    return sn.SurvivalNeedsLedger(**kwargs)


def test_register_returns_full_needs_and_rejects_duplicate():
    led = ledger()
    needs = led.register("c1", at_ms=0)
    assert needs == {"hunger": 100, "thirst": 100, "warmth": 100}
    assert led.state_of("c1") == "normal"
    assert led.stats()["characters"] == 1
    with pytest.raises(sn.SurvivalError) as exc:
        led.register("c1", at_ms=0)
    assert exc.value.code == "SN_DUPLICATE_CHARACTER"


def test_register_rejects_unknown_need_key():
    led = ledger()
    with pytest.raises(sn.SurvivalError) as exc:
        led.register("c1", needs={"hunger": 50, "oxygen": 10}, at_ms=0)
    assert exc.value.code == "SN_UNKNOWN_NEED"
    assert led.stats()["characters"] == 0


def test_consume_rejects_negative_amount_and_unknown_need():
    led = ledger()
    led.register("c1", at_ms=0)
    with pytest.raises(sn.SurvivalError) as exc:
        led.consume("c1", "hunger", 0)
    assert exc.value.code == "SN_INVALID_AMOUNT"
    with pytest.raises(sn.SurvivalError) as exc:
        led.consume("c1", "oxygen", 5)
    assert exc.value.code == "SN_UNKNOWN_NEED"
    with pytest.raises(sn.SurvivalError) as exc:
        led.consume("ghost", "hunger", 5)
    assert exc.value.code == "SN_UNKNOWN_CHARACTER"


def test_consume_clamps_at_cap():
    led = ledger()
    led.register("c1", at_ms=0)
    assert led.consume("c1", "hunger", 40) == 100
    led.tick("c1", 10_000)
    assert led.consume("c1", "hunger", 5) == 95
    assert led.stats()["consumes"] == 2


def test_tick_decays_per_second():
    led = ledger()
    led.register("c1", at_ms=0)
    result = led.tick("c1", 5_000)
    assert result == {"hunger": 95, "thirst": 90, "warmth": 95}
    assert led.needs_of("c1") == result
    assert led.stats()["ticks"] == 1


def test_tick_rejects_time_rewind():
    led = ledger()
    led.register("c1", at_ms=1_000)
    led.tick("c1", 5_000)
    with pytest.raises(sn.SurvivalError) as exc:
        led.tick("c1", 4_000)
    assert exc.value.code == "SN_TIME_REWIND"
    assert led.needs_of("c1") == {"hunger": 96, "thirst": 92, "warmth": 96}


def test_tick_at_same_time_is_idempotent():
    led = ledger()
    led.register("c1", at_ms=0)
    led.tick("c1", 5_000)
    before = led.needs_of("c1")
    assert led.tick("c1", 5_000) == before
    assert led.needs_of("c1") == before
    assert before == {"hunger": 95, "thirst": 90, "warmth": 95}


def test_zero_need_enters_dying_and_freezes_decay():
    led = ledger()
    led.register("c1", at_ms=0)
    led.tick("c1", 100_000)
    assert led.needs_of("c1") == {"hunger": 0, "thirst": 0, "warmth": 0}
    assert led.state_of("c1") == "dying"
    assert led.stats()["dying"] == 1
    led.tick("c1", 200_000)
    assert led.needs_of("c1") == {"hunger": 0, "thirst": 0, "warmth": 0}


def test_revive_restores_floor_and_clears_dying():
    led = ledger()
    led.register("c1", at_ms=0)
    with pytest.raises(sn.SurvivalError) as exc:
        led.revive("c1", at_ms=1_000)
    assert exc.value.code == "SN_NOT_DYING"

    led.tick("c1", 100_000)
    restored = led.revive("c1", at_ms=120_000)
    assert restored == {"hunger": 25, "thirst": 25, "warmth": 25}
    assert led.state_of("c1") == "normal"
    assert led.stats()["revivals"] == 1
    assert led.tick("c1", 121_000) == {"hunger": 24, "thirst": 23, "warmth": 24}


def test_effect_multiplies_single_need_decay():
    led = ledger()
    led.register("c1", at_ms=0)
    led.apply_effect("c1", {"effect_id": "e1", "need": "thirst",
                            "multiplier": 2.0, "priority": 10,
                            "expires_at_ms": 100_000})
    assert led.tick("c1", 5_000) == {"hunger": 95, "thirst": 80, "warmth": 95}
    active = led.effects_of("c1")
    assert len(active) == 1
    assert active[0].effect_id == "e1"
    assert active[0].need == "thirst"


def test_effect_stops_applying_after_expiry():
    led = ledger()
    led.register("c1", at_ms=0)
    led.apply_effect("c1", {"effect_id": "e1", "need": "thirst",
                            "multiplier": 2.0, "priority": 10,
                            "expires_at_ms": 4_000})
    assert led.tick("c1", 4_000)["thirst"] == 84
    assert led.tick("c1", 8_000)["thirst"] == 76
    assert led.effects_of("c1") == ()


def test_offline_catchup_matches_continuous_decay():
    led = ledger()
    led.register("c1", at_ms=0)
    caught = led.offline_catchup("c1", from_ms=0, to_ms=30_000)
    assert caught == {"hunger": 70, "thirst": 40, "warmth": 70}
    other = ledger()
    other.register("c1", at_ms=0)
    assert other.tick("c1", 30_000) == caught
    assert led.stats()["catchups"] == 1


def test_offline_catchup_rejects_reverse_window():
    led = ledger()
    led.register("c1", at_ms=0)
    with pytest.raises(sn.SurvivalError) as exc:
        led.offline_catchup("c1", from_ms=5_000, to_ms=1_000)
    assert exc.value.code == "SN_TIME_REWIND"
    assert led.needs_of("c1") == {"hunger": 100, "thirst": 100, "warmth": 100}
    assert led.stats()["catchups"] == 0


def test_snapshot_restore_keeps_effect_remaining_time():
    led = ledger()
    led.register("c1", at_ms=0)
    led.apply_effect("c1", {"effect_id": "e1", "need": "thirst",
                            "multiplier": 2.0, "priority": 10,
                            "expires_at_ms": 10_000})
    led.tick("c1", 5_000)
    state = led.snapshot()
    clone = ledger()
    clone.restore(state)
    assert clone.needs_of("c1") == {"hunger": 95, "thirst": 80, "warmth": 95}
    assert clone.tick("c1", 10_000)["thirst"] == 60
    assert clone.tick("c1", 15_000)["thirst"] == 50
    assert clone.effects_of("c1") == ()


def test_restore_rejects_malformed_state():
    led = ledger()
    led.register("c1", at_ms=0)
    led.tick("c1", 5_000)
    for bad in (None, {}, {"version": 1, "characters": "nope", "counters": {}, "stats": {}}):
        with pytest.raises(sn.SurvivalError) as exc:
            led.restore(bad)
        assert exc.value.code == "SN_SNAPSHOT_INVALID"
    assert led.needs_of("c1") == {"hunger": 95, "thirst": 90, "warmth": 95}
