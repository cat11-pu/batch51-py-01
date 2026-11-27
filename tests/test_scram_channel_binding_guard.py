import copy
import threading

import pytest

import scram_channel_binding_guard as sg

PLUS = "SCRAM-SHA-256-PLUS"
PLAIN = "SCRAM-SHA-256"


def guard(**kwargs):
    return sg.ScramChannelBindingGuard(**kwargs)


def negotiated(session_id="s1", digest="chan-1", **kwargs):
    instance = guard(**kwargs)
    instance.offer(session_id=session_id, mechanisms=[PLAIN, PLUS])
    instance.select_mechanism(session_id=session_id)
    instance.bind_channel(session_id=session_id, channel_digest=digest)
    return instance


def test_offer_records_sorted_unique_mechanisms():
    instance = guard()
    out = instance.offer(session_id="s1", mechanisms=[PLAIN, PLUS, PLAIN])
    assert (out.session_id, out.state) == ("s1", "offered")
    assert out.mechanisms == (PLAIN, PLUS)
    assert instance.session_state("s1") == "offered"
    assert instance.stats()["offers"] == 1


def test_offer_rejects_empty_and_unsupported_input():
    instance = guard()
    with pytest.raises(sg.ScramError) as exc:
        instance.offer(session_id="s1", mechanisms=[])
    assert exc.value.code == "SCRAM_REQUEST_INVALID"

    with pytest.raises(sg.ScramError) as exc:
        instance.offer(session_id="s1", mechanisms=[PLAIN, 5])
    assert exc.value.code == "SCRAM_REQUEST_INVALID"

    with pytest.raises(sg.ScramError) as exc:
        instance.offer(session_id="s2", mechanisms=["SCRAM-SHA-1"])
    assert exc.value.code == "SCRAM_MECHANISM_UNSUPPORTED"


def test_close_session_releases_negotiation_record():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLAIN])
    assert instance.close_session("s1") is True
    with pytest.raises(sg.ScramError) as exc:
        instance.offer(session_id="s1", mechanisms=[PLAIN])
    assert exc.value.code == "SCRAM_SESSION_CLOSED"
    assert instance.close_session("s1") is False
    with pytest.raises(sg.ScramError) as exc:
        instance.session_state("s1")
    assert exc.value.code == "SCRAM_SESSION_UNKNOWN"


def test_auto_select_prefers_binding_variant():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLAIN, PLUS])
    assert instance.select_mechanism(session_id="s1") == PLUS
    assert instance.session_state("s1") == "negotiated"
    assert instance.stats()["negotiations"] == 1


def test_require_policy_without_binding_variant_is_no_acceptable():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLAIN])
    with pytest.raises(sg.ScramError) as exc:
        instance.select_mechanism(session_id="s1")
    assert exc.value.code == "SCRAM_NO_ACCEPTABLE_MECHANISM"
    assert instance.session_state("s1") == "offered"


def test_explicit_non_binding_choice_is_downgrade():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLAIN, PLUS])
    with pytest.raises(sg.ScramError) as exc:
        instance.select_mechanism(session_id="s1", mechanism=PLAIN)
    assert exc.value.code == "SCRAM_DOWNGRADE_REJECTED"
    assert instance.session_state("s1") == "rejected"
    assert instance.stats()["downgrades"] == 1


def test_optional_policy_accepts_non_binding_mechanism():
    instance = guard(policy="optional")
    instance.offer(session_id="s1", mechanisms=[PLAIN])
    assert instance.select_mechanism(session_id="s1") == PLAIN
    instance.bind_channel(session_id="s1", channel_digest="chan-9")
    verdict = instance.verify_binding(session_id="s1", binding_data="chan-9")
    assert (verdict.mechanism, verdict.status) == (PLAIN, "verified")


def test_select_requires_offer_and_runs_once():
    instance = guard()
    with pytest.raises(sg.ScramError) as exc:
        instance.select_mechanism(session_id="s-ghost")
    assert exc.value.code == "SCRAM_SESSION_UNKNOWN"

    instance.offer(session_id="s1", mechanisms=[PLUS])
    instance.select_mechanism(session_id="s1")
    with pytest.raises(sg.ScramError) as exc:
        instance.select_mechanism(session_id="s1")
    assert exc.value.code == "SCRAM_STATE_INVALID"


def test_selected_mechanism_must_be_supported_and_offered():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLUS])
    with pytest.raises(sg.ScramError) as exc:
        instance.select_mechanism(session_id="s1", mechanism="SCRAM-SHA-1")
    assert exc.value.code == "SCRAM_MECHANISM_UNSUPPORTED"

    with pytest.raises(sg.ScramError) as exc:
        instance.select_mechanism(session_id="s1", mechanism=PLAIN)
    assert exc.value.code == "SCRAM_MECHANISM_NOT_OFFERED"
    assert instance.session_state("s1") == "offered"


def test_binding_verification_succeeds_with_matching_digest():
    instance = negotiated()
    verdict = instance.verify_binding(session_id="s1", binding_data="chan-1")
    assert (verdict.session_id, verdict.mechanism) == ("s1", PLUS)
    assert (verdict.status, verdict.digest) == ("verified", "chan-1")
    assert instance.session_state("s1") == "verified"
    assert instance.stats()["verified"] == 1


def test_binding_mismatch_keeps_negotiated_state():
    instance = negotiated()
    with pytest.raises(sg.ScramError) as exc:
        instance.verify_binding(session_id="s1", binding_data="chan-2")
    assert exc.value.code == "SCRAM_BINDING_MISMATCH"
    assert instance.session_state("s1") == "negotiated"
    assert instance.stats()["mismatch"] == 1

    verdict = instance.verify_binding(session_id="s1", binding_data="chan-1")
    assert verdict.status == "verified"


def test_binding_requires_selected_mechanism_and_registered_channel():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLUS])
    with pytest.raises(sg.ScramError) as exc:
        instance.verify_binding(session_id="s1", binding_data="chan-1")
    assert exc.value.code == "SCRAM_STATE_INVALID"

    instance.select_mechanism(session_id="s1")
    with pytest.raises(sg.ScramError) as exc:
        instance.verify_binding(session_id="s1", binding_data="chan-1")
    assert exc.value.code == "SCRAM_CHANNEL_UNBOUND"


def test_reject_downgrade_records_reason_once():
    instance = guard()
    instance.offer(session_id="s1", mechanisms=[PLAIN])
    assert instance.reject_downgrade(
        session_id="s1", mechanism=PLAIN) == "SCRAM_DOWNGRADE_REJECTED"
    assert instance.session_state("s1") == "rejected"
    assert instance.stats()["downgrades"] == 1

    with pytest.raises(sg.ScramError) as exc:
        instance.reject_downgrade(session_id="s1", mechanism=PLAIN)
    assert exc.value.code == "SCRAM_STATE_INVALID"


def test_concurrent_sessions_negotiate_independently():
    instance = guard()
    statuses = []
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        session = f"s-{index}"
        try:
            barrier.wait(timeout=5)
            instance.offer(session_id=session, mechanisms=[PLAIN, PLUS])
            instance.select_mechanism(session_id=session)
            instance.bind_channel(session_id=session,
                                  channel_digest=f"d-{index}")
            verdict = instance.verify_binding(session_id=session,
                                              binding_data=f"d-{index}")
            statuses.append(verdict.status)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert statuses == ["verified"] * 8
    assert instance.stats()["verified"] == 8
    assert instance.stats()["offers"] == 8
    assert instance.stats()["negotiations"] == 8


def test_snapshot_restore_roundtrip_and_malformed_state():
    instance = negotiated()
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "sessions", "stats"}
    state["sessions"].clear()
    state["stats"]["verified"] = 99
    assert instance.session_state("s1") == "negotiated"

    clone = guard()
    clone.restore(pristine)
    assert clone.session_state("s1") == "negotiated"
    assert clone.verify_binding(session_id="s1",
                                binding_data="chan-1").status == "verified"

    bad_states = [
        None,
        {},
        {"version": 2, "sessions": {}, "stats": {}},
        {"version": 1, "sessions": [], "stats": {}},
        {"version": 1, "sessions": {}, "stats": {"offers": 1}},
        {"version": 1, "sessions": {"s1": []}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(sg.ScramError) as exc:
            instance.restore(bad)
        assert exc.value.code == "SCRAM_SNAPSHOT_INVALID"
    assert instance.session_state("s1") == "negotiated"
    assert instance.stats()["verified"] == 0
