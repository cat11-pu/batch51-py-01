import copy
import hashlib
import threading

import pytest

import ntlm_channel_binding_guard as ng

T0 = 1_800_000_000
SERVICE = "cifs"
SPN = "cifs/files01.corp.example.com"
MATERIAL = "tls-server-end-point:0011223344"
FLAGS = ng.FLAG_CBT_CAPABLE | ng.FLAG_NTLM | ng.FLAG_EXTENDED_SESSION_SECURITY
NT_RESPONSE = "00112233445566778899aabbccddeeff"


def token_for(connection_id, service=SERVICE, flags=FLAGS, material=MATERIAL):
    raw = f"challenge|{connection_id}|{service}|{flags}|{material}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def cbt_for(material=MATERIAL):
    return hashlib.sha256(f"cbt|{material}".encode()).hexdigest()


def expected_session_key(connection_id, nt_response=NT_RESPONSE):
    return hashlib.sha256(
        f"session|{token_for(connection_id)}|{nt_response}".encode()).hexdigest()


def fields_for(connection_id, *, user="alice", domain="CORP", target=SPN,
               at=T0, nt_response=NT_RESPONSE, mic="auto", cbt="auto"):
    token = token_for(connection_id)
    if cbt == "auto":
        cbt = cbt_for()
    if mic == "auto":
        mic = hashlib.sha256(f"mic|{token}|{nt_response}".encode()).hexdigest()
    return {"user": user, "domain": domain, "target_name": target,
            "cbt": cbt, "mic": mic, "timestamp": at, "nt_response": nt_response}


def started(guard, connection_id="c-1", *, service=SERVICE, flags=FLAGS,
            material=MATERIAL, source="10.0.0.5", at=T0):
    return guard.begin(connection_id, service=service, client_flags=flags,
                       binding_material=material, source=source, at=at)


def test_service_policy_roundtrip_and_unknown_service():
    guard = ng.NtlmBindingGuard()
    policy = guard.register_service(SERVICE, spn=SPN, require_cbt=True, strict_mic=True)
    assert policy.service == SERVICE
    assert policy.spn == SPN
    assert policy.require_cbt is True
    assert policy.strict_mic is True
    assert guard.service_policy(SERVICE) == policy
    with pytest.raises(ng.NtlmError) as exc:
        guard.service_policy("ldap")
    assert exc.value.code == "NTLM_SERVICE_UNKNOWN"
    with pytest.raises(ng.NtlmError) as exc:
        started(guard, "c-9", service="ldap")
    assert exc.value.code == "NTLM_SERVICE_UNKNOWN"


def test_begin_issues_deterministic_challenge():
    guard = ng.NtlmBindingGuard(max_attempts=4)
    guard.register_service(SERVICE, spn=SPN)
    challenge = started(guard)
    assert challenge.token == token_for("c-1")
    assert challenge.spn == SPN
    assert challenge.require_cbt is True
    assert challenge.attempts_left == 4
    assert challenge.started_at == T0
    assert guard.attempts_left("c-1") == 4


def test_complete_authenticates_and_derives_session_key():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    result = guard.complete("c-1", fields=fields_for("c-1"), at=T0 + 5)
    assert result.status == "authenticated"
    assert result.code == "NTLM_OK"
    assert result.mic_status == "ok"
    assert result.session_key == expected_session_key("c-1")
    assert guard.session_key("c-1") == expected_session_key("c-1")
    assert guard.attempts_left("c-1") == 3
    assert guard.stats()["authenticated"] == 1


def test_timestamp_skew_is_refused_and_costs_attempt():
    guard = ng.NtlmBindingGuard(max_skew_seconds=300)
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    result = guard.complete("c-1", fields=fields_for("c-1", at=T0 - 301), at=T0)
    assert result.status == "refused"
    assert result.code == "NTLM_SKEW_EXCEEDED"
    assert result.session_key is None
    assert guard.attempts_left("c-1") == 2
    assert guard.session_key("c-1") is None
    assert [row.code for row in guard.refusals()] == ["NTLM_SKEW_EXCEEDED"]


def test_attempt_budget_exhaustion_stops_processing():
    guard = ng.NtlmBindingGuard(max_skew_seconds=60, max_attempts=2)
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    for _ in range(2):
        assert guard.complete(
            "c-1", fields=fields_for("c-1", at=T0 - 600), at=T0
        ).code == "NTLM_SKEW_EXCEEDED"
    exhausted = guard.complete("c-1", fields={"broken": True}, at=T0)
    assert exhausted.status == "refused"
    assert exhausted.code == "NTLM_ATTEMPTS_EXHAUSTED"
    assert guard.attempts_left("c-1") == 0


def test_unknown_connection_is_refused():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    with pytest.raises(ng.NtlmError) as exc:
        guard.complete("c-missing", fields=fields_for("c-missing"), at=T0)
    assert exc.value.code == "NTLM_SESSION_UNKNOWN"
    with pytest.raises(ng.NtlmError) as exc:
        guard.session_key("c-missing")
    assert exc.value.code == "NTLM_SESSION_UNKNOWN"
    assert guard.close("c-missing") is False


def test_target_name_must_match_local_spn():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    result = guard.complete(
        "c-1",
        fields=fields_for("c-1", target="cifs/files02.corp.example.com"),
        at=T0)
    assert result.status == "refused"
    assert result.code == "NTLM_SPN_MISMATCH"
    assert guard.attempts_left("c-1") == 2


def test_channel_binding_value_must_match_binding_material():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    wrong = hashlib.sha256(b"cbt|other").hexdigest()
    result = guard.complete("c-1", fields=fields_for("c-1", cbt=wrong), at=T0)
    assert result.code == "NTLM_CBT_MISMATCH"
    assert guard.channel_binding_status(
        fields_for("c-1", cbt=wrong), MATERIAL) == "mismatch"
    assert guard.channel_binding_status(fields_for("c-1"), MATERIAL) == "ok"


def test_malformed_type3_fields_are_rejected():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    good = fields_for("c-1")
    broken = [
        {key: value for key, value in good.items() if key != "nt_response"},
        dict(good, nt_response="zzzz"),
        dict(good, timestamp="1800000000"),
        dict(good, mic=7),
    ]
    for fields in broken:
        with pytest.raises(ng.NtlmError) as exc:
            guard.parse_type3(fields)
        assert exc.value.code == "NTLM_MESSAGE_INVALID"
    started(guard)
    with pytest.raises(ng.NtlmError) as exc:
        guard.complete("c-1", fields=dict(good, nt_response="zzzz"), at=T0)
    assert exc.value.code == "NTLM_MESSAGE_INVALID"


def test_strict_service_refuses_missing_mic():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN, strict_mic=True)
    started(guard)
    result = guard.complete("c-1", fields=fields_for("c-1", mic=None), at=T0)
    assert result.status == "refused"
    assert result.code == "NTLM_MIC_MISSING"
    assert result.mic_status == "missing"
    assert guard.attempts_left("c-1") == 2


def test_closed_connection_cannot_be_completed():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    assert guard.close("c-1") is True
    assert guard.close("c-1") is False
    with pytest.raises(ng.NtlmError) as exc:
        guard.complete("c-1", fields=fields_for("c-1"), at=T0)
    assert exc.value.code == "NTLM_SESSION_UNKNOWN"


def test_refusals_are_queryable_by_source():
    guard = ng.NtlmBindingGuard(max_skew_seconds=60)
    guard.register_service(SERVICE, spn=SPN)
    started(guard, "c-1", source="10.0.0.5")
    started(guard, "c-2", source="10.0.0.9")
    guard.complete("c-1", fields=fields_for("c-1", at=T0 - 600), at=T0)
    guard.complete("c-2",
                   fields=fields_for("c-2", target="cifs/elsewhere.corp.example.com"),
                   at=T0)
    rows = guard.refusals()
    assert [(row.connection_id, row.code) for row in rows] == [
        ("c-1", "NTLM_SKEW_EXCEEDED"), ("c-2", "NTLM_SPN_MISMATCH")]
    only = guard.refusals(source="10.0.0.5")
    assert [row.connection_id for row in only] == ["c-1"]
    assert only[0].source == "10.0.0.5"
    assert only[0].at == T0


def test_snapshot_is_detached_and_restore_roundtrips():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    guard.complete("c-1", fields=fields_for("c-1"), at=T0 + 5)
    state = guard.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "services", "sessions", "refusals", "stats"}
    state["services"].clear()
    state["sessions"].clear()
    state["stats"]["authenticated"] = 99
    assert guard.stats()["authenticated"] == 1
    assert guard.session_key("c-1") == expected_session_key("c-1")
    clone = ng.NtlmBindingGuard()
    clone.restore(pristine)
    assert clone.stats() == guard.stats()
    assert clone.service_policy(SERVICE).spn == SPN
    assert clone.session_key("c-1") == expected_session_key("c-1")
    assert clone.attempts_left("c-1") == 3


def test_restore_rejects_malformed_state():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    bad_states = [
        None,
        {},
        {"version": 2, "services": {}, "sessions": {}, "refusals": [], "stats": {}},
        {"version": 1, "services": [], "sessions": {}, "refusals": [], "stats": {}},
        {"version": 1, "services": {}, "sessions": [], "refusals": [], "stats": {}},
        {"version": 1, "services": {}, "sessions": {}, "refusals": [],
         "stats": {"authenticated": 1}},
    ]
    for state in bad_states:
        with pytest.raises(ng.NtlmError) as exc:
            guard.restore(state)
        assert exc.value.code == "NTLM_SNAPSHOT_INVALID"
    assert guard.service_policy(SERVICE).spn == SPN
    assert guard.stats()["authenticated"] == 0


def test_concurrent_complete_establishes_one_session():
    guard = ng.NtlmBindingGuard()
    guard.register_service(SERVICE, spn=SPN)
    started(guard)
    fields = fields_for("c-1")
    results = []
    errors = []
    barrier = threading.Barrier(2)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(guard.complete("c-1", fields=fields, at=T0 + 1))
        except ng.NtlmError as exc:  # pragma: no cover - reported through errors
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 2
    assert sorted(row.status for row in results) == ["authenticated", "refused"]
    assert [row.code for row in results if row.status == "refused"] == [
        "NTLM_SESSION_COMPLETED"]
    assert guard.stats()["authenticated"] == 1
    assert guard.session_key("c-1") == expected_session_key("c-1")
