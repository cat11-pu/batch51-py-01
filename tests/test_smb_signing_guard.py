import threading

import pytest

import smb_signing_guard as sg

NOW = 1000


def guard(**kwargs):
    return sg.SmbSigningGuard(**kwargs)


def negotiated(g, client_id="c1", dialects=("2.0.2", "3.1.1"),
               capabilities=("signing",)):
    return g.negotiate(client_id, dialects, capabilities, now=NOW)


def active_session(g, client_id="c1", session_id="s1"):
    negotiated(g, client_id=client_id)
    return g.open_session(client_id, session_id, now=NOW)


def test_negotiate_picks_highest_common_dialect():
    g = guard()
    result = negotiated(g, dialects=("1.0", "2.0.2", "2.1"))
    assert result.dialect == "2.1"
    assert result.dialects == ("2.0.2", "2.1")
    assert result.capabilities == ("signing",)
    assert result.signing_required is True
    assert result.encryption_required is False
    assert g.negotiation_for("c1") == result
    assert g.negotiation_for("c9") is None


def test_negotiate_without_common_dialect_is_refused():
    g = guard()
    with pytest.raises(sg.SmbError) as exc:
        negotiated(g, dialects=("9.9", "10.0"))
    assert exc.value.code == "SMB_DIALECT_UNSUPPORTED"
    assert g.stats()["refused"] == 1
    assert g.stats()["negotiated"] == 0


def test_client_without_signing_capability_is_refused():
    g = guard()
    with pytest.raises(sg.SmbError) as exc:
        negotiated(g, capabilities=("dfs",))
    assert exc.value.code == "SMB_SIGNING_UNAVAILABLE"
    assert g.negotiation_for("c1") is None
    assert g.stats()["refused"] == 1


def test_encryption_and_signing_can_both_be_required():
    g = guard()
    result = negotiated(g, capabilities=("dfs", "encryption", "signing"))
    assert result.capabilities == ("dfs", "encryption", "signing")
    assert result.signing_required is True
    assert result.encryption_required is True


def test_sessions_get_isolated_keys():
    g = guard()
    negotiated(g)
    first = g.open_session("c1", "s1", now=NOW)
    second = g.open_session("c1", "s2", now=NOW)
    assert (first.state, second.state) == ("active", "active")
    assert first.dialect == "3.1.1"
    assert first.opened_at == NOW
    assert g.session_state("s1") == "active"
    assert len(g.session_key("s1")) == 32
    assert len(g.session_key("s2")) == 32
    assert g.session_key("s1") != g.session_key("s2")
    assert g.session_state("s9") == "unknown"


def test_sign_and_verify_roundtrip():
    g = guard()
    active_session(g)
    signature = g.sign("s1", "tree-connect")
    assert isinstance(signature, str) and len(signature) == 64
    assert g.verify("s1", "tree-connect", signature) is True
    assert g.stats()["signatures"] == 1
    assert g.stats()["signature_failures"] == 0


def test_tampered_message_fails_signature_check():
    g = guard()
    active_session(g)
    signature = g.sign("s1", "tree-connect")
    with pytest.raises(sg.SmbError) as exc:
        g.verify("s1", "tree-connect-x", signature)
    assert exc.value.code == "SMB_SIGNATURE_INVALID"
    assert g.stats()["signature_failures"] == 1
    assert g.failure_log() == (("c1", "SMB_SIGNATURE_INVALID"),)


def test_verify_on_closed_session_is_refused():
    g = guard()
    active_session(g)
    assert g.close_session("s1", reason="idle") is True
    assert g.close_session("s1", reason="idle") is False
    assert g.session_state("s1") == "closed"
    with pytest.raises(sg.SmbError) as exc:
        g.verify("s1", "echo", "irrelevant")
    assert exc.value.code == "SMB_SESSION_CLOSED"


def test_signature_from_another_session_is_rejected():
    g = guard()
    negotiated(g)
    g.open_session("c1", "s1", now=NOW)
    g.open_session("c1", "s2", now=NOW)
    foreign = g.sign("s2", "tree-connect")
    with pytest.raises(sg.SmbError) as exc:
        g.verify("s1", "tree-connect", foreign)
    assert exc.value.code == "SMB_SIGNATURE_INVALID"


def test_second_negotiate_for_same_client_is_refused():
    g = guard()
    negotiated(g)
    with pytest.raises(sg.SmbError) as exc:
        negotiated(g, dialects=("2.1",))
    assert exc.value.code == "SMB_NEGOTIATION_DUPLICATE"
    assert g.stats()["negotiated"] == 1


def test_preauth_chain_matches_and_counts_mismatch():
    g = guard()
    first = g.preauth_update("conn-1", "negotiate-request")
    second = g.preauth_update("conn-1", "session-setup")
    assert first != second
    assert len(second) == 64
    assert g.preauth_hash("conn-1") == second
    assert g.verify_preauth("conn-1", second) is True
    assert g.verify_preauth("conn-1", "00" * 32) is False
    assert g.stats()["preauth_updates"] == 2
    assert g.stats()["preauth_mismatches"] == 1


def test_session_limit_is_enforced():
    g = guard(max_sessions=1)
    negotiated(g)
    g.open_session("c1", "s1", now=NOW)
    with pytest.raises(sg.SmbError) as exc:
        g.open_session("c1", "s2", now=NOW)
    assert exc.value.code == "SMB_SESSION_LIMIT"
    assert g.session_state("s2") == "unknown"


def test_stats_count_negotiate_sessions_and_signature_events():
    g = guard()
    negotiated(g)
    with pytest.raises(sg.SmbError):
        negotiated(g, client_id="c2", dialects=("9.9",))
    with pytest.raises(sg.SmbError):
        negotiated(g, client_id="c3", capabilities=())
    g.open_session("c1", "s1", now=NOW)
    signature = g.sign("s1", "echo")
    assert g.verify("s1", "echo", signature) is True
    with pytest.raises(sg.SmbError):
        g.verify("s1", "echo2", signature)
    g.preauth_update("conn-1", "negotiate")
    g.verify_preauth("conn-1", "ff" * 32)
    assert g.stats() == {
        "negotiated": 1,
        "refused": 2,
        "sessions": 1,
        "signatures": 1,
        "signature_failures": 1,
        "preauth_updates": 1,
        "preauth_mismatches": 1,
    }
    assert g.failure_log("c1") == (("c1", "SMB_SIGNATURE_INVALID"),)


def test_snapshot_restore_keeps_sessions_and_keys():
    g = guard()
    negotiated(g)
    g.open_session("c1", "s1", now=NOW)
    signature = g.sign("s1", "echo")
    state = g.snapshot()
    assert set(state) == {"version", "negotiations", "sessions", "keys",
                          "preauth", "stats"}
    state["sessions"].clear()
    assert g.session_state("s1") == "active"

    clone = guard()
    clone.restore(g.snapshot())
    assert clone.negotiation_for("c1").dialect == "3.1.1"
    assert clone.session_state("s1") == "active"
    assert clone.session_key("s1") == g.session_key("s1")
    assert clone.verify("s1", "echo", signature) is True
    assert clone.stats() == g.stats()


def test_concurrent_sessions_are_all_registered():
    g = guard()
    errors = []
    keys = []
    barrier = threading.Barrier(8)

    def worker(index):
        client = f"c{index}"
        try:
            barrier.wait(timeout=5)
            g.negotiate(client, ("2.1", "3.1.1"), ("signing",), now=NOW)
            g.open_session(client, f"s{index}", now=NOW)
            keys.append(g.session_key(f"s{index}"))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(set(keys)) == 8
    assert g.stats()["sessions"] == 8
    assert g.stats()["negotiated"] == 8
