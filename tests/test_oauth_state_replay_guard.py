import base64
import copy
import hashlib
import threading

import pytest

import oauth_state_replay_guard as og

NOW = 1_000_000
REDIRECT = "https://app.example.com/cb"
VERIFIER = "verifier-" + "a" * 43


def challenge(verifier=VERIFIER):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def guard(**kwargs):
    instance = og.OauthStateReplayGuard(**kwargs)
    instance.register_client("t1", "c1", redirect_uris=(REDIRECT,), methods=("S256",))
    return instance


def begin(g, state, **over):
    kwargs = dict(redirect_uri=REDIRECT, state=state, code_challenge=challenge(), now=NOW)
    kwargs.update(over)
    tenant = kwargs.pop("tenant", "t1")
    client = kwargs.pop("client_id", "c1")
    return g.begin_authorization(tenant, client, **kwargs)


def callback(g, state, *, subject="user-42", now=NOW + 5, client_id="c1"):
    return g.handle_callback("t1", client_id, state=state, subject=subject, now=now)


def exchange(g, state, code, *, verifier=VERIFIER, now=NOW + 10,
             redirect_uri=REDIRECT, client_id="c1"):
    return g.exchange_code("t1", client_id, state=state, code=code,
                           redirect_uri=redirect_uri, code_verifier=verifier, now=now)


def test_begin_authorization_records_pending_request():
    g = guard()
    request = begin(g, "state-0001", scopes=("openid", "profile"))

    assert (request.tenant, request.client_id, request.state) == ("t1", "c1", "state-0001")
    assert request.redirect_uri == REDIRECT
    assert request.challenge_method == "S256"
    assert request.code_challenge == challenge()
    assert request.scopes == ("openid", "profile")
    assert (request.issued_at, request.expires_at) == (NOW, NOW + 600)
    assert request.consumed is False
    assert request.code is None
    assert [row.state for row in g.pending_for("t1", "c1")] == ["state-0001"]
    assert g.stats()["authorizations"] == 1


def test_unregistered_redirect_uri_rejected():
    g = guard()
    for uri in ("https://evil.example.net/cb", "http://app.example.com/cb"):
        with pytest.raises(og.OauthError) as exc:
            begin(g, "state-0002", redirect_uri=uri)
        assert exc.value.code == "OAUTH_REDIRECT_URI_MISMATCH"

    assert g.pending_for("t1", "c1") == ()
    assert g.stats()["authorizations"] == 0


def test_pkce_plain_method_rejected():
    g = guard()
    with pytest.raises(og.OauthError) as exc:
        begin(g, "state-0003", challenge_method="plain")
    assert exc.value.code == "OAUTH_PKCE_METHOD_REJECTED"

    registration = g.register_client("t1", "c2", redirect_uris=(REDIRECT,), methods=("S256",))
    assert registration.methods == ("S256",)
    with pytest.raises(og.OauthError) as exc:
        begin(g, "state-0004", client_id="c2", challenge_method="S512")
    assert exc.value.code == "OAUTH_PKCE_METHOD_REJECTED"


def test_code_challenge_shape_enforced():
    g = guard()
    for bad in ("x" * 40, challenge() + "=", "a+b" + "c" * 40):
        with pytest.raises(og.OauthError) as exc:
            begin(g, "state-0005", code_challenge=bad)
        assert exc.value.code == "OAUTH_INVALID_REQUEST"
    assert g.pending_for("t1", "c1") == ()


def test_state_cannot_be_reused_for_new_authorization():
    g = guard()
    begin(g, "state-0006")
    with pytest.raises(og.OauthError) as exc:
        begin(g, "state-0006")
    assert exc.value.code == "OAUTH_STATE_REUSED"
    assert g.stats()["replays"] == 1
    assert len(g.pending_for("t1", "c1")) == 1


def test_unknown_state_callback_rejected():
    g = guard()
    with pytest.raises(og.OauthError) as exc:
        callback(g, "state-ghost")
    assert exc.value.code == "OAUTH_STATE_UNKNOWN"
    assert g.stats()["callbacks"] == 0


def test_expired_state_cannot_be_redeemed():
    g = guard(state_ttl=60)
    begin(g, "state-0007")
    with pytest.raises(og.OauthError) as exc:
        callback(g, "state-0007", now=NOW + 60)
    assert exc.value.code == "OAUTH_STATE_EXPIRED"
    assert g.pending_for("t1", "c1")[0].code is None


def test_callback_then_exchange_returns_receipt():
    g = guard()
    begin(g, "state-0008", scopes=("openid", "profile"))
    issued = callback(g, "state-0008")

    assert isinstance(issued.code, str) and issued.code
    assert issued.code_issued_at == NOW + 5
    assert issued.consumed is False

    receipt = exchange(g, "state-0008", issued.code)
    assert (receipt.tenant, receipt.client_id, receipt.subject) == ("t1", "c1", "user-42")
    assert receipt.scopes == ("openid", "profile")
    assert receipt.state == "state-0008"
    assert receipt.redirect_uri == REDIRECT
    assert len(receipt.token_id) == 32
    assert receipt.token_id == receipt.token_id.lower()
    assert all(char in "0123456789abcdef" for char in receipt.token_id)
    assert g.stats()["callbacks"] == 1
    assert g.stats()["exchanges"] == 1


def test_verifier_mismatch_leaves_state_usable():
    g = guard()
    begin(g, "state-0009")
    issued = callback(g, "state-0009")

    with pytest.raises(og.OauthError) as exc:
        exchange(g, "state-0009", issued.code, verifier="z" * 43)
    assert exc.value.code == "OAUTH_VERIFIER_MISMATCH"

    receipt = exchange(g, "state-0009", issued.code, now=NOW + 11)
    assert receipt.subject == "user-42"
    assert g.stats()["exchanges"] == 1


def test_state_is_single_use_after_successful_exchange():
    g = guard()
    begin(g, "state-0010")
    issued = callback(g, "state-0010")
    exchange(g, "state-0010", issued.code)

    with pytest.raises(og.OauthError) as exc:
        exchange(g, "state-0010", issued.code, now=NOW + 12)
    assert exc.value.code == "OAUTH_STATE_CONSUMED"
    assert g.stats()["exchanges"] == 1
    assert g.stats()["replays"] == 1


def test_concurrent_exchange_succeeds_exactly_once():
    g = guard()
    begin(g, "state-0011")
    issued = callback(g, "state-0011")

    outcomes = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            outcomes.append(exchange(g, "state-0011", issued.code).token_id)
        except og.OauthError as exc:
            outcomes.append(exc.code)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(outcomes) == 8
    issued_tokens = [item for item in outcomes if len(item) == 32]
    assert len(issued_tokens) == 1
    assert outcomes.count("OAUTH_STATE_CONSUMED") == 7
    assert g.stats()["exchanges"] == 1


def test_code_expiry_and_code_mismatch_are_distinct():
    g = guard(code_ttl=120)
    begin(g, "state-0012")
    issued = callback(g, "state-0012", now=NOW + 5)

    with pytest.raises(og.OauthError) as exc:
        exchange(g, "state-0012", "wrong-code", now=NOW + 6)
    assert exc.value.code == "OAUTH_CODE_MISMATCH"

    with pytest.raises(og.OauthError) as exc:
        exchange(g, "state-0012", issued.code, now=NOW + 5 + 120)
    assert exc.value.code == "OAUTH_CODE_EXPIRED"


def test_pending_capacity_per_client_is_capped():
    g = guard(max_pending_per_client=2)
    begin(g, "state-0013-a")
    begin(g, "state-0013-b")

    with pytest.raises(og.OauthError) as exc:
        begin(g, "state-0013-c")
    assert exc.value.code == "OAUTH_CAPACITY_EXCEEDED"
    assert len(g.pending_for("t1", "c1")) == 2


def test_revoke_client_clears_pending_and_blocks_further_use():
    g = guard()
    begin(g, "state-0014")

    assert g.revoke_client("t1", "c1", now=NOW) == 1
    assert g.pending_for("t1", "c1") == ()
    assert g.stats()["revoked"] == 1

    with pytest.raises(og.OauthError) as exc:
        begin(g, "state-0015")
    assert exc.value.code == "OAUTH_CLIENT_UNKNOWN"

    with pytest.raises(og.OauthError) as exc:
        callback(g, "state-0014")
    assert exc.value.code == "OAUTH_CLIENT_UNKNOWN"


def test_snapshot_detached_and_restore_roundtrip():
    g = guard()
    begin(g, "state-0016")
    issued = callback(g, "state-0016")

    state = g.snapshot()
    assert set(state) == {"version", "clients", "requests", "tokens", "audit", "stats"}
    pristine = copy.deepcopy(state)

    state["requests"].clear()
    state["stats"]["exchanges"] = 99
    assert g.stats()["exchanges"] == 0

    clone = og.OauthStateReplayGuard()
    clone.restore(pristine)
    assert clone.stats()["restores"] == 1
    assert clone.stats()["callbacks"] == 1

    receipt = clone.exchange_code("t1", "c1", state="state-0016", code=issued.code,
                                  redirect_uri=REDIRECT, code_verifier=VERIFIER, now=NOW + 10)
    assert receipt.subject == "user-42"
    assert clone.stats()["exchanges"] == 1

    for bad in (
        None,
        {},
        {"version": 1, "clients": [], "requests": {}, "tokens": {}, "audit": [], "stats": {}},
        {"version": 1, "clients": {}, "requests": {}, "tokens": {}, "audit": [],
         "stats": {"authorizations": 1}},
    ):
        with pytest.raises(og.OauthError) as exc:
            clone.restore(bad)
        assert exc.value.code == "OAUTH_SNAPSHOT_INVALID"

    assert clone.stats()["exchanges"] == 1
