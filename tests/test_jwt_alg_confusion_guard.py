import base64
import copy
import json
import threading

import pytest

import jwt_alg_confusion_guard as jg

NOW = 1_000_000
ISSUER = "https://issuer.example"
AUD = "api"


def b64(payload):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def token(header, claims, signature="sig"):
    return f"{b64(header)}.{b64(claims)}.{signature}"


def claims(**overrides):
    base = {
        "iss": ISSUER,
        "aud": AUD,
        "sub": "user-7",
        "exp": NOW + 60_000,
        "nbf": NOW - 1000,
        "iat": NOW - 500,
    }
    base.update(overrides)
    return base


class Backend:
    """按材料登记期望签名的替身后端，记录每次调用。"""

    def __init__(self, signatures):
        self.signatures = dict(signatures)
        self.calls = []

    def __call__(self, alg, material, signing_input, signature):
        self.calls.append((alg, material, signing_input, signature))
        return self.signatures.get(material) == signature


def guard(**kwargs):
    instance = jg.JwtAlgConfusionGuard(**kwargs)
    instance.register_tenant("t1", issuer=ISSUER, audience=AUD)
    return instance


def install(g, kid="k1", *, alg="RS256", material="m1", kind="rsa",
            not_before=0, expires_at=None, tenant="t1"):
    return g.install_key(tenant, kid, alg=alg, material=material, kind=kind,
                         not_before=not_before, expires_at=expires_at)


def hs(kid="k1", alg="RS256", payload=None, signature="sig"):
    return token({"alg": alg, "kid": kid}, claims() if payload is None else payload, signature)


def test_malformed_token_rejected_before_any_key_lookup():
    g = guard(max_token_bytes=64)
    backend = Backend({"m1": "sig"})
    install(g)

    too_long = "a" * 80 + ".b.c"
    with pytest.raises(jg.JwtError) as exc:
        g.verify(too_long, tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_MALFORMED"

    with pytest.raises(jg.JwtError) as exc:
        g.verify("only-two.parts", tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_MALFORMED"

    with pytest.raises(jg.JwtError) as exc:
        g.verify(f"{b64({'alg': 'RS256'})}.{b64(claims())}.sig.extra", tenant="t1",
                 now=NOW, backend=backend)
    assert exc.value.code == "JWT_MALFORMED"

    assert backend.calls == []
    assert g.stats()["lookups"] == 0


def test_alg_none_and_unlisted_alg_rejected():
    g = guard()
    backend = Backend({"m1": "sig"})
    install(g)

    for bad_alg in ("none", "", "HS512"):
        with pytest.raises(jg.JwtError) as exc:
            g.verify(hs(alg=bad_alg), tenant="t1", now=NOW, backend=backend)
        assert exc.value.code == "JWT_ALG_REJECTED"

    assert backend.calls == []
    assert g.audit_log()[-1]["code"] == "JWT_ALG_REJECTED"
    assert g.stats()["rejected"] == 3


def test_alg_family_confusion_rejected_without_calling_backend():
    g = guard(allowed_algs=("RS256", "HS256"))
    backend = Backend({"m1": "sig"})
    install(g, kid="k1", alg="RS256", material="m1", kind="rsa")

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(kid="k1", alg="HS256"), tenant="t1", now=NOW, backend=backend)

    assert exc.value.code == "JWT_ALG_CONFUSION"
    detail = exc.value.detail
    assert detail["kid"] == "k1"
    assert detail["alg"] == "HS256"
    assert detail["kind"] == "rsa"
    assert backend.calls == []


def test_kid_path_traversal_and_empty_kid_rejected_before_lookup():
    g = guard()
    backend = Backend({"m1": "sig"})
    install(g)

    for kid in ("../../etc/keys/k1", "tenant/../k1", "a\\b", "..", ""):
        with pytest.raises(jg.JwtError) as exc:
            g.verify(hs(kid=kid), tenant="t1", now=NOW, backend=backend)
        assert exc.value.code == "JWT_KID_REJECTED"

    assert g.stats()["lookups"] == 0
    assert backend.calls == []


def test_unknown_and_revoked_key_have_distinct_codes():
    g = guard()
    backend = Backend({"m1": "sig"})
    install(g)

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(kid="ghost"), tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_KEY_UNKNOWN"
    assert g.stats()["lookups"] == 1

    assert g.revoke_key("t1", "k1", now=NOW) == 1
    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(kid="k1"), tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_KEY_REVOKED"

    assert g.revoke_key("t1", "k1", now=NOW) == 0
    assert g.stats()["revocations"] == 1


def test_key_validity_window_boundaries():
    g = guard()
    backend = Backend({"m1": "sig", "m2": "sig"})
    install(g, kid="old", material="m1", not_before=NOW - 10, expires_at=NOW)
    install(g, kid="pending", material="m2", not_before=NOW + 500, expires_at=None)

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(kid="old"), tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_KEY_EXPIRED"

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(kid="pending"), tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_KEY_NOT_YET_VALID"


def test_signature_failure_is_reported_before_claim_errors():
    g = guard()
    backend = Backend({"m1": "good"})
    install(g, material="m1")
    broken = claims(exp=NOW - 5000, nbf=NOW + 5000, aud="other", iss="https://evil.example")

    with pytest.raises(jg.JwtError) as exc:
        g.verify(token({"alg": "RS256", "kid": "k1"}, broken, "bad"),
                 tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_SIGNATURE_INVALID"
    assert len(backend.calls) == 1

    with pytest.raises(jg.JwtError) as exc:
        g.verify(token({"alg": "RS256", "kid": "k1"}, broken, "good"),
                 tenant="t1", now=NOW, backend=backend)
    assert exc.value.code in {
        "JWT_EXPIRED",
        "JWT_NOT_YET_VALID",
        "JWT_ISSUER_MISMATCH",
        "JWT_AUDIENCE_MISMATCH",
    }


def test_claim_expiry_honours_clock_skew():
    g = guard(clock_skew=60)
    backend = Backend({"m1": "sig"})
    install(g, material="m1")

    soft = g.verify(hs(payload=claims(exp=NOW - 30)), tenant="t1", now=NOW, backend=backend)
    assert soft.claims["exp"] == NOW - 30

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(payload=claims(exp=NOW - 60)), tenant="t1", now=NOW, backend=backend)
    assert exc.value.code == "JWT_EXPIRED"


def test_issuer_and_audience_enforced():
    g = guard()
    backend = Backend({"m1": "sig"})
    install(g, material="m1")

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(), tenant="t1", now=NOW, backend=backend, expected_aud="other-api")
    assert exc.value.code == "JWT_AUDIENCE_MISMATCH"

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(payload=claims(iss="https://evil.example")), tenant="t1",
                 now=NOW, backend=backend)
    assert exc.value.code == "JWT_ISSUER_MISMATCH"


def test_success_verdict_fields_and_audit_entry():
    g = guard()
    backend = Backend({"m1": "sig"})
    install(g, material="m1")

    verdict = g.verify(hs(payload=claims(scope="read")), tenant="t1", now=NOW, backend=backend)

    assert isinstance(verdict, jg.Verdict)
    assert (verdict.tenant, verdict.kid, verdict.alg) == ("t1", "k1", "RS256")
    assert verdict.subject == "user-7"
    assert verdict.claims["scope"] == "read"
    assert verdict.warnings == ()
    assert verdict.key_lookups == 1

    entry = g.audit_log()[-1]
    assert entry["code"] == "JWT_OK"
    assert (entry["tenant"], entry["kid"], entry["alg"], entry["key_lookups"]) == (
        "t1", "k1", "RS256", 1)
    assert g.stats()["verdicts"] == 1
    assert g.stats()["rejected"] == 0


def test_key_capacity_per_tenant_is_hard_capped():
    g = guard(max_keys_per_tenant=2)
    install(g, kid="k1", material="m1", expires_at=NOW + 10_000)
    install(g, kid="k2", material="m2", expires_at=NOW + 10_000)

    with pytest.raises(jg.JwtError) as exc:
        install(g, kid="k3", material="m3", expires_at=NOW + 10_000)
    assert exc.value.code == "JWT_KEY_CAPACITY"
    assert len(g.key_inventory("t1", now=NOW)) == 2


def test_rotation_keeps_old_key_read_only_until_expiry():
    g = guard()
    backend = Backend({"m1": "sig", "m2": "sig"})
    install(g, kid="k1", material="m1", expires_at=NOW + 1000)

    rotated = g.rotate_key("t1", "k1", new_kid="k1-v2", alg="RS256", material="m2",
                           kind="rsa", expires_at=NOW + 90_000, now=NOW)
    assert (rotated.kid, rotated.readonly) == ("k1-v2", False)

    rows = {row.kid: row for row in g.key_inventory("t1", now=NOW)}
    assert rows["k1"].readonly is True
    assert rows["k1-v2"].readonly is False

    verdict = g.verify(hs(kid="k1", signature="sig"), tenant="t1", now=NOW + 10,
                       backend=backend)
    assert verdict.warnings == ("JWT_KEY_READ_ONLY",)

    with pytest.raises(jg.JwtError) as exc:
        g.verify(hs(kid="k1", signature="sig"), tenant="t1", now=NOW + 1000,
                 backend=backend)
    assert exc.value.code == "JWT_KEY_EXPIRED"

    with pytest.raises(jg.JwtError) as exc:
        g.rotate_key("t1", "k1-v2", new_kid="k1-v2", alg="RS256", material="m3",
                     kind="rsa", expires_at=NOW + 5, now=NOW)
    assert exc.value.code == "JWT_KEY_CONFLICT"
    assert g.stats()["rotations"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    backend = Backend({"m1": "sig"})
    install(g, material="m1", expires_at=NOW + 10_000)
    g.verify(hs(), tenant="t1", now=NOW, backend=backend)
    g.revoke_key("t1", "k1", now=NOW)

    state = g.snapshot()
    assert set(state) == {"version", "tenants", "keys", "audit", "stats"}
    pristine = copy.deepcopy(state)

    state["keys"].clear()
    state["audit"].clear()
    state["stats"]["verdicts"] = 99
    assert g.stats()["verdicts"] == 1
    assert len(g.audit_log()) == 2

    clone = jg.JwtAlgConfusionGuard()
    clone.restore(pristine)
    assert clone.stats()["verdicts"] == 1
    assert clone.stats()["restores"] == 1
    rows = clone.key_inventory("t1", now=NOW)
    assert [(row.kid, row.revoked) for row in rows] == [("k1", True)]


def test_restore_rejects_malformed_snapshot_and_keeps_live_data():
    g = guard()
    install(g, material="m1", expires_at=NOW + 10_000)

    bad_states = [
        None,
        {},
        {"version": 1, "tenants": [], "keys": {}, "audit": [], "stats": {}},
        {"version": 1, "tenants": {}, "keys": [], "audit": [], "stats": {}},
        {"version": 1, "tenants": {}, "keys": {}, "audit": [], "stats": {"verdicts": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(jg.JwtError) as exc:
            g.restore(bad)
        assert exc.value.code == "JWT_SNAPSHOT_INVALID"

    assert len(g.key_inventory("t1", now=NOW)) == 1
    assert g.stats()["restores"] == 0


def test_concurrent_verify_and_rotate_keep_consistent_counters():
    g = guard()
    backend = Backend({"m1": "sig", "m3": "sig"})
    install(g, kid="steady", material="m1", expires_at=NOW + 90_000)
    install(g, kid="spin", material="m1", expires_at=NOW + 90_000)
    credentials = hs(kid="steady")

    results = []
    errors = []
    barrier = threading.Barrier(9)

    def verifier():
        try:
            barrier.wait(timeout=5)
            results.append(g.verify(credentials, tenant="t1", now=NOW, backend=backend).kid)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    def rotator():
        try:
            barrier.wait(timeout=5)
            g.rotate_key("t1", "spin", new_kid="spin-v2", alg="RS256", material="m3",
                         kind="rsa", expires_at=NOW + 90_000, now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=verifier) for _ in range(8)]
    threads.append(threading.Thread(target=rotator))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert results == ["steady"] * 8
    assert g.stats() == {"verdicts": 8, "rejected": 0, "rotations": 1,
                         "revocations": 0, "lookups": 8, "restores": 0}
