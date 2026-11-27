import copy
import threading

import pytest

import breached_password_range_checker as br

NOW = 1_800_000_000


class SpyFetcher:
    def __init__(self, buckets):
        self.buckets = dict(buckets)
        self.calls = []

    def __call__(self, prefix):
        self.calls.append(prefix)
        return list(self.buckets.get(prefix, []))


def checker(buckets=None, **kwargs):
    spy = SpyFetcher(buckets or {})
    return br.BreachRangeChecker(fetcher=spy, **kwargs), spy


def register(chk, tenant="t1", **kwargs):
    return chk.register_tenant(tenant, **kwargs)


def test_cold_prefix_query_fetches_and_charges_budget():
    chk, spy = checker({"AAAAA": ["0A1B2C", "FFFFFF"]})
    register(chk, budget=4)
    view = chk.query_prefix("t1", prefix="AAAAA", now=NOW)
    assert view.prefix == "AAAAA"
    assert view.source == "network"
    assert view.version == 1
    assert view.suffix_count == 2
    assert view.fetched_at == NOW
    assert spy.calls == ["AAAAA"]
    assert chk.budget_remaining("t1") == 3
    assert chk.stats()["fetches"] == 1


def test_check_password_reports_breach_with_prefix_and_version():
    chk, spy = checker({"AAAAA": ["0A1B2C"]})
    register(chk, budget=4)
    verdict = chk.check_password("t1", digest="aaaaa0a1b2c", now=NOW)
    assert verdict.status == "breached"
    assert verdict.reason == "BREACH_HIT"
    assert verdict.prefix == "AAAAA"
    assert verdict.bucket_version == 1
    assert verdict.allowed is False
    assert chk.stats()["breaches"] == 1
    assert len(spy.calls) == 1


def test_check_password_miss_is_clear():
    chk, spy = checker({"AAAAA": ["0A1B2C"]})
    register(chk, budget=4)
    verdict = chk.check_password("t1", digest="AAAAA999999", now=NOW)
    assert verdict.status == "clear"
    assert verdict.reason == "BREACH_CLEAR"
    assert verdict.allowed is True
    assert chk.stats()["clears"] == 1


def test_bucket_with_bad_entries_is_rejected():
    chk, spy = checker({"AAAAA": ["0A1B2C", 17]})
    register(chk, budget=4)
    with pytest.raises(br.BreachError) as exc:
        chk.query_prefix("t1", prefix="AAAAA", now=NOW)
    assert exc.value.code == "BREACH_BUCKET_INVALID"
    assert chk.bucket_state("AAAAA") is None
    assert len(spy.calls) == 1


def test_budget_exhaustion_blocks_by_default():
    chk, spy = checker({"AAAAA": [], "BBBBB": []})
    register(chk, budget=1, offline_mode="block")
    assert chk.check_password("t1", digest="AAAAA111111", now=NOW).allowed is True
    verdict = chk.check_password("t1", digest="BBBBB111111", now=NOW)
    assert verdict.status == "undetermined"
    assert verdict.reason == "BREACH_BUDGET_EXHAUSTED"
    assert verdict.allowed is False
    assert spy.calls == ["AAAAA"]
    assert chk.budget_remaining("t1") == 0


def test_budget_exhaustion_allows_when_tenant_policy_says_so():
    chk, spy = checker({"AAAAA": [], "BBBBB": []})
    register(chk, budget=1, offline_mode="allow")
    assert chk.check_password("t1", digest="AAAAA111111", now=NOW).status == "clear"
    verdict = chk.check_password("t1", digest="BBBBB111111", now=NOW)
    assert verdict.status == "undetermined"
    assert verdict.reason == "BREACH_BUDGET_EXHAUSTED"
    assert verdict.allowed is True
    assert spy.calls == ["AAAAA"]
    assert chk.stats()["budget_exhausted"] == 1


def test_budgets_and_policies_are_per_tenant():
    chk, spy = checker({"AAAAA": [], "BBBBB": [], "CCCCC": []})
    register(chk, tenant="t1", budget=1, offline_mode="block")
    register(chk, tenant="t2", budget=1, offline_mode="allow")
    chk.check_password("t1", digest="AAAAA111111", now=NOW)
    assert chk.check_password("t1", digest="BBBBB111111", now=NOW).allowed is False
    assert chk.check_password("t2", digest="CCCCC111111", now=NOW).status == "clear"
    assert spy.calls == ["AAAAA", "CCCCC"]
    assert chk.budget_remaining("t1") == 0
    assert chk.budget_remaining("t2") == 0
    assert chk.tenant_policy("t2").offline_mode == "allow"


def test_prewarm_fills_cache_and_charges_budget():
    chk, spy = checker({"AAAAA": [], "BBBBB": [], "CCCCC": []})
    register(chk, budget=5)
    assert chk.prewarm("t1", ["AAAAA", "BBBBB", "CCCCC"]) == 3
    assert chk.budget_remaining("t1") == 2
    assert sorted(spy.calls) == ["AAAAA", "BBBBB", "CCCCC"]
    state = chk.bucket_state("BBBBB")
    assert state["prefix"] == "BBBBB"
    assert state["version"] == 1
    assert state["suffix_count"] == 0


def test_invalid_digest_and_prefix_are_refused():
    chk, spy = checker({"AAAAA": []})
    register(chk, budget=3)
    for bad in ["AAAA", "AAAAAZ1111", "", 12345, "AAAAA 11111"]:
        with pytest.raises(br.BreachError) as exc:
            chk.check_password("t1", digest=bad, now=NOW)
        assert exc.value.code == "BREACH_INVALID_DIGEST"
    with pytest.raises(br.BreachError) as exc:
        chk.query_prefix("t1", prefix="ZZZZZ", now=NOW)
    assert exc.value.code == "BREACH_INVALID_DIGEST"
    assert spy.calls == []


def test_tenant_registration_errors():
    chk, spy = checker({"AAAAA": []})
    register(chk, budget=2)
    with pytest.raises(br.BreachError) as exc:
        register(chk, budget=2)
    assert exc.value.code == "BREACH_TENANT_EXISTS"
    with pytest.raises(br.BreachError) as exc:
        chk.register_tenant("t2", budget=-1)
    assert exc.value.code == "BREACH_INVALID_POLICY"
    with pytest.raises(br.BreachError) as exc:
        chk.register_tenant("t3", budget=2, offline_mode="maybe")
    assert exc.value.code == "BREACH_INVALID_POLICY"
    with pytest.raises(br.BreachError) as exc:
        chk.check_password("ghost", digest="AAAAA111111", now=NOW)
    assert exc.value.code == "BREACH_UNKNOWN_TENANT"
    with pytest.raises(br.BreachError) as exc:
        chk.tenant_policy("ghost")
    assert exc.value.code == "BREACH_UNKNOWN_TENANT"


def test_submit_change_accepts_clear_password():
    chk, spy = checker({"AAAAA": ["0A1B2C"]})
    register(chk, budget=4)
    out = chk.submit_change("t1", "u-1", digest="AAAAA777777", now=NOW)
    assert out.status == "accepted"
    assert out.code == "PASSWORD_ACCEPTED"
    assert out.allowed is True
    assert chk.budget_remaining("t1") == 3


def test_purge_cache_drops_expired_buckets():
    chk, spy = checker({"AAAAA": [], "BBBBB": []})
    register(chk, budget=4)
    chk.query_prefix("t1", prefix="AAAAA", now=NOW)
    assert chk.purge_cache(now=NOW + 3599) == 0
    assert chk.purge_cache(now=NOW + 3600) == 1
    assert chk.bucket_state("AAAAA") is None
    assert chk.bucket_state("BBBBB") is None
    assert chk.query_prefix("t1", prefix="AAAAA", now=NOW + 3601).source == "network"
    assert spy.calls == ["AAAAA", "AAAAA"]


def test_snapshot_is_detached_and_restore_roundtrips():
    chk, spy = checker({"AAAAA": ["0A1B2C"]})
    register(chk, budget=4, offline_mode="allow")
    chk.check_password("t1", digest="AAAAA0A1B2C", now=NOW)
    chk.mark_login_failure("u-1")
    chk.mark_login_failure("u-1")
    state = chk.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "tenants", "buckets", "login_failures", "stats"}
    state["tenants"].clear()
    state["buckets"].clear()
    state["stats"]["fetches"] = 99
    assert chk.stats()["fetches"] == 1
    assert chk.budget_remaining("t1") == 3
    assert chk.login_locked("u-1") is False
    clone, clone_spy = checker({"AAAAA": []})
    clone.restore(pristine)
    assert clone.stats() == chk.stats()
    assert clone.budget_remaining("t1") == 3
    assert clone.bucket_state("AAAAA")["version"] == 1
    assert clone.check_password("t1", digest="AAAAA0A1B2C", now=NOW + 1).status == "breached"
    assert clone_spy.calls == []


def test_restore_rejects_malformed_state():
    chk, spy = checker({"AAAAA": []})
    register(chk, budget=4)
    chk.check_password("t1", digest="AAAAA111111", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "tenants": {}, "buckets": {}, "login_failures": {}, "stats": {}},
        {"version": 1, "tenants": [], "buckets": {}, "login_failures": {}, "stats": {}},
        {"version": 1, "tenants": {}, "buckets": [], "login_failures": {}, "stats": {}},
        {"version": 1, "tenants": {}, "buckets": {}, "login_failures": {},
         "stats": {"fetches": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(br.BreachError) as exc:
            chk.restore(bad)
        assert exc.value.code == "BREACH_SNAPSHOT_INVALID"
    assert chk.budget_remaining("t1") == 3
    assert chk.bucket_state("AAAAA")["version"] == 1


def test_concurrent_same_prefix_shares_one_fetch():
    chk, spy = checker({"AAAAA": ["0A1B2C"]})
    register(chk, budget=5)
    results = []
    errors = []
    barrier = threading.Barrier(6)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(chk.check_password("t1", digest="AAAAA0A1B2C", now=NOW))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert [row.status for row in results] == ["breached"] * 6
    assert spy.calls == ["AAAAA"]
    assert chk.budget_remaining("t1") == 4
    assert chk.stats()["fetches"] == 1
