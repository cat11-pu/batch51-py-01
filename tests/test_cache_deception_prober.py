import copy
import threading

import pytest

import cache_deception_prober as cdp

ORIGIN = "https://cdn.example.com"
MARKER = "ALICE-PRIVATE-42"


def _auth(headers):
    return any(name.lower() == "authorization" for name in headers)


def pages_fetcher(pages):
    def fetch(method, url, headers):
        path = url[len(ORIGIN):]
        key = (path, _auth(headers))
        if key not in pages:
            return cdp.Response(404, {}, "not found")
        return pages[key]

    return fetch


def build(pages=None, **kwargs):
    kwargs.setdefault("origin", ORIGIN)
    kwargs.setdefault("max_probes_per_path", 7)
    return cdp.CacheDeceptionProber(fetcher=pages_fetcher(pages or {}), **kwargs)


def test_plan_emits_fixed_variant_order():
    prober = build()
    variants = prober.plan("/account/settings")
    assert [v.kind for v in variants] == [
        "css", "js", "jpg", "semicolon", "null_byte", "uppercase", "extra_slash"
    ]
    assert [v.path for v in variants] == [
        "/account/settings.css",
        "/account/settings.js",
        "/account/settings.jpg",
        "/account/settings;.css",
        "/account/settings%00.css",
        "/account/settings.Css",
        "/account/settings/.css",
    ]
    assert {v.auth_required for v in variants} == {True}
    assert len({v.variant_id for v in variants}) == 7


def test_plan_caps_variant_count_and_normalises_trailing_slash():
    prober = build(max_probes_per_path=3)
    variants = prober.plan("/account/orders/")
    assert len(variants) == 3
    assert variants[0].path == "/account/orders.css"
    assert variants[2].path == "/account/orders.jpg"
    assert prober.plan("/account/orders")[0].path == "/account/orders.css"


def test_plan_rejects_paths_outside_private_prefix():
    prober = build()
    for path in ("/public/report", "/accounting/ledger", "/"):
        with pytest.raises(cdp.CacheError) as exc:
            prober.plan(path)
        assert exc.value.code == "CACHE_PATH_FORBIDDEN"


def test_probe_issues_authenticated_requests_and_records_state():
    seen = []

    def fetch(method, url, headers):
        seen.append((method, url, dict(headers)))
        return cdp.Response(200, {"age": "0"}, MARKER)

    prober = cdp.CacheDeceptionProber(origin=ORIGIN, fetcher=fetch, max_probes_per_path=7)
    records = prober.probe("/account/settings", victim_marker=MARKER)
    assert len(records) == 7
    assert len(seen) == 7
    assert all("Authorization" in headers for _, _, headers in seen)
    assert [record.first_status for record in records] == [200] * 7
    assert records[0].cache_key == "cdn.example.com/account/settings.css"
    assert dict(records[0].first_headers)["age"] == "0"
    assert records[0].requests == 1
    assert prober.probes_for("/account/settings") == records
    assert prober.stats() == {
        "probes": 7,
        "verifications": 0,
        "requests": 7,
        "cached": 0,
        "not_cached": 0,
    }


def test_probe_rejects_blank_victim_marker():
    prober = build()
    for marker in ("", "   ", None):
        with pytest.raises(cdp.CacheError) as exc:
            prober.probe("/account/settings", victim_marker=marker)
        assert exc.value.code == "CACHE_INVALID_REQUEST"
    assert prober.stats()["requests"] == 0


def test_cache_key_normalises_host_and_repeated_slashes():
    prober = build()
    assert prober.cache_key_for(ORIGIN + "//account///settings/") == (
        "cdn.example.com/account/settings"
    )
    assert prober.cache_key_for("https://CDN.EXAMPLE.COM/account/settings") == (
        "cdn.example.com/account/settings"
    )
    assert prober.cache_key_for(ORIGIN + "/account/") == "cdn.example.com/account"


def test_verify_marks_hit_when_anonymous_request_returns_marker():
    pages = {
        ("/account/invoices.css", True): cdp.Response(200, {"age": "0"}, MARKER),
        ("/account/invoices.css", False): cdp.Response(
            200, {"age": "240", "x-cache": "HIT"}, MARKER
        ),
    }
    prober = build(pages)
    records = prober.probe("/account/invoices", victim_marker=MARKER)
    verdict = prober.verify_cache(records[0].probe_id)
    assert verdict.status == "cached"
    assert verdict.reason == "anonymous_marker_hit"
    assert verdict.evidence["second_status"] == 200
    assert verdict.evidence["age"] == "240"
    assert prober.stats()["cached"] == 1
    assert prober.stats()["requests"] == 8


def test_verify_treats_anonymous_miss_as_not_cached():
    pages = {("/account/invoices.css", True): cdp.Response(200, {}, MARKER)}
    prober = build(pages)
    records = prober.probe("/account/invoices", victim_marker=MARKER)
    verdict = prober.verify_cache(records[0].probe_id)
    assert verdict.status == "not_cached"
    assert verdict.reason == "anonymous_miss"
    assert verdict.evidence["second_status"] == 404
    assert prober.stats()["not_cached"] == 1
    assert prober.stats()["requests"] == 8


def test_vary_cookie_blocks_caching_without_second_request():
    pages = {
        ("/account/profile.css", True): cdp.Response(200, {"vary": "Cookie, Accept-Encoding"}, MARKER)
    }
    prober = build(pages)
    records = prober.probe("/account/profile", victim_marker=MARKER)
    verdict = prober.verify_cache(records[0].probe_id)
    assert verdict.status == "not_cached"
    assert verdict.reason == "vary_cookie"
    assert prober.stats()["requests"] == 7


def test_no_store_blocks_caching_without_second_request():
    pages = {
        ("/account/profile.css", True): cdp.Response(
            200, {"cache-control": "no-store, max-age=0"}, MARKER
        )
    }
    prober = build(pages)
    records = prober.probe("/account/profile", victim_marker=MARKER)
    verdict = prober.verify_cache(records[0].probe_id)
    assert verdict.status == "not_cached"
    assert verdict.reason == "no_store"
    assert prober.stats()["requests"] == 7


def test_classify_is_inconclusive_until_verified():
    pages = {
        ("/account/invoices.css", True): cdp.Response(200, {}, MARKER),
        ("/account/invoices.css", False): cdp.Response(200, {}, MARKER),
    }
    prober = build(pages)
    records = prober.probe("/account/invoices", victim_marker=MARKER)
    pending = prober.classify(records[0].probe_id)
    assert pending.status == "inconclusive"
    assert pending.reason == "not_verified"

    verified = prober.verify_cache(records[0].probe_id)
    assert prober.classify(records[0].probe_id) == verified

    for missing in ("css:/account/absent.css", "nope"):
        with pytest.raises(cdp.CacheError) as exc:
            prober.classify(missing)
        assert exc.value.code == "CACHE_PROBE_UNKNOWN"
        with pytest.raises(cdp.CacheError) as exc:
            prober.verify_cache(missing)
        assert exc.value.code == "CACHE_PROBE_UNKNOWN"


def test_report_counts_verdicts_and_sorted_paths():
    pages = {
        ("/account/a.css", True): cdp.Response(200, {}, MARKER),
        ("/account/a.css", False): cdp.Response(200, {}, MARKER),
        ("/account/b.css", True): cdp.Response(200, {}, MARKER),
    }
    prober = build(pages)
    records_a = prober.probe("/account/b", victim_marker=MARKER)
    records_b = prober.probe("/account/a", victim_marker=MARKER)
    prober.verify_cache(records_a[0].probe_id)
    prober.verify_cache(records_b[0].probe_id)
    report = prober.report()
    assert report["origin"] == ORIGIN
    assert report["paths"] == ("/account/a", "/account/b")
    assert report["probes"] == 14
    assert report["requests"] == 16
    assert report["verdicts"] == {"cached": 1, "not_cached": 1, "inconclusive": 12}
    assert report["cached_paths"] == ("/account/a",)


def test_total_request_budget_is_enforced_atomically():
    prober = build({}, max_total_requests=3, max_probes_per_path=7)
    with pytest.raises(cdp.CacheError) as exc:
        prober.probe("/account/settings", victim_marker=MARKER)
    assert exc.value.code == "CACHE_LIMIT_EXCEEDED"
    assert prober.stats()["requests"] == 3
    assert prober.stats()["probes"] == 0
    assert prober.probes_for("/account/settings") == ()


def test_concurrent_probes_of_same_path_share_one_round():
    pages = {
        (path, True): cdp.Response(200, {}, MARKER)
        for path in (
            "/account/settings.css",
            "/account/settings.js",
            "/account/settings.jpg",
            "/account/settings;.css",
            "/account/settings%00.css",
            "/account/settings.Css",
            "/account/settings/.css",
        )
    }
    prober = build(pages)
    barrier = threading.Barrier(6)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(prober.probe("/account/settings", victim_marker=MARKER))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 6
    assert all(len(records) == 7 for records in results)
    assert len({tuple(r.probe_id for r in records) for records in results}) == 1
    assert prober.stats()["requests"] == 7
    assert prober.stats()["probes"] == 7


def test_snapshot_restore_roundtrip_and_invalid_state():
    pages = {
        ("/account/invoices.css", True): cdp.Response(200, {}, MARKER),
        ("/account/invoices.css", False): cdp.Response(200, {}, MARKER),
    }
    prober = build(pages)
    records = prober.probe("/account/invoices", victim_marker=MARKER)
    prober.verify_cache(records[0].probe_id)

    state = prober.snapshot()
    assert set(state) == {"version", "origin", "probes", "verdicts", "stats"}
    pristine = copy.deepcopy(state)
    state["probes"].clear()
    state["stats"]["requests"] = 999
    assert len(prober.probes_for("/account/invoices")) == 7
    assert prober.stats()["requests"] == 8

    clone = build({})
    clone.restore(pristine)
    assert clone.stats()["requests"] == 8
    assert clone.stats()["cached"] == 1
    assert len(clone.probes_for("/account/invoices")) == 7

    for bad in ({}, None, {"version": 1}, {"version": 1, "origin": ORIGIN,
                                         "probes": "nope", "verdicts": {},
                                         "stats": {}}):
        with pytest.raises(cdp.CacheError) as exc:
            clone.restore(bad)
        assert exc.value.code == "CACHE_SNAPSHOT_INVALID"
    assert clone.stats()["requests"] == 8
