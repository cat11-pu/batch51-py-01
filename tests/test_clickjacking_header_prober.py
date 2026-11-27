import copy
import threading
import time

import pytest

import clickjacking_header_prober as hcp

TARGET = "https://shop.example.com/checkout"
LOGIN = "https://shop.example.com/login"


def pages_fetcher(pages):
    def fetch(url):
        if url not in pages:
            raise AssertionError(f"unexpected fetch for {url}")
        return pages[url]

    return fetch


def build(pages=None, **kwargs):
    kwargs.setdefault("fetcher", pages_fetcher(pages or {}))
    return hcp.ClickjackingHeaderProber(**kwargs)


def page(status=200, headers=None):
    return {"status": status, "headers": dict(headers or {})}


def hs(headers, url=TARGET, status=200):
    return hcp.HeaderSet(
        url=url,
        status=status,
        pairs=tuple((name.lower(), value) for name, value in headers.items()),
        hops=(url,),
    )


def test_fetch_headers_keeps_lowercase_names_and_order():
    prober = build({TARGET: page(headers={
        "X-Frame-Options": "SAMEORIGIN",
        "Content-Type": "text/html; charset=utf-8",
    })})
    result = prober.fetch_headers(TARGET)
    assert result.status == 200
    assert result.url == TARGET
    assert result.hops == (TARGET,)
    assert result.pairs == (
        ("x-frame-options", "SAMEORIGIN"),
        ("content-type", "text/html; charset=utf-8"),
    )


def test_fetch_headers_follows_redirect_chain():
    prober = build({
        TARGET: page(302, {"Location": LOGIN}),
        LOGIN: page(200, {"Content-Security-Policy": "frame-ancestors 'self'"}),
    })
    result = prober.fetch_headers(TARGET)
    assert result.status == 200
    assert result.hops == (TARGET, LOGIN)
    assert dict(result.pairs)["content-security-policy"] == "frame-ancestors 'self'"


def test_fetch_headers_stops_at_redirect_limit():
    first = "https://shop.example.com/a"
    second = "https://shop.example.com/b"
    third = "https://shop.example.com/c"
    prober = build({
        first: page(301, {"Location": second}),
        second: page(301, {"Location": third}),
        third: page(301, {"Location": first}),
    }, max_redirects=1)
    with pytest.raises(hcp.FrameError) as exc:
        prober.fetch_headers(first)
    assert exc.value.code == "FRAME_REDIRECT_LIMIT"


def test_parse_xfo_accepts_deny_and_sameorigin():
    prober = build()
    deny = prober.parse_xfo(hs({"X-Frame-Options": "DENY"}))
    assert (deny.mode, deny.supported, deny.raw) == ("deny", True, "DENY")
    same = prober.parse_xfo(hs({"X-Frame-Options": "SAMEORIGIN"}))
    assert (same.mode, same.supported, same.raw) == ("sameorigin", True, "SAMEORIGIN")


def test_parse_xfo_treats_allow_from_as_unsupported():
    prober = build()
    policy = prober.parse_xfo(hs({"X-Frame-Options": "ALLOW-FROM https://partner.example"}))
    assert policy.mode == "unsupported"
    assert policy.supported is False


def test_parse_xfo_rejects_unknown_values():
    prober = build()
    with pytest.raises(hcp.FrameError) as exc:
        prober.parse_xfo(hs({"X-Frame-Options": "ALLOWALL"}))
    assert exc.value.code == "FRAME_HEADER_INVALID"


def test_parse_frame_ancestors_reads_directive_sources():
    prober = build()
    parsed = prober.parse_frame_ancestors(hs({
        "Content-Security-Policy": (
            "default-src 'self'; frame-ancestors 'self' https://app.example.com:8443; report-uri /csp"
        )
    }))
    assert parsed.present is True
    assert parsed.sources == ("'self'", "https://app.example.com:8443")


def test_parse_frame_ancestors_absent_and_empty_directive():
    prober = build()
    absent = prober.parse_frame_ancestors(hs({"X-Frame-Options": "DENY"}))
    assert absent.present is False
    assert absent.sources == ()
    with pytest.raises(hcp.FrameError) as exc:
        prober.parse_frame_ancestors(hs({"Content-Security-Policy": "frame-ancestors"}))
    assert exc.value.code == "FRAME_HEADER_INVALID"


def test_evaluate_csp_self_only_allows_same_origin():
    prober = build({TARGET: page(headers={
        "Content-Security-Policy": "frame-ancestors 'self'",
    })})
    allowed = prober.evaluate(TARGET, ancestors=("https://shop.example.com",))
    assert (allowed.status, allowed.reason) == ("embeddable", "csp_allows")
    blocked = prober.evaluate(TARGET, ancestors=("https://evil.example",))
    assert (blocked.status, blocked.reason) == ("blocked", "csp_blocks")
    assert blocked.evidence["ancestors"] == ("https://evil.example",)


def test_evaluate_csp_matches_host_and_port_exactly():
    prober = build({TARGET: page(headers={
        "Content-Security-Policy": "frame-ancestors https://app.example.com:8443",
    })})
    assert prober.evaluate(TARGET, ancestors=("https://app.example.com:8443",)).status == "embeddable"
    assert prober.evaluate(TARGET, ancestors=("https://app.example.com",)).status == "blocked"
    assert prober.evaluate(TARGET, ancestors=("http://app.example.com:8443",)).status == "blocked"


def test_evaluate_without_any_header_is_embeddable():
    prober = build({TARGET: page()})
    verdict = prober.evaluate(TARGET, ancestors=("https://evil.example",))
    assert (verdict.status, verdict.reason) == ("embeddable", "no_protection")


def test_evaluate_requires_every_ancestor_in_chain():
    prober = build({TARGET: page(headers={
        "Content-Security-Policy": (
            "frame-ancestors https://outer.example https://inner.example"
        )
    })})
    allowed = prober.evaluate(
        TARGET, ancestors=("https://outer.example", "https://inner.example")
    )
    assert (allowed.status, allowed.reason) == ("embeddable", "csp_allows")
    blocked = prober.evaluate(
        TARGET, ancestors=("https://outer.example", "https://evil.example")
    )
    assert (blocked.status, blocked.reason) == ("blocked", "csp_blocks")


def test_concurrent_probes_of_one_target_are_serialised():
    state = {"inflight": 0, "peak": 0}
    guard = threading.Lock()

    def fetch(url):
        with guard:
            state["inflight"] += 1
            state["peak"] = max(state["peak"], state["inflight"])
        time.sleep(0.01)
        with guard:
            state["inflight"] -= 1
        return page({"X-Frame-Options": "DENY"})

    prober = hcp.ClickjackingHeaderProber(fetcher=fetch, max_probes_per_target=8)
    barrier = threading.Barrier(6)
    verdicts = []
    errors = []

    def worker(index):
        try:
            barrier.wait(timeout=5)
            verdicts.append(
                prober.evaluate(TARGET, ancestors=(f"https://a{index}.example",))
            )
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(verdicts) == 6
    assert {verdict.status for verdict in verdicts} == {"blocked"}
    assert state["peak"] == 1
    assert prober.stats()["probes"] == 6


def test_probe_cap_and_report_aggregation():
    prober = build({TARGET: page(headers={"X-Frame-Options": "DENY"})},
                   max_probes_per_target=2)
    prober.evaluate(TARGET, ancestors=("https://a.example",))
    prober.evaluate(TARGET, ancestors=("https://b.example",))
    with pytest.raises(hcp.FrameError) as exc:
        prober.evaluate(TARGET, ancestors=("https://c.example",))
    assert exc.value.code == "FRAME_PROBE_LIMIT_EXCEEDED"

    report = prober.report()
    assert set(report) == {"targets", "embeddable", "blocked", "counts", "probes"}
    assert report["targets"] == ("https://shop.example.com",)
    assert report["blocked"] == ("https://shop.example.com",)
    assert report["embeddable"] == ()
    assert report["counts"] == {"embeddable": 0, "blocked": 1}
    assert report["probes"] == 2
    assert prober.probe_count("https://shop.example.com") == 2


def test_snapshot_restore_roundtrip_and_invalid_state():
    prober = build({TARGET: page(headers={"X-Frame-Options": "DENY"})})
    prober.evaluate(TARGET, ancestors=("https://a.example",))
    state = prober.snapshot()
    assert set(state) == {"version", "probes", "verdicts", "stats"}
    pristine = copy.deepcopy(state)
    state["probes"].clear()
    state["stats"]["probes"] = 99
    assert prober.stats()["probes"] == 1
    assert prober.report()["probes"] == 1

    clone = build({})
    clone.restore(pristine)
    assert clone.stats() == prober.stats()
    assert clone.probe_count("https://shop.example.com") == 1
    assert clone.report()["blocked"] == ("https://shop.example.com",)

    for bad in ({}, None, {"version": 1}, {"version": 1, "probes": "nope",
                                         "verdicts": {}, "stats": {}}):
        with pytest.raises(hcp.FrameError) as exc:
            clone.restore(bad)
        assert exc.value.code == "FRAME_SNAPSHOT_INVALID"
    assert clone.stats()["probes"] == 1
