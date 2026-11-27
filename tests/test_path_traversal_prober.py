import copy
import threading

import pytest

import path_traversal_prober as probe

TARGET = "https://target.example/app"


def transport_factory(calls):
    def transport(url):
        calls.append(url)
        if "etc/passwd" in url or "%2f" in url:
            return probe.Response(200, "root:x:0:0:root:/root:/bin/sh")
        return probe.Response(200, "<html>home</html>")
    return transport


def prober(**kwargs):
    calls = kwargs.pop("calls", [])
    kwargs.setdefault("transport", transport_factory(calls))
    return probe.PathTraversalProber(**kwargs)


def test_generate_variants_covers_all_layers_in_order():
    p = prober()
    variants = p.generate_variants(depth=2)
    assert len(variants) == len(probe.LAYERS) == 9
    assert [v.layer for v in variants] == list(probe.LAYERS)
    assert variants[0].raw == "../../etc/passwd"
    assert variants[1].raw == "..\\..\\etc/passwd"
    assert variants[2].raw == "..%2f..%2fetc/passwd"
    assert variants[3].raw == "%252e%252e%252f%252e%252e%252fetc/passwd"
    assert variants[5].raw == "..;/..;/etc/passwd"
    assert variants[6].raw == ".../.../etc/passwd"
    assert variants[8].raw == "/etc/passwd"
    assert variants[0].key == probe.variant_key("../../etc/passwd")
    assert p.stats()["generated"] == 9


def test_generate_variants_rejects_invalid_depth():
    p = prober(max_depth=3)
    for depth in (0, -1, 4):
        with pytest.raises(probe.ProbeError) as exc:
            p.generate_variants(depth=depth)
        assert exc.value.code == "PROBE_VARIANT_INVALID"
    with pytest.raises(probe.ProbeError) as exc:
        p.generate_variants(depth="2")
    assert exc.value.code == "PROBE_VARIANT_INVALID"


def test_dedupe_keeps_first_occurrence_and_order():
    p = prober()
    variants = p.generate_variants(depth=1)
    duplicated = variants + (variants[0], variants[3])
    assert len(duplicated) == 11
    deduped = p.dedupe(duplicated)
    assert len(deduped) == 9
    assert [v.layer for v in deduped] == list(probe.LAYERS)
    assert deduped[0] == variants[0]
    same_length = probe.Variant("plain", "../a", "k1"), probe.Variant(
        "backslash", "..\\a", "k2")
    assert p.dedupe(same_length) == same_length


def test_send_uses_one_baseline_per_length():
    calls = []
    p = prober(calls=calls)
    variants = p.generate_variants(depth=1)
    records = p.send(TARGET, variants)
    expected_baselines = len({len(v.raw) for v in variants})
    assert len(records) == 9
    assert len(calls) == expected_baselines + 9
    first = records[0]
    assert probe.baseline_path(TARGET, 13) == "https://target.example/app/" + "a" * 13
    assert (first.layer, first.raw, first.key) == (
        "plain", "../etc/passwd", probe.variant_key("../etc/passwd"))
    assert first.baseline_status == 200
    assert first.baseline_length == len(first.baseline_body)
    assert first.variant_body == "root:x:0:0:root:/root:/bin/sh"
    assert p.stats()["sent"] == 9
    assert p.stats()["requests"] == len(calls)


def test_send_reuses_cached_baseline_on_second_call():
    calls = []
    p = prober(calls=calls)
    variants = p.generate_variants(depth=1)
    p.send(TARGET, variants)
    after_first = len(calls)
    records = p.send(TARGET, variants)
    assert len(calls) == after_first + 9
    assert len(records) == 9
    assert p.stats()["requests"] == len(calls)


def test_send_rejects_bad_target_and_request_budget():
    calls = []
    p = prober(calls=calls, max_requests=10)
    variants = p.generate_variants(depth=1)
    with pytest.raises(probe.ProbeError) as exc:
        p.send("ftp://target.example/app", variants)
    assert exc.value.code == "PROBE_TARGET_INVALID"
    with pytest.raises(probe.ProbeError) as exc:
        p.send(TARGET, variants)
    assert exc.value.code == "PROBE_REQUEST_LIMIT"
    assert calls == []
    assert p.send(TARGET, ()) == ()


def test_send_propagates_transport_failure():
    def broken(url):
        raise RuntimeError("connection reset")

    p = probe.PathTraversalProber(transport=broken)
    with pytest.raises(probe.ProbeError) as exc:
        p.send(TARGET, p.generate_variants(depth=1))
    assert exc.value.code == "PROBE_TRANSPORT_FAILED"


def test_judge_marks_signature_hit():
    p = prober()
    records = p.send(TARGET, p.generate_variants(depth=1))
    verdicts = p.judge(records)
    assert len(verdicts) == 9
    assert all(v.hit is True for v in verdicts)
    assert all(v.reason == "signature" for v in verdicts)
    assert verdicts[0].key == records[0].key
    assert p.stats()["hits"] == 9


def test_judge_marks_status_and_length_hit():
    p = prober()
    record = probe.ProbeRecord(
        layer="plain", raw="../etc/passwd", key="k", baseline_status=404,
        baseline_length=0, baseline_body="", variant_status=200,
        variant_body="x" * 40)
    verdicts = p.judge([record])
    assert [(v.hit, v.reason) for v in verdicts] == [(True, "length")]


def test_judge_same_200_response_is_a_miss():
    p = prober()
    body = "<html>home</html>"
    record = probe.ProbeRecord(
        layer="plain", raw="../etc/passwd", key="k", baseline_status=200,
        baseline_length=len(body), baseline_body=body, variant_status=200,
        variant_body=body)
    verdicts = p.judge([record])
    assert [(v.hit, v.reason) for v in verdicts] == [(False, "none")]


def test_judge_blocked_responses_are_undecidable():
    p = prober()
    records = [
        probe.ProbeRecord("plain", "../a", "k1", 200, 12, "<html>home</html>",
                          403, "Forbidden"),
        probe.ProbeRecord("plain", "../b", "k2", 200, 12, "<html>home</html>",
                          429, "Too Many Requests"),
    ]
    verdicts = p.judge(records)
    assert [(v.hit, v.reason) for v in verdicts] == [
        (False, "undecidable"), (False, "undecidable")]


def test_report_counts_hits_by_layer():
    p = prober()
    records = p.send(TARGET, p.generate_variants(depth=1))
    verdicts = p.judge(records)
    out = p.report(verdicts)
    assert out["total"] == 9
    assert out["hits"] == 9
    assert out["misses"] == 0
    assert out["undecidable"] == 0
    assert out["by_layer"] == {layer: 1 for layer in probe.LAYERS}
    assert out["hit_keys"] == sorted(record.key for record in records)


def test_snapshot_is_detached_and_restore_roundtrips():
    p = prober()
    variants = p.generate_variants(depth=1)
    records = p.send(TARGET, variants)
    p.judge(records)

    state = p.snapshot()
    assert state["counters"] == {"generated": 9, "sent": 9,
                                 "requests": len(state["baselines"]) + 9,
                                 "hits": 9}
    assert len(state["probed"]) == 9
    pristine = copy.deepcopy(state)
    state["baselines"].clear()
    assert p.stats()["sent"] == 9

    clone = prober()
    clone.restore(pristine)
    assert clone.snapshot() == pristine
    assert clone.stats() == p.stats()


def test_restore_rejects_malformed_state_without_touching_data():
    p = prober()
    p.send(TARGET, p.generate_variants(depth=1))
    before = p.stats()
    for bad in (None, {}, {"baselines": [], "probed": [], "counters": {}}):
        with pytest.raises(probe.ProbeError) as exc:
            p.restore(bad)
        assert exc.value.code == "PROBE_SNAPSHOT_INVALID"
    assert p.stats() == before


def test_concurrent_send_fetches_baseline_once():
    calls = []
    p = prober(calls=calls, max_requests=64)
    variants = p.generate_variants(depth=1)
    errors = []
    barrier = threading.Barrier(9)

    def worker(variant):
        try:
            barrier.wait(timeout=5)
            p.send(TARGET, (variant,))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(variant,))
               for variant in variants]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    expected_baselines = len({len(v.raw) for v in variants})
    assert len(calls) == expected_baselines + 9
    assert p.stats()["sent"] == 9
