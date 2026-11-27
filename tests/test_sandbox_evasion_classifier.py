import copy
import threading

import pytest

import sandbox_evasion_classifier as sandbox


def classifier(**kwargs):
    return sandbox.SandboxEvasionClassifier(**kwargs)


def test_ingest_records_hit_with_effective_score():
    box = classifier()
    hit = box.ingest_event("s1", "name_blocklist", key="proc.exe", ts_ms=100)
    assert (hit.indicator, hit.category, hit.key, hit.ts_ms, hit.effective) == (
        "name_blocklist", "identity", "proc.exe", 100, 36)
    assert sandbox.effective_score(30, 0.5) == 15
    assert sandbox.effective_score(35, 0.9) == 31
    assert box.stats() == {"samples": 1, "hits": 1, "duplicates": 0,
                           "truncated": 0, "resets": 0}


def test_ingest_rejects_unknown_indicator_and_bad_arguments():
    box = classifier()
    with pytest.raises(sandbox.SandboxError) as exc:
        box.ingest_event("s1", "sleep_forever")
    assert exc.value.code == "SANDBOX_UNKNOWN_INDICATOR"

    with pytest.raises(sandbox.SandboxError) as exc:
        box.ingest_event("", "no_input")
    assert exc.value.code == "SANDBOX_SAMPLE_INVALID"

    with pytest.raises(sandbox.SandboxError) as exc:
        box.ingest_event("s1", "no_input", ts_ms=-1)
    assert exc.value.code == "SANDBOX_EVENT_INVALID"

    with pytest.raises(sandbox.SandboxError) as exc:
        box.ingest_event("s1", "no_input", key=5)
    assert exc.value.code == "SANDBOX_EVENT_INVALID"
    assert box.stats()["hits"] == 0


def test_window_dedupe_counts_signal_once():
    box = classifier(window_ms=1000)
    first = box.ingest_event("s1", "name_blocklist", key="a.exe", ts_ms=1000)
    duplicate = box.ingest_event("s1", "name_blocklist", key="a.exe", ts_ms=1999)
    assert first.ts_ms == 1000
    assert duplicate.ts_ms == 1000
    assert box.stats()["hits"] == 1
    assert box.stats()["duplicates"] == 1

    later = box.ingest_event("s1", "name_blocklist", key="a.exe", ts_ms=2000)
    assert later.ts_ms == 2000
    assert box.stats()["hits"] == 2
    assert box.stats()["duplicates"] == 1


def test_category_score_takes_max_not_sum():
    box = classifier()
    box.ingest_event("s1", "env_vm", key="vmware", ts_ms=0)
    box.ingest_event("s1", "debugger_attach", key="dbg", ts_ms=1)
    box.ingest_event("s1", "debugger_attach", key="dbg2", ts_ms=2)
    verdict = box.evaluate("s1")
    assert verdict.hits == 3
    assert verdict.categories == ("environment",)
    assert verdict.score == 31
    assert verdict.verdict == "suspicious"
    assert verdict.truncated is False


def test_low_score_stays_clean():
    box = classifier()
    box.ingest_event("s1", "no_input", key="mouse", ts_ms=0)
    verdict = box.evaluate("s1")
    assert (verdict.score, verdict.verdict, verdict.categories) == (
        12, "clean", ("interaction",))


def test_single_category_cannot_reach_evasive():
    box = classifier()
    box.add_indicator("heavy", "custom", 100, 1.0)
    box.ingest_event("s1", "heavy", key="k", ts_ms=0)
    verdict = box.evaluate("s1")
    assert (verdict.score, verdict.verdict, verdict.categories) == (
        100, "suspicious", ("custom",))
    assert sandbox.classify_score(100, ("custom",)) == "suspicious"


def test_multiple_categories_reach_evasive():
    box = classifier()
    box.ingest_event("s1", "name_blocklist", key="a", ts_ms=0)
    box.ingest_event("s1", "debugger_attach", key="b", ts_ms=1)
    box.ingest_event("s1", "no_input", key="c", ts_ms=2)
    verdict = box.evaluate("s1")
    assert verdict.score == 79
    assert verdict.categories == ("environment", "identity", "interaction")
    assert verdict.verdict == "evasive"
    assert sandbox.classify_score(79, verdict.categories) == "evasive"


def test_add_indicator_registers_and_scores():
    box = classifier()
    indicator = box.add_indicator("sleep_short", "timing", 20, 0.5)
    assert (indicator.name, indicator.category, indicator.weight,
            indicator.confidence) == ("sleep_short", "timing", 20, 0.5)
    box.ingest_event("s1", "sleep_short", key="k", ts_ms=0)
    assert box.evaluate("s1").score == 10


def test_add_indicator_rejects_invalid_and_duplicate():
    box = classifier()
    with pytest.raises(sandbox.SandboxError) as exc:
        box.add_indicator("no_input", "interaction", 10, 0.5)
    assert exc.value.code == "SANDBOX_INDICATOR_EXISTS"

    invalid = [
        ("zero", "cat", 0, 0.5),
        ("wide", "cat", 10, 1.5),
        ("noname", "cat", 10, 0.5),
        ("", "cat", 10, 0.5),
        ("badweight", "cat", 10.5, 0.5),
    ]
    for name, category, weight, confidence in invalid:
        with pytest.raises(sandbox.SandboxError) as exc:
            box.add_indicator(name, category, weight, confidence)
        assert exc.value.code == "SANDBOX_INDICATOR_INVALID"

    capped = classifier(max_indicators=8)
    capped.add_indicator("extra", "cat", 10, 0.5)
    with pytest.raises(sandbox.SandboxError) as exc:
        capped.add_indicator("overflow", "cat", 10, 0.5)
    assert exc.value.code == "SANDBOX_INDICATOR_LIMIT"


def test_explain_reports_categories_and_ranking():
    box = classifier()
    box.ingest_event("s1", "name_blocklist", key="a", ts_ms=0)
    box.ingest_event("s1", "debugger_attach", key="b", ts_ms=1)
    assert box.explain("s1") == {
        "score": 67,
        "verdict": "suspicious",
        "hits": 2,
        "categories": {
            "environment": {"hits": 1, "score": 31,
                            "indicators": ["debugger_attach"]},
            "identity": {"hits": 1, "score": 36,
                         "indicators": ["name_blocklist"]},
        },
        "top": ["name_blocklist", "debugger_attach"],
    }


def test_reset_clears_sample_and_counts():
    box = classifier()
    box.ingest_event("s1", "name_blocklist", key="a", ts_ms=0)
    box.ingest_event("s1", "no_input", key="b", ts_ms=1)
    assert box.reset("s1") == 2
    verdict = box.evaluate("s1")
    assert (verdict.score, verdict.hits, verdict.verdict) == (0, 0, "clean")
    assert box.stats()["resets"] == 1
    with pytest.raises(sandbox.SandboxError) as exc:
        box.reset("missing")
    assert exc.value.code == "SANDBOX_SAMPLE_UNKNOWN"


def test_unknown_sample_raises_for_evaluate_and_explain():
    box = classifier()
    for call in (box.evaluate, box.explain):
        with pytest.raises(sandbox.SandboxError) as exc:
            call("missing")
        assert exc.value.code == "SANDBOX_SAMPLE_UNKNOWN"


def test_trace_event_limit_is_enforced():
    box = classifier(max_events=2)
    box.ingest_event("s1", "no_input", key="a", ts_ms=0)
    box.ingest_event("s1", "no_input", key="b", ts_ms=1)
    with pytest.raises(sandbox.SandboxError) as exc:
        box.ingest_event("s1", "no_input", key="c", ts_ms=2)
    assert exc.value.code == "SANDBOX_TRACE_LIMIT"
    assert box.evaluate("s1").hits == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    box = classifier()
    box.add_indicator("custom1", "custom", 50, 1.0)
    box.ingest_event("s1", "custom1", key="k", ts_ms=0)
    box.ingest_event("s1", "debugger_attach", key="d", ts_ms=1)

    state = box.snapshot()
    pristine = copy.deepcopy(state)
    state["samples"].clear()
    assert box.evaluate("s1").score == 81

    clone = classifier()
    clone.restore(pristine)
    assert clone.explain("s1") == box.explain("s1")
    assert clone.stats() == box.stats()
    assert clone.evaluate("s1").score == 81

    for bad in (None, {}, {"samples": [], "indicators": {}}):
        with pytest.raises(sandbox.SandboxError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SANDBOX_SNAPSHOT_INVALID"
    assert clone.stats() == box.stats()


def test_concurrent_ingest_records_every_signal_once():
    box = classifier(max_events=256)
    errors = []
    barrier = threading.Barrier(16)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            box.ingest_event("s1", "no_input", key=f"key-{index}", ts_ms=index)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert box.stats()["hits"] == 16
    assert box.stats()["duplicates"] == 0
    verdict = box.evaluate("s1")
    assert verdict.hits == 16
    assert verdict.score == 12
