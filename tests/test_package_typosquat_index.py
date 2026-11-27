import copy

import pytest

import package_typosquat_index as tp


def index(**kwargs):
    return tp.PackageTyposquatIndex(**kwargs)


def test_add_watch_normalizes_and_lists_sorted():
    idx = index()
    assert idx.add_watch("Requests_Pkg") == "requests-pkg"
    assert idx.add_watch("Django.REST") == "django-rest"
    assert idx.add_watch("Flask") == "flask"
    assert idx.watches() == ["django-rest", "flask", "requests-pkg"]
    assert idx.stats()["watches"] == 3
    assert idx.stats()["watch_adds"] == 3


def test_add_watch_is_idempotent():
    idx = index()
    assert idx.add_watch("requests") == "requests"
    assert idx.add_watch("  REQUESTS  ") == "requests"
    assert idx.add_watch("Requests") == "requests"
    assert idx.watches() == ["requests"]
    assert idx.stats()["watches"] == 1
    assert idx.stats()["watch_adds"] == 1


def test_add_watch_rejects_bad_names():
    idx = index()
    for bad in ["", "   ", None, 42, "a" * 65]:
        with pytest.raises(tp.TyposquatError) as exc:
            idx.add_watch(bad)
        assert exc.value.code == "TYPO_INVALID_NAME"
    assert idx.watches() == []
    assert idx.stats()["watch_adds"] == 0


def test_watch_capacity_is_hard_limit():
    idx = index(max_watches=2)
    idx.add_watch("requests")
    idx.add_watch("flask")
    with pytest.raises(tp.TyposquatError) as exc:
        idx.add_watch("numpy")
    assert exc.value.code == "TYPO_WATCH_LIMIT"
    assert idx.watches() == ["flask", "requests"]
    assert idx.add_watch("requests") == "requests"


def test_remove_watch_reports_whether_removed():
    idx = index()
    idx.add_watch("requests")
    idx.add_watch("flask")
    assert idx.remove_watch("Requests") is True
    assert idx.watches() == ["flask"]
    assert idx.remove_watch("requests") is False
    assert idx.stats()["removed"] == 1
    assert idx.stats()["watches"] == 1


def test_similarity_identical_names_are_one():
    idx = index()
    assert idx.similarity("requests", "requests") == 1.0
    assert idx.similarity("Requests", "requests") == 1.0
    assert idx.similarity("requests", "  requests  ") == 1.0


def test_similarity_counts_single_edit_over_longest_name():
    idx = index()
    assert idx.similarity("requests", "request") == 0.875
    assert idx.similarity("request", "requests") == 0.875


def test_similarity_discounts_keyboard_neighbours():
    idx = index()
    assert idx.similarity("requests", "requesys") == 0.9375
    assert idx.similarity("requests", "requesys") < 1.0


def test_similarity_is_symmetric_and_bounded():
    idx = index()
    assert idx.similarity("flask", "flaskk") == 0.8333
    assert idx.similarity("flaskk", "flask") == 0.8333
    assert idx.similarity("requests", "numpy") < 0.5
    assert 0.0 <= idx.similarity("requests", "numpy") <= 1.0


def test_classify_exact_match():
    idx = index()
    idx.add_watch("requests")
    out = idx.classify("Requests")
    assert out == {"level": "exact", "package": "requests", "similarity": 1.0}


def test_classify_high_and_near_bands():
    idx = index()
    idx.add_watch("sqlalchemy")
    idx.add_watch("requests")
    high = idx.classify("sqlalchemx")
    assert high["level"] == "high"
    assert high["package"] == "sqlalchemy"
    assert high["similarity"] == 0.9
    near = idx.classify("request")
    assert near["level"] == "near"
    assert near["package"] == "requests"
    assert near["similarity"] == 0.875
    assert idx.stats()["queries"] == 2


def test_classify_reports_far_when_nothing_close():
    idx = index()
    idx.add_watch("requests")
    out = idx.classify("totally-different-thing")
    assert out["level"] == "far"
    assert out["package"] is None
    assert 0.0 <= out["similarity"] < 0.8


def test_candidate_sorts_by_similarity_then_name():
    idx = index()
    idx.add_watch("requestes")
    idx.add_watch("requests")
    idx.add_watch("flask")
    rows = idx.candidate("requestss")
    assert [row["package"] for row in rows] == ["requestes", "requests"]
    assert [row["similarity"] for row in rows] == [0.8889, 0.8889]
    assert [row["level"] for row in rows] == ["near", "near"]
    assert idx.candidate("requestss", limit=1) == [
        {"package": "requestes", "similarity": 0.8889, "level": "near"},
    ]
    assert idx.candidate("requestss", limit=0) == []


def test_observe_records_history_per_watch():
    idx = index()
    idx.add_watch("requests")
    idx.add_watch("sqlalchemy")
    out = idx.observe("request")
    assert out["recorded"] == ["requests"]
    assert out["package"] == "requests"
    assert out["level"] == "near"
    assert out["similarity"] == 0.875
    assert idx.history_for("requests") == ["request"]
    idx.observe("request")
    assert idx.history_for("requests") == ["request"]
    idx.observe("requests")
    assert idx.history_for("requests") == ["request", "requests"]
    assert idx.history_for("sqlalchemy") == []
    assert idx.history_for("never-watched") == []
    assert idx.stats()["observed"] == 3


def test_snapshot_roundtrip_and_counters():
    idx = index()
    idx.add_watch("requests")
    idx.observe("request")
    idx.classify("request")
    state = idx.snapshot()
    assert set(state) == {"version", "watches", "history", "thresholds", "stats"}
    pristine = copy.deepcopy(state)
    assert pristine["watches"] == ["requests"]
    assert pristine["history"]["requests"] == ["request"]
    assert pristine["thresholds"] == {"high": 0.9, "near": 0.8}

    before = dict(idx.stats())
    assert before["watches"] == 1
    assert before["observed"] == 1
    assert before["queries"] == 1

    state["watches"].clear()
    state["stats"]["observed"] = 99
    assert idx.watches() == ["requests"]
    assert idx.stats()["observed"] == 1

    clone = index()
    clone.restore(pristine)
    assert clone.watches() == ["requests"]
    assert clone.history_for("requests") == ["request"]
    assert clone.stats()["restores"] == 1
    assert clone.stats()["observed"] == 1
    assert clone.classify("request")["similarity"] == 0.875

    for bad in [None, {}, {"version": 2, "watches": [], "history": {}, "thresholds": {}}]:
        with pytest.raises(tp.TyposquatError) as exc:
            clone.restore(bad)
        assert exc.value.code == "TYPO_SNAPSHOT_INVALID"
    assert clone.watches() == ["requests"]
    assert clone.stats()["restores"] == 1
