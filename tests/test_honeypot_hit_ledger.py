import copy
import hashlib

import pytest

import honeypot_hit_ledger as hp

SRC = "203.0.113.7"
CLIENT = "Curl/8.0"
FP_120 = "203.0.113|curl/8.0|120"


def ledger(**kwargs):
    return hp.HoneypotHitLedger(**kwargs)


def hit(led, source=SRC, client=CLIENT, at=125, path="/login"):
    return led.record_hit(source, client=client, path=path, at=at)


def good_stats(**overrides):
    stats = {"hits": 0, "records": 0, "sources": 0, "folded": 0,
             "payloads": 0, "payload_overflow": 0, "restores": 0}
    stats.update(overrides)
    return stats


def test_first_hit_builds_entry_with_exact_fingerprint():
    led = ledger()
    row = hit(led)
    assert row.fingerprint == FP_120
    assert row.subnet == "203.0.113"
    assert row.client == "curl/8.0"
    assert row.window_start == 120
    assert row.hits == 1
    assert row.folded is False
    assert row.first_seen == 125
    assert row.last_seen == 125
    assert row.path == "/login"
    assert row.sources == ("203.0.113.7",)
    assert [entry.fingerprint for entry in led.entries()] == [FP_120]
    assert led.fingerprint_for(SRC, client=CLIENT, at=125) == FP_120


def test_repeat_hit_in_window_folds_without_new_entry():
    led = ledger()
    hit(led, at=125)
    second = hit(led, at=130)
    third = hit(led, at=179)
    assert second.folded is True
    assert third.folded is True
    assert third.hits == 3
    assert third.first_seen == 125
    assert third.last_seen == 179
    assert len(led.entries()) == 1
    assert led.stats()["hits"] == 3
    assert led.stats()["records"] == 1
    assert led.stats()["folded"] == 2


def test_hit_in_next_window_starts_new_entry():
    led = ledger()
    hit(led, at=179)
    later = hit(led, at=180)
    assert later.window_start == 180
    assert later.folded is False
    assert later.hits == 1
    assert [entry.window_start for entry in led.entries()] == [120, 180]
    assert led.stats()["records"] == 2
    assert led.stats()["folded"] == 0


def test_same_subnet_sources_cluster_into_one_fingerprint():
    led = ledger()
    hit(led, source="203.0.113.7", at=125)
    second = hit(led, source="203.0.113.9", at=140)
    assert second.fingerprint == FP_120
    assert second.sources == ("203.0.113.7", "203.0.113.9")
    clusters = led.cluster_by_fingerprint()
    assert len(clusters) == 1
    assert clusters[0].sources == ("203.0.113.7", "203.0.113.9")
    assert clusters[0].hits == 2
    assert len(led.entries()) == 1


def test_cluster_view_is_sorted_and_filterable_by_window():
    led = ledger()
    hit(led, source="203.0.113.7", client="curl", at=125)
    hit(led, source="198.51.100.4", client="curl", at=125)
    hit(led, source="203.0.113.7", client="curl", at=185)
    rows = led.cluster_by_fingerprint()
    assert [row.fingerprint for row in rows] == [
        "198.51.100|curl|120",
        "203.0.113|curl|120",
        "203.0.113|curl|180",
    ]
    only = led.cluster_by_fingerprint(window_start=120)
    assert [row.fingerprint for row in only] == [
        "198.51.100|curl|120",
        "203.0.113|curl|120",
    ]
    assert [row.hits for row in only] == [1, 1]


def test_dedupe_window_reports_records_hits_and_folded():
    led = ledger()
    hit(led, at=125)
    hit(led, at=130)
    hit(led, at=155)
    hit(led, at=190)
    summary = led.dedupe_window(at=150)
    assert summary.window_start == 120
    assert summary.records == 1
    assert summary.hits == 3
    assert summary.folded == 2
    empty = led.dedupe_window(at=0)
    assert empty.window_start == 0
    assert (empty.records, empty.hits, empty.folded) == (0, 0, 0)


def test_archive_small_payload_stores_bytes_and_digest():
    led = ledger()
    row = hit(led)
    body = b"GET /admin HTTP/1.1"
    result = led.archive_payload(row.fingerprint, body, at=130)
    assert result.status == "stored"
    assert result.truncated is False
    assert result.stored_bytes == len(body)
    assert result.digest == hashlib.sha256(body).hexdigest()
    assert result.at == 130
    assert led.payload_for(row.fingerprint) == body
    assert led.stats()["payloads"] == 1
    assert led.stats()["payload_overflow"] == 0


def test_archive_over_single_limit_keeps_digest_only():
    led = ledger(max_payload_bytes=8)
    row = hit(led)
    body = b"0123456789"
    result = led.archive_payload(row.fingerprint, body)
    assert result.status == "digest_only"
    assert result.truncated is True
    assert result.stored_bytes == 0
    assert result.digest == hashlib.sha256(body).hexdigest()
    assert led.payload_for(row.fingerprint) is None
    assert led.stats()["payload_overflow"] == 0


def test_archive_total_budget_degrades_to_digest_only():
    led = ledger(max_payload_bytes=16, max_total_payload=20)
    row = hit(led)
    led.archive_payload(row.fingerprint, b"12345678")
    led.archive_payload(row.fingerprint, b"abcdefgh")
    third = led.archive_payload(row.fingerprint, b"ABCDEFGH")
    assert third.status == "digest_only"
    assert third.truncated is True
    assert third.stored_bytes == 0
    assert led.stats()["payload_overflow"] == 1
    assert led.payload_for(row.fingerprint) == b"abcdefgh"


def test_archive_unknown_fingerprint_is_rejected():
    led = ledger()
    with pytest.raises(hp.HoneypotError) as exc:
        led.archive_payload("203.0.113|anon|0", b"x")
    assert exc.value.code == "HONEY_UNKNOWN_FINGERPRINT"
    assert led.stats()["payloads"] == 0


def test_invalid_hit_inputs_are_rejected():
    led = ledger()
    bad = [
        dict(source_ip="", at=1),
        dict(source_ip="   ", at=1),
        dict(source_ip=SRC, at=-1),
        dict(source_ip=SRC, at="125"),
    ]
    for kwargs in bad:
        with pytest.raises(hp.HoneypotError) as exc:
            led.record_hit(**kwargs)
        assert exc.value.code == "HONEY_INVALID_HIT"
    assert len(led.entries()) == 0
    assert led.stats()["hits"] == 0


def test_entry_cap_blocks_new_fingerprints_but_not_folding():
    led = ledger(max_entries=1)
    hit(led, at=125)
    with pytest.raises(hp.HoneypotError) as exc:
        hit(led, source="198.51.100.4", at=125)
    assert exc.value.code == "HONEY_CAPACITY_EXCEEDED"
    assert len(led.entries()) == 1
    folded = hit(led, source="203.0.113.8", at=140)
    assert folded.hits == 2
    assert led.stats()["records"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    led = ledger()
    row = hit(led)
    led.archive_payload(row.fingerprint, b"body")
    state = led.snapshot()
    assert set(state) == {"version", "window_seconds", "records", "archives", "stats"}
    pristine = copy.deepcopy(state)
    state["records"].clear()
    state["stats"]["hits"] = 999
    assert led.stats()["hits"] == 1
    assert len(led.entries()) == 1

    clone = ledger()
    clone.restore(pristine)
    assert [entry.fingerprint for entry in clone.entries()] == [FP_120]
    assert clone.entries()[0].hits == 1
    assert clone.payload_for(FP_120) == b"body"
    assert clone.stats()["hits"] == 1
    assert clone.stats()["payloads"] == 1
    assert clone.stats()["restores"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    led = ledger()
    hit(led)
    stats = good_stats(hits=1, records=1, sources=1)
    bad_states = [
        None,
        {},
        {"version": 2, "window_seconds": 60, "records": [], "archives": [],
         "stats": stats},
        {"version": 1, "window_seconds": 60, "records": "nope", "archives": [],
         "stats": stats},
        {"version": 1, "window_seconds": 60, "records": [], "archives": [],
         "stats": {"hits": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(hp.HoneypotError) as exc:
            led.restore(bad)
        assert exc.value.code == "HONEY_SNAPSHOT_INVALID"

    assert led.stats() == stats
    assert [entry.fingerprint for entry in led.entries()] == [FP_120]


def test_stats_counts_exact_operations():
    led = ledger()
    row = hit(led, at=125)
    hit(led, source="203.0.113.9", at=130)
    led.archive_payload(row.fingerprint, b"abc")
    assert led.stats() == {
        "hits": 2,
        "records": 1,
        "sources": 2,
        "folded": 1,
        "payloads": 1,
        "payload_overflow": 0,
        "restores": 0,
    }
