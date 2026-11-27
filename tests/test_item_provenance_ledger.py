import copy
import threading

import pytest

import item_provenance_ledger as ip

T0 = "2026-11-24T10:00:00+00:00"
T1 = "2026-11-24T10:05:00+00:00"


def ledger(**kwargs):
    return ip.ItemProvenanceLedger(**kwargs)


def seeded(**kwargs):
    led = ledger(**kwargs)
    led.ingest_event("drop", "sword-1", actor="shard-a", qty=1, at=T0)
    return led


def test_ingest_drop_assigns_first_seq_and_owner():
    led = ledger()
    seq = led.ingest_event("drop", "sword-1", actor="shard-a", qty=1, at=T0)
    assert seq == 1
    assert led.owner_of("sword-1") == "shard-a"
    assert led.qty_of("sword-1") == 1
    events = led.chain_of("sword-1")
    assert len(events) == 1
    assert (events[0].seq, events[0].kind, events[0].instance, events[0].actor) == (
        1, "drop", "sword-1", "shard-a")
    assert led.holdings_of("shard-a") == ["sword-1"]
    assert led.holdings_of("shard-b") == []


def test_event_numbers_are_global_and_monotonic():
    led = ledger()
    first = led.ingest_event("drop", "sword-1", actor="s1", at=T0)
    second = led.ingest_event("craft", "sword-2", actor="s1", qty=3, at=T0)
    third = led.transfer("sword-2", "s1", "s2", at=T1)
    assert (first, second, third) == (1, 2, 3)
    assert [event.seq for event in led.chain_of("sword-2")] == [2, 3]
    assert led.stats() == {"instances": 2, "live": 2, "events": 3, "duplicates": 0,
                           "transfers": 1, "splits": 0, "merges": 0, "quarantined": 0}


def test_repeated_event_key_is_dropped():
    led = ledger()
    first = led.ingest_event("drop", "sword-1", actor="s1", event_key="shard1:e1", at=T0)
    again = led.ingest_event("drop", "sword-1", actor="s1", event_key="shard1:e1", at=T0)
    assert first == again == 1
    assert len(led.chain_of("sword-1")) == 1
    assert led.stats()["duplicates"] == 1
    assert led.stats()["events"] == 1


def test_second_source_event_for_same_instance_is_rejected():
    led = seeded()
    with pytest.raises(ip.LedgerError) as exc:
        led.ingest_event("mail", "sword-1", actor="shard-b", qty=9, at=T1)
    assert exc.value.code == "LEDGER_DUPLICATE_INSTANCE"
    assert led.owner_of("sword-1") == "shard-a"
    assert led.qty_of("sword-1") == 1
    assert len(led.chain_of("sword-1")) == 1
    assert led.stats()["instances"] == 1


def test_invalid_event_input_is_rejected():
    led = ledger()
    bad_calls = [
        dict(kind="sell", instance="sword-1", actor="s1"),
        dict(kind="", instance="sword-1", actor="s1"),
        dict(kind="drop", instance="", actor="s1"),
        dict(kind="drop", instance="   ", actor="s1"),
        dict(kind="drop", instance="sword-1", actor=""),
        dict(kind="drop", instance="sword-1", actor="s1", qty=0),
        dict(kind="drop", instance="sword-1", actor="s1", qty=-2),
    ]
    for kwargs in bad_calls:
        with pytest.raises(ip.LedgerError) as exc:
            led.ingest_event(at=T0, **kwargs)
        assert exc.value.code == "LEDGER_INVALID_EVENT"
    assert led.stats()["events"] == 0
    assert led.stats()["instances"] == 0


def test_transfer_moves_owner_and_appends_event():
    led = ledger()
    led.ingest_event("drop", "sword-1", actor="s1", qty=2, at=T0)
    led.transfer("sword-1", "s1", "s2", at=T1)
    assert led.owner_of("sword-1") == "s2"
    assert led.qty_of("sword-1") == 2
    assert led.holdings_of("s1") == []
    assert led.holdings_of("s2") == ["sword-1"]
    kinds = [event.kind for event in led.chain_of("sword-1")]
    assert kinds == ["drop", "transfer"]
    assert led.chain_of("sword-1")[-1].actor == "s2"
    assert led.stats()["transfers"] == 1


def test_transfer_from_stale_holder_is_rejected():
    led = seeded()
    led.transfer("sword-1", "shard-a", "shard-b", at=T1)
    with pytest.raises(ip.LedgerError) as exc:
        led.transfer("sword-1", "shard-a", "shard-c", at=T1)
    assert exc.value.code == "LEDGER_STALE_HOLDER"
    assert led.owner_of("sword-1") == "shard-b"
    assert len(led.chain_of("sword-1")) == 2
    assert led.stats()["transfers"] == 1
    led.transfer("sword-1", "shard-b", "shard-c", at=T1)
    assert led.owner_of("sword-1") == "shard-c"


def test_unknown_instance_is_reported_consistently():
    led = ledger()
    for call in (lambda: led.owner_of("ghost"),
                 lambda: led.qty_of("ghost"),
                 lambda: led.chain_of("ghost"),
                 lambda: led.transfer("ghost", "s1", "s2"),
                 lambda: led.split("ghost", 1, new_instance="ghost-2")):
        with pytest.raises(ip.LedgerError) as exc:
            call()
        assert exc.value.code == "LEDGER_NO_SUCH_INSTANCE"


def test_split_lets_child_inherit_parent_chain():
    led = ledger()
    led.ingest_event("drop", "stack-1", actor="s1", qty=10, at=T0)
    child = led.split("stack-1", 3, new_instance="stack-2", at=T1)
    assert child == "stack-2"
    assert led.qty_of("stack-1") == 7
    assert led.qty_of("stack-2") == 3
    assert led.owner_of("stack-2") == "s1"
    parent_events = led.chain_of("stack-1")
    child_events = led.chain_of("stack-2")
    assert [event.seq for event in child_events[:-1]] == [
        event.seq for event in parent_events[:-1]]
    assert child_events[-1].kind == "split"
    assert parent_events[-1].kind == "split"
    assert child_events[-1].seq > parent_events[-2].seq
    assert sorted(led.holdings_of("s1")) == ["stack-1", "stack-2"]


def test_split_rejects_bad_quantity_and_taken_id():
    led = ledger()
    led.ingest_event("drop", "stack-1", actor="s1", qty=2, at=T0)
    led.ingest_event("drop", "stack-2", actor="s1", qty=1, at=T0)
    for bad_qty in (0, 2, -1):
        with pytest.raises(ip.LedgerError) as exc:
            led.split("stack-1", bad_qty, new_instance="stack-9", at=T1)
        assert exc.value.code == "LEDGER_QTY_INVALID"
    with pytest.raises(ip.LedgerError) as exc:
        led.split("stack-1", 1, new_instance="stack-2", at=T1)
    assert exc.value.code == "LEDGER_DUPLICATE_INSTANCE"
    assert led.qty_of("stack-1") == 2
    assert led.stats()["splits"] == 0


def test_merge_sums_quantity_and_archives_sources():
    led = ledger()
    led.ingest_event("drop", "a", actor="s1", qty=2, at=T0)
    led.ingest_event("drop", "b", actor="s1", qty=3, at=T0)
    led.ingest_event("drop", "c", actor="s1", qty=5, at=T0)
    total = led.merge("a", ["b", "c"], at=T1)
    assert total == 10
    assert led.qty_of("a") == 10
    assert led.chain_of("a")[-1].kind == "merge"
    assert led.chain_of("b")[-1].kind == "merge"
    assert len(led.chain_of("b")) == 2
    with pytest.raises(ip.LedgerError) as exc:
        led.owner_of("b")
    assert exc.value.code == "LEDGER_NO_SUCH_INSTANCE"
    assert led.holdings_of("s1") == ["a"]
    assert led.stats()["merges"] == 1


def test_chain_length_cap_blocks_new_events():
    led = ledger(max_chain=3)
    led.ingest_event("drop", "x", actor="s1", at=T0)
    led.transfer("x", "s1", "s2", at=T1)
    led.transfer("x", "s2", "s3", at=T1)
    with pytest.raises(ip.LedgerError) as exc:
        led.transfer("x", "s3", "s4", at=T1)
    assert exc.value.code == "LEDGER_CHAIN_LIMIT"
    assert len(led.chain_of("x")) == 3
    assert led.owner_of("x") == "s3"


def test_snapshot_is_detached_and_restore_roundtrips():
    led = ledger()
    led.ingest_event("drop", "a", actor="s1", qty=4, at=T0)
    led.transfer("a", "s1", "s2", at=T1)
    assert led.scan_duplicates() == []
    assert led.quarantine() == []
    state = led.snapshot()
    assert set(state) == {"version", "instances", "chains", "events",
                          "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["instances"].clear()
    state["stats"]["events"] = 99
    assert led.owner_of("a") == "s2"
    clone = ledger()
    clone.restore(pristine)
    assert clone.owner_of("a") == "s2"
    assert clone.qty_of("a") == 4
    assert [event.seq for event in clone.chain_of("a")] == [1, 2]
    assert clone.stats() == led.stats()


def test_restore_rejects_malformed_state():
    led = seeded()
    bad_states = [
        None,
        {},
        {"version": 1, "instances": [], "chains": {}, "events": [],
         "counters": {}, "stats": {}},
        {"version": 1, "instances": {}, "chains": [], "events": [],
         "counters": {}, "stats": {}},
        {"version": 1, "instances": {}, "chains": {}, "events": {},
         "counters": {}, "stats": {}},
        {"version": 1, "instances": {}, "chains": {}, "events": [],
         "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ip.LedgerError) as exc:
            led.restore(bad)
        assert exc.value.code == "LEDGER_SNAPSHOT_INVALID"
    assert led.owner_of("sword-1") == "shard-a"
    assert led.stats()["events"] == 1


def test_concurrent_transfers_let_exactly_one_winner():
    led = seeded()
    winners = []
    failures = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            led.transfer("sword-1", "shard-a", f"buyer-{index}", at=T1)
            winners.append(index)
        except ip.LedgerError as exc:
            failures.append(exc.code)
        except Exception as exc:  # pragma: no cover - surfaced through failures
            failures.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(winners) == 1
    assert failures == ["LEDGER_STALE_HOLDER"] * 7
    assert led.owner_of("sword-1") == f"buyer-{winners[0]}"
    assert len(led.chain_of("sword-1")) == 2
    assert led.stats()["transfers"] == 1
