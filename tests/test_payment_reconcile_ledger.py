import copy
import threading

import pytest

import payment_reconcile_ledger as pr

SNAPSHOT_KEYS = {"version", "config", "orders", "txns", "balances", "settled",
                 "suspended", "counters"}


def ledger(**kwargs):
    return pr.PaymentReconcileLedger(**kwargs)


def order(g, order_id="o-1", account="acct-a", *, amount=1000, channel="alipay",
          currency="CNY", created_at=0):
    return g.register_order(order_id, account, channel=channel, currency=currency,
                            amount=amount, created_at=created_at)


def txn(txn_id="t-1", order_id="o-1", *, amount=1000, fee=0, channel="alipay",
        currency="CNY", paid_at=5, kind="pay"):
    return pr.ChannelTxn(txn_id=txn_id, order_id=order_id, channel=channel,
                         currency=currency, amount=amount, fee=fee,
                         paid_at=paid_at, kind=kind)


def settled_ledger(amount=1000):
    g = ledger()
    order(g, amount=amount)
    g.ingest(txn(amount=amount, fee=30))
    g.reconcile()
    return g


def test_register_order_validates_and_refuses_duplicates():
    g = ledger()
    created = order(g)
    assert (created.order_id, created.account, created.channel) == (
        "o-1", "acct-a", "alipay")
    assert (created.currency, created.amount, created.created_at) == (
        "CNY", 1000, 0)
    with pytest.raises(pr.ReconcileError) as exc:
        order(g)
    assert exc.value.code == "PAYMENT_ORDER_EXISTS"
    with pytest.raises(pr.ReconcileError) as exc:
        order(g, "o-2", currency="USD")
    assert exc.value.code == "PAYMENT_CURRENCY_MISMATCH"
    for bad_amount in (0, -1):
        with pytest.raises(pr.ReconcileError) as exc:
            order(g, "o-3", amount=bad_amount)
        assert exc.value.code == "PAYMENT_INVALID_AMOUNT"
    with pytest.raises(pr.ReconcileError) as exc:
        order(g, "o-4", account="  ")
    assert exc.value.code == "PAYMENT_INVALID_REQUEST"
    assert g.stats()["orders"] == 1


def test_ingest_applies_each_channel_txn_once():
    g = ledger()
    order(g)
    line = txn(fee=30)
    assert g.ingest(line) == "applied"
    assert g.ingest(line) == "duplicate"
    assert g.stats()["ingested"] == 1
    assert g.stats()["duplicate_txns"] == 1


def test_ingest_rejects_bad_currency_amount_and_unknown_order():
    g = ledger()
    order(g)
    cases = [
        (txn(order_id="o-404"), "PAYMENT_UNKNOWN_ORDER"),
        (txn(currency="USD"), "PAYMENT_CURRENCY_MISMATCH"),
        (txn(amount=0), "PAYMENT_INVALID_AMOUNT"),
        (txn(amount=-10), "PAYMENT_INVALID_AMOUNT"),
        (txn(kind="chargeback"), "PAYMENT_INVALID_REQUEST"),
        (txn(txn_id="   "), "PAYMENT_INVALID_REQUEST"),
    ]
    for bad, code in cases:
        with pytest.raises(pr.ReconcileError) as exc:
            g.ingest(bad)
        assert exc.value.code == code
    assert g.stats()["ingested"] == 0


def test_match_uses_order_amount_and_reports_delta():
    g = ledger()
    order(g)
    g.ingest(txn(amount=990))
    result = g.match("o-1")
    assert (result.order_id, result.status) == ("o-1", "amount_mismatch")
    assert result.txn_id == "t-1"
    assert (result.expected, result.actual, result.delta) == (1000, 990, 10)
    order(g, "o-2", amount=500)
    g.ingest(txn("t-2", "o-2", amount=500))
    matched = g.match("o-2")
    assert (matched.status, matched.txn_id, matched.delta) == ("matched", "t-2", 0)


def test_match_rejects_unknown_order_and_reports_unmatched():
    g = ledger()
    order(g)
    with pytest.raises(pr.ReconcileError) as exc:
        g.match("o-404")
    assert exc.value.code == "PAYMENT_UNKNOWN_ORDER"
    result = g.match("o-1")
    assert (result.status, result.txn_id, result.actual) == ("unmatched", None, 0)
    assert result.delta == 1000


def test_reconcile_credits_once_and_is_idempotent():
    g = ledger()
    order(g)
    g.ingest(txn())
    first = g.reconcile()
    assert (first.matched, first.unmatched, first.mismatched) == (1, 0, 0)
    assert (first.duplicates, first.credited) == (0, 1000)
    assert g.balance_of("acct-a") == 1000
    second = g.reconcile()
    assert (second.matched, second.credited, second.duplicates) == (0, 0, 1)
    assert second.lines[0].duplicate is True
    assert second.lines[0].credited == 0
    assert g.balance_of("acct-a") == 1000


def test_reconcile_walks_orders_by_creation_and_pending_filters_settled():
    g = ledger()
    order(g, "o-3", amount=300, created_at=30)
    order(g, "o-1", amount=100, created_at=10)
    order(g, "o-2", amount=200, created_at=10)
    g.ingest(txn("t-1", "o-1", amount=100))
    g.ingest(txn("t-2", "o-2", amount=200))
    assert g.pending_orders() == ("o-1", "o-2", "o-3")
    report = g.reconcile()
    assert [line.order_id for line in report.lines] == ["o-1", "o-2", "o-3"]
    assert (report.matched, report.unmatched, report.credited) == (2, 1, 300)
    assert g.pending_orders() == ("o-3",)


def test_second_matching_callback_never_credits_twice():
    g = ledger()
    order(g)
    g.ingest(txn("t-1", amount=1000, paid_at=5))
    g.ingest(txn("t-2", amount=1000, paid_at=6))
    report = g.reconcile()
    assert report.credited == 1000
    assert g.balance_of("acct-a") == 1000
    assert g.stats()["duplicate_pay"] == 1


def test_partial_refund_reduces_balance_and_rejects_over_refund():
    g = settled_ledger()
    first = g.refund("o-1", 400, at=30)
    assert (first.amount, first.balance, first.refunded_total) == (400, 600, 400)
    with pytest.raises(pr.ReconcileError) as exc:
        g.refund("o-1", 700, at=31)
    assert exc.value.code == "PAYMENT_REFUND_EXCEEDS"
    assert g.balance_of("acct-a") == 600
    rest = g.refund("o-1", 600, at=32)
    assert (rest.balance, rest.refunded_total) == (0, 1000)


def test_refund_requires_settled_order_and_valid_amount():
    g = ledger()
    order(g)
    with pytest.raises(pr.ReconcileError) as exc:
        g.refund("o-404", 100, at=1)
    assert exc.value.code == "PAYMENT_UNKNOWN_ORDER"
    with pytest.raises(pr.ReconcileError) as exc:
        g.refund("o-1", 100, at=1)
    assert exc.value.code == "PAYMENT_NOT_SETTLED"
    g.ingest(txn())
    g.reconcile()
    for bad_amount in (0, -1):
        with pytest.raises(pr.ReconcileError) as exc:
            g.refund("o-1", bad_amount, at=2)
        assert exc.value.code == "PAYMENT_INVALID_AMOUNT"


def test_reverse_grant_allows_negative_balance_and_flags_suspension():
    g = settled_ledger()
    assert g.spend("acct-a", 300) == 700
    reverse = g.reverse_grant("o-1", at=40)
    assert (reverse.amount, reverse.balance) == (1000, -300)
    assert reverse.suspended is True
    assert g.balance_of("acct-a") == -300
    with pytest.raises(pr.ReconcileError) as exc:
        g.reverse_grant("o-1", at=41)
    assert exc.value.code == "PAYMENT_ALREADY_REVERSED"


def test_spend_rejects_overdraft_and_unknown_kind():
    g = settled_ledger()
    assert g.spend("acct-a", 300) == 700
    with pytest.raises(pr.ReconcileError) as exc:
        g.spend("acct-a", 800)
    assert exc.value.code == "PAYMENT_INSUFFICIENT"
    assert g.balance_of("acct-a") == 700
    with pytest.raises(pr.ReconcileError) as exc:
        g.spend("acct-a", 0)
    assert exc.value.code == "PAYMENT_INVALID_AMOUNT"
    with pytest.raises(pr.ReconcileError) as exc:
        g.spend("acct-a", 10, kind="boost")
    assert exc.value.code == "PAYMENT_INVALID_REQUEST"
    with pytest.raises(pr.ReconcileError) as exc:
        g.spend("acct-empty", 10)
    assert exc.value.code == "PAYMENT_INSUFFICIENT"


def test_concurrent_ingest_of_one_txn_credits_it_once():
    g = ledger()
    order(g)
    line = txn()
    results = []
    barrier = threading.Barrier(16)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(g.ingest(line))
        except Exception as exc:  # pragma: no cover - reported through results
            results.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == ["applied"] + ["duplicate"] * 15
    assert g.stats()["ingested"] == 1
    g.reconcile()
    assert g.balance_of("acct-a") == 1000


def test_snapshot_is_detached_and_restore_roundtrips():
    g = settled_ledger()
    g.refund("o-1", 100, at=30)
    state = g.snapshot()
    assert set(state) == SNAPSHOT_KEYS
    pristine = copy.deepcopy(state)
    state["balances"]["acct-a"] = 999999
    state["orders"].clear()
    assert g.balance_of("acct-a") == 900
    assert g.pending_orders() == ()
    clone = ledger()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.balance_of("acct-a") == 900
    assert clone.reconcile().duplicates == 1


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = settled_ledger()
    good = g.snapshot()
    bad_states = [
        None,
        {},
        {"version": 1},
        dict(good, version="1"),
        dict(good, orders={}),
        dict(good, txns={}),
        dict(good, balances=[]),
        dict(good, settled=[]),
        dict(good, suspended={}),
        dict(good, counters=[]),
    ]
    for bad in bad_states:
        with pytest.raises(pr.ReconcileError) as exc:
            g.restore(bad)
        assert exc.value.code == "PAYMENT_SNAPSHOT_INVALID"
    assert g.balance_of("acct-a") == 1000
    assert g.stats()["orders"] == 1
