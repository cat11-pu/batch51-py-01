"""渠道充值对账台账：流水幂等入账、订单匹配、部分退款冲正与负余额挂起。"""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_CURRENCY = "CNY"
TXN_KINDS = ("pay",)
SPEND_KINDS = ("normal", "gift")
MATCH_STATUSES = ("matched", "unmatched", "amount_mismatch")

SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = {"version", "config", "orders", "txns", "balances", "settled",
                 "suspended", "counters"}


class ReconcileError(ValueError):
    """Raised when a reconciliation operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Order:
    order_id: str
    account: str
    channel: str
    currency: str
    amount: int
    created_at: int


@dataclass(frozen=True)
class ChannelTxn:
    txn_id: str
    order_id: str
    channel: str
    currency: str
    amount: int
    fee: int
    paid_at: int
    kind: str = "pay"


@dataclass(frozen=True)
class MatchResult:
    order_id: str
    status: str
    txn_id: str | None
    expected: int
    actual: int
    delta: int


@dataclass(frozen=True)
class ReconcileLine:
    order_id: str
    account: str
    txn_id: str | None
    credited: int
    duplicate: bool
    status: str


@dataclass(frozen=True)
class ReconcileReport:
    lines: tuple[ReconcileLine, ...]
    matched: int
    unmatched: int
    mismatched: int
    duplicates: int
    credited: int


@dataclass(frozen=True)
class RefundResult:
    order_id: str
    amount: int
    balance: int
    refunded_total: int


@dataclass(frozen=True)
class ReverseResult:
    order_id: str
    amount: int
    balance: int
    suspended: bool


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonempty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


class PaymentReconcileLedger:
    """Match channel statements against internal orders and keep a per-account ledger."""

    def __init__(self, *, currency: str = DEFAULT_CURRENCY,
                 max_pending_orders: int = 2000) -> None:
        if not _is_nonempty_str(currency):
            raise ReconcileError("PAYMENT_INVALID_REQUEST", "currency")
        if not _is_int(max_pending_orders) or max_pending_orders < 0:
            raise ReconcileError("PAYMENT_INVALID_REQUEST", "max_pending_orders")

        self.currency = currency
        self.max_pending_orders = max_pending_orders
        self._lock = threading.RLock()

        self._orders: dict[str, Order] = {}
        self._txns: dict[str, ChannelTxn] = {}
        self._balances: dict[str, int] = {}
        # order_id -> settlement details. A settlement is intentionally sticky:
        # refunds, reversals and late channel callbacks never remove it.
        self._settled: dict[str, dict] = {}
        self._suspended: set[str] = set()
        self._fees: dict[str, int] = {}
        self._fee_booked: set[str] = set()
        self._duplicate_counted: set[str] = set()
        self._counters: dict[str, int] = {
            "orders": 0,
            "ingested": 0,
            "duplicate_txns": 0,
            "duplicate_pay": 0,
            "refunds": 0,
            "refunded": 0,
            "reversals": 0,
            "reversed": 0,
            "spent": 0,
            "scheduled": 0,
            "scheduled_paused": 0,
        }

    def _pending_count(self) -> int:
        return sum(1 for order_id in self._orders if order_id not in self._settled)

    def _txns_for(self, order: Order) -> list[ChannelTxn]:
        return [txn for txn in self._txns.values()
                if txn.order_id == order.order_id]

    def _select_txn(self, order: Order) -> ChannelTxn | None:
        txns = self._txns_for(order)
        if not txns:
            return None
        exact = [txn for txn in txns if txn.amount == order.amount]
        candidates = exact or txns
        return min(candidates, key=lambda txn: (txn.paid_at, txn.txn_id))

    def _book_fee(self, txn: ChannelTxn) -> None:
        if txn.txn_id in self._fee_booked:
            return
        self._fee_booked.add(txn.txn_id)
        self._fees[txn.channel] = self._fees.get(txn.channel, 0) + txn.fee

    def _account_duplicate_pay(self, order: Order) -> None:
        settlement = self._settled.get(order.order_id)
        if settlement is None:
            selected = self._select_txn(order)
        else:
            selected = self._txns.get(settlement["txn_id"])
        if selected is None:
            return
        same_amount = sorted(
            (txn for txn in self._txns_for(order)
             if txn.amount == selected.amount),
            key=lambda txn: (txn.paid_at, txn.txn_id),
        )
        for txn in same_amount:
            if txn.txn_id == selected.txn_id:
                continue
            if txn.txn_id in self._duplicate_counted:
                continue
            self._duplicate_counted.add(txn.txn_id)
            self._counters["duplicate_pay"] += 1

    def register_order(self, order_id: str, account: str, *, channel: str,
                       currency: str, amount: int, created_at: int) -> Order:
        """Register the internal order that the channel statement is expected to match."""
        with self._lock:
            if not _is_nonempty_str(order_id):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "order_id")
            if order_id in self._orders:
                raise ReconcileError("PAYMENT_ORDER_EXISTS", order_id)
            if not _is_nonempty_str(account):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "account")
            if not _is_nonempty_str(channel):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "channel")
            if currency != self.currency:
                raise ReconcileError("PAYMENT_CURRENCY_MISMATCH", currency)
            if not _is_int(amount) or amount <= 0:
                raise ReconcileError("PAYMENT_INVALID_AMOUNT", amount)
            if not _is_int(created_at):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "created_at")
            if self._pending_count() >= self.max_pending_orders:
                raise ReconcileError("PAYMENT_QUEUE_FULL", order_id)

            order = Order(
                order_id=order_id,
                account=account,
                channel=channel,
                currency=currency,
                amount=amount,
                created_at=created_at,
            )
            self._orders[order_id] = order
            self._counters["orders"] += 1
            return order

    def ingest(self, txn: ChannelTxn) -> str:
        """Store one channel statement line; repeated txn_id yields "duplicate"."""
        with self._lock:
            if isinstance(txn, Mapping):
                try:
                    txn = ChannelTxn(**txn)
                except (TypeError, ValueError):
                    raise ReconcileError("PAYMENT_INVALID_REQUEST", "txn") from None
            if not isinstance(txn, ChannelTxn):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "txn")
            if not _is_nonempty_str(txn.txn_id):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "txn_id")

            if txn.txn_id in self._txns:
                self._counters["duplicate_txns"] += 1
                return "duplicate"

            order = self._orders.get(txn.order_id)
            if order is None:
                raise ReconcileError("PAYMENT_UNKNOWN_ORDER", txn.order_id)
            if txn.kind not in TXN_KINDS:
                raise ReconcileError("PAYMENT_INVALID_REQUEST", txn.kind)
            if txn.currency != order.currency:
                raise ReconcileError("PAYMENT_CURRENCY_MISMATCH", txn.currency)
            if not _is_int(txn.amount) or txn.amount <= 0:
                raise ReconcileError("PAYMENT_INVALID_AMOUNT", txn.amount)
            if not _is_int(txn.fee) or txn.fee < 0:
                raise ReconcileError("PAYMENT_INVALID_AMOUNT", txn.fee)
            if not _is_int(txn.paid_at):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "paid_at")
            if not _is_nonempty_str(txn.channel):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "channel")

            self._txns[txn.txn_id] = txn
            self._counters["ingested"] += 1
            return "applied"

    def match(self, order_id: str) -> MatchResult:
        """Match one registered order against the ingested pay statements."""
        with self._lock:
            order = self._orders.get(order_id)
            if order is None:
                raise ReconcileError("PAYMENT_UNKNOWN_ORDER", order_id)

            self._account_duplicate_pay(order)
            selected = self._select_txn(order)
            if selected is None:
                return MatchResult(
                    order_id=order_id,
                    status="unmatched",
                    txn_id=None,
                    expected=order.amount,
                    actual=0,
                    delta=order.amount,
                )

            if order_id not in self._settled:
                self._book_fee(selected)
            status = ("matched" if selected.amount == order.amount
                      else "amount_mismatch")
            return MatchResult(
                order_id=order_id,
                status=status,
                txn_id=selected.txn_id,
                expected=order.amount,
                actual=selected.amount,
                delta=order.amount - selected.amount,
            )

    def reconcile(self, order_id: str | None = None) -> ReconcileReport:
        """Credit every matched order once, walking them in creation order."""
        with self._lock:
            if order_id is None:
                targets = sorted(
                    self._orders.values(),
                    key=lambda order: (order.created_at, order.order_id),
                )
            else:
                order = self._orders.get(order_id)
                if order is None:
                    raise ReconcileError("PAYMENT_UNKNOWN_ORDER", order_id)
                targets = [order]

            lines: list[ReconcileLine] = []
            matched = unmatched = mismatched = duplicates = credited = 0

            for order in targets:
                settlement = self._settled.get(order.order_id)
                if settlement is not None:
                    self._account_duplicate_pay(order)
                    lines.append(ReconcileLine(
                        order_id=order.order_id,
                        account=order.account,
                        txn_id=settlement["txn_id"],
                        credited=0,
                        duplicate=True,
                        status="duplicate",
                    ))
                    duplicates += 1
                    continue

                selected = self._select_txn(order)
                self._account_duplicate_pay(order)
                if selected is None:
                    lines.append(ReconcileLine(
                        order_id=order.order_id,
                        account=order.account,
                        txn_id=None,
                        credited=0,
                        duplicate=False,
                        status="unmatched",
                    ))
                    unmatched += 1
                    continue

                self._book_fee(selected)
                if selected.amount != order.amount:
                    lines.append(ReconcileLine(
                        order_id=order.order_id,
                        account=order.account,
                        txn_id=selected.txn_id,
                        credited=0,
                        duplicate=False,
                        status="amount_mismatch",
                    ))
                    mismatched += 1
                    continue

                self._balances[order.account] = (
                    self._balances.get(order.account, 0) + order.amount
                )
                self._settled[order.order_id] = {
                    "txn_id": selected.txn_id,
                    "credited": order.amount,
                    "refunded_total": 0,
                    "reversed": False,
                    "reversed_amount": 0,
                }
                lines.append(ReconcileLine(
                    order_id=order.order_id,
                    account=order.account,
                    txn_id=selected.txn_id,
                    credited=order.amount,
                    duplicate=False,
                    status="matched",
                ))
                matched += 1
                credited += order.amount

            return ReconcileReport(
                lines=tuple(lines),
                matched=matched,
                unmatched=unmatched,
                mismatched=mismatched,
                duplicates=duplicates,
                credited=credited,
            )

    def refund(self, order_id: str, amount: int, *, at: int) -> RefundResult:
        """Apply one partial refund against an already credited order."""
        with self._lock:
            order = self._orders.get(order_id)
            if order is None:
                raise ReconcileError("PAYMENT_UNKNOWN_ORDER", order_id)
            if not _is_int(amount) or amount <= 0:
                raise ReconcileError("PAYMENT_INVALID_AMOUNT", amount)

            settlement = self._settled.get(order_id)
            if settlement is None:
                raise ReconcileError("PAYMENT_NOT_SETTLED", order_id)

            available = (settlement["credited"]
                         - settlement["refunded_total"]
                         - settlement["reversed_amount"])
            if amount > available:
                raise ReconcileError("PAYMENT_REFUND_EXCEEDS", amount)

            settlement["refunded_total"] += amount
            self._balances[order.account] = (
                self._balances.get(order.account, 0) - amount
            )
            self._counters["refunds"] += 1
            self._counters["refunded"] += amount
            return RefundResult(
                order_id=order_id,
                amount=amount,
                balance=self._balances[order.account],
                refunded_total=settlement["refunded_total"],
            )

    def reverse_grant(self, order_id: str, *, at: int) -> ReverseResult:
        """Reverse the still-outstanding part of one order's grant."""
        with self._lock:
            order = self._orders.get(order_id)
            if order is None:
                raise ReconcileError("PAYMENT_UNKNOWN_ORDER", order_id)
            settlement = self._settled.get(order_id)
            if settlement is None:
                raise ReconcileError("PAYMENT_NOT_SETTLED", order_id)
            if settlement["reversed"]:
                raise ReconcileError("PAYMENT_ALREADY_REVERSED", order_id)

            remaining = (settlement["credited"]
                         - settlement["refunded_total"]
                         - settlement["reversed_amount"])
            remaining = max(remaining, 0)
            self._balances[order.account] = (
                self._balances.get(order.account, 0) - remaining
            )
            settlement["reversed"] = True
            settlement["reversed_amount"] += remaining
            self._suspended.add(order.account)
            self._counters["reversals"] += 1
            self._counters["reversed"] += remaining
            return ReverseResult(
                order_id=order_id,
                amount=remaining,
                balance=self._balances[order.account],
                suspended=True,
            )

    def balance_of(self, account: str) -> int:
        """Current credited balance of one account, which may be negative."""
        with self._lock:
            return self._balances.get(account, 0)

    def fees_total(self, channel: str) -> int:
        """Sum of the channel fees booked as expense for one channel."""
        with self._lock:
            return self._fees.get(channel, 0)

    def spend(self, account: str, amount: int, *, kind: str = "normal") -> int:
        """Consume balance and return the remaining amount."""
        with self._lock:
            if not _is_int(amount) or amount <= 0:
                raise ReconcileError("PAYMENT_INVALID_AMOUNT", amount)
            if kind not in SPEND_KINDS:
                raise ReconcileError("PAYMENT_INVALID_REQUEST", kind)
            if kind == "gift" and account in self._suspended:
                raise ReconcileError("PAYMENT_ACCOUNT_SUSPENDED", account)

            balance = self._balances.get(account, 0)
            if balance < amount:
                raise ReconcileError("PAYMENT_INSUFFICIENT", account)
            balance -= amount
            self._balances[account] = balance
            self._counters["spent"] += amount
            return balance

    def deliver_scheduled(self, account: str, grant_id: str, amount: int) -> str:
        """Deliver one scheduled grant, pausing it while the account is suspended."""
        with self._lock:
            if not _is_nonempty_str(account):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "account")
            if not _is_nonempty_str(grant_id):
                raise ReconcileError("PAYMENT_INVALID_REQUEST", "grant_id")
            if not _is_int(amount) or amount <= 0:
                raise ReconcileError("PAYMENT_INVALID_AMOUNT", amount)

            if account in self._suspended:
                self._counters["scheduled_paused"] += 1
                return "paused"

            self._balances[account] = self._balances.get(account, 0) + amount
            self._counters["scheduled"] += 1
            return "delivered"

    def pending_orders(self) -> tuple[str, ...]:
        """Registered orders that still have no credited settlement."""
        with self._lock:
            orders = (order for order in self._orders.values()
                      if order.order_id not in self._settled)
            return tuple(order.order_id for order in sorted(
                orders, key=lambda order: (order.created_at, order.order_id)))

    def snapshot(self) -> dict:
        """Deep-copied ledger state for restart recovery."""
        with self._lock:
            orders = {
                order_id: {
                    "order_id": order.order_id,
                    "account": order.account,
                    "channel": order.channel,
                    "currency": order.currency,
                    "amount": order.amount,
                    "created_at": order.created_at,
                }
                for order_id, order in self._orders.items()
            }
            txns = {
                txn_id: {
                    "txn_id": txn.txn_id,
                    "order_id": txn.order_id,
                    "channel": txn.channel,
                    "currency": txn.currency,
                    "amount": txn.amount,
                    "fee": txn.fee,
                    "paid_at": txn.paid_at,
                    "kind": txn.kind,
                    "fee_booked": txn.txn_id in self._fee_booked,
                    "duplicate_counted": txn.txn_id in self._duplicate_counted,
                }
                for txn_id, txn in self._txns.items()
            }
            settled = {
                order_id: {
                    "txn_id": settlement["txn_id"],
                    "credited": settlement["credited"],
                    "refunded_total": settlement["refunded_total"],
                    "reversed": settlement["reversed"],
                    "reversed_amount": settlement["reversed_amount"],
                }
                for order_id, settlement in self._settled.items()
            }
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "currency": self.currency,
                    "max_pending_orders": self.max_pending_orders,
                },
                "orders": orders,
                "txns": txns,
                "balances": dict(self._balances),
                "settled": settled,
                "suspended": sorted(self._suspended),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        """Replace the ledger state from a snapshot, rejecting malformed payloads."""
        with self._lock:
            try:
                snapshot = copy.deepcopy(state)
                if not isinstance(snapshot, dict):
                    raise ValueError("snapshot")
                if set(snapshot) != SNAPSHOT_KEYS:
                    raise ValueError("keys")
                if (not _is_int(snapshot["version"])
                        or snapshot["version"] != SNAPSHOT_VERSION):
                    raise ValueError("version")

                config = snapshot["config"]
                if not isinstance(config, dict):
                    raise ValueError("config")
                currency = config.get("currency")
                max_pending = config.get("max_pending_orders")
                if not _is_nonempty_str(currency):
                    raise ValueError("currency")
                if not _is_int(max_pending) or max_pending < 0:
                    raise ValueError("max_pending_orders")

                raw_orders = snapshot["orders"]
                if not isinstance(raw_orders, dict):
                    raise ValueError("orders")
                orders: dict[str, Order] = {}
                for order_id, raw in raw_orders.items():
                    if not _is_nonempty_str(order_id) or not isinstance(raw, dict):
                        raise ValueError("order")
                    order = Order(
                        order_id=raw["order_id"],
                        account=raw["account"],
                        channel=raw["channel"],
                        currency=raw["currency"],
                        amount=raw["amount"],
                        created_at=raw["created_at"],
                    )
                    if order.order_id != order_id:
                        raise ValueError("order id")
                    if not _is_nonempty_str(order.account):
                        raise ValueError("order account")
                    if not _is_nonempty_str(order.channel):
                        raise ValueError("order channel")
                    if order.currency != currency:
                        raise ValueError("order currency")
                    if not _is_int(order.amount) or order.amount <= 0:
                        raise ValueError("order amount")
                    if not _is_int(order.created_at):
                        raise ValueError("order created_at")
                    orders[order_id] = order

                raw_txns = snapshot["txns"]
                if not isinstance(raw_txns, dict):
                    raise ValueError("txns")
                txns: dict[str, ChannelTxn] = {}
                fee_booked: set[str] = set()
                duplicate_counted: set[str] = set()
                for txn_id, raw in raw_txns.items():
                    if not _is_nonempty_str(txn_id) or not isinstance(raw, dict):
                        raise ValueError("txn")
                    txn = ChannelTxn(
                        txn_id=raw["txn_id"],
                        order_id=raw["order_id"],
                        channel=raw["channel"],
                        currency=raw["currency"],
                        amount=raw["amount"],
                        fee=raw["fee"],
                        paid_at=raw["paid_at"],
                        kind=raw["kind"],
                    )
                    if txn.txn_id != txn_id:
                        raise ValueError("txn id")
                    order = orders.get(txn.order_id)
                    if order is None:
                        raise ValueError("txn order")
                    if txn.kind not in TXN_KINDS:
                        raise ValueError("txn kind")
                    if txn.currency != order.currency:
                        raise ValueError("txn currency")
                    if not _is_int(txn.amount) or txn.amount <= 0:
                        raise ValueError("txn amount")
                    if not _is_int(txn.fee) or txn.fee < 0:
                        raise ValueError("txn fee")
                    if not _is_int(txn.paid_at):
                        raise ValueError("txn paid_at")
                    if not _is_nonempty_str(txn.channel):
                        raise ValueError("txn channel")
                    is_fee_booked = raw.get("fee_booked", False)
                    is_duplicate_counted = raw.get("duplicate_counted", False)
                    if not isinstance(is_fee_booked, bool):
                        raise ValueError("fee_booked")
                    if not isinstance(is_duplicate_counted, bool):
                        raise ValueError("duplicate_counted")
                    if is_fee_booked:
                        fee_booked.add(txn_id)
                    if is_duplicate_counted:
                        duplicate_counted.add(txn_id)
                    txns[txn_id] = txn

                raw_balances = snapshot["balances"]
                if not isinstance(raw_balances, dict):
                    raise ValueError("balances")
                balances: dict[str, int] = {}
                for account, balance in raw_balances.items():
                    if not isinstance(account, str) or not _is_int(balance):
                        raise ValueError("balance")
                    balances[account] = balance

                raw_settled = snapshot["settled"]
                if not isinstance(raw_settled, dict):
                    raise ValueError("settled")
                settled: dict[str, dict] = {}
                for order_id, raw in raw_settled.items():
                    if order_id not in orders or not isinstance(raw, dict):
                        raise ValueError("settlement")
                    txn_id = raw["txn_id"]
                    if txn_id not in txns:
                        raise ValueError("settlement txn")
                    if txns[txn_id].order_id != order_id:
                        raise ValueError("settlement order")

                    credited = raw["credited"]
                    refunded_total = raw["refunded_total"]
                    reversed_flag = raw["reversed"]
                    reversed_amount = raw["reversed_amount"]
                    if not _is_int(credited) or credited <= 0:
                        raise ValueError("credited")
                    if credited != orders[order_id].amount:
                        raise ValueError("credited amount")
                    if (not _is_int(refunded_total)
                            or refunded_total < 0
                            or refunded_total > credited):
                        raise ValueError("refunded_total")
                    if not isinstance(reversed_flag, bool):
                        raise ValueError("reversed")
                    if (not _is_int(reversed_amount)
                            or reversed_amount < 0
                            or reversed_amount > credited - refunded_total):
                        raise ValueError("reversed_amount")
                    if not reversed_flag and reversed_amount != 0:
                        raise ValueError("reversed state")
                    settled[order_id] = {
                        "txn_id": txn_id,
                        "credited": credited,
                        "refunded_total": refunded_total,
                        "reversed": reversed_flag,
                        "reversed_amount": reversed_amount,
                    }

                raw_suspended = snapshot["suspended"]
                if not isinstance(raw_suspended, list):
                    raise ValueError("suspended")
                suspended: set[str] = set()
                for account in raw_suspended:
                    if not isinstance(account, str):
                        raise ValueError("suspended account")
                    suspended.add(account)

                raw_counters = snapshot["counters"]
                if not isinstance(raw_counters, dict):
                    raise ValueError("counters")
                if set(raw_counters) != set(self._counters):
                    raise ValueError("counter keys")
                counters: dict[str, int] = {}
                for key, value in raw_counters.items():
                    if not isinstance(key, str) or not _is_int(value) or value < 0:
                        raise ValueError("counter")
                    counters[key] = value
                if counters["orders"] != len(orders):
                    raise ValueError("orders counter")
                if counters["ingested"] != len(txns):
                    raise ValueError("ingested counter")
                if counters["duplicate_pay"] != len(duplicate_counted):
                    raise ValueError("duplicate_pay counter")

                fees: dict[str, int] = {}
                for txn_id in fee_booked:
                    txn = txns[txn_id]
                    fees[txn.channel] = fees.get(txn.channel, 0) + txn.fee
            except Exception:
                raise ReconcileError("PAYMENT_SNAPSHOT_INVALID", "malformed state") from None

            self.currency = currency
            self.max_pending_orders = max_pending
            self._orders = orders
            self._txns = txns
            self._balances = balances
            self._settled = settled
            self._suspended = suspended
            self._fees = fees
            self._fee_booked = fee_booked
            self._duplicate_counted = duplicate_counted
            self._counters = counters

    def stats(self) -> dict:
        """Counters collected since the ledger was created."""
        with self._lock:
            return dict(self._counters)
