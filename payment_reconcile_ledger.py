"""渠道充值对账台账：流水幂等入账、订单匹配、部分退款冲正与负余额挂起。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

DEFAULT_CURRENCY = "CNY"
TXN_KINDS = ("pay",)
SPEND_KINDS = ("normal", "gift")
MATCH_STATUSES = ("matched", "unmatched", "amount_mismatch")


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


class PaymentReconcileLedger:
    """Match channel statements against internal orders and keep a per-account ledger."""

    def __init__(self, *, currency: str = DEFAULT_CURRENCY,
                 max_pending_orders: int = 2000) -> None:
        self.currency = currency
        self.max_pending_orders = max_pending_orders
        self._lock = threading.RLock()

    def register_order(self, order_id: str, account: str, *, channel: str,
                       currency: str, amount: int, created_at: int) -> Order:
        """Register the internal order that the channel statement is expected to match."""
        raise NotImplementedError

    def ingest(self, txn: ChannelTxn) -> str:
        """Store one channel statement line; repeated txn_id yields "duplicate"."""
        raise NotImplementedError

    def match(self, order_id: str) -> MatchResult:
        """Match one registered order against the ingested pay statements."""
        raise NotImplementedError

    def reconcile(self, order_id: str | None = None) -> ReconcileReport:
        """Credit every matched order once, walking them in creation order."""
        raise NotImplementedError

    def refund(self, order_id: str, amount: int, *, at: int) -> RefundResult:
        """Apply one partial refund against an already credited order."""
        raise NotImplementedError

    def reverse_grant(self, order_id: str, *, at: int) -> ReverseResult:
        """Reverse the still-outstanding part of one order's grant."""
        raise NotImplementedError

    def balance_of(self, account: str) -> int:
        """Current credited balance of one account, which may be negative."""
        raise NotImplementedError

    def fees_total(self, channel: str) -> int:
        """Sum of the channel fees booked as expense for one channel."""
        raise NotImplementedError

    def spend(self, account: str, amount: int, *, kind: str = "normal") -> int:
        """Consume balance and return the remaining amount."""
        raise NotImplementedError

    def deliver_scheduled(self, account: str, grant_id: str, amount: int) -> str:
        """Deliver one scheduled grant, pausing it while the account is suspended."""
        raise NotImplementedError

    def pending_orders(self) -> tuple[str, ...]:
        """Registered orders that still have no credited settlement."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep-copied ledger state for restart recovery."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the ledger state from a snapshot, rejecting malformed payloads."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters collected since the ledger was created."""
        raise NotImplementedError
