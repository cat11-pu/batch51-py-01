"""Invite referral tree: three-level attribution, milestone payout, refund clawback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ReferralError(ValueError):
    """Raised when a referral operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NodeView:
    account: str
    inviter: str | None
    level: int
    bound_at: str | None
    device: str | None
    milestone_count: int
    paid: int


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    account: str
    kind: str
    amount: int
    milestone: str | None
    at: str | None


class ReferralTree:
    """Keep the invite forest, per-node payout state and one shared ledger."""

    MAX_LEVELS = 3
    SHARES_BPS = (10000, 5000, 2500)

    def __init__(self, *, max_levels: int = 3, max_children: int = 16,
                 shares_bps=SHARES_BPS, milestones=None,
                 max_depth: int = 64) -> None:
        self.max_levels = max_levels
        self.max_children = max_children
        self.shares_bps = tuple(shares_bps)
        self.milestones = dict(milestones or {})
        self.max_depth = max_depth
        self._lock = threading.RLock()

    def register_account(self, account: str, *, device: str | None = None,
                         now: str | None = None) -> NodeView:
        """Create a root node that has no inviter yet."""
        raise NotImplementedError

    def bind_invite(self, account: str, inviter: str, *,
                    now: str | None = None) -> NodeView:
        """Bind an account under an existing inviter and record the moment."""
        raise NotImplementedError

    def record_milestone(self, account: str, milestone: str, *,
                         now: str | None = None) -> int:
        """Settle one milestone once and return the total credited in this call."""
        raise NotImplementedError

    def claim_rewards(self, account: str) -> int:
        """Move claimable rewards into the spendable balance."""
        raise NotImplementedError

    def clawback(self, account: str, milestone: str) -> dict[str, int]:
        """Reverse one settlement along the path that actually paid it."""
        raise NotImplementedError

    def tree_of(self, account: str) -> list[NodeView]:
        """Return the subtree in preorder with children sorted by account."""
        raise NotImplementedError

    def balance_of(self, account: str) -> int:
        """Spendable balance, never negative."""
        raise NotImplementedError

    def claimable_of(self, account: str) -> int:
        """Rewards credited but not claimed yet."""
        raise NotImplementedError

    def pending_debt(self, account: str) -> int:
        """Suspended amount that still has to be recovered."""
        raise NotImplementedError

    def reward_state(self, account: str) -> dict[str, int]:
        """Return balance, claimable and debt in one mapping."""
        raise NotImplementedError

    def ledger_of(self, account: str) -> list[LedgerEntry]:
        """Ledger entries of one account ordered by sequence."""
        raise NotImplementedError

    def ban_account(self, account: str, *, now: str | None = None) -> int:
        """Ban an account together with its downstream subtree."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of the whole tree, ledger and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the counters exposed to the operations dashboard."""
        raise NotImplementedError
