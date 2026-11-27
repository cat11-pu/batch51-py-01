"""Invite referral tree: three-level attribution, milestone payout, refund clawback."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any


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


@dataclass
class _Node:
    account: str
    inviter: str | None
    level: int
    bound_at: str | None
    device: str | None
    banned: bool = False
    paid: int = 0
    claimable: int = 0
    balance: int = 0
    debt: int = 0


class ReferralTree:
    """Keep the invite forest, per-node payout state and one shared ledger."""

    MAX_LEVELS = 3
    SHARES_BPS = (10000, 5000, 2500)
    MAX_NODES = 100_000
    MAX_PENDING_DEBT = 1_000_000_000_000_000_000
    SNAPSHOT_VERSION = 1

    _SNAPSHOT_KEYS = {
        "version",
        "nodes",
        "milestones",
        "ledger",
        "counters",
        "stats",
    }
    _NODE_KEYS = {
        "account",
        "inviter",
        "level",
        "bound_at",
        "device",
        "banned",
        "paid",
        "claimable",
        "balance",
        "debt",
    }
    _STATS_KEYS = {
        "accounts",
        "bound",
        "milestones",
        "paid",
        "claimable",
        "reversed",
        "debt",
    }

    def __init__(self, *, max_levels: int = 3, max_children: int = 16,
                 shares_bps=SHARES_BPS, milestones=None,
                 max_depth: int = 64, max_nodes: int | None = None,
                 max_pending_debt: int | None = None, **limits) -> None:
        self.max_levels = self._non_negative_int(max_levels, "max_levels")
        self.max_children = self._non_negative_int(max_children, "max_children")
        self.shares_bps = tuple(
            self._non_negative_int(share, "shares_bps")
            for share in shares_bps
        )
        self.max_depth = self._non_negative_int(max_depth, "max_depth")
        self.max_nodes = self._non_negative_int(
            self.MAX_NODES if max_nodes is None else max_nodes,
            "max_nodes",
        )
        self.max_pending_debt = self._non_negative_int(
            self.MAX_PENDING_DEBT
            if max_pending_debt is None
            else max_pending_debt,
            "max_pending_debt",
        )

        # A few callers use these shorter names when constructing a bounded tree.
        if "node_limit" in limits:
            if max_nodes is not None:
                raise ReferralError("REFERRAL_INVALID_REQUEST", "max_nodes")
            self.max_nodes = self._non_negative_int(
                limits.pop("node_limit"), "node_limit"
            )
        if "max_debt" in limits:
            if max_pending_debt is not None:
                raise ReferralError("REFERRAL_INVALID_REQUEST", "max_pending_debt")
            self.max_pending_debt = self._non_negative_int(
                limits.pop("max_debt"), "max_debt"
            )
        if limits:
            raise ReferralError("REFERRAL_INVALID_REQUEST", "unknown option")

        self.milestones: dict[str, int] = {}
        if milestones is not None:
            if not isinstance(milestones, dict):
                raise ReferralError("REFERRAL_INVALID_REQUEST", "milestones")
            for name, amount in milestones.items():
                key = self._name(name, "milestone")
                value = self._non_negative_int(amount, "milestone amount")
                self.milestones[key] = value

        self._lock = threading.RLock()
        self._nodes: dict[str, _Node] = {}
        self._settled: set[tuple[str, str]] = set()
        self._paths: dict[tuple[str, str], list[tuple[str, int]]] = {}
        self._ledger: list[LedgerEntry] = []
        self._seq = 0
        self._reversed = 0

    @staticmethod
    def _non_negative_int(value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReferralError("REFERRAL_INVALID_REQUEST", field)
        return value

    @staticmethod
    def _name(value: Any, field: str = "account") -> str:
        if not isinstance(value, str):
            raise ReferralError("REFERRAL_INVALID_REQUEST", field)
        name = value.strip()
        if not name:
            raise ReferralError("REFERRAL_INVALID_REQUEST", field)
        return name

    @classmethod
    def _device_name(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ReferralError("REFERRAL_INVALID_REQUEST", "device")
        device = value.strip()
        return device or None

    def _require(self, account: str) -> _Node:
        node = self._nodes.get(account)
        if node is None:
            raise ReferralError("REFERRAL_NO_SUCH_ACCOUNT", account)
        return node

    def _child_names(self, account: str) -> list[str]:
        return sorted(
            name for name, node in self._nodes.items()
            if node.inviter == account
        )

    def _children_map(self) -> dict[str, list[str]]:
        children: dict[str, list[str]] = {name: [] for name in self._nodes}
        for name, node in self._nodes.items():
            if node.inviter is not None:
                children[node.inviter].append(name)
        for values in children.values():
            values.sort()
        return children

    def _is_descendant(self, candidate: str, ancestor: str) -> bool:
        seen: set[str] = set()
        cursor: str | None = candidate
        while cursor is not None:
            if cursor == ancestor:
                return True
            if cursor in seen:
                return True
            seen.add(cursor)
            node = self._nodes.get(cursor)
            if node is None:
                return False
            cursor = node.inviter
        return False

    def _refresh_levels(self, account: str, level: int) -> None:
        children = self._children_map()
        stack = [(account, level)]
        while stack:
            name, next_level = stack.pop()
            node = self._nodes[name]
            node.level = next_level
            for child in reversed(children.get(name, ())):
                stack.append((child, next_level + 1))

    def _view(self, node: _Node) -> NodeView:
        milestone_count = sum(
            1 for account, _ in self._settled if account == node.account
        )
        return NodeView(
            account=node.account,
            inviter=node.inviter,
            level=node.level,
            bound_at=node.bound_at,
            device=node.device,
            milestone_count=milestone_count,
            paid=node.paid,
        )

    def _append_ledger(self, account: str, kind: str, amount: int,
                       milestone: str | None, at: str | None) -> None:
        self._seq += 1
        self._ledger.append(
            LedgerEntry(
                seq=self._seq,
                account=account,
                kind=kind,
                amount=amount,
                milestone=milestone,
                at=at,
            )
        )

    def _credit(self, account: str, amount: int, milestone: str,
                now: str | None) -> None:
        node = self._nodes[account]
        node.paid += amount
        node.claimable += amount
        self._append_ledger(account, "credit", amount, milestone, now)
        if node.debt and amount:
            offset = min(node.debt, amount)
            node.debt -= offset
            node.claimable -= offset
            self._append_ledger(account, "offset", -offset, milestone, now)

    def _stats_unlocked(self) -> dict[str, int]:
        return {
            "accounts": len(self._nodes),
            "bound": sum(
                1 for node in self._nodes.values() if node.inviter is not None
            ),
            "milestones": len(self._settled),
            "paid": sum(node.paid for node in self._nodes.values()),
            "claimable": sum(node.claimable for node in self._nodes.values()),
            "reversed": self._reversed,
            "debt": sum(node.debt for node in self._nodes.values()),
        }

    def register_account(self, account: str, *, device: str | None = None,
                         now: str | None = None) -> NodeView:
        """Create a root node that has no inviter yet."""
        name = self._name(account)
        clean_device = self._device_name(device)
        with self._lock:
            if name in self._nodes:
                raise ReferralError("REFERRAL_ALREADY_EXISTS", name)
            if len(self._nodes) >= self.max_nodes:
                raise ReferralError("REFERRAL_NODE_LIMIT", self.max_nodes)
            node = _Node(
                account=name,
                inviter=None,
                level=0,
                bound_at=now,
                device=clean_device,
            )
            self._nodes[name] = node
            return self._view(node)

    def bind_invite(self, account: str, inviter: str, *,
                    now: str | None = None) -> NodeView:
        """Bind an account under an existing inviter and record the moment."""
        name = self._name(account)
        parent_name = self._name(inviter, "inviter")
        with self._lock:
            if name == parent_name:
                raise ReferralError("REFERRAL_CYCLE", name)
            parent = self._nodes.get(parent_name)
            if parent is None:
                raise ReferralError("REFERRAL_NO_SUCH_ACCOUNT", parent_name)
            if parent.banned:
                raise ReferralError("REFERRAL_ACCOUNT_BANNED", parent_name)

            node = self._nodes.get(name)
            if node is not None:
                if node.banned:
                    raise ReferralError("REFERRAL_ACCOUNT_BANNED", name)
                if node.inviter == parent_name:
                    return self._view(node)
                if node.inviter is not None:
                    # Do not disclose the identity of the previous inviter.
                    raise ReferralError(
                        "REFERRAL_ALREADY_BOUND",
                        "invitee is already bound",
                    )

            if node is not None and self._is_descendant(parent_name, name):
                raise ReferralError("REFERRAL_CYCLE", name)

            if node is None and len(self._nodes) >= self.max_nodes:
                raise ReferralError("REFERRAL_NODE_LIMIT", self.max_nodes)
            if len(self._child_names(parent_name)) >= self.max_children:
                raise ReferralError("REFERRAL_NODE_LIMIT", parent_name)

            if node is None:
                node = _Node(
                    account=name,
                    inviter=parent_name,
                    level=parent.level + 1,
                    bound_at=now,
                    device=None,
                )
                self._nodes[name] = node
            else:
                node.inviter = parent_name
                node.level = parent.level + 1
                node.bound_at = now
                self._refresh_levels(name, node.level)
            return self._view(node)

    def record_milestone(self, account: str, milestone: str, *,
                         now: str | None = None) -> int:
        """Settle one milestone once and return the total credited in this call."""
        name = self._name(account)
        milestone_name = self._name(milestone, "milestone")
        with self._lock:
            target = self._require(name)
            if target.banned:
                raise ReferralError("REFERRAL_ACCOUNT_BANNED", name)
            if milestone_name not in self.milestones:
                raise ReferralError("REFERRAL_UNKNOWN_MILESTONE", milestone_name)

            key = (name, milestone_name)
            if key in self._settled:
                return 0

            amount = self.milestones[milestone_name]
            limit = min(self.max_levels, len(self.shares_bps))
            recipients: list[tuple[str, int]] = []
            cursor = target.inviter
            distance = 1
            while cursor is not None and distance <= limit:
                payer = self._nodes.get(cursor)
                if payer is None:
                    break
                if not payer.banned:
                    gross = amount * self.shares_bps[distance - 1] // 10_000
                    if gross:
                        recipients.append((cursor, gross))
                cursor = payer.inviter
                distance += 1

            self._settled.add(key)
            path: list[tuple[str, int]] = []
            total = 0
            for payer_name, gross in recipients:
                self._credit(payer_name, gross, milestone_name, now)
                path.append((payer_name, gross))
                total += gross
            self._paths[key] = path
            return total

    def claim_rewards(self, account: str) -> int:
        """Move claimable rewards into the spendable balance."""
        name = self._name(account)
        with self._lock:
            node = self._require(name)
            amount = node.claimable
            if not amount:
                return 0
            node.claimable = 0
            node.balance += amount
            self._append_ledger(name, "claim", amount, None, None)
            return amount

    def clawback(self, account: str, milestone: str) -> dict[str, int]:
        """Reverse one settlement along the path that actually paid it."""
        name = self._name(account)
        milestone_name = self._name(milestone, "milestone")
        with self._lock:
            self._require(name)
            if milestone_name not in self.milestones:
                raise ReferralError("REFERRAL_UNKNOWN_MILESTONE", milestone_name)
            key = (name, milestone_name)
            if key not in self._settled or key not in self._paths:
                raise ReferralError("REFERRAL_NOT_SETTLED", milestone_name)

            path = self._paths[key]
            projected_debt = sum(node.debt for node in self._nodes.values())
            for payer_name, gross in path:
                payer = self._nodes[payer_name]
                available = payer.claimable + payer.balance
                projected_debt += max(0, gross - available)
            if projected_debt > self.max_pending_debt:
                raise ReferralError(
                    "REFERRAL_DEBT_LIMIT",
                    self.max_pending_debt,
                )

            taken: dict[str, int] = {}
            for payer_name, gross in path:
                payer = self._nodes[payer_name]
                available = payer.claimable + payer.balance
                actual = min(gross, available)
                from_claimable = min(payer.claimable, actual)
                payer.claimable -= from_claimable
                payer.balance -= actual - from_claimable
                deficit = gross - actual
                if deficit:
                    payer.debt += deficit
                if actual:
                    self._append_ledger(
                        payer_name,
                        "reverse",
                        -actual,
                        milestone_name,
                        None,
                    )
                self._reversed += actual
                taken[payer_name] = actual

            del self._paths[key]
            return taken

    def tree_of(self, account: str) -> list[NodeView]:
        """Return the subtree in preorder with children sorted by account."""
        name = self._name(account)
        with self._lock:
            root = self._require(name)
            children = self._children_map()
            views: list[NodeView] = []
            stack = [root.account]
            while stack:
                current = stack.pop()
                views.append(self._view(self._nodes[current]))
                stack.extend(reversed(children.get(current, ())))
            return views

    def balance_of(self, account: str) -> int:
        """Spendable balance, never negative."""
        name = self._name(account)
        with self._lock:
            return self._require(name).balance

    def claimable_of(self, account: str) -> int:
        """Rewards credited but not claimed yet."""
        name = self._name(account)
        with self._lock:
            return self._require(name).claimable

    def pending_debt(self, account: str) -> int:
        """Suspended amount that still has to be recovered."""
        name = self._name(account)
        with self._lock:
            return self._require(name).debt

    def reward_state(self, account: str) -> dict[str, int]:
        """Return balance, claimable and debt in one mapping."""
        name = self._name(account)
        with self._lock:
            node = self._require(name)
            return {
                "balance": node.balance,
                "claimable": node.claimable,
                "debt": node.debt,
            }

    def ledger_of(self, account: str) -> list[LedgerEntry]:
        """Ledger entries of one account ordered by sequence."""
        name = self._name(account)
        with self._lock:
            self._require(name)
            return [
                entry for entry in self._ledger if entry.account == name
            ]

    def ban_account(self, account: str, *, now: str | None = None) -> int:
        """Ban an account together with its downstream subtree."""
        name = self._name(account)
        with self._lock:
            root = self._require(name)
            children = self._children_map()
            changed = 0
            stack = [root.account]
            while stack:
                current = stack.pop()
                node = self._nodes[current]
                if not node.banned:
                    node.banned = True
                    changed += 1
                stack.extend(children.get(current, ()))
            return changed

    def snapshot(self) -> dict:
        """Deep copy of the whole tree, ledger and counters."""
        with self._lock:
            nodes = {
                name: {
                    "account": node.account,
                    "inviter": node.inviter,
                    "level": node.level,
                    "bound_at": node.bound_at,
                    "device": node.device,
                    "banned": node.banned,
                    "paid": node.paid,
                    "claimable": node.claimable,
                    "balance": node.balance,
                    "debt": node.debt,
                }
                for name, node in self._nodes.items()
            }

            milestones: dict[str, dict[str, list[dict[str, Any]] | None]] = {}
            for target, milestone_name in sorted(self._settled):
                key = (target, milestone_name)
                target_state = milestones.setdefault(target, {})
                if key not in self._paths:
                    target_state[milestone_name] = None
                    continue
                target_state[milestone_name] = [
                    {"account": payer, "amount": amount}
                    for payer, amount in self._paths[key]
                ]

            ledger = [
                {
                    "seq": entry.seq,
                    "account": entry.account,
                    "kind": entry.kind,
                    "amount": entry.amount,
                    "milestone": entry.milestone,
                    "at": entry.at,
                }
                for entry in self._ledger
            ]
            return {
                "version": self.SNAPSHOT_VERSION,
                "nodes": nodes,
                "milestones": milestones,
                "ledger": ledger,
                "counters": {
                    "seq": self._seq,
                    "reversed": self._reversed,
                },
                "stats": self._stats_unlocked(),
            }

    @classmethod
    def _invalid_snapshot(cls, detail: object = None) -> ReferralError:
        return ReferralError("REFERRAL_SNAPSHOT_INVALID", detail)

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise ValueError("state")
                if not self._SNAPSHOT_KEYS.issubset(state):
                    raise ValueError("keys")
                if state.get("version") != self.SNAPSHOT_VERSION:
                    raise ValueError("version")

                raw_nodes = state["nodes"]
                raw_milestones = state["milestones"]
                raw_ledger = state["ledger"]
                raw_counters = state["counters"]
                raw_stats = state["stats"]
                if not isinstance(raw_nodes, dict):
                    raise ValueError("nodes")
                if not isinstance(raw_milestones, dict):
                    raise ValueError("milestones")
                if not isinstance(raw_ledger, list):
                    raise ValueError("ledger")
                if not isinstance(raw_counters, dict):
                    raise ValueError("counters")
                if not isinstance(raw_stats, dict):
                    raise ValueError("stats")

                nodes: dict[str, _Node] = {}
                for key, raw in raw_nodes.items():
                    if (
                        not isinstance(key, str)
                        or key != key.strip()
                        or not key
                        or not isinstance(raw, dict)
                        or not self._NODE_KEYS.issubset(raw)
                    ):
                        raise ValueError("node")
                    account = raw["account"]
                    inviter = raw["inviter"]
                    bound_at = raw["bound_at"]
                    device = raw["device"]
                    if account != key:
                        raise ValueError("node account")
                    if not isinstance(inviter, (str, type(None))):
                        raise ValueError("node inviter")
                    if inviter is not None and (
                        not inviter or inviter != inviter.strip()
                    ):
                        raise ValueError("node inviter")
                    level = self._non_negative_int(raw["level"], "level")
                    if bound_at is not None and not isinstance(bound_at, str):
                        raise ValueError("node bound_at")
                    if device is not None and not isinstance(device, str):
                        raise ValueError("node device")
                    banned = raw["banned"]
                    if not isinstance(banned, bool):
                        raise ValueError("node banned")
                    paid = self._non_negative_int(raw["paid"], "paid")
                    claimable = self._non_negative_int(
                        raw["claimable"], "claimable"
                    )
                    balance = self._non_negative_int(raw["balance"], "balance")
                    debt = self._non_negative_int(raw["debt"], "debt")
                    nodes[key] = _Node(
                        account=account,
                        inviter=inviter,
                        level=level,
                        bound_at=bound_at,
                        device=device,
                        banned=banned,
                        paid=paid,
                        claimable=claimable,
                        balance=balance,
                        debt=debt,
                    )

                if len(nodes) > self.max_nodes:
                    raise ValueError("too many nodes")
                if (
                    sum(node.debt for node in nodes.values())
                    > self.max_pending_debt
                ):
                    raise ValueError("pending debt")
                child_counts: dict[str, int] = {}
                for account, node in nodes.items():
                    if node.inviter is None:
                        if node.level != 0:
                            raise ValueError("root level")
                        continue
                    parent = nodes.get(node.inviter)
                    if parent is None:
                        raise ValueError("orphan")
                    if node.level != parent.level + 1:
                        raise ValueError("level")
                    if parent.banned and not node.banned:
                        raise ValueError("banned subtree")
                    child_counts[parent.account] = (
                        child_counts.get(parent.account, 0) + 1
                    )
                if any(
                    count > self.max_children
                    for count in child_counts.values()
                ):
                    raise ValueError("children")

                for start in nodes:
                    seen: set[str] = set()
                    cursor: str | None = start
                    while cursor is not None:
                        if cursor in seen:
                            raise ValueError("cycle")
                        seen.add(cursor)
                        cursor = nodes[cursor].inviter

                settled: set[tuple[str, str]] = set()
                paths: dict[tuple[str, str], list[tuple[str, int]]] = {}
                for target, raw_target in raw_milestones.items():
                    if (
                        not isinstance(target, str)
                        or target not in nodes
                        or not isinstance(raw_target, dict)
                    ):
                        raise ValueError("milestone target")
                    for milestone_name, raw_path in raw_target.items():
                        if (
                            not isinstance(milestone_name, str)
                            or not milestone_name
                            or milestone_name != milestone_name.strip()
                        ):
                            raise ValueError("milestone name")
                        key = (target, milestone_name)
                        if key in settled:
                            raise ValueError("duplicate milestone")
                        settled.add(key)
                        if raw_path is None:
                            continue
                        if not isinstance(raw_path, list):
                            raise ValueError("milestone path")
                        if len(raw_path) > min(
                            self.max_levels, len(self.shares_bps)
                        ):
                            raise ValueError("milestone path length")
                        path: list[tuple[str, int]] = []
                        seen_payers: set[str] = set()
                        for raw_payment in raw_path:
                            if (
                                not isinstance(raw_payment, dict)
                                or set(raw_payment) != {"account", "amount"}
                            ):
                                raise ValueError("payment")
                            payer = raw_payment["account"]
                            amount = raw_payment["amount"]
                            if (
                                not isinstance(payer, str)
                                or payer not in nodes
                                or payer in seen_payers
                            ):
                                raise ValueError("payment account")
                            amount = self._non_negative_int(amount, "payment")
                            if amount <= 0:
                                raise ValueError("payment amount")
                            seen_payers.add(payer)
                            path.append((payer, amount))
                        paths[key] = path

                ledger: list[LedgerEntry] = []
                paid_by_account: dict[str, int] = {}
                assets_by_account: dict[str, int] = {}
                last_seq = 0
                reversed_total = 0
                for raw in raw_ledger:
                    if not isinstance(raw, dict) or set(raw) != {
                        "seq",
                        "account",
                        "kind",
                        "amount",
                        "milestone",
                        "at",
                    }:
                        raise ValueError("ledger entry")
                    seq = self._non_negative_int(raw["seq"], "seq")
                    account = raw["account"]
                    kind = raw["kind"]
                    amount = raw["amount"]
                    milestone_name = raw["milestone"]
                    at = raw["at"]
                    if seq <= last_seq or seq == 0 or account not in nodes:
                        raise ValueError("ledger sequence")
                    if not isinstance(kind, str):
                        raise ValueError("ledger kind")
                    if isinstance(amount, bool) or not isinstance(amount, int):
                        raise ValueError("ledger amount")
                    if milestone_name is not None:
                        if (
                            not isinstance(milestone_name, str)
                            or not milestone_name
                            or milestone_name != milestone_name.strip()
                        ):
                            raise ValueError("ledger milestone")
                    if at is not None and not isinstance(at, str):
                        raise ValueError("ledger at")

                    if kind == "credit":
                        if amount < 0:
                            raise ValueError("credit amount")
                        paid_by_account[account] = (
                            paid_by_account.get(account, 0) + amount
                        )
                        assets_by_account[account] = (
                            assets_by_account.get(account, 0) + amount
                        )
                    elif kind == "claim":
                        if amount < 0:
                            raise ValueError("claim amount")
                    elif kind == "reverse":
                        if amount > 0:
                            raise ValueError("reverse amount")
                        assets_by_account[account] = (
                            assets_by_account.get(account, 0) + amount
                        )
                        reversed_total += -amount
                    elif kind == "offset":
                        if amount > 0:
                            raise ValueError("offset amount")
                        assets_by_account[account] = (
                            assets_by_account.get(account, 0) + amount
                        )
                    else:
                        raise ValueError("ledger kind")

                    ledger.append(
                        LedgerEntry(
                            seq=seq,
                            account=account,
                            kind=kind,
                            amount=amount,
                            milestone=milestone_name,
                            at=at,
                        )
                    )
                    last_seq = seq

                for account, node in nodes.items():
                    if paid_by_account.get(account, 0) != node.paid:
                        raise ValueError("paid reconciliation")
                    if (
                        assets_by_account.get(account, 0)
                        != node.balance + node.claimable
                    ):
                        raise ValueError("balance reconciliation")

                seq = self._non_negative_int(
                    raw_counters.get("seq", last_seq), "counter seq"
                )
                reversed_value = self._non_negative_int(
                    raw_counters.get("reversed", reversed_total),
                    "counter reversed",
                )
                if seq != last_seq or reversed_value != reversed_total:
                    raise ValueError("counters")

                expected_stats = {
                    "accounts": len(nodes),
                    "bound": sum(
                        1 for node in nodes.values() if node.inviter is not None
                    ),
                    "milestones": len(settled),
                    "paid": sum(node.paid for node in nodes.values()),
                    "claimable": sum(
                        node.claimable for node in nodes.values()
                    ),
                    "reversed": reversed_value,
                    "debt": sum(node.debt for node in nodes.values()),
                }
                if not self._STATS_KEYS.issubset(raw_stats):
                    raise ValueError("stats keys")
                for key, expected in expected_stats.items():
                    value = raw_stats[key]
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value != expected
                    ):
                        raise ValueError("stats")

                self._nodes = nodes
                self._settled = settled
                self._paths = paths
                self._ledger = ledger
                self._seq = seq
                self._reversed = reversed_value
            except ReferralError as exc:
                if exc.code == "REFERRAL_SNAPSHOT_INVALID":
                    raise
                raise self._invalid_snapshot(exc.detail) from exc
            except Exception as exc:
                raise self._invalid_snapshot(str(exc)) from exc

    def stats(self) -> dict:
        """Return the counters exposed to the operations dashboard."""
        with self._lock:
            return self._stats_unlocked()
