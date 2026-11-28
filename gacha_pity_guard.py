"""Gacha pity accounting: soft/hard pity, pool-group carryover, draw audit."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GachaError(ValueError):
    """Raised when a gacha operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PoolView:
    pool_id: str
    group: str
    base_rate_bps: int
    hard_pity: int
    soft_pity: int
    step_bps: int
    counter: int
    total_pulls: int
    golds: int
    pity_triggers: int


@dataclass(frozen=True)
class DrawOutcome:
    pool_id: str
    index: int
    roll: int
    rate_bps: int
    natural: bool
    pity: bool
    gold: bool
    counter_after: int


@dataclass(frozen=True)
class TenPullReport:
    pool_id: str
    outcomes: tuple[DrawOutcome, ...]
    golds: int
    pity_triggers: int
    counter_after: int


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    pool_id: str
    group: str
    kind: str
    roll: int | None
    gold: bool
    pity: bool
    counter_before: int
    counter_after: int


@dataclass
class _Pool:
    pool_id: str
    group: str
    base_rate_bps: int
    hard_pity: int
    soft_pity: int
    step_bps: int
    counter: int = 0
    total_pulls: int = 0
    golds: int = 0
    pity_triggers: int = 0


_SNAPSHOT_VERSION = 1
_POOL_FIELDS = frozenset({
    "pool_id", "group", "base_rate_bps", "hard_pity", "soft_pity",
    "step_bps", "counter", "total_pulls", "golds", "pity_triggers",
})
_AUDIT_FIELDS = frozenset({
    "seq", "pool_id", "group", "kind", "roll", "gold", "pity",
    "counter_before", "counter_after",
})
_STAT_FIELDS = frozenset({
    "pools", "draws", "golds", "pity_triggers", "switches", "carried",
})


def _is_int(value: object) -> bool:
    return type(value) is int


class GachaPityGuard:
    """Keep per-pool pity water levels and adjudicate every pull."""

    def __init__(self, *, max_pools: int = 16, max_audit: int = 256) -> None:
        self.max_pools = max_pools
        self.max_audit = max_audit
        self._lock = threading.RLock()
        self._pools: dict[str, _Pool] = {}
        self._audit: list[AuditEntry] = []
        self._seq = 0
        self._switches = 0
        self._carried = 0

    @staticmethod
    def _clean_pool_id(pool_id: object) -> str:
        if not isinstance(pool_id, str):
            raise GachaError("GACHA_POOL_INVALID", {"field": "pool_id"})
        cleaned = pool_id.strip()
        if not cleaned:
            raise GachaError("GACHA_POOL_INVALID", {"field": "pool_id"})
        return cleaned

    @staticmethod
    def _clean_group(group: object, pool_id: str) -> str:
        if group is None:
            return pool_id
        if not isinstance(group, str):
            raise GachaError("GACHA_POOL_INVALID", {"field": "group"})
        cleaned = group.strip()
        if not cleaned:
            raise GachaError("GACHA_POOL_INVALID", {"field": "group"})
        return cleaned

    @staticmethod
    def _validate_roll(roll: object) -> int:
        if not _is_int(roll) or not 0 <= roll <= 9999:
            raise GachaError("GACHA_INVALID_ROLL", roll)
        return roll

    def _known_pool(self, pool_id: object) -> _Pool:
        if not isinstance(pool_id, str):
            raise GachaError("GACHA_UNKNOWN_POOL", pool_id)
        cleaned = pool_id.strip()
        pool = self._pools.get(cleaned)
        if pool is None:
            raise GachaError("GACHA_UNKNOWN_POOL", pool_id)
        return pool

    @staticmethod
    def _view(pool: _Pool) -> PoolView:
        return PoolView(
            pool_id=pool.pool_id,
            group=pool.group,
            base_rate_bps=pool.base_rate_bps,
            hard_pity=pool.hard_pity,
            soft_pity=pool.soft_pity,
            step_bps=pool.step_bps,
            counter=pool.counter,
            total_pulls=pool.total_pulls,
            golds=pool.golds,
            pity_triggers=pool.pity_triggers,
        )

    @staticmethod
    def _effective_rate(pool: _Pool) -> int:
        rate = pool.base_rate_bps
        if pool.counter >= pool.soft_pity:
            rate += (pool.counter - pool.soft_pity + 1) * pool.step_bps
        return min(10000, rate)

    def _append_audit(self, entry: AuditEntry) -> None:
        self._audit.append(entry)
        overflow = len(self._audit) - self.max_audit
        if overflow > 0:
            del self._audit[:overflow]

    def _draw_locked(self, pool: _Pool, roll: int) -> DrawOutcome:
        counter_before = pool.counter
        rate = self._effective_rate(pool)
        natural = roll < rate

        if natural:
            pity = False
            gold = True
            counter_after = 0
        else:
            next_counter = counter_before + 1
            pity = next_counter >= pool.hard_pity
            gold = pity
            counter_after = 0 if pity else next_counter

        index = pool.total_pulls
        pool.counter = counter_after
        pool.total_pulls += 1
        if gold:
            pool.golds += 1
        if pity:
            pool.pity_triggers += 1

        self._seq += 1
        self._append_audit(AuditEntry(
            seq=self._seq,
            pool_id=pool.pool_id,
            group=pool.group,
            kind="draw",
            roll=roll,
            gold=gold,
            pity=pity,
            counter_before=counter_before,
            counter_after=counter_after,
        ))
        return DrawOutcome(
            pool_id=pool.pool_id,
            index=index,
            roll=roll,
            rate_bps=rate,
            natural=natural,
            pity=pity,
            gold=gold,
            counter_after=counter_after,
        )

    def register_pool(self, pool_id: str, *, group: str | None = None,
                      base_rate_bps: int = 60, hard_pity: int = 90,
                      soft_pity: int = 75, step_bps: int = 600) -> PoolView:
        """Register one banner and return its opening view."""
        with self._lock:
            cleaned_id = self._clean_pool_id(pool_id)
            cleaned_group = self._clean_group(group, cleaned_id)
            if not _is_int(base_rate_bps) or not 0 <= base_rate_bps <= 10000:
                raise GachaError("GACHA_POOL_INVALID", {"field": "base_rate_bps"})
            if not _is_int(hard_pity) or hard_pity < 1:
                raise GachaError("GACHA_POOL_INVALID", {"field": "hard_pity"})
            if (not _is_int(soft_pity) or soft_pity < 0
                    or soft_pity >= hard_pity):
                raise GachaError("GACHA_POOL_INVALID", {"field": "soft_pity"})
            if not _is_int(step_bps) or step_bps < 0:
                raise GachaError("GACHA_POOL_INVALID", {"field": "step_bps"})
            if cleaned_id in self._pools:
                raise GachaError("GACHA_POOL_EXISTS", cleaned_id)
            if len(self._pools) >= self.max_pools:
                raise GachaError("GACHA_CAPACITY", self.max_pools)

            pool = _Pool(
                pool_id=cleaned_id,
                group=cleaned_group,
                base_rate_bps=base_rate_bps,
                hard_pity=hard_pity,
                soft_pity=soft_pity,
                step_bps=step_bps,
            )
            self._pools[cleaned_id] = pool
            return self._view(pool)

    def pool_view(self, pool_id: str) -> PoolView:
        """Return the immutable view of one banner."""
        with self._lock:
            return self._view(self._known_pool(pool_id))

    def current_counter(self, pool_id: str) -> int:
        """Return the pity water level used by the next pull."""
        with self._lock:
            return self._known_pool(pool_id).counter

    def rate_bps(self, pool_id: str) -> int:
        """Effective gold rate of the next pull, in basis points."""
        with self._lock:
            return self._effective_rate(self._known_pool(pool_id))

    def pity_left(self, pool_id: str) -> int:
        """Pulls still needed before the hard pity line."""
        with self._lock:
            pool = self._known_pool(pool_id)
            return max(0, pool.hard_pity - pool.counter)

    def draw(self, pool_id: str, *, roll: int) -> DrawOutcome:
        """Adjudicate one single pull from an explicit roll value."""
        with self._lock:
            pool = self._known_pool(pool_id)
            checked_roll = self._validate_roll(roll)
            return self._draw_locked(pool, checked_roll)

    def draw_ten(self, pool_id: str, *, rolls) -> TenPullReport:
        """Adjudicate one ten-pull batch atomically."""
        with self._lock:
            pool = self._known_pool(pool_id)
            try:
                batch = list(rolls)
            except TypeError:
                raise GachaError("GACHA_BATCH_SIZE", "rolls must be iterable")
            if len(batch) != 10:
                raise GachaError("GACHA_BATCH_SIZE", len(batch))
            checked_rolls = [self._validate_roll(roll) for roll in batch]

            outcomes = tuple(
                self._draw_locked(pool, roll) for roll in checked_rolls
            )
            return TenPullReport(
                pool_id=pool.pool_id,
                outcomes=outcomes,
                golds=sum(1 for row in outcomes if row.gold),
                pity_triggers=sum(1 for row in outcomes if row.pity),
                counter_after=pool.counter,
            )

    def switch_pool(self, source_pool: str, target_pool: str) -> int:
        """Carry the pity water level inside one pool group."""
        with self._lock:
            source_id = (
                source_pool.strip() if isinstance(source_pool, str) else None
            )
            target_id = (
                target_pool.strip() if isinstance(target_pool, str) else None
            )
            if source_id is not None and source_id == target_id:
                raise GachaError("GACHA_POOL_INVALID", "source and target match")

            source = self._known_pool(source_pool)
            target = self._known_pool(target_pool)
            if source.group != target.group:
                raise GachaError(
                    "GACHA_GROUP_MISMATCH",
                    {"source": source.group, "target": target.group},
                )

            carried = source.counter
            counter_before = target.counter
            source.counter = 0
            target.counter = carried
            self._switches += 1
            self._carried += carried

            self._seq += 1
            self._append_audit(AuditEntry(
                seq=self._seq,
                pool_id=target.pool_id,
                group=target.group,
                kind="carry",
                roll=None,
                gold=False,
                pity=False,
                counter_before=counter_before,
                counter_after=carried,
            ))
            return carried

    def audit(self, pool_id: str | None = None) -> list[AuditEntry]:
        """Return audit entries in sequence order, optionally scoped."""
        with self._lock:
            if pool_id is None:
                return list(self._audit)
            pool = self._known_pool(pool_id)
            return [entry for entry in self._audit
                    if entry.pool_id == pool.pool_id]

    def snapshot(self) -> dict:
        """Deep copy of pools, audit trail and counters."""
        with self._lock:
            pools = {
                pool_id: {
                    "pool_id": pool.pool_id,
                    "group": pool.group,
                    "base_rate_bps": pool.base_rate_bps,
                    "hard_pity": pool.hard_pity,
                    "soft_pity": pool.soft_pity,
                    "step_bps": pool.step_bps,
                    "counter": pool.counter,
                    "total_pulls": pool.total_pulls,
                    "golds": pool.golds,
                    "pity_triggers": pool.pity_triggers,
                }
                for pool_id, pool in self._pools.items()
            }
            audit = [
                {
                    "seq": entry.seq,
                    "pool_id": entry.pool_id,
                    "group": entry.group,
                    "kind": entry.kind,
                    "roll": entry.roll,
                    "gold": entry.gold,
                    "pity": entry.pity,
                    "counter_before": entry.counter_before,
                    "counter_after": entry.counter_after,
                }
                for entry in self._audit
            ]
            return {
                "version": _SNAPSHOT_VERSION,
                "pools": pools,
                "audit": audit,
                "counters": {
                    "seq": self._seq,
                    "switches": self._switches,
                    "carried": self._carried,
                },
                "stats": self.stats(),
            }

    @staticmethod
    def _snapshot_error(detail: object) -> GachaError:
        return GachaError("GACHA_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise self._snapshot_error("snapshot must be a dict")
        required = {"version", "pools", "audit", "counters", "stats"}
        if set(state) != required:
            raise self._snapshot_error("snapshot keys")
        if (not _is_int(state["version"])
                or state["version"] != _SNAPSHOT_VERSION):
            raise self._snapshot_error("version")

        raw_pools = state["pools"]
        if not isinstance(raw_pools, dict):
            raise self._snapshot_error("pools")

        pools: dict[str, _Pool] = {}
        for pool_id, raw in raw_pools.items():
            if not isinstance(pool_id, str) or not pool_id:
                raise self._snapshot_error("pool id")
            if pool_id != pool_id.strip():
                raise self._snapshot_error("pool id")
            if not isinstance(raw, dict) or set(raw) != _POOL_FIELDS:
                raise self._snapshot_error("pool fields")
            if raw["pool_id"] != pool_id:
                raise self._snapshot_error("pool id mismatch")
            group = raw["group"]
            if (not isinstance(group, str) or not group
                    or group != group.strip()):
                raise self._snapshot_error("pool group")

            base_rate_bps = raw["base_rate_bps"]
            hard_pity = raw["hard_pity"]
            soft_pity = raw["soft_pity"]
            step_bps = raw["step_bps"]
            counter = raw["counter"]
            total_pulls = raw["total_pulls"]
            golds = raw["golds"]
            pity_triggers = raw["pity_triggers"]
            if not _is_int(base_rate_bps) or not 0 <= base_rate_bps <= 10000:
                raise self._snapshot_error("base_rate_bps")
            if not _is_int(hard_pity) or hard_pity < 1:
                raise self._snapshot_error("hard_pity")
            if (not _is_int(soft_pity) or soft_pity < 0
                    or soft_pity >= hard_pity):
                raise self._snapshot_error("soft_pity")
            if not _is_int(step_bps) or step_bps < 0:
                raise self._snapshot_error("step_bps")
            if not _is_int(counter) or not 0 <= counter < hard_pity:
                raise self._snapshot_error("counter")
            if not _is_int(total_pulls) or total_pulls < 0:
                raise self._snapshot_error("total_pulls")
            if not _is_int(golds) or not 0 <= golds <= total_pulls:
                raise self._snapshot_error("golds")
            if (not _is_int(pity_triggers)
                    or not 0 <= pity_triggers <= golds):
                raise self._snapshot_error("pity_triggers")

            pools[pool_id] = _Pool(
                pool_id=pool_id,
                group=group,
                base_rate_bps=base_rate_bps,
                hard_pity=hard_pity,
                soft_pity=soft_pity,
                step_bps=step_bps,
                counter=counter,
                total_pulls=total_pulls,
                golds=golds,
                pity_triggers=pity_triggers,
            )

        if len(pools) > self.max_pools:
            raise GachaError("GACHA_CAPACITY", self.max_pools)

        raw_audit = state["audit"]
        if not isinstance(raw_audit, list):
            raise self._snapshot_error("audit")
        if len(raw_audit) > self.max_audit:
            raw_audit = raw_audit[-self.max_audit:] if self.max_audit > 0 else []

        audit: list[AuditEntry] = []
        previous_seq: int | None = None
        for raw in raw_audit:
            if not isinstance(raw, dict) or set(raw) != _AUDIT_FIELDS:
                raise self._snapshot_error("audit fields")
            seq = raw["seq"]
            pool_id = raw["pool_id"]
            group = raw["group"]
            kind = raw["kind"]
            roll = raw["roll"]
            gold = raw["gold"]
            pity = raw["pity"]
            counter_before = raw["counter_before"]
            counter_after = raw["counter_after"]

            if (not _is_int(seq) or seq < 1
                    or (previous_seq is not None
                        and seq != previous_seq + 1)):
                raise self._snapshot_error("audit seq")
            previous_seq = seq
            if (not isinstance(pool_id, str) or pool_id not in pools
                    or pool_id != pool_id.strip()):
                raise self._snapshot_error("audit pool")
            pool = pools[pool_id]
            if group != pool.group:
                raise self._snapshot_error("audit group")
            if kind not in {"draw", "carry"}:
                raise self._snapshot_error("audit kind")
            if type(gold) is not bool or type(pity) is not bool:
                raise self._snapshot_error("audit flags")
            if (not _is_int(counter_before) or not 0 <= counter_before
                    or not _is_int(counter_after) or not 0 <= counter_after):
                raise self._snapshot_error("audit counters")
            if counter_before >= pool.hard_pity or counter_after >= pool.hard_pity:
                raise self._snapshot_error("audit counters")

            if kind == "draw":
                if not _is_int(roll) or not 0 <= roll <= 9999:
                    raise self._snapshot_error("audit roll")
            else:
                if roll is not None or gold or pity:
                    raise self._snapshot_error("audit carry")

            audit.append(AuditEntry(
                seq=seq,
                pool_id=pool_id,
                group=group,
                kind=kind,
                roll=roll,
                gold=gold,
                pity=pity,
                counter_before=counter_before,
                counter_after=counter_after,
            ))

        raw_counters = state["counters"]
        if (not isinstance(raw_counters, dict)
                or set(raw_counters) != {"seq", "switches", "carried"}):
            raise self._snapshot_error("counters")
        seq = raw_counters["seq"]
        switches = raw_counters["switches"]
        carried = raw_counters["carried"]
        if (not _is_int(seq) or seq < 0
                or not _is_int(switches) or switches < 0
                or not _is_int(carried) or carried < 0):
            raise self._snapshot_error("counters")
        if audit and audit[-1].seq != seq:
            raise self._snapshot_error("audit seq")

        raw_stats = state["stats"]
        if (not isinstance(raw_stats, dict)
                or set(raw_stats) != _STAT_FIELDS):
            raise self._snapshot_error("stats")
        for value in raw_stats.values():
            if not _is_int(value) or value < 0:
                raise self._snapshot_error("stats")
        expected_stats = {
            "pools": len(pools),
            "draws": sum(pool.total_pulls for pool in pools.values()),
            "golds": sum(pool.golds for pool in pools.values()),
            "pity_triggers": sum(
                pool.pity_triggers for pool in pools.values()
            ),
            "switches": switches,
            "carried": carried,
        }
        if raw_stats != expected_stats:
            raise self._snapshot_error("stats")

        return pools, audit, seq, switches, carried

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        with self._lock:
            pools, audit, seq, switches, carried = self._parse_snapshot(state)
            self._pools = pools
            self._audit = audit
            self._seq = seq
            self._switches = switches
            self._carried = carried

    def stats(self) -> dict:
        """Return counters exposed to the operations dashboard."""
        with self._lock:
            return {
                "pools": len(self._pools),
                "draws": sum(pool.total_pulls for pool in self._pools.values()),
                "golds": sum(pool.golds for pool in self._pools.values()),
                "pity_triggers": sum(
                    pool.pity_triggers for pool in self._pools.values()
                ),
                "switches": self._switches,
                "carried": self._carried,
            }
