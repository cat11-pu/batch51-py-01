"""Convolution reverb bus scheduling: head/partition split, IR swapping and tail accounting."""

from __future__ import annotations

import math
import numbers
import threading
from dataclasses import dataclass, field


class ReverbError(ValueError):
    """Raised when a reverb schedule operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class IrBinding:
    """Result of installing one impulse response on a bus."""

    bus: str
    ir_id: str
    version: int
    taps: int
    head_samples: int
    partitions: int


@dataclass(frozen=True)
class BlockResult:
    """Accounting for one processed block."""

    bus: str
    seq: int
    samples: int
    head_samples: int
    partition_samples: int
    tail_remaining: int
    fade_remaining: int


@dataclass
class _IrReference:
    ir_id: str
    taps: int
    refs: int = 0


@dataclass
class _Chain:
    ir_id: str
    taps: int
    version: int
    partitions: int
    processed: int = 0
    fade_remaining: int = 0
    fade_total: int = 0
    fade_entered: bool = False

    @property
    def key(self) -> tuple[str, int]:
        return (self.ir_id, self.taps)


@dataclass
class _Bus:
    name: str
    wet: float = 1.0
    last_seq: int = 0
    current: _Chain | None = None
    retiring: list[_Chain] = field(default_factory=list)


_SNAPSHOT_VERSION = 1
_STAT_KEYS = ("buses", "loads", "swaps", "blocks", "samples", "released")
_BUS_FIELDS = (
    "bus",
    "ir_id",
    "ir_taps",
    "version",
    "partitions",
    "wet",
    "processed",
    "last_seq",
    "fade_remaining",
    "retiring",
)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_real(value: object) -> bool:
    return isinstance(value, numbers.Real) and not isinstance(value, bool)


class ReverbScheduler:
    """Maintain one convolution instance per audio bus with partitioned IR scheduling."""

    def __init__(self, *, max_buses: int = 8, max_partitions: int = 32,
                 head_samples: int = 64, block_size: int = 128,
                 fade_blocks: int = 4) -> None:
        self.max_buses = max_buses
        self.max_partitions = max_partitions
        self.head_samples = head_samples
        self.block_size = block_size
        self.fade_blocks = fade_blocks
        self._lock = threading.RLock()
        self._buses: dict[str, _Bus] = {}
        self._ir_cache: dict[tuple[str, int], _IrReference] = {}
        self._counters = {
            "loads": 0,
            "swaps": 0,
            "blocks": 0,
            "samples": 0,
            "released": 0,
        }

    @staticmethod
    def _normalize_bus(name: object) -> str:
        if not isinstance(name, str):
            raise ReverbError("REVERB_INVALID_NAME", {"name": name})
        normalized = name.strip()
        if not normalized:
            raise ReverbError("REVERB_INVALID_NAME", {"name": name})
        return normalized

    @staticmethod
    def _normalize_ir(ir_id: object) -> str:
        if not isinstance(ir_id, str):
            raise ReverbError("REVERB_IR_INVALID", {"ir_id": ir_id})
        normalized = ir_id.strip()
        if not normalized:
            raise ReverbError("REVERB_IR_INVALID", {"ir_id": ir_id})
        return normalized

    @staticmethod
    def _validate_taps(taps: object) -> int:
        if not _is_int(taps) or taps <= 0:
            raise ReverbError("REVERB_IR_INVALID", {"taps": taps})
        return taps

    def _partitions_for(self, taps: int) -> int:
        if taps <= self.head_samples:
            return 0
        if self.block_size <= 0:
            raise ReverbError("REVERB_IR_INVALID", {"block_size": self.block_size})
        return (taps - self.head_samples + self.block_size - 1) // self.block_size

    def _checked_partitions(self, taps: int) -> int:
        partitions = self._partitions_for(taps)
        if partitions > self.max_partitions:
            raise ReverbError(
                "REVERB_PARTITION_LIMIT",
                {"taps": taps, "partitions": partitions,
                 "max_partitions": self.max_partitions},
            )
        return partitions

    def _lookup_locked(self, name: str) -> _Bus:
        bus = self._buses.get(name)
        if bus is None:
            raise ReverbError("REVERB_BUS_UNKNOWN", {"bus": name})
        return bus

    def _acquire_ir(self, chain: _Chain) -> None:
        reference = self._ir_cache.get(chain.key)
        if reference is None:
            self._ir_cache[chain.key] = _IrReference(
                ir_id=chain.ir_id, taps=chain.taps, refs=1
            )
        else:
            reference.refs += 1

    def _release_ir(self, chain: _Chain) -> None:
        reference = self._ir_cache.get(chain.key)
        if reference is None:
            return
        reference.refs -= 1
        if reference.refs <= 0:
            del self._ir_cache[chain.key]

    def create_bus(self, name: str) -> str:
        normalized = self._normalize_bus(name)
        with self._lock:
            if normalized in self._buses:
                raise ReverbError("REVERB_BUS_EXISTS", {"bus": normalized})
            if len(self._buses) >= self.max_buses:
                raise ReverbError(
                    "REVERB_CAPACITY",
                    {"bus": normalized, "max_buses": self.max_buses},
                )
            self._buses[normalized] = _Bus(name=normalized)
            return normalized

    def load_ir(self, bus: str, ir_id: str, *, taps: int) -> IrBinding:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            if target.current is not None:
                raise ReverbError(
                    "REVERB_IR_PRESENT",
                    {"bus": normalized_bus, "ir_id": target.current.ir_id},
                )
            normalized_ir = self._normalize_ir(ir_id)
            checked_taps = self._validate_taps(taps)
            partitions = self._checked_partitions(checked_taps)
            chain = _Chain(
                ir_id=normalized_ir,
                taps=checked_taps,
                version=1,
                partitions=partitions,
            )
            self._acquire_ir(chain)
            target.current = chain
            self._counters["loads"] += 1
            return IrBinding(
                bus=normalized_bus,
                ir_id=normalized_ir,
                version=1,
                taps=checked_taps,
                head_samples=self.head_samples,
                partitions=partitions,
            )

    def swap_ir(self, bus: str, ir_id: str, *, taps: int) -> IrBinding:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            old = target.current
            if old is None:
                raise ReverbError("REVERB_NO_IR", {"bus": normalized_bus})
            normalized_ir = self._normalize_ir(ir_id)
            if normalized_ir == old.ir_id:
                raise ReverbError(
                    "REVERB_IR_UNCHANGED",
                    {"bus": normalized_bus, "ir_id": normalized_ir},
                )
            checked_taps = self._validate_taps(taps)
            partitions = self._checked_partitions(checked_taps)
            fade_total = max(0, self.fade_blocks * self.block_size)
            new_chain = _Chain(
                ir_id=normalized_ir,
                taps=checked_taps,
                version=old.version + 1,
                partitions=partitions,
                fade_remaining=fade_total,
                fade_total=fade_total,
                fade_entered=True,
            )
            self._acquire_ir(new_chain)
            target.current = new_chain
            if old.taps - old.processed > 0:
                target.retiring.append(old)
            else:
                self._release_ir(old)
            self._counters["swaps"] += 1
            return IrBinding(
                bus=normalized_bus,
                ir_id=normalized_ir,
                version=new_chain.version,
                taps=checked_taps,
                head_samples=self.head_samples,
                partitions=partitions,
            )

    def set_mix(self, bus: str, *, wet: float) -> float:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            if not _is_real(wet):
                raise ReverbError(
                    "REVERB_MIX_OUT_OF_RANGE", {"bus": normalized_bus, "wet": wet}
                )
            try:
                value = float(wet)
            except (OverflowError, ValueError):
                raise ReverbError(
                    "REVERB_MIX_OUT_OF_RANGE", {"bus": normalized_bus, "wet": wet}
                ) from None
            if not math.isfinite(value) or value < 0.0 or value > 1.0:
                raise ReverbError(
                    "REVERB_MIX_OUT_OF_RANGE", {"bus": normalized_bus, "wet": wet}
                )
            target.wet = value
            return value

    def process_block(self, bus: str, *, seq: int, samples: int) -> BlockResult:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            current = target.current
            if current is None:
                raise ReverbError("REVERB_NO_IR", {"bus": normalized_bus})
            if not _is_int(samples) or samples <= 0:
                raise ReverbError(
                    "REVERB_BLOCK_INVALID",
                    {"bus": normalized_bus, "samples": samples},
                )
            if samples > self.block_size:
                raise ReverbError(
                    "REVERB_BLOCK_TOO_LARGE",
                    {"bus": normalized_bus, "samples": samples,
                     "block_size": self.block_size},
                )
            if not _is_int(seq) or seq != target.last_seq + 1:
                raise ReverbError(
                    "REVERB_SEQ_MISMATCH",
                    {"bus": normalized_bus, "seq": seq,
                     "expected": target.last_seq + 1},
                )

            current.processed += samples
            if current.fade_entered:
                current.fade_remaining = max(0, current.fade_remaining - samples)

            for retiring in list(target.retiring):
                retiring.processed += samples
                if retiring.taps - retiring.processed <= 0:
                    self._release_ir(retiring)
                    target.retiring.remove(retiring)

            target.last_seq = seq
            self._counters["blocks"] += 1
            self._counters["samples"] += samples

            head = min(samples, self.head_samples)
            return BlockResult(
                bus=normalized_bus,
                seq=seq,
                samples=samples,
                head_samples=head,
                partition_samples=samples - head,
                tail_remaining=max(0, current.taps - current.processed),
                fade_remaining=current.fade_remaining,
            )

    def tail_of(self, bus: str) -> int:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            current = target.current
            if current is None:
                return 0
            return max(0, current.taps - current.processed)

    def fade_progress(self, bus: str) -> float:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            current = target.current
            if current is None or not current.fade_entered:
                return 0.0
            if current.fade_total <= 0:
                return 1.0
            consumed = current.fade_total - current.fade_remaining
            consumed = max(0, min(current.fade_total, consumed))
            return consumed / current.fade_total

    def partition_count(self, bus: str) -> int:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            return target.current.partitions if target.current is not None else 0

    def release_bus(self, bus: str) -> int:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            chains = list(target.retiring)
            if target.current is not None:
                chains.append(target.current)
            for chain in chains:
                self._release_ir(chain)
            del self._buses[normalized_bus]
            released = len(chains)
            self._counters["released"] += released
            return released

    def bus_state(self, bus: str) -> dict:
        normalized_bus = self._normalize_bus(bus)
        with self._lock:
            target = self._lookup_locked(normalized_bus)
            current = target.current
            return {
                "bus": target.name,
                "ir_id": current.ir_id if current is not None else None,
                "version": current.version if current is not None else 0,
                "taps": current.taps if current is not None else 0,
                "partitions": current.partitions if current is not None else 0,
                "wet": target.wet,
                "processed": current.processed if current is not None else 0,
                "last_seq": target.last_seq,
                "fade_remaining": (
                    current.fade_remaining if current is not None else 0
                ),
                "retiring": len(target.retiring),
            }

    @staticmethod
    def _chain_snapshot(chain: _Chain) -> dict:
        return {
            "ir_id": chain.ir_id,
            "ir_taps": chain.taps,
            "version": chain.version,
            "partitions": chain.partitions,
            "processed": chain.processed,
            "fade_remaining": chain.fade_remaining,
            "fade_total": chain.fade_total,
            "fade_entered": chain.fade_entered,
        }

    def _stats_locked(self) -> dict:
        return {
            "buses": len(self._buses),
            "loads": self._counters["loads"],
            "swaps": self._counters["swaps"],
            "blocks": self._counters["blocks"],
            "samples": self._counters["samples"],
            "released": self._counters["released"],
        }

    def snapshot(self) -> dict:
        with self._lock:
            buses = []
            for target in self._buses.values():
                current = target.current
                record = {
                    "bus": target.name,
                    "ir_id": current.ir_id if current is not None else None,
                    "ir_taps": current.taps if current is not None else 0,
                    "version": current.version if current is not None else 0,
                    "partitions": (
                        current.partitions if current is not None else 0
                    ),
                    "wet": target.wet,
                    "processed": current.processed if current is not None else 0,
                    "last_seq": target.last_seq,
                    "fade_remaining": (
                        current.fade_remaining if current is not None else 0
                    ),
                    "retiring": len(target.retiring),
                    "retiring_chains": [
                        self._chain_snapshot(chain)
                        for chain in target.retiring
                    ],
                }
                if current is not None:
                    record["fade_total"] = current.fade_total
                    record["fade_entered"] = current.fade_entered
                else:
                    record["fade_total"] = 0
                    record["fade_entered"] = False
                buses.append(record)
            return {
                "version": _SNAPSHOT_VERSION,
                "buses": buses,
                "stats": self._stats_locked(),
            }

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> ReverbError:
        return ReverbError("REVERB_SNAPSHOT_INVALID", detail)

    def _snapshot_chain(self, record: object, *, current: bool) -> _Chain:
        if not isinstance(record, dict):
            raise self._snapshot_invalid({"chain": record})
        required = ("ir_id", "ir_taps", "version", "partitions", "processed")
        if any(field_name not in record for field_name in required):
            raise self._snapshot_invalid({"chain": record})

        raw_ir = record["ir_id"]
        if not isinstance(raw_ir, str):
            raise self._snapshot_invalid({"ir_id": raw_ir})
        ir_id = raw_ir.strip()
        if not ir_id:
            raise self._snapshot_invalid({"ir_id": raw_ir})
        taps = record["ir_taps"]
        version = record["version"]
        partitions = record["partitions"]
        processed = record["processed"]
        if not _is_int(taps) or taps <= 0:
            raise self._snapshot_invalid({"ir_taps": taps})
        if not _is_int(version) or version <= 0:
            raise self._snapshot_invalid({"version": version})
        if not _is_int(partitions) or partitions < 0:
            raise self._snapshot_invalid({"partitions": partitions})
        if partitions != self._partitions_for(taps):
            raise self._snapshot_invalid(
                {"partitions": partitions, "expected": self._partitions_for(taps)}
            )
        if not _is_int(processed) or processed < 0:
            raise self._snapshot_invalid({"processed": processed})

        fade_remaining = record.get("fade_remaining", 0)
        if not _is_int(fade_remaining) or fade_remaining < 0:
            raise self._snapshot_invalid({"fade_remaining": fade_remaining})

        if "fade_entered" not in record and "fade_total" not in record:
            fade_entered = current and version > 1
            fade_total = (
                max(0, self.fade_blocks * self.block_size)
                if fade_entered
                else 0
            )
        else:
            if "fade_entered" not in record or "fade_total" not in record:
                raise self._snapshot_invalid({"fade_entered": record.get("fade_entered")})
            fade_entered = record["fade_entered"]
            fade_total = record["fade_total"]
            if not isinstance(fade_entered, bool):
                raise self._snapshot_invalid({"fade_entered": fade_entered})
            if not _is_int(fade_total) or fade_total < 0:
                raise self._snapshot_invalid({"fade_total": fade_total})

        if not fade_entered:
            if fade_remaining != 0 or fade_total != 0:
                raise self._snapshot_invalid({"fade_remaining": fade_remaining})
        elif fade_remaining > fade_total:
            raise self._snapshot_invalid(
                {"fade_remaining": fade_remaining, "fade_total": fade_total}
            )

        return _Chain(
            ir_id=ir_id,
            taps=taps,
            version=version,
            partitions=partitions,
            processed=processed,
            fade_remaining=fade_remaining,
            fade_total=fade_total,
            fade_entered=fade_entered,
        )

    def _retiring_from_snapshot(
        self, record: dict, current: _Chain | None
    ) -> list[_Chain]:
        raw_count = record["retiring"]
        raw_chains = record.get("retiring_chains")

        if isinstance(raw_count, list):
            if raw_chains is not None:
                raise self._snapshot_invalid({"retiring": raw_count})
            raw_chains = raw_count
            count = len(raw_chains)
        elif _is_int(raw_count):
            if raw_count < 0:
                raise self._snapshot_invalid({"retiring": raw_count})
            count = raw_count
        else:
            raise self._snapshot_invalid({"retiring": raw_count})

        if raw_chains is not None:
            if not isinstance(raw_chains, list) or len(raw_chains) != count:
                raise self._snapshot_invalid({"retiring_chains": raw_chains})
            return [
                self._snapshot_chain(chain, current=False)
                for chain in raw_chains
            ]

        if count == 0:
            return []
        if current is None:
            raise self._snapshot_invalid({"retiring": count})
        version = max(1, current.version - 1)
        return [
            _Chain(
                ir_id=current.ir_id,
                taps=current.taps,
                version=version,
                partitions=current.partitions,
            )
            for _ in range(count)
        ]

    def _build_restored(self, state: object):
        if not isinstance(state, dict):
            raise self._snapshot_invalid({"snapshot": state})
        if not _is_int(state.get("version")) or state["version"] != _SNAPSHOT_VERSION:
            raise self._snapshot_invalid({"version": state.get("version")})
        bus_records = state.get("buses")
        stats_record = state.get("stats")
        if not isinstance(bus_records, list) or not isinstance(stats_record, dict):
            raise self._snapshot_invalid({"buses": bus_records, "stats": stats_record})
        if any(key not in stats_record for key in _STAT_KEYS):
            raise self._snapshot_invalid({"stats": stats_record})
        if any(
            not _is_int(stats_record[key]) or stats_record[key] < 0
            for key in _STAT_KEYS
        ):
            raise self._snapshot_invalid({"stats": stats_record})
        if stats_record["buses"] != len(bus_records):
            raise self._snapshot_invalid({"stats": stats_record})
        if len(bus_records) > self.max_buses:
            raise self._snapshot_invalid({"buses": len(bus_records)})

        buses: dict[str, _Bus] = {}
        cache: dict[tuple[str, int], _IrReference] = {}

        def acquire(chain: _Chain) -> None:
            reference = cache.get(chain.key)
            if reference is None:
                cache[chain.key] = _IrReference(
                    ir_id=chain.ir_id, taps=chain.taps, refs=1
                )
            else:
                reference.refs += 1

        for record in bus_records:
            if not isinstance(record, dict):
                raise self._snapshot_invalid({"bus": record})
            if any(field_name not in record for field_name in _BUS_FIELDS):
                raise self._snapshot_invalid({"bus": record})

            raw_name = record["bus"]
            if not isinstance(raw_name, str):
                raise self._snapshot_invalid({"bus": raw_name})
            name = raw_name.strip()
            if not name or name in buses:
                raise self._snapshot_invalid({"bus": raw_name})

            wet = record["wet"]
            if not _is_real(wet):
                raise self._snapshot_invalid({"wet": wet})
            wet_value = float(wet)
            if (
                not math.isfinite(wet_value)
                or wet_value < 0.0
                or wet_value > 1.0
            ):
                raise self._snapshot_invalid({"wet": wet})

            last_seq = record["last_seq"]
            if not _is_int(last_seq) or last_seq < 0:
                raise self._snapshot_invalid({"last_seq": last_seq})

            raw_ir = record["ir_id"]
            current: _Chain | None
            if raw_ir is None:
                version = record["version"]
                taps = record["ir_taps"]
                partitions = record["partitions"]
                processed = record["processed"]
                fade_remaining = record["fade_remaining"]
                if (
                    not _is_int(version)
                    or version != 0
                    or not _is_int(taps)
                    or taps != 0
                    or not _is_int(partitions)
                    or partitions != 0
                    or not _is_int(processed)
                    or processed != 0
                    or not _is_int(fade_remaining)
                    or fade_remaining != 0
                ):
                    raise self._snapshot_invalid({"bus": name})
                if (
                    "fade_entered" in record
                    and record["fade_entered"] is not False
                ):
                    raise self._snapshot_invalid({"bus": name})
                if (
                    "fade_total" in record
                    and (
                        not _is_int(record["fade_total"])
                        or record["fade_total"] != 0
                    )
                ):
                    raise self._snapshot_invalid({"bus": name})
                current = None
            else:
                current = self._snapshot_chain(record, current=True)

            retiring = self._retiring_from_snapshot(record, current)
            if current is None and retiring:
                raise self._snapshot_invalid({"bus": name})
            if current is not None:
                acquire(current)
            for chain in retiring:
                acquire(chain)

            buses[name] = _Bus(
                name=name,
                wet=wet_value,
                last_seq=last_seq,
                current=current,
                retiring=retiring,
            )

        counters = {
            key: stats_record[key]
            for key in ("loads", "swaps", "blocks", "samples", "released")
        }
        return buses, cache, counters

    def restore(self, state: dict) -> None:
        try:
            buses, cache, counters = self._build_restored(state)
        except ReverbError as exc:
            if exc.code == "REVERB_SNAPSHOT_INVALID":
                raise
            raise self._snapshot_invalid({"error": exc.code}) from None
        except Exception as exc:
            raise self._snapshot_invalid({"error": str(exc)}) from None
        with self._lock:
            self._buses = buses
            self._ir_cache = cache
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()
