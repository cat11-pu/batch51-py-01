"""Ray tracing instance ledger: id pool, visibility masks and BLAS refcounts."""

from __future__ import annotations

import copy
import threading
from bisect import insort
from dataclasses import dataclass, replace


_SNAPSHOT_VERSION = 1
_MAX_MASK = 0xFFFF
_STAT_KEYS = ("instances", "removed", "rebuilds", "dirty")


class InstanceLedgerError(ValueError):
    """Raised when an instance ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class InstanceRecord:
    """One instance entry as it would be uploaded to the buffer."""

    instance_id: int
    blas: str
    transform: tuple
    mask: int
    dirty: bool


@dataclass(frozen=True)
class BuildReport:
    """Summary of one instance buffer rebuild."""

    written: int
    dirty: int
    high_water: int


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_mask(value: object) -> bool:
    return _is_int(value) and 0 <= value <= _MAX_MASK


def _valid_instance_id(value: object) -> bool:
    return _is_int(value) and value > 0


def _copy_transform(transform: object) -> tuple:
    copied = copy.deepcopy(transform)
    if isinstance(copied, tuple):
        return copied
    try:
        return tuple(copied)
    except TypeError as exc:
        raise ValueError("transform must be iterable") from exc


class RayInstanceLedger:
    """Keep instance ids dense and stable while tracking BLAS references."""

    def __init__(self, *, max_instances: int = 1024) -> None:
        if not _is_int(max_instances) or max_instances < 0:
            raise ValueError("max_instances must be a non-negative integer")
        self.max_instances = max_instances
        self._lock = threading.RLock()
        self._instances: dict[int, InstanceRecord] = {}
        self._free: list[int] = []
        self._blas: dict[object, int] = {}
        self._blas_instance_refs: dict[object, int] = {}
        self._next_id = 1
        self._stats = {"instances": 0, "removed": 0, "rebuilds": 0,
                       "dirty": 0}

    def add_instance(self, *, blas: str, transform=(0.0, 0.0, 0.0),
                     mask: int = 1, instance_id=None) -> int:
        with self._lock:
            if not _valid_mask(mask):
                self._invalid_mask(mask)
            if not self._has_blas(blas):
                raise KeyError(blas)
            if instance_id is not None:
                if not _valid_instance_id(instance_id):
                    raise InstanceLedgerError(
                        "LEDGER_INVALID_ID", {"instance_id": instance_id}
                    )
                if instance_id in self._instances:
                    raise InstanceLedgerError(
                        "LEDGER_DUPLICATE_ID", {"instance_id": instance_id}
                    )
            if len(self._instances) >= self.max_instances:
                raise InstanceLedgerError(
                    "LEDGER_CAPACITY_EXCEEDED",
                    {
                        "instances": len(self._instances),
                        "max_instances": self.max_instances,
                    },
                )

            normalized_transform = _copy_transform(transform)
            if instance_id is None:
                if self._free:
                    allocated = self._free.pop(0)
                else:
                    allocated = self._next_id
                    self._next_id += 1
            else:
                allocated = instance_id
                try:
                    self._free.remove(allocated)
                except ValueError:
                    pass
                if allocated >= self._next_id:
                    self._next_id = allocated + 1

            record = InstanceRecord(
                instance_id=allocated,
                blas=blas,
                transform=normalized_transform,
                mask=mask,
                dirty=True,
            )
            self._instances[allocated] = record
            self._blas[blas] += 1
            self._blas_instance_refs[blas] = (
                self._blas_instance_refs.get(blas, 0) + 1
            )
            self._stats["instances"] = len(self._instances)
            self._stats["dirty"] += 1
            return allocated

    def remove_instance(self, instance_id: int) -> int:
        with self._lock:
            record = self._require_instance(instance_id)
            refcount = self._blas.get(record.blas)
            if refcount is None or refcount <= 0:
                raise InstanceLedgerError(
                    "LEDGER_NEGATIVE_REFCOUNT",
                    {"blas": record.blas, "refcount": refcount},
                )

            del self._instances[instance_id]
            insort(self._free, instance_id)

            remaining = refcount - 1
            if remaining == 0:
                del self._blas[record.blas]
            else:
                self._blas[record.blas] = remaining

            instance_refs = self._blas_instance_refs.get(record.blas, 0) - 1
            if instance_refs == 0:
                self._blas_instance_refs.pop(record.blas, None)
            else:
                self._blas_instance_refs[record.blas] = instance_refs

            self._stats["instances"] = len(self._instances)
            self._stats["removed"] += 1
            if record.dirty:
                self._stats["dirty"] -= 1
            return instance_id

    def set_mask(self, instance_id: int, mask: int) -> InstanceRecord:
        with self._lock:
            record = self._require_instance(instance_id)
            if not _valid_mask(mask):
                self._invalid_mask(mask)
            dirty = record.dirty
            updated = replace(record, mask=mask, dirty=True)
            self._instances[instance_id] = updated
            if not dirty:
                self._stats["dirty"] += 1
            return updated

    def mark_transform(self, instance_id: int,
                       transform) -> InstanceRecord:
        with self._lock:
            record = self._require_instance(instance_id)
            updated = replace(
                record,
                transform=_copy_transform(transform),
                dirty=True,
            )
            self._instances[instance_id] = updated
            if not record.dirty:
                self._stats["dirty"] += 1
            return updated

    def ref_blas(self, blas: str) -> int:
        with self._lock:
            self._blas[blas] = self._blas.get(blas, 0) + 1
            return self._blas[blas]

    def release_blas(self, blas: str) -> int:
        with self._lock:
            if blas not in self._blas:
                raise KeyError(blas)
            refcount = self._blas[blas]
            instance_refs = self._blas_instance_refs.get(blas, 0)
            if refcount <= instance_refs:
                raise InstanceLedgerError(
                    "LEDGER_NEGATIVE_REFCOUNT",
                    {
                        "blas": blas,
                        "refcount": refcount,
                        "instance_refs": instance_refs,
                    },
                )

            remaining = refcount - 1
            if remaining == 0:
                del self._blas[blas]
            else:
                self._blas[blas] = remaining
            return remaining

    def blas_refcount(self, blas: str) -> int:
        with self._lock:
            try:
                return self._blas[blas]
            except (KeyError, TypeError):
                raise KeyError(blas) from None

    def instance_buffer(self) -> tuple:
        with self._lock:
            return tuple(
                self._instances[instance_id]
                for instance_id in sorted(self._instances)
            )

    def visible_instances(self, layer_mask: int = 0xFFFF) -> tuple:
        with self._lock:
            if not _valid_mask(layer_mask):
                self._invalid_mask(layer_mask)
            return tuple(
                instance_id
                for instance_id in sorted(self._instances)
                if self._matches_layer(
                    self._instances[instance_id].mask, layer_mask
                )
            )

    def rebuild_buffer(self) -> BuildReport:
        with self._lock:
            written = len(self._instances)
            dirty = 0
            for instance_id, record in self._instances.items():
                if record.dirty:
                    dirty += 1
                    self._instances[instance_id] = replace(
                        record, dirty=False
                    )
            self._stats["rebuilds"] += 1
            self._stats["dirty"] = 0
            return BuildReport(
                written=written,
                dirty=dirty,
                high_water=self._next_id,
            )

    def allocated_ids(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._instances))

    def free_ids(self) -> tuple:
        with self._lock:
            return tuple(self._free)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "instances": {
                    instance_id: {
                        "instance_id": record.instance_id,
                        "blas": record.blas,
                        "transform": record.transform,
                        "mask": record.mask,
                        "dirty": record.dirty,
                    }
                    for instance_id, record
                    in sorted(self._instances.items())
                },
                "free": list(self._free),
                "blas": dict(self._blas),
                "next_id": self._next_id,
                "stats": {
                    key: self._stats[key]
                    for key in _STAT_KEYS
                },
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except InstanceLedgerError:
                raise
            except Exception as exc:
                raise InstanceLedgerError(
                    "LEDGER_SNAPSHOT_INVALID",
                    {"reason": "UNREADABLE_STATE"},
                ) from exc

            self._instances = parsed["instances"]
            self._free = parsed["free"]
            self._blas = parsed["blas"]
            self._blas_instance_refs = parsed["blas_instance_refs"]
            self._next_id = parsed["next_id"]
            self._stats = parsed["stats"]

    def stats(self) -> dict:
        with self._lock:
            return {
                "instances": len(self._instances),
                "removed": self._stats["removed"],
                "rebuilds": self._stats["rebuilds"],
                "dirty": sum(
                    record.dirty for record in self._instances.values()
                ),
            }

    def _has_blas(self, blas: object) -> bool:
        try:
            return self._blas.get(blas, 0) > 0
        except TypeError:
            return False

    @staticmethod
    def _matches_layer(mask: int, layer_mask: int) -> bool:
        if mask == 1:
            return bool(layer_mask & 0b0011)
        return bool(mask & layer_mask)

    def _require_instance(self, instance_id: object) -> InstanceRecord:
        if not _valid_instance_id(instance_id):
            raise KeyError(instance_id)
        try:
            return self._instances[instance_id]
        except KeyError:
            raise KeyError(instance_id) from None

    @staticmethod
    def _invalid_mask(mask: object) -> None:
        raise InstanceLedgerError(
            "LEDGER_INVALID_MASK", {"mask": mask}
        )

    def _snapshot_invalid(self, reason: str, **detail: object) -> None:
        payload = {"reason": reason}
        payload.update(detail)
        raise InstanceLedgerError("LEDGER_SNAPSHOT_INVALID", payload)

    def _parse_snapshot(self, state: object) -> dict:
        try:
            candidate = copy.deepcopy(state)
        except Exception as exc:
            raise InstanceLedgerError(
                "LEDGER_SNAPSHOT_INVALID",
                {"reason": "UNCOPYABLE_STATE"},
            ) from exc

        expected_keys = {
            "version", "instances", "free", "blas", "next_id", "stats"
        }
        if not isinstance(candidate, dict):
            self._snapshot_invalid("STATE_NOT_OBJECT")
        if set(candidate) != expected_keys:
            self._snapshot_invalid(
                "INVALID_KEYS", keys=sorted(map(str, candidate))
            )
        version = candidate["version"]
        if not _is_int(version) or version != _SNAPSHOT_VERSION:
            self._snapshot_invalid(
                "UNSUPPORTED_VERSION", version=version
            )

        raw_instances = candidate["instances"]
        records: dict[int, InstanceRecord] = {}
        if isinstance(raw_instances, dict):
            instance_items = list(raw_instances.items())
        elif isinstance(raw_instances, (list, tuple)):
            instance_items = [(None, item) for item in raw_instances]
        else:
            self._snapshot_invalid("INSTANCES_NOT_COLLECTION")

        for key, raw_record in instance_items:
            record = self._parse_snapshot_instance(key, raw_record)
            if record.instance_id in records:
                self._snapshot_invalid(
                    "DUPLICATE_INSTANCE_ID",
                    instance_id=record.instance_id,
                )
            records[record.instance_id] = record

        if len(records) > self.max_instances:
            self._snapshot_invalid(
                "CAPACITY_EXCEEDED",
                instances=len(records),
                max_instances=self.max_instances,
            )

        raw_next_id = candidate["next_id"]
        if not _valid_instance_id(raw_next_id):
            self._snapshot_invalid("INVALID_NEXT_ID", next_id=raw_next_id)
        next_id = raw_next_id

        raw_free = candidate["free"]
        if not isinstance(raw_free, (list, tuple)):
            self._snapshot_invalid("FREE_NOT_LIST")
        free: list[int] = []
        seen_free: set[int] = set()
        for instance_id in raw_free:
            if not _valid_instance_id(instance_id):
                self._snapshot_invalid(
                    "INVALID_FREE_ID", instance_id=instance_id
                )
            if instance_id in seen_free:
                self._snapshot_invalid(
                    "DUPLICATE_FREE_ID", instance_id=instance_id
                )
            if instance_id in records:
                self._snapshot_invalid(
                    "FREE_ID_IS_ALLOCATED", instance_id=instance_id
                )
            if instance_id >= next_id:
                self._snapshot_invalid(
                    "FREE_ID_ABOVE_NEXT_ID", instance_id=instance_id
                )
            seen_free.add(instance_id)
            free.append(instance_id)
        free.sort()

        for instance_id in records:
            if instance_id >= next_id:
                self._snapshot_invalid(
                    "INSTANCE_ID_ABOVE_NEXT_ID",
                    instance_id=instance_id,
                )

        raw_blas = candidate["blas"]
        if not isinstance(raw_blas, dict):
            self._snapshot_invalid("BLAS_NOT_OBJECT")
        blas: dict[object, int] = {}
        for name, refcount in raw_blas.items():
            try:
                hash(name)
            except TypeError:
                self._snapshot_invalid("UNHASHABLE_BLAS")
            if not _is_int(refcount) or refcount <= 0:
                self._snapshot_invalid(
                    "INVALID_BLAS_REFCOUNT", blas=name, refcount=refcount
                )
            blas[name] = refcount

        live_blas: dict[object, int] = {}
        for record in records.values():
            if record.blas not in blas:
                self._snapshot_invalid(
                    "INSTANCE_BLAS_MISSING", blas=record.blas
                )
            live_blas[record.blas] = live_blas.get(record.blas, 0) + 1
        for name, instance_refs in live_blas.items():
            if blas[name] < instance_refs:
                self._snapshot_invalid(
                    "BLAS_REFCOUNT_UNDERFLOW",
                    blas=name,
                    refcount=blas[name],
                    instance_refs=instance_refs,
                )

        raw_stats = candidate["stats"]
        if not isinstance(raw_stats, dict):
            self._snapshot_invalid("STATS_NOT_OBJECT")
        if set(raw_stats) != set(_STAT_KEYS):
            self._snapshot_invalid("INVALID_STATS_KEYS")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                self._snapshot_invalid(
                    "INVALID_STAT", stat=key, value=value
                )
            stats[key] = value
        dirty = sum(record.dirty for record in records.values())
        if stats["instances"] != len(records):
            self._snapshot_invalid("INSTANCE_STAT_MISMATCH")
        if stats["dirty"] != dirty:
            self._snapshot_invalid("DIRTY_STAT_MISMATCH")

        return {
            "instances": records,
            "free": free,
            "blas": blas,
            "blas_instance_refs": live_blas,
            "next_id": next_id,
            "stats": stats,
        }

    def _parse_snapshot_instance(
        self, key: object, raw_record: object
    ) -> InstanceRecord:
        if isinstance(raw_record, InstanceRecord):
            instance_id = raw_record.instance_id
            blas = raw_record.blas
            transform = raw_record.transform
            mask = raw_record.mask
            dirty = raw_record.dirty
        elif isinstance(raw_record, dict):
            instance_id = raw_record.get("instance_id", key)
            if "blas" not in raw_record or "transform" not in raw_record \
                    or "mask" not in raw_record or "dirty" not in raw_record:
                self._snapshot_invalid("INCOMPLETE_INSTANCE")
            blas = raw_record["blas"]
            transform = raw_record["transform"]
            mask = raw_record["mask"]
            dirty = raw_record["dirty"]
        else:
            self._snapshot_invalid("INSTANCE_NOT_OBJECT")

        if key is not None:
            try:
                normalized_key = int(key)
            except (TypeError, ValueError):
                self._snapshot_invalid("INVALID_INSTANCE_KEY", key=key)
            if not _valid_instance_id(instance_id) \
                    or instance_id != normalized_key:
                self._snapshot_invalid(
                    "INVALID_INSTANCE_ID", instance_id=instance_id
                )
        elif not _valid_instance_id(instance_id):
            self._snapshot_invalid(
                "INVALID_INSTANCE_ID", instance_id=instance_id
            )

        try:
            hash(blas)
        except TypeError:
            self._snapshot_invalid("UNHASHABLE_BLAS")
        if not _valid_mask(mask):
            self._snapshot_invalid("INVALID_MASK", mask=mask)
        if not isinstance(dirty, bool):
            self._snapshot_invalid("INVALID_DIRTY", dirty=dirty)
        if not isinstance(transform, (list, tuple)) or len(transform) != 3:
            self._snapshot_invalid("INVALID_TRANSFORM")
        try:
            normalized_transform = _copy_transform(transform)
        except Exception as exc:
            raise InstanceLedgerError(
                "LEDGER_SNAPSHOT_INVALID",
                {"reason": "INVALID_TRANSFORM"},
            ) from exc

        return InstanceRecord(
            instance_id=instance_id,
            blas=blas,
            transform=normalized_transform,
            mask=mask,
            dirty=dirty,
        )
