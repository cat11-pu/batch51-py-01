"""Ray tracing instance ledger: id pool, visibility masks and BLAS refcounts."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class RayInstanceLedger:
    """Keep instance ids dense and stable while tracking BLAS references."""

    def __init__(self, *, max_instances: int = 1024) -> None:
        self.max_instances = max_instances
        self._lock = threading.RLock()
        self._instances: dict = {}
        self._free: list = []
        self._blas: dict = {}
        self._next_id = 1
        self._stats = {"instances": 0, "removed": 0, "rebuilds": 0,
                       "dirty": 0}

    def add_instance(self, *, blas: str, transform=(0.0, 0.0, 0.0),
                     mask: int = 1, instance_id=None) -> int:
        raise NotImplementedError

    def remove_instance(self, instance_id: int) -> int:
        raise NotImplementedError

    def set_mask(self, instance_id: int, mask: int) -> InstanceRecord:
        raise NotImplementedError

    def mark_transform(self, instance_id: int,
                       transform) -> InstanceRecord:
        raise NotImplementedError

    def ref_blas(self, blas: str) -> int:
        raise NotImplementedError

    def release_blas(self, blas: str) -> int:
        raise NotImplementedError

    def blas_refcount(self, blas: str) -> int:
        raise NotImplementedError

    def instance_buffer(self) -> tuple:
        raise NotImplementedError

    def visible_instances(self, layer_mask: int = 0xFFFF) -> tuple:
        raise NotImplementedError

    def rebuild_buffer(self) -> BuildReport:
        raise NotImplementedError

    def allocated_ids(self) -> tuple:
        raise NotImplementedError

    def free_ids(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
