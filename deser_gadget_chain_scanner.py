"""Serialization stream walker with type allowlist and gadget chain depth checks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


DANGEROUS_TYPES = frozenset({
    "java.lang.Runtime",
    "java.lang.ProcessBuilder",
    "java.lang.reflect.Method",
    "javax.naming.InitialContext",
    "java.util.PriorityQueue",
})

FORMAT_MAGIC = {
    b"JSE1": "java-serial-v1",
    b"PKL2": "pickle-proto2",
    b"MPK1": "msgpack-map",
}

ORIGINS = ("local", "vendor")
PURPOSES = ("data", "exec")


class DeserError(ValueError):
    """Raised when a stream or a type registration is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class WalkResult:
    format: str
    root: str
    visited: tuple
    depth: int
    truncated: bool
    denied: tuple


class DeserGadgetChainScanner:
    """Sniff the stream header, walk the object graph and grade each type."""

    def __init__(self, *, max_depth: int = 8, allowlist: dict | None = None) -> None:
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._allowlist = dict(allowlist or {})

    def register_type(self, type_name: str, *, origin: str, purpose: str) -> str:
        raise NotImplementedError

    def revoke_type(self, type_name: str) -> bool:
        raise NotImplementedError

    def check_allowlist(self, type_name: str) -> str:
        raise NotImplementedError

    def sniff_format(self, stream: bytes) -> str:
        raise NotImplementedError

    def walk_objects(self, stream: bytes) -> WalkResult:
        raise NotImplementedError

    def chain_depth(self, stream: bytes, start_id: str | None = None) -> int:
        raise NotImplementedError

    def dangerous_starts(self, stream: bytes) -> tuple:
        raise NotImplementedError

    def report(self, stream: bytes) -> dict:
        raise NotImplementedError

    def describe_object(self, stream: bytes, object_id: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
