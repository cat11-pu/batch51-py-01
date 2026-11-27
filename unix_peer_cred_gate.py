"""Unix socket peer credential gate: frozen identity, id mapping, namespace checks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PeerCredError(ValueError):
    """Raised when the gate refuses a configuration or connection operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PeerCredential:
    connection_id: str
    pid: int
    uid: int
    gid: int
    start_time: int
    user_ns: str
    pid_ns: str


@dataclass(frozen=True)
class VerifyResult:
    status: str
    reason: str
    credential: PeerCredential | None
    mapped_pid: int | None


class UnixPeerCredGate:
    """Bind peer credentials at accept time and verify them against tenant rules."""

    def __init__(self, *, max_connections: int = 16) -> None:
        self.max_connections = int(max_connections)
        self._lock = threading.RLock()
        self._tenants: dict[str, dict] = {}
        self._connections: dict[str, PeerCredential] = {}
        self._closed: set[str] = set()
        self._mappings: dict[str, dict[int, int]] = {}
        self._stats = {
            "accepted": 0,
            "closed": 0,
            "allowed": 0,
            "rejected": 0,
            "unverifiable": 0,
            "refused": 0,
        }

    def register_tenant(self, tenant: str, *, uids, user_ns: str, pid_ns: str,
                        processes=()) -> None:
        raise NotImplementedError

    def tenant_config(self, tenant: str) -> dict | None:
        raise NotImplementedError

    def accept_connection(self, connection_id: str, *, pid: int, uid: int,
                          gid: int = 0, start_time: int, user_ns: str,
                          pid_ns: str) -> PeerCredential:
        raise NotImplementedError

    def snapshot_cred(self, connection_id: str) -> PeerCredential | None:
        raise NotImplementedError

    def append_cred(self, connection_id: str, *, pid: int, uid: int,
                    start_time: int, gid: int = 0, user_ns: str = "",
                    pid_ns: str = "") -> bool:
        raise NotImplementedError

    def add_id_mapping(self, *, pid_ns: str, inner_pid: int,
                       outer_pid: int) -> None:
        raise NotImplementedError

    def map_ids(self, *, pid_ns: str, outer_pid: int) -> int | None:
        raise NotImplementedError

    def verify_peer(self, connection_id: str, *, tenant: str) -> VerifyResult:
        raise NotImplementedError

    def close_connection(self, connection_id: str) -> bool:
        raise NotImplementedError

    def open_connections(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
