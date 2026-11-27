"""Local socket registry: name claiming, path permissions, peer credential checks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SocketError(ValueError):
    """Raised when a socket registration or access request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_REGISTERED = "registered"
STATE_BOUND = "bound"
STATE_RELEASED = "released"
STATE_EXPIRED = "expired"


@dataclass(frozen=True)
class Binding:
    binding_id: str
    namespace: str
    kind: str
    name: str
    owner_uid: int
    owner_pid: int
    mode: int
    dir_mode: int
    state: str
    bound_at: int | None
    expires_at: int | None


@dataclass(frozen=True)
class PeerCred:
    pid: int
    uid: int
    gid: int
    exe: str


@dataclass(frozen=True)
class Decision:
    status: str
    code: str
    binding_id: str
    peer_uid: int


@dataclass(frozen=True)
class Connection:
    conn_id: str
    binding_id: str
    peer: PeerCred
    opened_at: int
    state: str


class UnixSocketGuard:
    """Register local sockets and decide whether a peer may talk to them."""

    def __init__(self, *, lease_ttl: int = 60, max_bindings: int = 128) -> None:
        self.lease_ttl = lease_ttl
        self.max_bindings = max_bindings
        self._lock = threading.RLock()

    def register(self, binding_id: str, *, namespace: str, owner_uid: int,
                 owner_pid: int, mode: int = 0o600, dir_mode: int = 0o755,
                 abstract: str | None = None, path: str | None = None,
                 now: int = 0) -> Binding:
        raise NotImplementedError

    def bind(self, binding_id: str, *, now: int) -> Binding:
        raise NotImplementedError

    def authorize(self, binding_id: str, peer: PeerCred, *, now: int) -> Decision:
        raise NotImplementedError

    def connect(self, binding_id: str, peer: PeerCred, *, now: int) -> Connection:
        raise NotImplementedError

    def verify(self, conn_id: str, current: PeerCred) -> str:
        raise NotImplementedError

    def release(self, binding_id: str) -> bool:
        raise NotImplementedError

    def heartbeat(self, binding_id: str, *, now: int) -> Binding:
        raise NotImplementedError

    def expire(self, now: int) -> int:
        raise NotImplementedError

    def lookup(self, namespace: str, name: str) -> Binding | None:
        raise NotImplementedError

    def bindings(self) -> tuple[Binding, ...]:
        raise NotImplementedError

    def connections(self) -> tuple[Connection, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
