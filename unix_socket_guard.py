"""Local socket registry: name claiming, path permissions, peer credential checks."""

from __future__ import annotations

import os
import stat
import threading
import uuid
from dataclasses import asdict, dataclass


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

_ACTIVE_STATES = frozenset((STATE_REGISTERED, STATE_BOUND))
_ALL_STATES = frozenset(
    (STATE_REGISTERED, STATE_BOUND, STATE_RELEASED, STATE_EXPIRED)
)

_COUNTER_NAMES = (
    "registered",
    "binds",
    "connections",
    "allowed",
    "denied",
    "released",
    "expired",
    "ended",
)

_BINDING_FIELDS = (
    "binding_id",
    "namespace",
    "kind",
    "name",
    "owner_uid",
    "owner_pid",
    "mode",
    "dir_mode",
    "state",
    "bound_at",
    "expires_at",
)

_CONNECTION_FIELDS = ("conn_id", "binding_id", "peer", "opened_at", "state")


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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _invalid(detail: object) -> SocketError:
    return SocketError("SOCKET_INVALID_REQUEST", detail)


def _snapshot_invalid(detail: object) -> SocketError:
    return SocketError("SOCKET_SNAPSHOT_INVALID", detail)


class UnixSocketGuard:
    """Register local sockets and decide whether a peer may talk to them."""

    def __init__(self, *, lease_ttl: int = 60, max_bindings: int = 128) -> None:
        self.lease_ttl = lease_ttl
        self.max_bindings = max_bindings
        # The public constructor only has one capacity knob.  Each independent
        # limit therefore uses that value, while being enforced separately.
        self.max_namespace_bindings = max_bindings
        self.max_connections = max_bindings
        self._lock = threading.RLock()
        self._bindings: dict[str, Binding] = {}
        self._connections: dict[str, Connection] = {}
        self._counters = {name: 0 for name in _COUNTER_NAMES}

    @staticmethod
    def _active(binding: Binding | None) -> bool:
        return binding is not None and binding.state in _ACTIVE_STATES

    def _active_binding(self, binding_id: str) -> Binding | None:
        binding = self._bindings.get(binding_id)
        return binding if self._active(binding) else None

    def _active_bindings(self) -> list[Binding]:
        return [row for row in self._bindings.values() if self._active(row)]

    def _end_connections(self, binding_id: str) -> None:
        for conn_id, conn in tuple(self._connections.items()):
            if conn.binding_id == binding_id and conn.state == "open":
                self._connections[conn_id] = Connection(
                    conn_id=conn.conn_id,
                    binding_id=conn.binding_id,
                    peer=conn.peer,
                    opened_at=conn.opened_at,
                    state="ended",
                )
                self._counters["ended"] += 1

    def _selected_name(self, abstract: object, path: object) -> tuple[str, str]:
        abstract_given = abstract is not None
        path_given = path is not None
        if abstract_given == path_given:
            raise _invalid("exactly one of abstract or path is required")
        if abstract_given:
            if not isinstance(abstract, str) or not abstract:
                raise _invalid("abstract name must be a non-empty string")
            return "abstract", abstract
        if not isinstance(path, str) or not path or not os.path.isabs(path):
            raise _invalid("path must be an absolute path")
        return "path", path

    def _check_path_directory(self, binding: Binding) -> None:
        if binding.kind != "path":
            return
        if binding.dir_mode & 0o022:
            raise SocketError(
                "SOCKET_DIR_INSECURE",
                f"parent directory mode {binding.dir_mode & 0o777:04o} "
                "allows non-owners to write",
            )
        parent = os.path.dirname(binding.name) or os.sep
        try:
            info = os.stat(parent)
        except FileNotFoundError:
            # The supplied dir_mode is the fallback when there is no concrete
            # directory to inspect yet.
            return
        except OSError as exc:
            raise SocketError("SOCKET_DIR_INSECURE", str(exc)) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise SocketError("SOCKET_DIR_INSECURE", "parent is not a directory")
        actual_mode = stat.S_IMODE(info.st_mode)
        if actual_mode & 0o022:
            raise SocketError(
                "SOCKET_DIR_INSECURE",
                f"parent directory mode {actual_mode:04o} allows non-owners to write",
            )

    def register(self, binding_id: str, *, namespace: str, owner_uid: int,
                 owner_pid: int, mode: int = 0o600, dir_mode: int = 0o755,
                 abstract: str | None = None, path: str | None = None,
                 now: int = 0) -> Binding:
        kind, name = self._selected_name(abstract, path)
        if not isinstance(binding_id, str) or not binding_id:
            raise _invalid("binding_id must be a non-empty string")
        if not isinstance(namespace, str) or not namespace:
            raise _invalid("namespace must be a non-empty string")
        if not _is_int(owner_uid) or owner_uid < 0:
            raise _invalid("owner_uid must be a non-negative integer")
        if not _is_int(owner_pid):
            raise _invalid("owner_pid must be an integer")
        if not _is_int(mode):
            raise _invalid("mode must be an integer")
        if mode & 0o077:
            raise SocketError(
                "SOCKET_MODE_INSECURE",
                "socket mode grants permissions to group or other",
            )
        if not _is_int(dir_mode):
            raise _invalid("dir_mode must be an integer")
        if not _is_int(now):
            raise _invalid("now must be an integer")

        with self._lock:
            existing_id = self._active_binding(binding_id)
            if existing_id is not None:
                raise SocketError(
                    "SOCKET_NAME_TAKEN",
                    f"binding id {binding_id!r} is already active",
                )
            for existing in self._active_bindings():
                if existing.namespace == namespace and existing.name == name:
                    raise SocketError(
                        "SOCKET_NAME_TAKEN",
                        f"{kind} name {name!r} is already active in {namespace!r}",
                    )

            active = self._active_bindings()
            if len(active) >= self.max_bindings:
                raise SocketError(
                    "SOCKET_CAPACITY_EXCEEDED",
                    "maximum number of bindings reached",
                )
            in_namespace = sum(1 for row in active if row.namespace == namespace)
            if in_namespace >= self.max_namespace_bindings:
                raise SocketError(
                    "SOCKET_CAPACITY_EXCEEDED",
                    f"maximum number of bindings in namespace {namespace!r} reached",
                )

            binding = Binding(
                binding_id=binding_id,
                namespace=namespace,
                kind=kind,
                name=name,
                owner_uid=owner_uid,
                owner_pid=owner_pid,
                mode=mode,
                dir_mode=dir_mode,
                state=STATE_REGISTERED,
                bound_at=None,
                expires_at=None,
            )
            self._bindings[binding_id] = binding
            self._counters["registered"] += 1
            return binding

    def bind(self, binding_id: str, *, now: int) -> Binding:
        with self._lock:
            binding = self._active_binding(binding_id)
            if binding is None:
                raise SocketError(
                    "SOCKET_BINDING_UNKNOWN",
                    f"binding {binding_id!r} is not registered",
                )
            if binding.state == STATE_BOUND:
                raise SocketError(
                    "SOCKET_ALREADY_BOUND",
                    f"binding {binding_id!r} is already bound",
                )

            self._check_path_directory(binding)
            rebound = Binding(
                binding_id=binding.binding_id,
                namespace=binding.namespace,
                kind=binding.kind,
                name=binding.name,
                owner_uid=binding.owner_uid,
                owner_pid=binding.owner_pid,
                mode=binding.mode,
                dir_mode=binding.dir_mode,
                state=STATE_BOUND,
                bound_at=now,
                expires_at=now + self.lease_ttl,
            )
            self._bindings[binding_id] = rebound
            self._counters["binds"] += 1
            return rebound

    def _decide(self, binding_id: str, peer: PeerCred, *, now: int) -> Decision:
        binding = self._active_binding(binding_id)
        if binding is None:
            self._counters["denied"] += 1
            return Decision("deny", "BINDING_UNKNOWN", binding_id, peer.uid)
        if binding.state != STATE_BOUND:
            self._counters["denied"] += 1
            return Decision("deny", "NOT_BOUND", binding_id, peer.uid)
        if binding.expires_at is None or now >= binding.expires_at:
            self._counters["denied"] += 1
            return Decision("deny", "LEASE_EXPIRED", binding_id, peer.uid)
        if peer.uid == binding.owner_uid or peer.uid == 0:
            self._counters["allowed"] += 1
            return Decision("allow", "", binding_id, peer.uid)
        self._counters["denied"] += 1
        return Decision("deny", "PEER_NOT_PERMITTED", binding_id, peer.uid)

    def authorize(self, binding_id: str, peer: PeerCred, *, now: int) -> Decision:
        with self._lock:
            return self._decide(binding_id, peer, now=now)

    def connect(self, binding_id: str, peer: PeerCred, *, now: int) -> Connection:
        with self._lock:
            decision = self._decide(binding_id, peer, now=now)
            if decision.status != "allow":
                raise SocketError(decision.code, decision.binding_id)
            open_count = sum(
                1 for conn in self._connections.values() if conn.state == "open"
            )
            if open_count >= self.max_connections:
                raise SocketError(
                    "SOCKET_CAPACITY_EXCEEDED",
                    "maximum number of connections reached",
                )
            conn = Connection(
                conn_id=uuid.uuid4().hex,
                binding_id=binding_id,
                peer=peer,
                opened_at=now,
                state="open",
            )
            self._connections[conn.conn_id] = conn
            self._counters["connections"] += 1
            return conn

    def verify(self, conn_id: str, current: PeerCred) -> str:
        with self._lock:
            conn = self._connections.get(conn_id)
            if conn is None:
                return "unknown"
            if conn.state != "open":
                return "ended"
            if conn.peer == current:
                return "open"
            self._connections[conn_id] = Connection(
                conn_id=conn.conn_id,
                binding_id=conn.binding_id,
                peer=conn.peer,
                opened_at=conn.opened_at,
                state="ended",
            )
            self._counters["ended"] += 1
            return "ended"

    def release(self, binding_id: str) -> bool:
        with self._lock:
            binding = self._active_binding(binding_id)
            if binding is None:
                return False
            self._bindings[binding_id] = Binding(
                binding_id=binding.binding_id,
                namespace=binding.namespace,
                kind=binding.kind,
                name=binding.name,
                owner_uid=binding.owner_uid,
                owner_pid=binding.owner_pid,
                mode=binding.mode,
                dir_mode=binding.dir_mode,
                state=STATE_RELEASED,
                bound_at=binding.bound_at,
                expires_at=binding.expires_at,
            )
            self._end_connections(binding_id)
            self._counters["released"] += 1
            return True

    def heartbeat(self, binding_id: str, *, now: int) -> Binding:
        with self._lock:
            binding = self._active_binding(binding_id)
            if binding is None:
                raise SocketError(
                    "SOCKET_BINDING_UNKNOWN",
                    f"binding {binding_id!r} is not registered",
                )
            if binding.state != STATE_BOUND:
                raise SocketError(
                    "NOT_BOUND",
                    f"binding {binding_id!r} is not bound",
                )
            if binding.expires_at is None or now >= binding.expires_at:
                raise SocketError(
                    "LEASE_EXPIRED",
                    f"binding {binding_id!r} lease has expired",
                )
            refreshed = Binding(
                binding_id=binding.binding_id,
                namespace=binding.namespace,
                kind=binding.kind,
                name=binding.name,
                owner_uid=binding.owner_uid,
                owner_pid=binding.owner_pid,
                mode=binding.mode,
                dir_mode=binding.dir_mode,
                state=STATE_BOUND,
                bound_at=binding.bound_at,
                expires_at=now + self.lease_ttl,
            )
            self._bindings[binding_id] = refreshed
            return refreshed

    def expire(self, now: int) -> int:
        with self._lock:
            reclaimed = 0
            for binding_id, binding in tuple(self._bindings.items()):
                if (
                    binding.state == STATE_BOUND
                    and binding.expires_at is not None
                    and now >= binding.expires_at
                ):
                    self._bindings[binding_id] = Binding(
                        binding_id=binding.binding_id,
                        namespace=binding.namespace,
                        kind=binding.kind,
                        name=binding.name,
                        owner_uid=binding.owner_uid,
                        owner_pid=binding.owner_pid,
                        mode=binding.mode,
                        dir_mode=binding.dir_mode,
                        state=STATE_EXPIRED,
                        bound_at=binding.bound_at,
                        expires_at=binding.expires_at,
                    )
                    self._end_connections(binding_id)
                    self._counters["expired"] += 1
                    reclaimed += 1
            return reclaimed

    def lookup(self, namespace: str, name: str) -> Binding | None:
        with self._lock:
            for binding in self._bindings.values():
                if (
                    self._active(binding)
                    and binding.namespace == namespace
                    and binding.name == name
                ):
                    return binding
            return None

    def bindings(self) -> tuple[Binding, ...]:
        with self._lock:
            return tuple(self._active_bindings())

    def connections(self) -> tuple[Connection, ...]:
        with self._lock:
            return tuple(self._connections.values())

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "bindings": [asdict(row) for row in self._bindings.values()],
                "connections": [
                    asdict(row) for row in self._connections.values()
                ],
                "counters": dict(self._counters),
            }

    @staticmethod
    def _parse_binding(raw: object) -> Binding:
        if not isinstance(raw, dict):
            raise _snapshot_invalid("binding record must be a dict")
        missing = [field for field in _BINDING_FIELDS if field not in raw]
        if missing:
            raise _snapshot_invalid(f"binding record missing {missing[0]}")

        binding_id = raw["binding_id"]
        namespace = raw["namespace"]
        kind = raw["kind"]
        name = raw["name"]
        owner_uid = raw["owner_uid"]
        owner_pid = raw["owner_pid"]
        mode = raw["mode"]
        dir_mode = raw["dir_mode"]
        state = raw["state"]
        bound_at = raw["bound_at"]
        expires_at = raw["expires_at"]

        if not isinstance(binding_id, str) or not binding_id:
            raise _snapshot_invalid("binding_id must be a non-empty string")
        if not isinstance(namespace, str) or not namespace:
            raise _snapshot_invalid("namespace must be a non-empty string")
        if kind not in ("abstract", "path"):
            raise _snapshot_invalid("unknown binding kind")
        if not isinstance(name, str) or not name:
            raise _snapshot_invalid("name must be a non-empty string")
        if kind == "path" and not os.path.isabs(name):
            raise _snapshot_invalid("path binding name must be absolute")
        if not _is_int(owner_uid) or owner_uid < 0:
            raise _snapshot_invalid("owner_uid must be a non-negative integer")
        if not _is_int(owner_pid):
            raise _snapshot_invalid("owner_pid must be an integer")
        if not _is_int(mode) or mode & 0o077:
            raise _snapshot_invalid("mode is invalid or insecure")
        if not _is_int(dir_mode):
            raise _snapshot_invalid("dir_mode must be an integer")
        if state not in _ALL_STATES:
            raise _snapshot_invalid("unknown binding state")
        if bound_at is not None and not _is_int(bound_at):
            raise _snapshot_invalid("bound_at must be an integer or null")
        if expires_at is not None and not _is_int(expires_at):
            raise _snapshot_invalid("expires_at must be an integer or null")
        if state == STATE_REGISTERED:
            if bound_at is not None or expires_at is not None:
                raise _snapshot_invalid("registered binding has a lease")
        if state == STATE_BOUND:
            if bound_at is None or expires_at is None:
                raise _snapshot_invalid("bound binding is missing its lease")

        return Binding(
            binding_id=binding_id,
            namespace=namespace,
            kind=kind,
            name=name,
            owner_uid=owner_uid,
            owner_pid=owner_pid,
            mode=mode,
            dir_mode=dir_mode,
            state=state,
            bound_at=bound_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _parse_peer(raw: object) -> PeerCred:
        if not isinstance(raw, dict):
            raise _snapshot_invalid("connection peer must be a dict")
        for field in ("pid", "uid", "gid", "exe"):
            if field not in raw:
                raise _snapshot_invalid(f"connection peer missing {field}")
        pid = raw["pid"]
        uid = raw["uid"]
        gid = raw["gid"]
        exe = raw["exe"]
        if not _is_int(pid) or not _is_int(uid) or not _is_int(gid):
            raise _snapshot_invalid("peer ids must be integers")
        if not isinstance(exe, str):
            raise _snapshot_invalid("peer exe must be a string")
        return PeerCred(pid=pid, uid=uid, gid=gid, exe=exe)

    @classmethod
    def _parse_connection(cls, raw: object) -> Connection:
        if not isinstance(raw, dict):
            raise _snapshot_invalid("connection record must be a dict")
        missing = [field for field in _CONNECTION_FIELDS if field not in raw]
        if missing:
            raise _snapshot_invalid(f"connection record missing {missing[0]}")
        conn_id = raw["conn_id"]
        binding_id = raw["binding_id"]
        opened_at = raw["opened_at"]
        state = raw["state"]
        if not isinstance(conn_id, str) or not conn_id:
            raise _snapshot_invalid("conn_id must be a non-empty string")
        if not isinstance(binding_id, str) or not binding_id:
            raise _snapshot_invalid("connection binding_id must be non-empty")
        if not _is_int(opened_at):
            raise _snapshot_invalid("opened_at must be an integer")
        if state not in ("open", "ended"):
            raise _snapshot_invalid("unknown connection state")
        return Connection(
            conn_id=conn_id,
            binding_id=binding_id,
            peer=cls._parse_peer(raw["peer"]),
            opened_at=opened_at,
            state=state,
        )

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, dict):
                raise _snapshot_invalid("snapshot must be a dict")
            for field in ("version", "bindings", "connections", "counters"):
                if field not in state:
                    raise _snapshot_invalid(f"snapshot missing {field}")
            version = state["version"]
            if not _is_int(version) or version != 1:
                raise _snapshot_invalid("unsupported snapshot version")
            raw_bindings = state["bindings"]
            raw_connections = state["connections"]
            raw_counters = state["counters"]
            if not isinstance(raw_bindings, list):
                raise _snapshot_invalid("bindings must be a list")
            if not isinstance(raw_connections, list):
                raise _snapshot_invalid("connections must be a list")
            if not isinstance(raw_counters, dict):
                raise _snapshot_invalid("counters must be a dict")

            counters = {}
            for name in _COUNTER_NAMES:
                if name not in raw_counters:
                    raise _snapshot_invalid(f"counters missing {name}")
                value = raw_counters[name]
                if not _is_int(value) or value < 0:
                    raise _snapshot_invalid(f"counter {name} must be non-negative")
                counters[name] = value

            bindings: dict[str, Binding] = {}
            active_names: set[tuple[str, str]] = set()
            namespace_counts: dict[str, int] = {}
            for raw in raw_bindings:
                binding = self._parse_binding(raw)
                if binding.binding_id in bindings:
                    raise _snapshot_invalid("duplicate binding_id")
                bindings[binding.binding_id] = binding
                if self._active(binding):
                    name_key = (binding.namespace, binding.name)
                    if name_key in active_names:
                        raise _snapshot_invalid("duplicate active socket name")
                    active_names.add(name_key)
                    namespace_counts[binding.namespace] = (
                        namespace_counts.get(binding.namespace, 0) + 1
                    )
            if len(active_names) > self.max_bindings:
                raise SocketError(
                    "SOCKET_CAPACITY_EXCEEDED",
                    "snapshot exceeds maximum number of bindings",
                )
            for namespace, count in namespace_counts.items():
                if count > self.max_namespace_bindings:
                    raise SocketError(
                        "SOCKET_CAPACITY_EXCEEDED",
                        f"snapshot exceeds namespace binding limit for {namespace!r}",
                    )

            connections: dict[str, Connection] = {}
            open_count = 0
            for raw in raw_connections:
                conn = self._parse_connection(raw)
                if conn.conn_id in connections:
                    raise _snapshot_invalid("duplicate conn_id")
                if conn.state == "open":
                    binding = bindings.get(conn.binding_id)
                    if binding is None:
                        raise _snapshot_invalid(
                            "open connection references an unknown binding"
                        )
                    if binding.state != STATE_BOUND:
                        conn = Connection(
                            conn_id=conn.conn_id,
                            binding_id=conn.binding_id,
                            peer=conn.peer,
                            opened_at=conn.opened_at,
                            state="ended",
                        )
                    else:
                        open_count += 1
                connections[conn.conn_id] = conn
            if open_count > self.max_connections:
                raise SocketError(
                    "SOCKET_CAPACITY_EXCEEDED",
                    "snapshot exceeds maximum number of connections",
                )

            # Everything has been validated.  Replace state only now so a bad
            # snapshot cannot partially overwrite a working registry.
            self._bindings = bindings
            self._connections = connections
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
