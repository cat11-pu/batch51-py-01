"""Unix socket peer credential gate: frozen identity, id mapping, namespace checks."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field


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


@dataclass
class _Connection:
    credential: PeerCredential
    closed: bool = False
    audit: list[PeerCredential] = field(default_factory=list)
    decisions: dict[str, VerifyResult] = field(default_factory=dict)


_STAT_KEYS = (
    "accepted",
    "closed",
    "allowed",
    "rejected",
    "unverifiable",
    "refused",
)


class UnixPeerCredGate:
    """Bind peer credentials at accept time and verify them against tenant rules."""

    def __init__(self, *, max_connections: int = 16) -> None:
        if isinstance(max_connections, bool):
            raise PeerCredError("PEER_INVALID_REQUEST",
                                {"field": "max_connections"})
        try:
            limit = int(max_connections)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PeerCredError("PEER_INVALID_REQUEST",
                                {"field": "max_connections"}) from exc
        if limit < 0:
            raise PeerCredError("PEER_INVALID_REQUEST",
                                {"field": "max_connections"})

        self.max_connections = limit
        self._lock = threading.RLock()
        self._tenants: dict[str, dict] = {}
        self._connections: dict[str, _Connection] = {}
        self._mappings: dict[str, dict[int, int]] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _is_positive_int(cls, value: object) -> bool:
        return cls._is_int(value) and value > 0

    @classmethod
    def _is_nonnegative_int(cls, value: object) -> bool:
        return cls._is_int(value) and value >= 0

    @staticmethod
    def _is_nonempty_text(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def _refuse(self, code: str, detail: object = None) -> None:
        self._stats["refused"] += 1
        raise PeerCredError(code, detail)

    def _validate_connection_id(self, connection_id: object) -> None:
        if not self._is_nonempty_text(connection_id):
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "connection_id", "value": connection_id})

    def _validate_credential(
        self,
        *,
        pid: object,
        uid: object,
        gid: object,
        start_time: object,
        user_ns: object,
        pid_ns: object,
        allow_empty_namespaces: bool = False,
    ) -> None:
        checks = (
            ("pid", pid, self._is_positive_int(pid)),
            ("uid", uid, self._is_nonnegative_int(uid)),
            ("gid", gid, self._is_nonnegative_int(gid)),
            ("start_time", start_time, self._is_positive_int(start_time)),
        )
        for name, value, valid in checks:
            if not valid:
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": name, "value": value})

        for name, value in (("user_ns", user_ns), ("pid_ns", pid_ns)):
            if not isinstance(value, str):
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": name, "value": value})
            if not value:
                if allow_empty_namespaces:
                    continue
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": name, "value": value})
            if not value.strip():
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": name, "value": value})

    @staticmethod
    def _sorted_unique_ints(values, *, field_name: str,
                            minimum: int) -> tuple[int, ...]:
        if isinstance(values, (str, bytes)):
            raise ValueError(field_name)
        try:
            items = list(values)
        except TypeError as exc:
            raise ValueError(field_name) from exc
        normalized: set[int] = set()
        for value in items:
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < minimum):
                raise ValueError(field_name)
            normalized.add(value)
        return tuple(sorted(normalized))

    @classmethod
    def _normalize_processes(cls, processes) -> tuple[tuple[int, int], ...]:
        if isinstance(processes, (str, bytes)):
            raise ValueError("processes")
        try:
            items = list(processes)
        except TypeError as exc:
            raise ValueError("processes") from exc
        normalized: set[tuple[int, int]] = set()
        for process in items:
            if not isinstance(process, (tuple, list)) or len(process) != 2:
                raise ValueError("processes")
            pid, start_time = process
            if (not isinstance(pid, int) or isinstance(pid, bool)
                    or pid <= 0):
                raise ValueError("processes")
            if (not isinstance(start_time, int)
                    or isinstance(start_time, bool) or start_time <= 0):
                raise ValueError("processes")
            normalized.add((pid, start_time))
        return tuple(sorted(normalized, key=lambda item: (item[0], item[1])))

    def _normalize_tenant(self, tenant: object, *, uids, user_ns: object,
                          pid_ns: object, processes) -> dict:
        if not self._is_nonempty_text(tenant):
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "tenant", "value": tenant})
        if not self._is_nonempty_text(user_ns):
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "user_ns", "value": user_ns})
        if not self._is_nonempty_text(pid_ns):
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "pid_ns", "value": pid_ns})
        try:
            normalized_uids = self._sorted_unique_ints(
                uids, field_name="uids", minimum=0)
        except ValueError:
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "uids", "value": uids})
        if not normalized_uids:
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "uids", "value": uids})
        try:
            normalized_processes = self._normalize_processes(processes)
        except ValueError:
            self._refuse("PEER_INVALID_REQUEST",
                         {"field": "processes", "value": processes})
        return {
            "uids": normalized_uids,
            "user_ns": user_ns,
            "pid_ns": pid_ns,
            "processes": normalized_processes,
        }

    def register_tenant(self, tenant: str, *, uids, user_ns: str, pid_ns: str,
                        processes=()) -> None:
        with self._lock:
            if not self._is_nonempty_text(tenant):
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": "tenant", "value": tenant})
            if tenant in self._tenants:
                self._refuse("PEER_TENANT_EXISTS", {"tenant": tenant})
            config = self._normalize_tenant(
                tenant, uids=uids, user_ns=user_ns, pid_ns=pid_ns,
                processes=processes)
            self._tenants[tenant] = config

    def tenant_config(self, tenant: str) -> dict | None:
        with self._lock:
            if not isinstance(tenant, str):
                return None
            config = self._tenants.get(tenant)
            return copy.deepcopy(config) if config is not None else None

    def accept_connection(self, connection_id: str, *, pid: int, uid: int,
                          gid: int = 0, start_time: int, user_ns: str,
                          pid_ns: str) -> PeerCredential:
        with self._lock:
            self._validate_connection_id(connection_id)
            self._validate_credential(
                pid=pid, uid=uid, gid=gid, start_time=start_time,
                user_ns=user_ns, pid_ns=pid_ns)

            if connection_id in self._connections:
                self._refuse("PEER_CONNECTION_EXISTS",
                             {"connection_id": connection_id})
            open_count = sum(
                1 for record in self._connections.values()
                if not record.closed
            )
            if open_count >= self.max_connections:
                self._refuse(
                    "PEER_CAPACITY_EXCEEDED",
                    {"max_connections": self.max_connections},
                )

            credential = PeerCredential(
                connection_id=connection_id,
                pid=pid,
                uid=uid,
                gid=gid,
                start_time=start_time,
                user_ns=user_ns,
                pid_ns=pid_ns,
            )
            self._connections[connection_id] = _Connection(credential)
            self._stats["accepted"] += 1
            return credential

    def snapshot_cred(self, connection_id: str) -> PeerCredential | None:
        with self._lock:
            if not isinstance(connection_id, str):
                return None
            record = self._connections.get(connection_id)
            return record.credential if record is not None else None

    def append_cred(self, connection_id: str, *, pid: int, uid: int,
                    start_time: int, gid: int = 0, user_ns: str = "",
                    pid_ns: str = "") -> bool:
        with self._lock:
            if not self._is_nonempty_text(connection_id):
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": "connection_id",
                              "value": connection_id})
            record = self._connections.get(connection_id)
            if record is None:
                self._refuse("PEER_UNKNOWN_CONNECTION",
                             {"connection_id": connection_id})
            if record.closed:
                self._refuse("PEER_CONNECTION_CLOSED",
                             {"connection_id": connection_id})

            self._validate_credential(
                pid=pid, uid=uid, gid=gid, start_time=start_time,
                user_ns=user_ns, pid_ns=pid_ns,
                allow_empty_namespaces=True)
            record.audit.append(PeerCredential(
                connection_id=connection_id,
                pid=pid,
                uid=uid,
                gid=gid,
                start_time=start_time,
                user_ns=user_ns,
                pid_ns=pid_ns,
            ))
            return True

    def add_id_mapping(self, *, pid_ns: str, inner_pid: int,
                       outer_pid: int) -> None:
        with self._lock:
            if not self._is_nonempty_text(pid_ns):
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": "pid_ns", "value": pid_ns})
            if not self._is_positive_int(inner_pid):
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": "inner_pid", "value": inner_pid})
            if not self._is_positive_int(outer_pid):
                self._refuse("PEER_INVALID_REQUEST",
                             {"field": "outer_pid", "value": outer_pid})

            namespace = self._mappings.setdefault(pid_ns, {})
            current = namespace.get(outer_pid)
            if current is not None and current != inner_pid:
                self._refuse(
                    "PEER_MAPPING_CONFLICT",
                    {
                        "pid_ns": pid_ns,
                        "outer_pid": outer_pid,
                        "inner_pid": inner_pid,
                        "existing_inner_pid": current,
                    },
                )
            namespace[outer_pid] = inner_pid

    def map_ids(self, *, pid_ns: str, outer_pid: int) -> int | None:
        with self._lock:
            if (not self._is_nonempty_text(pid_ns)
                    or not self._is_positive_int(outer_pid)):
                return None
            return self._mappings.get(pid_ns, {}).get(outer_pid)

    def _evaluate(
        self,
        credential: PeerCredential,
        tenant_config: dict,
    ) -> VerifyResult:
        if credential.uid not in tenant_config["uids"]:
            return VerifyResult(
                "rejected", "PEER_UID_MISMATCH", credential, None)
        if credential.user_ns != tenant_config["user_ns"]:
            return VerifyResult(
                "rejected", "PEER_USER_NS_MISMATCH", credential, None)
        if credential.pid_ns != tenant_config["pid_ns"]:
            return VerifyResult(
                "rejected", "PEER_PID_NS_MISMATCH", credential, None)
        if ((credential.pid, credential.start_time)
                not in tenant_config["processes"]):
            return VerifyResult(
                "rejected", "PEER_PROCESS_MISMATCH", credential, None)

        mapped_pid = self._mappings.get(
            credential.pid_ns, {}).get(credential.pid)
        if mapped_pid is None:
            return VerifyResult(
                "unverifiable", "PEER_ID_UNMAPPED", credential, None)
        return VerifyResult(
            "allowed", "PEER_TRUSTED", credential, mapped_pid)

    def verify_peer(self, connection_id: str, *, tenant: str) -> VerifyResult:
        with self._lock:
            record = self._connections.get(connection_id)
            if record is None:
                self._stats["rejected"] += 1
                return VerifyResult(
                    "rejected", "PEER_UNKNOWN_CONNECTION", None, None)

            credential = record.credential
            if record.closed:
                self._stats["rejected"] += 1
                return VerifyResult(
                    "rejected", "PEER_CONNECTION_CLOSED", credential, None)

            tenant_config = (
                self._tenants.get(tenant)
                if self._is_nonempty_text(tenant) else None
            )
            if tenant_config is None:
                self._stats["rejected"] += 1
                return VerifyResult(
                    "rejected", "PEER_UNKNOWN_TENANT", credential, None)

            result = record.decisions.get(tenant)
            if result is None:
                result = self._evaluate(credential, tenant_config)
                record.decisions[tenant] = result

            self._stats[result.status] += 1
            return result

    def close_connection(self, connection_id: str) -> bool:
        with self._lock:
            if not isinstance(connection_id, str):
                return False
            record = self._connections.get(connection_id)
            if record is None or record.closed:
                return False
            record.closed = True
            self._stats["closed"] += 1
            return True

    def open_connections(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(
                connection_id
                for connection_id, record in self._connections.items()
                if not record.closed
            ))

    @staticmethod
    def _credential_state(credential: PeerCredential) -> dict:
        return {
            "connection_id": credential.connection_id,
            "pid": credential.pid,
            "uid": credential.uid,
            "gid": credential.gid,
            "start_time": credential.start_time,
            "user_ns": credential.user_ns,
            "pid_ns": credential.pid_ns,
        }

    @staticmethod
    def _decision_state(result: VerifyResult) -> dict:
        return {
            "status": result.status,
            "reason": result.reason,
            "mapped_pid": result.mapped_pid,
        }

    def snapshot(self) -> dict:
        with self._lock:
            connections: dict[str, dict] = {}
            for connection_id, record in self._connections.items():
                state = self._credential_state(record.credential)
                state["closed"] = record.closed
                state["audit"] = [
                    self._credential_state(credential)
                    for credential in record.audit
                ]
                state["decisions"] = {
                    tenant: self._decision_state(result)
                    for tenant, result in record.decisions.items()
                }
                connections[connection_id] = state

            return {
                "version": 1,
                "tenants": copy.deepcopy(self._tenants),
                "connections": connections,
                "mappings": copy.deepcopy(self._mappings),
                "stats": copy.deepcopy(self._stats),
            }

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise PeerCredError("PEER_SNAPSHOT_INVALID", detail)

    @classmethod
    def _restore_text(cls, value: object, field_name: str) -> str:
        if not cls._is_nonempty_text(value):
            cls._snapshot_invalid({"field": field_name})
        return value

    @classmethod
    def _restore_credential(
        cls,
        state: object,
        *,
        connection_id: str,
        allow_empty_namespaces: bool = False,
    ) -> PeerCredential:
        if not isinstance(state, dict):
            cls._snapshot_invalid({"field": "connection.credential"})

        stored_id = state.get("connection_id", connection_id)
        if stored_id != connection_id:
            cls._snapshot_invalid({"field": "connection_id"})

        pid = state.get("pid")
        uid = state.get("uid")
        gid = state.get("gid")
        start_time = state.get("start_time")
        user_ns = state.get("user_ns")
        pid_ns = state.get("pid_ns")

        if not cls._is_positive_int(pid):
            cls._snapshot_invalid({"field": "pid"})
        if not cls._is_nonnegative_int(uid):
            cls._snapshot_invalid({"field": "uid"})
        if not cls._is_nonnegative_int(gid):
            cls._snapshot_invalid({"field": "gid"})
        if not cls._is_positive_int(start_time):
            cls._snapshot_invalid({"field": "start_time"})
        for field_name, value in (("user_ns", user_ns), ("pid_ns", pid_ns)):
            if not isinstance(value, str):
                cls._snapshot_invalid({"field": field_name})
            if not value:
                if allow_empty_namespaces:
                    continue
                cls._snapshot_invalid({"field": field_name})
            if not value.strip():
                cls._snapshot_invalid({"field": field_name})

        return PeerCredential(
            connection_id=connection_id,
            pid=pid,
            uid=uid,
            gid=gid,
            start_time=start_time,
            user_ns=user_ns,
            pid_ns=pid_ns,
        )

    @classmethod
    def _restore_tenant(cls, tenant: object, state: object) -> dict:
        if not cls._is_nonempty_text(tenant):
            cls._snapshot_invalid({"field": "tenant"})
        if not isinstance(state, dict):
            cls._snapshot_invalid({"field": "tenant_config"})
        for key in ("uids", "user_ns", "pid_ns", "processes"):
            if key not in state:
                cls._snapshot_invalid({"field": key})

        uids_state = state["uids"]
        if isinstance(uids_state, (str, bytes)) or not isinstance(
                uids_state, (tuple, list)):
            cls._snapshot_invalid({"field": "uids"})
        try:
            uids = cls._sorted_unique_ints(
                uids_state, field_name="uids", minimum=0)
        except ValueError:
            cls._snapshot_invalid({"field": "uids"})
        if not uids:
            cls._snapshot_invalid({"field": "uids"})

        user_ns = cls._restore_text(state["user_ns"], "user_ns")
        pid_ns = cls._restore_text(state["pid_ns"], "pid_ns")
        processes_state = state["processes"]
        if isinstance(processes_state, (str, bytes)) or not isinstance(
                processes_state, (tuple, list)):
            cls._snapshot_invalid({"field": "processes"})
        try:
            processes = cls._normalize_processes(processes_state)
        except ValueError:
            cls._snapshot_invalid({"field": "processes"})

        return {
            "uids": uids,
            "user_ns": user_ns,
            "pid_ns": pid_ns,
            "processes": processes,
        }

    @classmethod
    def _restore_decision(cls, state: object) -> tuple[str, str, int | None]:
        if not isinstance(state, dict):
            cls._snapshot_invalid({"field": "decision"})
        status = state.get("status")
        reason = state.get("reason")
        mapped_pid = state.get("mapped_pid")
        if status not in {"allowed", "rejected", "unverifiable"}:
            cls._snapshot_invalid({"field": "decision.status"})
        if not isinstance(reason, str) or not reason:
            cls._snapshot_invalid({"field": "decision.reason"})
        if mapped_pid is not None and not cls._is_positive_int(mapped_pid):
            cls._snapshot_invalid({"field": "decision.mapped_pid"})
        if status == "allowed" and mapped_pid is None:
            cls._snapshot_invalid({"field": "decision.mapped_pid"})
        if status != "allowed" and mapped_pid is not None:
            cls._snapshot_invalid({"field": "decision.mapped_pid"})
        return status, reason, mapped_pid

    @classmethod
    def _restore_connection(
        cls,
        connection_id: object,
        state: object,
    ) -> _Connection:
        connection_id = cls._restore_text(connection_id, "connection_id")
        if not isinstance(state, dict):
            cls._snapshot_invalid({"field": "connection"})

        credential_state = state.get("credential", state)
        credential = cls._restore_credential(
            credential_state, connection_id=connection_id)

        closed = state.get("closed", False)
        if not isinstance(closed, bool):
            cls._snapshot_invalid({"field": "closed"})

        audit_state = state.get("audit", [])
        if not isinstance(audit_state, (tuple, list)):
            cls._snapshot_invalid({"field": "audit"})
        audit = [
            cls._restore_credential(
                item, connection_id=connection_id,
                allow_empty_namespaces=True)
            for item in audit_state
        ]

        decisions_state = state.get("decisions", {})
        if not isinstance(decisions_state, dict):
            cls._snapshot_invalid({"field": "decisions"})
        decisions: dict[str, VerifyResult] = {}
        for tenant, decision_state in decisions_state.items():
            if not cls._is_nonempty_text(tenant):
                cls._snapshot_invalid({"field": "decision.tenant"})
            status, reason, mapped_pid = cls._restore_decision(decision_state)
            decisions[tenant] = VerifyResult(
                status, reason, credential, mapped_pid)

        return _Connection(
            credential=credential,
            closed=closed,
            audit=audit,
            decisions=decisions,
        )

    @classmethod
    def _restore_stats(cls, state: object) -> dict[str, int]:
        if not isinstance(state, dict) or set(state) != set(_STAT_KEYS):
            cls._snapshot_invalid({"field": "stats"})
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = state[key]
            if not cls._is_nonnegative_int(value):
                cls._snapshot_invalid({"field": f"stats.{key}"})
            stats[key] = value
        return stats

    @classmethod
    def _restore_mappings(cls, state: object) -> dict[str, dict[int, int]]:
        if not isinstance(state, dict):
            cls._snapshot_invalid({"field": "mappings"})
        mappings: dict[str, dict[int, int]] = {}
        for pid_ns, namespace_state in state.items():
            pid_ns = cls._restore_text(pid_ns, "mapping.pid_ns")
            if not isinstance(namespace_state, dict):
                cls._snapshot_invalid({"field": "mappings"})
            namespace: dict[int, int] = {}
            for outer_pid, inner_pid in namespace_state.items():
                if not cls._is_positive_int(outer_pid):
                    cls._snapshot_invalid({"field": "mapping.outer_pid"})
                if not cls._is_positive_int(inner_pid):
                    cls._snapshot_invalid({"field": "mapping.inner_pid"})
                namespace[outer_pid] = inner_pid
            mappings[pid_ns] = namespace
        return mappings

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                if not isinstance(state, dict):
                    self._snapshot_invalid({"field": "state"})
                required = {"version", "tenants", "connections",
                            "mappings", "stats"}
                if set(state) != required:
                    self._snapshot_invalid({"field": "state"})
                if (state["version"] != 1
                        or isinstance(state["version"], bool)):
                    self._snapshot_invalid({"field": "version"})

                tenants_state = state["tenants"]
                if not isinstance(tenants_state, dict):
                    self._snapshot_invalid({"field": "tenants"})
                tenants = {
                    tenant: self._restore_tenant(tenant, config)
                    for tenant, config in tenants_state.items()
                }

                connections_state = state["connections"]
                if not isinstance(connections_state, dict):
                    self._snapshot_invalid({"field": "connections"})
                connections = {
                    connection_id: self._restore_connection(
                        connection_id, connection_state)
                    for connection_id, connection_state
                    in connections_state.items()
                }
                open_count = sum(
                    1 for record in connections.values()
                    if not record.closed
                )
                if open_count > self.max_connections:
                    self._snapshot_invalid({"field": "connections.capacity"})

                mappings = self._restore_mappings(state["mappings"])
                stats = self._restore_stats(state["stats"])
            except PeerCredError as exc:
                if exc.code == "PEER_SNAPSHOT_INVALID":
                    raise
                self._snapshot_invalid({"field": "state"})
            except (TypeError, ValueError, KeyError, AttributeError):
                self._snapshot_invalid({"field": "state"})

            self._tenants = tenants
            self._connections = connections
            self._mappings = mappings
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)
