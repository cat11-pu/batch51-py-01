"""Trace interface governance: instance isolation, probe whitelist, slow-reader quotas."""

from __future__ import annotations

import copy
import re
import threading
from collections import deque
from dataclasses import dataclass, field, replace

KPROBE = "kprobe"
UPROBE = "uprobe"
PROBE_KINDS = (KPROBE, UPROBE)

PROBE_WHITELIST = {
    "vfs_read": (0, 64),
    "do_sys_openat2": (0, 32),
    "tcp_sendmsg": (0, 128),
    "__x64_sys_write": (0, 0),
}

_INSTANCE_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_PROBE_ID_RE = re.compile(r"^p([1-9][0-9]*)$")
_NUMERIC_READER_ID_RE = re.compile(r"^r([1-9][0-9]*)$")
_FILTER_TOKEN_RE = re.compile(
    r"(?P<space>\s+)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<number>0[xX][0-9A-Fa-f]+|[0-9]+)"
    r"|(?P<op>&&|\|\||==|!=|>=|<=|>|<|!)"
    r"|(?P<lparen>\()"
    r"|(?P<rparen>\))"
)
_COMPARISONS = frozenset(("==", "!=", ">=", "<=", ">", "<"))
_SNAPSHOT_KEYS = frozenset(("version", "instances", "probes", "readers", "counters"))


class TraceError(ValueError):
    """Raised when a tracing operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TraceInstance:
    name: str
    tenant: str
    buffer_size_kb: int
    filter: str | None
    active: bool


@dataclass(frozen=True)
class ProbeRecord:
    probe_id: str
    instance: str
    kind: str
    symbol: str
    offset: int
    filter: str
    enabled: bool


@dataclass(frozen=True)
class ReaderHandle:
    reader_id: str
    instance: str
    tenant: str
    lost: int
    closed: bool


@dataclass
class _InstanceState:
    name: str
    tenant: str
    buffer_size_kb: int
    filter: str | None
    active: bool


@dataclass
class _ReaderState:
    reader_id: str
    instance: str
    tenant: str
    lost: int = 0
    closed: bool = False
    queue: deque[str] = field(default_factory=deque)


class _FilterParser:
    """Small parser for the deliberately restricted trace filter language."""

    def __init__(self, expression: str) -> None:
        self._tokens: list[tuple[str, str]] = []
        self._position = 0
        self._lex(expression)

    def _lex(self, expression: str) -> None:
        position = 0
        while position < len(expression):
            match = _FILTER_TOKEN_RE.match(expression, position)
            if match is None:
                raise ValueError("unsupported filter character")
            position = match.end()
            kind = match.lastgroup
            if kind != "space":
                self._tokens.append((kind or "", match.group()))

    def parse(self) -> None:
        if not self._tokens:
            return
        self._parse_or()
        if self._position != len(self._tokens):
            raise ValueError("trailing filter tokens")

    def _peek(self) -> tuple[str, str] | None:
        if self._position >= len(self._tokens):
            return None
        return self._tokens[self._position]

    def _take(self) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of filter")
        self._position += 1
        return token

    def _parse_or(self) -> None:
        self._parse_and()
        while self._peek() == ("op", "||"):
            self._take()
            self._parse_and()

    def _parse_and(self) -> None:
        self._parse_not()
        while self._peek() == ("op", "&&"):
            self._take()
            self._parse_not()

    def _parse_not(self) -> None:
        if self._peek() == ("op", "!"):
            self._take()
            self._parse_not()
            return
        self._parse_comparison()

    def _parse_comparison(self) -> None:
        self._parse_primary()
        token = self._peek()
        if token is not None and token[0] == "op" and token[1] in _COMPARISONS:
            self._take()
            self._parse_primary()

    def _parse_primary(self) -> None:
        token = self._peek()
        if token is None:
            raise ValueError("missing filter operand")
        kind, value = token
        if kind == "lparen":
            self._take()
            self._parse_or()
            if self._take() != ("rparen", ")"):
                raise ValueError("unbalanced filter parentheses")
            return
        if kind in ("ident", "number"):
            self._take()
            return
        raise ValueError("unexpected filter token")


class TracefsAccessGuard:
    """Own tracefs instances, whitelisted probes and per-reader ring buffers."""

    def __init__(self, *, max_instances: int = 8,
                 max_probes_per_instance: int = 16, max_probes_total: int = 64,
                 max_readers_per_instance: int = 4, max_readers_total: int = 16,
                 reader_capacity: int = 8) -> None:
        self.max_instances = max_instances
        self.max_probes_per_instance = max_probes_per_instance
        self.max_probes_total = max_probes_total
        self.max_readers_per_instance = max_readers_per_instance
        self.max_readers_total = max_readers_total
        self.reader_capacity = reader_capacity
        self._lock = threading.RLock()
        self._instances: dict[str, _InstanceState] = {}
        self._probes: dict[str, ProbeRecord] = {}
        self._probe_ids_by_instance: dict[str, list[str]] = {}
        self._readers: dict[str, _ReaderState] = {}
        self._emitted = 0
        self._delivered = 0
        self._dropped = 0
        self._next_probe = 1
        self._next_reader = 1

    @staticmethod
    def _instance_view(state: _InstanceState) -> TraceInstance:
        return TraceInstance(
            name=state.name,
            tenant=state.tenant,
            buffer_size_kb=state.buffer_size_kb,
            filter=state.filter,
            active=state.active,
        )

    @staticmethod
    def _reader_view(state: _ReaderState) -> ReaderHandle:
        return ReaderHandle(
            reader_id=state.reader_id,
            instance=state.instance,
            tenant=state.tenant,
            lost=state.lost,
            closed=state.closed,
        )

    @staticmethod
    def _valid_name(name: object) -> bool:
        return isinstance(name, str) and _INSTANCE_NAME_RE.fullmatch(name) is not None

    @staticmethod
    def _valid_tenant(tenant: object) -> bool:
        return isinstance(tenant, str) and bool(tenant.strip())

    @staticmethod
    def _valid_integer(value: object, *, minimum: int = 0) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= minimum
        )

    @staticmethod
    def _validate_filter(expression: str) -> None:
        try:
            _FilterParser(expression).parse()
        except (RecursionError, ValueError) as exc:
            raise TraceError(
                "TRACE_FILTER_INVALID", "invalid filter expression"
            ) from exc

    @staticmethod
    def _valid_uprobe_path(symbol: object) -> bool:
        if not isinstance(symbol, str) or not symbol.startswith("/"):
            return False
        if "\x00" in symbol:
            return False
        return ".." not in symbol.split("/")

    def _require_instance(self, name: str) -> _InstanceState:
        state = self._instances.get(name) if isinstance(name, str) else None
        if state is None:
            raise TraceError("TRACE_INSTANCE_UNKNOWN", name)
        return state

    def _new_probe_id(self) -> str:
        while True:
            probe_id = f"p{self._next_probe}"
            self._next_probe += 1
            if probe_id not in self._probes:
                return probe_id

    def _new_reader_id(self) -> str:
        while True:
            reader_id = f"r{self._next_reader}"
            self._next_reader += 1
            if reader_id not in self._readers:
                return reader_id

    def create_instance(self, name: str, *, tenant: str,
                        buffer_size_kb: int = 1024,
                        filter: str | None = None) -> TraceInstance:
        if not self._valid_name(name):
            raise TraceError("TRACE_INSTANCE_INVALID", name)
        if not self._valid_tenant(tenant):
            raise TraceError("TRACE_INVALID_REQUEST", "tenant is required")
        if (
            not isinstance(buffer_size_kb, int)
            or isinstance(buffer_size_kb, bool)
            or not 1 <= buffer_size_kb <= 16384
        ):
            raise TraceError("TRACE_BUFFER_INVALID", buffer_size_kb)
        if filter is not None:
            if not isinstance(filter, str):
                raise TraceError("TRACE_FILTER_INVALID", filter)
            self._validate_filter(filter)

        with self._lock:
            if name in self._instances:
                raise TraceError("TRACE_INSTANCE_EXISTS", name)
            if len(self._instances) >= self.max_instances:
                raise TraceError("TRACE_LIMIT_EXCEEDED", "instances")
            state = _InstanceState(
                name=name,
                tenant=tenant,
                buffer_size_kb=buffer_size_kb,
                filter=filter,
                active=True,
            )
            self._instances[name] = state
            self._probe_ids_by_instance[name] = []
            return self._instance_view(state)

    def destroy_instance(self, name: str, *, force: bool = False,
                         tenant: str | None = None) -> dict:
        with self._lock:
            state = self._require_instance(name)
            if tenant is not None and tenant != state.tenant:
                raise TraceError("TRACE_TENANT_MISMATCH", tenant)
            attached = [
                reader
                for reader in self._readers.values()
                if reader.instance == name and not reader.closed
            ]
            if attached and not force:
                raise TraceError(
                    "TRACE_READERS_ATTACHED",
                    {"instance": name, "readers": len(attached)},
                )

            probe_ids = list(self._probe_ids_by_instance.get(name, ()))
            for probe_id in probe_ids:
                probe = self._probes[probe_id]
                self._probes[probe_id] = replace(probe, enabled=False)

            for reader in attached:
                reader.closed = True
                reader.queue.clear()

            for probe_id in probe_ids:
                self._probes.pop(probe_id, None)
            self._probe_ids_by_instance.pop(name, None)
            self._instances.pop(name, None)
            return {"probes": len(probe_ids), "readers": len(attached)}

    def instances(self, tenant: str | None = None) -> list[TraceInstance]:
        with self._lock:
            rows = [
                self._instance_view(state)
                for state in self._instances.values()
                if tenant is None or state.tenant == tenant
            ]
        return sorted(rows, key=lambda row: row.name)

    def register_probe(self, instance: str, *, symbol: str, kind: str = KPROBE,
                       offset: int = 0, filter: str = "") -> ProbeRecord:
        with self._lock:
            self._require_instance(instance)
            if kind not in PROBE_KINDS:
                raise TraceError("TRACE_INVALID_REQUEST", kind)

            if kind == KPROBE:
                window = (
                    PROBE_WHITELIST.get(symbol)
                    if isinstance(symbol, str)
                    else None
                )
                if window is None:
                    raise TraceError("TRACE_PROBE_SYMBOL_DENIED", symbol)
                minimum, maximum = window
            else:
                if not self._valid_uprobe_path(symbol):
                    raise TraceError("TRACE_PROBE_SYMBOL_DENIED", symbol)
                minimum, maximum = 0, None

            if (
                not isinstance(offset, int)
                or isinstance(offset, bool)
                or offset < minimum
                or (maximum is not None and offset > maximum)
            ):
                raise TraceError("TRACE_PROBE_OFFSET_INVALID", offset)

            if filter is None:
                filter = ""
            if not isinstance(filter, str):
                raise TraceError("TRACE_FILTER_INVALID", filter)
            self._validate_filter(filter)

            probe_ids = self._probe_ids_by_instance[instance]
            for probe_id in probe_ids:
                existing = self._probes[probe_id]
                if (
                    existing.kind == kind
                    and existing.symbol == symbol
                    and existing.offset == offset
                    and existing.filter == filter
                ):
                    return existing

            if (
                len(probe_ids) >= self.max_probes_per_instance
                or len(self._probes) >= self.max_probes_total
            ):
                raise TraceError("TRACE_LIMIT_EXCEEDED", "probes")

            probe_id = self._new_probe_id()
            record = ProbeRecord(
                probe_id=probe_id,
                instance=instance,
                kind=kind,
                symbol=symbol,
                offset=offset,
                filter=filter,
                enabled=False,
            )
            self._probes[probe_id] = record
            probe_ids.append(probe_id)
            return record

    def probes(self, instance: str, *, tenant: str | None = None) -> list[ProbeRecord]:
        with self._lock:
            state = self._require_instance(instance)
            if tenant is not None and tenant != state.tenant:
                raise TraceError("TRACE_TENANT_MISMATCH", tenant)
            return [
                self._probes[probe_id]
                for probe_id in self._probe_ids_by_instance[instance]
            ]

    def describe(self, probe_id: str, *, tenant: str | None = None) -> dict:
        with self._lock:
            probe = (
                self._probes.get(probe_id)
                if isinstance(probe_id, str)
                else None
            )
            if probe is None:
                raise TraceError("TRACE_PROBE_UNKNOWN", probe_id)
            if tenant is not None:
                state = self._require_instance(probe.instance)
                if tenant != state.tenant:
                    raise TraceError("TRACE_TENANT_MISMATCH", tenant)
            return {
                "probe_id": probe.probe_id,
                "instance": probe.instance,
                "symbol": probe.symbol,
                "offset": probe.offset,
                "filter": probe.filter,
                "address": "0x***",
            }

    def enable_event(self, instance: str, event: str, *,
                     enable: bool = True) -> int:
        with self._lock:
            self._require_instance(instance)
            matched = [
                probe_id
                for probe_id in self._probe_ids_by_instance[instance]
                if self._probes[probe_id].symbol == event
            ]
            if not matched:
                raise TraceError("TRACE_EVENT_UNKNOWN", event)
            enabled = bool(enable)
            for probe_id in matched:
                self._probes[probe_id] = replace(
                    self._probes[probe_id], enabled=enabled
                )
            return len(matched)

    def attach_reader(self, instance: str, *, tenant: str,
                      reader_id: str | None = None) -> ReaderHandle:
        if not self._valid_tenant(tenant):
            raise TraceError("TRACE_INVALID_REQUEST", "tenant is required")
        with self._lock:
            state = self._require_instance(instance)
            if tenant != state.tenant:
                raise TraceError("TRACE_TENANT_MISMATCH", tenant)

            active = [reader for reader in self._readers.values() if not reader.closed]
            if (
                sum(reader.instance == instance for reader in active)
                >= self.max_readers_per_instance
                or len(active) >= self.max_readers_total
            ):
                raise TraceError("TRACE_LIMIT_EXCEEDED", "readers")

            if reader_id is not None:
                if (
                    not isinstance(reader_id, str)
                    or not reader_id
                    or reader_id in self._readers
                ):
                    raise TraceError("TRACE_INVALID_REQUEST", reader_id)
                new_reader_id = reader_id
                numeric = _NUMERIC_READER_ID_RE.fullmatch(reader_id)
                if numeric is not None:
                    self._next_reader = max(
                        self._next_reader, int(numeric.group(1)) + 1
                    )
            else:
                new_reader_id = self._new_reader_id()

            reader = _ReaderState(
                reader_id=new_reader_id,
                instance=instance,
                tenant=tenant,
            )
            self._readers[new_reader_id] = reader
            return self._reader_view(reader)

    def detach_reader(self, reader_id: str, *,
                      tenant: str | None = None) -> bool:
        with self._lock:
            reader = (
                self._readers.get(reader_id)
                if isinstance(reader_id, str)
                else None
            )
            if reader is None:
                raise TraceError("TRACE_READER_UNKNOWN", reader_id)
            if tenant is not None and tenant != reader.tenant:
                raise TraceError("TRACE_TENANT_MISMATCH", tenant)
            if reader.closed:
                return False
            reader.closed = True
            reader.queue.clear()
            return True

    def emit_event(self, instance: str, event: str, *, count: int = 1) -> dict:
        if not self._valid_integer(count, minimum=1):
            raise TraceError("TRACE_INVALID_REQUEST", count)
        with self._lock:
            self._require_instance(instance)
            matching = [
                self._probes[probe_id]
                for probe_id in self._probe_ids_by_instance[instance]
                if (
                    self._probes[probe_id].symbol == event
                    and self._probes[probe_id].enabled
                )
            ]
            if not matching:
                raise TraceError("TRACE_EVENT_UNKNOWN", event)

            readers = [
                reader
                for reader in self._readers.values()
                if reader.instance == instance and not reader.closed
            ]
            delivered = 0
            dropped = 0
            for reader in readers:
                room = max(0, self.reader_capacity - len(reader.queue))
                accepted = min(count, room)
                if accepted:
                    reader.queue.extend([event] * accepted)
                    delivered += accepted
                lost = count - accepted
                if lost:
                    reader.lost += lost
                    dropped += lost

            self._emitted += count
            self._delivered += delivered
            self._dropped += dropped
            return {"delivered": delivered, "dropped": dropped}

    def read(self, reader_id: str, *, max_events: int = 64,
             tenant: str | None = None) -> list[str]:
        with self._lock:
            reader = (
                self._readers.get(reader_id)
                if isinstance(reader_id, str)
                else None
            )
            if reader is None:
                raise TraceError("TRACE_READER_UNKNOWN", reader_id)
            if tenant is not None and tenant != reader.tenant:
                raise TraceError("TRACE_TENANT_MISMATCH", tenant)
            if reader.closed:
                raise TraceError("TRACE_READER_CLOSED", reader_id)
            if not self._valid_integer(max_events, minimum=1):
                raise TraceError("TRACE_INVALID_REQUEST", max_events)
            take = min(max_events, len(reader.queue))
            return [reader.queue.popleft() for _ in range(take)]

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "version": 1,
                    "instances": [
                        {
                            "name": state.name,
                            "tenant": state.tenant,
                            "buffer_size_kb": state.buffer_size_kb,
                            "filter": state.filter,
                            "active": state.active,
                        }
                        for state in self._instances.values()
                    ],
                    "probes": [
                        {
                            "probe_id": probe.probe_id,
                            "instance": probe.instance,
                            "kind": probe.kind,
                            "symbol": probe.symbol,
                            "offset": probe.offset,
                            "filter": probe.filter,
                            "enabled": probe.enabled,
                        }
                        for probe in self._probes.values()
                    ],
                    "readers": [
                        {
                            "reader_id": reader.reader_id,
                            "instance": reader.instance,
                            "tenant": reader.tenant,
                            "lost": reader.lost,
                            "closed": reader.closed,
                            "queue": list(reader.queue),
                        }
                        for reader in self._readers.values()
                    ],
                    "counters": {
                        "emitted": self._emitted,
                        "delivered": self._delivered,
                        "dropped": self._dropped,
                        "next_probe": self._next_probe,
                        "next_reader": self._next_reader,
                    },
                }
            )

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except TraceError as exc:
                raise TraceError(
                    "TRACE_SNAPSHOT_INVALID", exc.detail or exc.code
                ) from exc
            except Exception as exc:
                raise TraceError("TRACE_SNAPSHOT_INVALID", str(exc)) from exc

            (
                instances,
                probes,
                probe_ids_by_instance,
                readers,
                emitted,
                delivered,
                dropped,
                next_probe,
                next_reader,
            ) = restored
            self._instances = instances
            self._probes = probes
            self._probe_ids_by_instance = probe_ids_by_instance
            self._readers = readers
            self._emitted = emitted
            self._delivered = delivered
            self._dropped = dropped
            self._next_probe = next_probe
            self._next_reader = next_reader

    def _parse_snapshot(self, state: object) -> tuple:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise TraceError("TRACE_SNAPSHOT_INVALID", "snapshot shape")
        version = state["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != 1
        ):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "version")
        raw_instances = state["instances"]
        raw_probes = state["probes"]
        raw_readers = state["readers"]
        raw_counters = state["counters"]
        if not all(
            isinstance(value, list)
            for value in (raw_instances, raw_probes, raw_readers)
        ):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "collection type")
        if not isinstance(raw_counters, dict):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "counters")
        if len(raw_instances) > self.max_instances:
            raise TraceError("TRACE_SNAPSHOT_INVALID", "instance limit")

        instances: dict[str, _InstanceState] = {}
        for row in raw_instances:
            if not isinstance(row, dict) or set(row) != {
                "name", "tenant", "buffer_size_kb", "filter", "active"
            }:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "instance shape")
            name = row["name"]
            tenant = row["tenant"]
            buffer_size_kb = row["buffer_size_kb"]
            expression = row["filter"]
            active = row["active"]
            if not self._valid_name(name) or name in instances:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "instance name")
            if not self._valid_tenant(tenant):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "instance tenant")
            if (
                not isinstance(buffer_size_kb, int)
                or isinstance(buffer_size_kb, bool)
                or not 1 <= buffer_size_kb <= 16384
            ):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "instance buffer")
            if expression is not None:
                if not isinstance(expression, str):
                    raise TraceError("TRACE_SNAPSHOT_INVALID", "instance filter")
                self._validate_filter(expression)
            if not isinstance(active, bool):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "instance active")
            instances[name] = _InstanceState(
                name=name,
                tenant=tenant,
                buffer_size_kb=buffer_size_kb,
                filter=expression,
                active=active,
            )

        if len(raw_probes) > self.max_probes_total:
            raise TraceError("TRACE_SNAPSHOT_INVALID", "probe limit")
        probes: dict[str, ProbeRecord] = {}
        probe_ids_by_instance: dict[str, list[str]] = {
            name: [] for name in instances
        }
        probe_identities: set[tuple] = set()
        max_probe_number = 0
        for row in raw_probes:
            if not isinstance(row, dict) or set(row) != {
                "probe_id", "instance", "kind", "symbol", "offset",
                "filter", "enabled",
            }:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe shape")
            probe_id = row["probe_id"]
            match = (
                _PROBE_ID_RE.fullmatch(probe_id)
                if isinstance(probe_id, str)
                else None
            )
            if match is None or probe_id in probes:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe id")
            instance = row["instance"]
            if instance not in instances:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe instance")
            kind = row["kind"]
            symbol = row["symbol"]
            offset = row["offset"]
            probe_filter = row["filter"]
            enabled = row["enabled"]
            if kind not in PROBE_KINDS:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe kind")
            if kind == KPROBE:
                window = (
                    PROBE_WHITELIST.get(symbol)
                    if isinstance(symbol, str)
                    else None
                )
                if window is None:
                    raise TraceError("TRACE_SNAPSHOT_INVALID", "probe symbol")
                minimum, maximum = window
            else:
                if not self._valid_uprobe_path(symbol):
                    raise TraceError("TRACE_SNAPSHOT_INVALID", "probe symbol")
                minimum, maximum = 0, None
            if (
                not isinstance(offset, int)
                or isinstance(offset, bool)
                or offset < minimum
                or (maximum is not None and offset > maximum)
            ):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe offset")
            if not isinstance(probe_filter, str):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe filter")
            self._validate_filter(probe_filter)
            if not isinstance(enabled, bool):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "probe enabled")
            identity = (instance, kind, symbol, offset, probe_filter)
            if identity in probe_identities:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "duplicate probe")
            probe_identities.add(identity)

            record = ProbeRecord(
                probe_id=probe_id,
                instance=instance,
                kind=kind,
                symbol=symbol,
                offset=offset,
                filter=probe_filter,
                enabled=enabled,
            )
            probes[probe_id] = record
            probe_ids_by_instance[instance].append(probe_id)
            max_probe_number = max(max_probe_number, int(match.group(1)))

        for name, probe_ids in probe_ids_by_instance.items():
            if len(probe_ids) > self.max_probes_per_instance:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "instance probe limit")

        readers: dict[str, _ReaderState] = {}
        active_readers = 0
        per_instance_readers: dict[str, int] = {}
        max_reader_number = 0
        for row in raw_readers:
            if not isinstance(row, dict) or set(row) != {
                "reader_id", "instance", "tenant", "lost", "closed", "queue"
            }:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader shape")
            reader_id = row["reader_id"]
            instance = row["instance"]
            tenant = row["tenant"]
            lost = row["lost"]
            closed = row["closed"]
            queue = row["queue"]
            if (
                not isinstance(reader_id, str)
                or not reader_id
                or reader_id in readers
            ):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader id")
            if instance not in instances and not closed:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader instance")
            if instance in instances and not closed:
                if tenant != instances[instance].tenant:
                    raise TraceError("TRACE_SNAPSHOT_INVALID", "reader tenant")
            if not isinstance(tenant, str) or not tenant:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader tenant")
            if not self._valid_integer(lost):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader lost")
            if not isinstance(closed, bool):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader closed")
            if not isinstance(queue, list) or not all(
                isinstance(event, str) for event in queue
            ):
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader queue")
            if len(queue) > self.reader_capacity:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "reader queue size")
            if closed and queue:
                raise TraceError("TRACE_SNAPSHOT_INVALID", "closed reader queue")

            reader = _ReaderState(
                reader_id=reader_id,
                instance=instance,
                tenant=tenant,
                lost=lost,
                closed=closed,
                queue=deque(queue),
            )
            readers[reader_id] = reader
            numeric = _NUMERIC_READER_ID_RE.fullmatch(reader_id)
            if numeric is not None:
                max_reader_number = max(max_reader_number, int(numeric.group(1)))
            if not closed:
                active_readers += 1
                per_instance_readers[instance] = (
                    per_instance_readers.get(instance, 0) + 1
                )

        if active_readers > self.max_readers_total:
            raise TraceError("TRACE_SNAPSHOT_INVALID", "reader limit")
        if any(
            count > self.max_readers_per_instance
            for count in per_instance_readers.values()
        ):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "instance reader limit")

        counter_keys = {"emitted", "delivered", "dropped"}
        if not counter_keys.issubset(raw_counters):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "counter shape")
        emitted = raw_counters["emitted"]
        delivered = raw_counters["delivered"]
        dropped = raw_counters["dropped"]
        if not all(self._valid_integer(value)
                   for value in (emitted, delivered, dropped)):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "counter value")
        next_probe = raw_counters.get("next_probe", max_probe_number + 1)
        next_reader = raw_counters.get("next_reader", max_reader_number + 1)
        if (
            not self._valid_integer(next_probe, minimum=1)
            or next_probe <= max_probe_number
            or not self._valid_integer(next_reader, minimum=1)
            or next_reader <= max_reader_number
        ):
            raise TraceError("TRACE_SNAPSHOT_INVALID", "id counter")

        return (
            instances,
            probes,
            probe_ids_by_instance,
            readers,
            emitted,
            delivered,
            dropped,
            next_probe,
            next_reader,
        )

    def stats(self) -> dict:
        with self._lock:
            return {
                "instances": len(self._instances),
                "probes": len(self._probes),
                "enabled_probes": sum(
                    probe.enabled for probe in self._probes.values()
                ),
                "readers": sum(
                    not reader.closed for reader in self._readers.values()
                ),
                "emitted": self._emitted,
                "delivered": self._delivered,
                "dropped": self._dropped,
            }
