"""DNS over TCP pipeline: two-byte framing, out-of-order matching, idle reaping."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field

SNAPSHOT_VERSION = 1
MIN_QID = 0
MAX_QID = 65535
SUPPORTED_QTYPES = (1, 2, 5, 6, 12, 15, 16, 28, 33, 35, 43)


class PipelineError(ValueError):
    """Raised when a pipeline operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ConnectionView:
    conn_id: str
    open: bool
    pending_bytes: int
    in_flight: int


@dataclass(frozen=True)
class QueryView:
    ticket: str
    conn_id: str
    qid: int
    qname: str
    qtype: int
    deadline: int


@dataclass(frozen=True)
class Delivery:
    conn_id: str
    qid: int
    qname: str
    qtype: int
    status: str


@dataclass
class _Query:
    ticket: str
    qid: int
    qname: str
    qtype: int
    deadline: int
    submitted_at: int
    name_key: str

    def view(self, conn_id: str) -> QueryView:
        return QueryView(
            ticket=self.ticket,
            conn_id=conn_id,
            qid=self.qid,
            qname=self.qname,
            qtype=self.qtype,
            deadline=self.deadline,
        )


@dataclass
class _Connection:
    conn_id: str
    open: bool
    half_closed: bool
    pending: bytearray
    last_activity: int
    complete_frames: int = 0
    queries: dict[int, _Query] = field(default_factory=dict)
    delivered: dict[int, tuple[str, str, int]] = field(default_factory=dict)

    def view(self) -> ConnectionView:
        return ConnectionView(
            conn_id=self.conn_id,
            open=self.open,
            pending_bytes=len(self.pending),
            in_flight=len(self.queries),
        )


def _name_key(qname: str) -> str:
    return qname.lower()


def _read_dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[bytes] = []
    visited: set[int] = set()
    cursor = offset
    next_offset: int | None = None
    wire_length = 0

    while True:
        if cursor in visited:
            raise PipelineError("PIPELINE_RESPONSE_INVALID", "compression loop")
        visited.add(cursor)
        if cursor >= len(message):
            raise PipelineError("PIPELINE_RESPONSE_INVALID", "truncated name")

        length = message[cursor]
        if length == 0:
            if next_offset is None:
                next_offset = cursor + 1
            break

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise PipelineError("PIPELINE_RESPONSE_INVALID", "truncated pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                raise PipelineError("PIPELINE_RESPONSE_INVALID", "pointer out of range")
            if next_offset is None:
                next_offset = cursor + 2
            cursor = pointer
            continue

        if length & 0xC0:
            raise PipelineError("PIPELINE_RESPONSE_INVALID", "unsupported label type")
        label_end = cursor + 1 + length
        if label_end > len(message):
            raise PipelineError("PIPELINE_RESPONSE_INVALID", "truncated label")
        wire_length += 1 + length
        if wire_length > 255:
            raise PipelineError("PIPELINE_RESPONSE_INVALID", "name too long")
        labels.append(message[cursor + 1:label_end])
        cursor = label_end

    raw_name = b".".join(labels)
    try:
        qname = raw_name.decode("ascii")
    except UnicodeDecodeError:
        qname = raw_name.decode("latin-1")
    if next_offset is None:
        raise PipelineError("PIPELINE_RESPONSE_INVALID", "missing name terminator")
    return qname, next_offset


def _parse_response_question(message: bytes) -> tuple[int, str, int]:
    if len(message) < 12:
        raise PipelineError("PIPELINE_RESPONSE_INVALID", "short DNS header")
    qid = int.from_bytes(message[0:2], "big")
    qdcount = int.from_bytes(message[4:6], "big")
    if qdcount < 1:
        raise PipelineError("PIPELINE_RESPONSE_INVALID", "missing question")

    qname, offset = _read_dns_name(message, 12)
    if offset + 4 > len(message):
        raise PipelineError("PIPELINE_RESPONSE_INVALID", "truncated question")
    qtype = int.from_bytes(message[offset:offset + 2], "big")
    return qid, qname, qtype


class DnsTcpPipelineGuard:
    """Keep per-connection frame buffers, in-flight queries and ID occupancy."""

    def __init__(self, *, idle_timeout: int = 30, query_timeout: int = 10,
                 max_connections: int = 8, max_in_flight: int = 16,
                 max_frame: int = 4096) -> None:
        self.idle_timeout = idle_timeout
        self.query_timeout = query_timeout
        self.max_connections = max_connections
        self.max_in_flight = max_in_flight
        self.max_frame = max_frame
        self._lock = threading.RLock()
        self._connections: dict[str, _Connection] = {}
        self._next_ticket = 1
        self._stats = {
            "queries": 0,
            "delivered": 0,
            "duplicates": 0,
            "unmatched": 0,
            "timeouts": 0,
            "idle_closed": 0,
            "frame_errors": 0,
        }

    def attach_connection(self, conn_id: str, now: int) -> ConnectionView:
        with self._lock:
            self._validate_conn_id(conn_id)
            if conn_id in self._connections:
                raise PipelineError(
                    "PIPELINE_CONNECTION_EXISTS", {"conn_id": conn_id}
                )
            if len(self._connections) >= self.max_connections:
                raise PipelineError(
                    "PIPELINE_CONNECTION_LIMIT",
                    {
                        "conn_id": conn_id,
                        "limit": self.max_connections,
                        "count": len(self._connections),
                    },
                )
            connection = _Connection(
                conn_id=conn_id,
                open=True,
                half_closed=False,
                pending=bytearray(),
                last_activity=now,
            )
            self._connections[conn_id] = connection
            return connection.view()

    def submit_query(self, conn_id: str, qid: int, qname: str, qtype: int,
                     now: int) -> QueryView:
        with self._lock:
            connection = self._require_connection(conn_id)
            self._require_receiving(connection)
            self._validate_query(qid, qname, qtype)
            if qid in connection.queries:
                raise PipelineError(
                    "PIPELINE_ID_IN_USE",
                    {"conn_id": conn_id, "qid": qid},
                )
            if len(connection.queries) >= self.max_in_flight:
                raise PipelineError(
                    "PIPELINE_IN_FLIGHT_LIMIT",
                    {
                        "conn_id": conn_id,
                        "limit": self.max_in_flight,
                        "in_flight": len(connection.queries),
                    },
                )

            ticket = str(self._next_ticket)
            self._next_ticket += 1
            query = _Query(
                ticket=ticket,
                qid=qid,
                qname=qname,
                qtype=qtype,
                deadline=now + self.query_timeout,
                submitted_at=now,
                name_key=_name_key(qname),
            )
            connection.queries[qid] = query
            connection.last_activity = now
            self._stats["queries"] += 1
            return query.view(conn_id)

    def accept_response(self, conn_id: str, message: bytes, now: int) -> Delivery:
        with self._lock:
            connection = self._require_connection(conn_id)
            self._require_receiving(connection)
            connection.last_activity = now
            raw = bytes(message)

            if len(raw) < 2:
                self._frame_failure(
                    connection,
                    "PIPELINE_FRAME_ERROR",
                    {"reason": "missing length prefix", "actual": len(raw)},
                    now,
                )

            declared = int.from_bytes(raw[0:2], "big")
            if declared == 0:
                self._frame_failure(
                    connection,
                    "PIPELINE_FRAME_ERROR",
                    {"reason": "zero length frame", "declared": declared},
                    now,
                )
            if declared > self.max_frame:
                self._frame_failure(
                    connection,
                    "PIPELINE_FRAME_TOO_LARGE",
                    {
                        "declared": declared,
                        "limit": self.max_frame,
                    },
                    now,
                )

            actual = len(raw) - 2
            if actual != declared:
                self._frame_failure(
                    connection,
                    "PIPELINE_FRAME_ERROR",
                    {
                        "reason": "length mismatch",
                        "declared": declared,
                        "actual": actual,
                    },
                    now,
                )

            connection.complete_frames += 1
            return self._deliver_payload(connection, raw[2:], now)

    def feed(self, conn_id: str, data: bytes, now: int) -> tuple[Delivery, ...]:
        with self._lock:
            connection = self._require_connection(conn_id)
            self._require_receiving(connection)
            connection.last_activity = now
            connection.pending.extend(data)
            return self._drain_pending(connection, now)

    def half_close(self, conn_id: str, now: int) -> tuple[Delivery, ...]:
        with self._lock:
            connection = self._require_connection(conn_id)
            if not connection.open or connection.half_closed:
                return ()
            connection.last_activity = now
            deliveries = self._drain_pending(connection, now)
            connection.half_closed = True
            return deliveries

    def close_connection(self, conn_id: str, now: int) -> tuple[Delivery, ...]:
        with self._lock:
            connection = self._require_connection(conn_id)
            if not connection.open:
                return ()
            deliveries = self._servfail_queries(connection)
            connection.open = False
            connection.half_closed = True
            connection.pending.clear()
            connection.last_activity = now
            return deliveries

    def expire_queries(self, now: int) -> tuple[Delivery, ...]:
        with self._lock:
            deliveries: list[Delivery] = []
            for connection in self._connections.values():
                expired = [
                    query for query in connection.queries.values()
                    if query.deadline <= now
                ]
                for query in expired:
                    del connection.queries[query.qid]
                    deliveries.append(
                        Delivery(
                            conn_id=connection.conn_id,
                            qid=query.qid,
                            qname=query.qname,
                            qtype=query.qtype,
                            status="servfail",
                        )
                    )
                    self._stats["timeouts"] += 1
            return tuple(deliveries)

    def expire_idle(self, now: int) -> tuple[str, ...]:
        with self._lock:
            closed: list[str] = []
            for connection in self._connections.values():
                if not connection.open:
                    continue
                if now - connection.last_activity < self.idle_timeout:
                    continue
                connection.open = False
                connection.half_closed = True
                connection.pending.clear()
                connection.queries.clear()
                self._stats["idle_closed"] += 1
                closed.append(connection.conn_id)
            return tuple(closed)

    def in_flight(self, conn_id: str) -> tuple[QueryView, ...]:
        with self._lock:
            connection = self._require_connection(conn_id)
            return tuple(
                query.view(connection.conn_id)
                for query in connection.queries.values()
            )

    def connection_view(self, conn_id: str) -> ConnectionView:
        with self._lock:
            return self._require_connection(conn_id).view()

    def connections(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._connections)

    def framing_stats(self, conn_id: str) -> dict:
        with self._lock:
            connection = self._require_connection(conn_id)
            return {
                "pending_bytes": len(connection.pending),
                "complete_frames": connection.complete_frames,
            }

    def snapshot(self) -> dict:
        with self._lock:
            connections: dict[str, dict] = {}
            for conn_id, connection in self._connections.items():
                queries = []
                for query in connection.queries.values():
                    queries.append(
                        {
                            "ticket": query.ticket,
                            "qid": query.qid,
                            "qname": query.qname,
                            "qtype": query.qtype,
                            "deadline": query.deadline,
                            "submitted_at": query.submitted_at,
                        }
                    )
                delivered = [
                    {
                        "qid": qid,
                        "name_key": item[0],
                        "qname": item[1],
                        "qtype": item[2],
                    }
                    for qid, item in connection.delivered.items()
                ]
                connections[conn_id] = {
                    "open": connection.open,
                    "half_closed": connection.half_closed,
                    "pending_hex": connection.pending.hex(),
                    "last_activity": connection.last_activity,
                    "complete_frames": connection.complete_frames,
                    "in_flight": queries,
                    "occupied_ids": sorted(connection.queries),
                    "delivered": delivered,
                }
            state = {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "idle_timeout": self.idle_timeout,
                    "query_timeout": self.query_timeout,
                    "max_connections": self.max_connections,
                    "max_in_flight": self.max_in_flight,
                    "max_frame": self.max_frame,
                },
                "next_ticket": self._next_ticket,
                "connections": connections,
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                raw = copy.deepcopy(state)
                if not isinstance(raw, dict):
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID", "snapshot must be a mapping"
                    )
                version = raw.get("version")
                if type(version) is not int or version != SNAPSHOT_VERSION:
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID",
                        {"version": version, "expected": SNAPSHOT_VERSION},
                    )

                config_raw = raw.get("config", {})
                if not isinstance(config_raw, dict):
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID", "invalid config"
                    )
                idle_timeout = self._snapshot_int(
                    config_raw, "idle_timeout", self.idle_timeout
                )
                query_timeout = self._snapshot_int(
                    config_raw, "query_timeout", self.query_timeout
                )
                max_connections = self._snapshot_int(
                    config_raw, "max_connections", self.max_connections
                )
                max_in_flight = self._snapshot_int(
                    config_raw, "max_in_flight", self.max_in_flight
                )
                max_frame = self._snapshot_int(
                    config_raw, "max_frame", self.max_frame
                )

                connections_raw = raw.get("connections")
                if not isinstance(connections_raw, dict):
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID", "invalid connections"
                    )
                if len(connections_raw) > max_connections:
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID", "connection limit exceeded"
                    )

                restored_connections: dict[str, _Connection] = {}
                tickets: set[str] = set()
                for conn_id, item in connections_raw.items():
                    if not isinstance(conn_id, str) or not conn_id:
                        raise PipelineError(
                            "PIPELINE_SNAPSHOT_INVALID", "invalid connection id"
                        )
                    if not isinstance(item, dict):
                        raise PipelineError(
                            "PIPELINE_SNAPSHOT_INVALID",
                            {"conn_id": conn_id, "reason": "invalid state"},
                        )
                    restored_connections[conn_id] = self._restore_connection(
                        conn_id,
                        item,
                        max_in_flight,
                        max_frame,
                        query_timeout,
                        tickets,
                    )

                next_ticket = raw.get("next_ticket")
                if type(next_ticket) is not int or next_ticket < 1:
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID", "invalid ticket counter"
                    )

                stats_raw = raw.get("stats")
                if not isinstance(stats_raw, dict):
                    raise PipelineError(
                        "PIPELINE_SNAPSHOT_INVALID", "invalid stats"
                    )
                restored_stats = {}
                for key in self._stats:
                    value = stats_raw.get(key)
                    if type(value) is not int or value < 0:
                        raise PipelineError(
                            "PIPELINE_SNAPSHOT_INVALID",
                            {"stat": key, "value": value},
                        )
                    restored_stats[key] = value
            except PipelineError:
                raise
            except Exception as exc:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID", str(exc)
                ) from exc

            self.idle_timeout = idle_timeout
            self.query_timeout = query_timeout
            self.max_connections = max_connections
            self.max_in_flight = max_in_flight
            self.max_frame = max_frame
            self._next_ticket = next_ticket
            self._connections = restored_connections
            self._stats = restored_stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _restore_connection(
        self,
        conn_id: str,
        item: dict,
        max_in_flight: int,
        max_frame: int,
        query_timeout: int,
        tickets: set[str],
    ) -> _Connection:
        open_flag = item.get("open")
        half_closed = item.get("half_closed", False)
        if type(open_flag) is not bool or type(half_closed) is not bool:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid flags"},
            )

        pending_hex = item.get("pending_hex", "")
        if not isinstance(pending_hex, str):
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid pending bytes"},
            )
        try:
            pending = bytearray(bytes.fromhex(pending_hex))
        except ValueError as exc:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid pending bytes"},
            ) from exc
        if len(pending) > max_frame + 2:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "pending buffer too large"},
            )

        last_activity = item.get("last_activity")
        complete_frames = item.get("complete_frames")
        if type(last_activity) is not int:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid last activity"},
            )
        if type(complete_frames) is not int or complete_frames < 0:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid frame count"},
            )

        queries_raw = item.get("in_flight")
        if not isinstance(queries_raw, list):
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid in-flight queries"},
            )
        if len(queries_raw) > max_in_flight:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "in-flight limit exceeded"},
            )

        queries: dict[int, _Query] = {}
        for query_raw in queries_raw:
            if not isinstance(query_raw, dict):
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid query"},
                )
            try:
                ticket = query_raw["ticket"]
                qid = query_raw["qid"]
                qname = query_raw["qname"]
                qtype = query_raw["qtype"]
                deadline = query_raw["deadline"]
                submitted_at = query_raw.get(
                    "submitted_at", deadline - query_timeout
                )
                self._validate_query(qid, qname, qtype)
            except (KeyError, PipelineError) as exc:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid query"},
                ) from exc
            if not isinstance(ticket, str) or not ticket or ticket in tickets:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid ticket"},
                )
            if type(deadline) is not int or type(submitted_at) is not int:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid deadline"},
                )
            if qid in queries:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "duplicate qid"},
                )
            tickets.add(ticket)
            queries[qid] = _Query(
                ticket=ticket,
                qid=qid,
                qname=qname,
                qtype=qtype,
                deadline=deadline,
                submitted_at=submitted_at,
                name_key=_name_key(qname),
            )

        occupied = item.get("occupied_ids", sorted(queries))
        if not isinstance(occupied, list):
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid occupied ids"},
            )
        occupied_set = set()
        for qid in occupied:
            if type(qid) is not int or not MIN_QID <= qid <= MAX_QID:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid occupied id"},
                )
            occupied_set.add(qid)
        if occupied_set != set(queries):
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "occupied id mismatch"},
            )

        delivered_raw = item.get("delivered", [])
        if not isinstance(delivered_raw, list):
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID",
                {"conn_id": conn_id, "reason": "invalid delivery cache"},
            )
        delivered: dict[int, tuple[str, str, int]] = {}
        for delivery_raw in delivered_raw:
            if not isinstance(delivery_raw, dict):
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid delivery"},
                )
            qid = delivery_raw.get("qid")
            name_key = delivery_raw.get("name_key")
            qname = delivery_raw.get("qname")
            qtype = delivery_raw.get("qtype")
            if type(qid) is not int or not MIN_QID <= qid <= MAX_QID:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid delivery id"},
                )
            if not isinstance(name_key, str) or not isinstance(qname, str):
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid delivery name"},
                )
            if type(qtype) is not int:
                raise PipelineError(
                    "PIPELINE_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "reason": "invalid delivery type"},
                )
            delivered[qid] = (name_key, qname, qtype)

        return _Connection(
            conn_id=conn_id,
            open=open_flag,
            half_closed=half_closed,
            pending=pending,
            last_activity=last_activity,
            complete_frames=complete_frames,
            queries=queries,
            delivered=delivered,
        )

    def _drain_pending(self, connection: _Connection,
                       now: int) -> tuple[Delivery, ...]:
        deliveries: list[Delivery] = []
        pending = connection.pending
        while len(pending) >= 2:
            declared = int.from_bytes(pending[0:2], "big")
            if declared == 0:
                self._frame_failure(
                    connection,
                    "PIPELINE_FRAME_ERROR",
                    {"reason": "zero length frame", "declared": declared},
                    now,
                )
            if declared > self.max_frame:
                self._frame_failure(
                    connection,
                    "PIPELINE_FRAME_TOO_LARGE",
                    {"declared": declared, "limit": self.max_frame},
                    now,
                )
            frame_length = declared + 2
            if len(pending) < frame_length:
                break
            payload = bytes(pending[2:frame_length])
            del pending[:frame_length]
            connection.complete_frames += 1
            deliveries.append(self._deliver_payload(connection, payload, now))
        return tuple(deliveries)

    def _deliver_payload(self, connection: _Connection, payload: bytes,
                         now: int) -> Delivery:
        qid, qname, qtype = _parse_response_question(payload)
        normalized = _name_key(qname)
        query = connection.queries.get(qid)
        if (
            query is not None
            and query.name_key == normalized
            and query.qtype == qtype
        ):
            del connection.queries[qid]
            connection.delivered[qid] = (query.name_key, query.qname, query.qtype)
            connection.last_activity = now
            self._stats["delivered"] += 1
            return Delivery(
                conn_id=connection.conn_id,
                qid=qid,
                qname=query.qname,
                qtype=query.qtype,
                status="delivered",
            )

        previous = connection.delivered.get(qid)
        if previous is not None and previous[0] == normalized and previous[2] == qtype:
            connection.last_activity = now
            self._stats["duplicates"] += 1
            return Delivery(
                conn_id=connection.conn_id,
                qid=qid,
                qname=previous[1],
                qtype=previous[2],
                status="duplicate",
            )

        connection.last_activity = now
        self._stats["unmatched"] += 1
        return Delivery(
            conn_id=connection.conn_id,
            qid=qid,
            qname=qname,
            qtype=qtype,
            status="unmatched",
        )

    def _frame_failure(self, connection: _Connection, code: str,
                       detail: dict, now: int) -> None:
        self._stats["frame_errors"] += 1
        connection.open = False
        connection.half_closed = True
        connection.pending.clear()
        connection.queries.clear()
        connection.last_activity = now
        raise PipelineError(code, detail)

    def _servfail_queries(self, connection: _Connection) -> tuple[Delivery, ...]:
        deliveries = tuple(
            Delivery(
                conn_id=connection.conn_id,
                qid=query.qid,
                qname=query.qname,
                qtype=query.qtype,
                status="servfail",
            )
            for query in connection.queries.values()
        )
        connection.queries.clear()
        return deliveries

    def _require_connection(self, conn_id: str) -> _Connection:
        if not isinstance(conn_id, str):
            raise PipelineError(
                "PIPELINE_CONNECTION_NOT_FOUND", {"conn_id": conn_id}
            )
        connection = self._connections.get(conn_id)
        if connection is None:
            raise PipelineError(
                "PIPELINE_CONNECTION_NOT_FOUND", {"conn_id": conn_id}
            )
        return connection

    def _require_receiving(self, connection: _Connection) -> None:
        if not connection.open or connection.half_closed:
            raise PipelineError(
                "PIPELINE_CONNECTION_CLOSED",
                {"conn_id": connection.conn_id},
            )

    @staticmethod
    def _validate_conn_id(conn_id: str) -> None:
        if not isinstance(conn_id, str) or not conn_id:
            raise PipelineError(
                "PIPELINE_INVALID_CONNECTION", {"conn_id": conn_id}
            )

    @staticmethod
    def _validate_query(qid: int, qname: str, qtype: int) -> None:
        if type(qid) is not int or not MIN_QID <= qid <= MAX_QID:
            raise PipelineError(
                "PIPELINE_INVALID_QUERY", {"qid": qid}
            )
        if not isinstance(qname, str) or not qname or len(qname) > 255:
            raise PipelineError(
                "PIPELINE_INVALID_QUERY", {"qname": qname}
            )
        if type(qtype) is not int or qtype not in SUPPORTED_QTYPES:
            raise PipelineError(
                "PIPELINE_INVALID_QUERY", {"qtype": qtype}
            )

    @staticmethod
    def _snapshot_int(source: dict, key: str, default: int) -> int:
        value = source.get(key, default)
        if type(value) is not int or value < 0:
            raise PipelineError(
                "PIPELINE_SNAPSHOT_INVALID", {"config": key, "value": value}
            )
        return value
