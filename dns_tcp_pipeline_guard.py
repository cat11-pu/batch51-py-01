"""DNS over TCP pipeline: two-byte framing, out-of-order matching, idle reaping."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

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
        self._lock = threading.Lock()
        self._connections: dict[str, dict] = {}
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
        raise NotImplementedError

    def submit_query(self, conn_id: str, qid: int, qname: str, qtype: int,
                     now: int) -> QueryView:
        raise NotImplementedError

    def accept_response(self, conn_id: str, message: bytes, now: int) -> Delivery:
        raise NotImplementedError

    def feed(self, conn_id: str, data: bytes, now: int) -> tuple[Delivery, ...]:
        raise NotImplementedError

    def half_close(self, conn_id: str, now: int) -> tuple[Delivery, ...]:
        raise NotImplementedError

    def close_connection(self, conn_id: str, now: int) -> tuple[Delivery, ...]:
        raise NotImplementedError

    def expire_queries(self, now: int) -> tuple[Delivery, ...]:
        raise NotImplementedError

    def expire_idle(self, now: int) -> tuple[str, ...]:
        raise NotImplementedError

    def in_flight(self, conn_id: str) -> tuple[QueryView, ...]:
        raise NotImplementedError

    def connection_view(self, conn_id: str) -> ConnectionView:
        raise NotImplementedError

    def connections(self) -> tuple[str, ...]:
        raise NotImplementedError

    def framing_stats(self, conn_id: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
