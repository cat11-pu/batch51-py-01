"""SRT ARQ guard: 32-bit sequence wrap, retransmit budget, handshake bound to a stream."""

from __future__ import annotations

import threading
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
SEQ_MODULUS = 1 << 32
SEQ_HALF = 1 << 31
STREAM_STATES = ("listening", "connected", "closed")


class SrtError(ValueError):
    """Raised when a stream handshake, packet or acknowledgement is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Stream:
    stream_id: str
    role: str
    state: str
    passphrase: str | None
    initial_seq: int
    next_seq: int
    window: int
    latency_ms: int


@dataclass(frozen=True)
class Packet:
    stream_id: str
    sequence: int
    payload: object
    submitted_at: int
    retransmits: int
    delivered: bool


@dataclass(frozen=True)
class AckState:
    stream_id: str
    ack_seq: int
    acked_packets: int
    pending: int


@dataclass(frozen=True)
class KeyMaterial:
    stream_id: str
    key_id: int
    salt: str


class SrtArqGuard:
    """Own stream sequence spaces, ARQ windows and handshake key material."""

    def __init__(self, *, max_streams: int = 8, window: int = 16,
                 max_retransmits: int = 3, latency_ms: int = 120) -> None:
        self.max_streams = max_streams
        self.window = window
        self.max_retransmits = max_retransmits
        self.latency_ms = latency_ms
        self._lock = threading.RLock()

    def open_listener(self, stream_id: str, *, passphrase: str | None = None,
                      latency_ms: int | None = None, window: int | None = None,
                      initial_seq: int = 0) -> Stream:
        raise NotImplementedError

    def connect_caller(self, stream_id: str, *, passphrase: str | None = None,
                       now: int = 0) -> Stream:
        raise NotImplementedError

    def submit_packet(self, stream_id: str, payload: object, *,
                      now: int = 0) -> Packet:
        raise NotImplementedError

    def handle_ack(self, stream_id: str, ack_seq: int) -> AckState:
        raise NotImplementedError

    def handle_nak(self, stream_id: str, seq: int, *, now: int = 0):
        raise NotImplementedError

    def receive_packet(self, stream_id: str, sequence: int, payload: object, *,
                       now: int = 0) -> bool:
        raise NotImplementedError

    def deliver(self, stream_id: str, *, now: int = 0) -> tuple[Packet, ...]:
        raise NotImplementedError

    def pending_packets(self, stream_id: str) -> tuple[int, ...]:
        raise NotImplementedError

    def stream_state(self, stream_id: str) -> str:
        raise NotImplementedError

    def retransmit_count(self, stream_id: str) -> int:
        raise NotImplementedError

    def too_late_count(self, stream_id: str) -> int:
        raise NotImplementedError

    def close_stream(self, stream_id: str) -> int:
        raise NotImplementedError

    def key_material(self, stream_id: str) -> KeyMaterial:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
