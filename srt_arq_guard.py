"""SRT ARQ guard: 32-bit sequence wrap, retransmit budget, handshake bound to a stream."""

from __future__ import annotations

import copy
import hashlib
import secrets
import threading
from dataclasses import dataclass, field

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


@dataclass
class _RxRecord:
    index: int
    sequence: int
    payload: object
    arrival: int


@dataclass
class _Stream:
    stream_id: str
    role: str
    state: str
    passphrase: str | None
    initial_seq: int
    next_seq: int
    window: int
    latency_ms: int
    key: KeyMaterial | None = None
    key_generation: int = 0
    submitted_total: int = 0
    queued_total: int = 0
    acked_total: int = 0
    retransmit_total: int = 0
    too_late_total: int = 0
    last_ack_seq: int = 0
    last_ack_index: int = -1
    max_submitted_index: int = -1
    sent: dict[int, Packet] = field(default_factory=dict)
    queue: list[tuple[int, Packet]] = field(default_factory=list)
    rx_anchor_seq: int = 0
    rx_high_index: int = -1
    rx_latest_time: int | None = None
    rx_buffer: dict[int, _RxRecord] = field(default_factory=dict)
    rx_delivered: dict[int, int] = field(default_factory=dict)
    rx_seq_index: dict[int, int] = field(default_factory=dict)


class SrtArqGuard:
    """Own stream sequence spaces, ARQ windows and handshake key material."""

    def __init__(self, *, max_streams: int = 8, window: int = 16,
                 max_retransmits: int = 3, latency_ms: int = 120) -> None:
        if (not isinstance(max_streams, int) or isinstance(max_streams, bool)
                or max_streams < 1):
            raise SrtError("SRT_INVALID_REQUEST", "invalid max_streams")
        if not isinstance(window, int) or isinstance(window, bool) or window < 1:
            raise SrtError("SRT_INVALID_REQUEST", "invalid window")
        if (not isinstance(max_retransmits, int)
                or isinstance(max_retransmits, bool) or max_retransmits < 0):
            raise SrtError("SRT_INVALID_REQUEST", "invalid max_retransmits")
        if (not isinstance(latency_ms, int) or isinstance(latency_ms, bool)
                or latency_ms < 0):
            raise SrtError("SRT_INVALID_REQUEST", "invalid latency_ms")
        self.max_streams = max_streams
        self.window = window
        self.max_retransmits = max_retransmits
        self.latency_ms = latency_ms
        self._lock = threading.RLock()
        self._streams: dict[str, _Stream] = {}
        self._stats = {
            "submitted": 0,
            "queued": 0,
            "acked": 0,
            "retransmitted": 0,
            "too_late": 0,
        }

    # ------------------------------------------------------------------
    # validation and small helpers

    @staticmethod
    def _check_stream_id(stream_id: object) -> str:
        if (not isinstance(stream_id, str) or not stream_id.strip()
                or len(stream_id) > 64):
            raise SrtError("SRT_INVALID_REQUEST", "invalid stream id")
        return stream_id

    @staticmethod
    def _check_seq(sequence: object, code: str = "SRT_INVALID_REQUEST") -> int:
        if (not isinstance(sequence, int) or isinstance(sequence, bool)
                or sequence < 0 or sequence >= SEQ_MODULUS):
            raise SrtError(code, "invalid sequence number")
        return sequence

    def _get(self, stream_id: object) -> _Stream:
        stream_id = self._check_stream_id(stream_id)
        stream = self._streams.get(stream_id)
        if stream is None:
            raise SrtError("SRT_STREAM_STATE", "unknown stream")
        return stream

    def _connected(self, stream_id: object) -> _Stream:
        stream = self._get(stream_id)
        if stream.state != "connected":
            raise SrtError("SRT_STREAM_STATE", stream.state)
        return stream

    @staticmethod
    def _public(stream: _Stream, *, role: str | None = None) -> Stream:
        return Stream(
            stream_id=stream.stream_id,
            role=stream.role if role is None else role,
            state=stream.state,
            passphrase=stream.passphrase,
            initial_seq=stream.initial_seq,
            next_seq=stream.next_seq,
            window=stream.window,
            latency_ms=stream.latency_ms,
        )

    @staticmethod
    def _pending(stream: _Stream) -> list[tuple[int, Packet]]:
        pending = list(stream.sent.items()) + list(stream.queue)
        pending.sort(key=lambda item: item[0])
        return pending

    @staticmethod
    def _promote(stream: _Stream) -> None:
        while len(stream.sent) < stream.window and stream.queue:
            index, packet = stream.queue.pop(0)
            stream.sent[index] = packet

    @staticmethod
    def _rx_index(stream: _Stream, sequence: int) -> int:
        base = (sequence - stream.rx_anchor_seq) % SEQ_MODULUS
        if base >= SEQ_HALF:
            base -= SEQ_MODULUS
        if stream.rx_high_index < 0:
            return base
        offset = stream.rx_high_index - base
        cycle = (offset + SEQ_HALF) // SEQ_MODULUS
        return base + cycle * SEQ_MODULUS

    @staticmethod
    def _new_key(stream_id: str, generation: int) -> KeyMaterial:
        nonce = secrets.token_hex(16)
        digest = hashlib.sha256(
            f"{stream_id}:{generation}:{nonce}".encode("utf-8")
        ).hexdigest()
        return KeyMaterial(stream_id=stream_id, key_id=generation, salt=digest)

    # ------------------------------------------------------------------
    # stream lifecycle and handshake

    @staticmethod
    def _validate_config(*, window: int, latency_ms: int,
                         initial_seq: int) -> None:
        if (not isinstance(window, int) or isinstance(window, bool)
                or window < 1):
            raise SrtError("SRT_INVALID_REQUEST", "invalid window")
        if (not isinstance(latency_ms, int) or isinstance(latency_ms, bool)
                or latency_ms < 0):
            raise SrtError("SRT_INVALID_REQUEST", "invalid latency")
        if (not isinstance(initial_seq, int) or isinstance(initial_seq, bool)
                or initial_seq < 0 or initial_seq >= SEQ_MODULUS):
            raise SrtError("SRT_INVALID_REQUEST", "invalid initial sequence")

    def open_listener(self, stream_id: str, *, passphrase: str | None = None,
                      latency_ms: int | None = None, window: int | None = None,
                      initial_seq: int = 0) -> Stream:
        with self._lock:
            stream_id = self._check_stream_id(stream_id)
            existing = self._streams.get(stream_id)
            if existing is not None and existing.state != "closed":
                raise SrtError("SRT_STREAM_EXISTS", stream_id)

            active = sum(
                1 for stream in self._streams.values()
                if stream.state != "closed"
            )
            if active >= self.max_streams:
                raise SrtError("SRT_CAPACITY_EXCEEDED", stream_id)

            selected_window = self.window if window is None else window
            selected_latency = self.latency_ms if latency_ms is None else latency_ms
            self._validate_config(
                window=selected_window,
                latency_ms=selected_latency,
                initial_seq=initial_seq,
            )

            stream = _Stream(
                stream_id=stream_id,
                role="listener",
                state="listening",
                passphrase=passphrase,
                initial_seq=initial_seq,
                next_seq=initial_seq,
                window=selected_window,
                latency_ms=selected_latency,
                last_ack_seq=(initial_seq - 1) % SEQ_MODULUS,
                rx_anchor_seq=initial_seq,
            )
            self._streams[stream_id] = stream
            return self._public(stream)

    def connect_caller(self, stream_id: str, *, passphrase: str | None = None,
                       now: int = 0) -> Stream:
        with self._lock:
            stream = self._get(stream_id)
            if stream.state == "closed":
                raise SrtError("SRT_STREAM_STATE", "closed")

            # Invalidate the old session before any authentication check.  A
            # reconnect attempt can therefore never keep encrypting with stale
            # key material, even when the new handshake fails.
            stream.key = None
            stream.state = "listening"
            stream.role = "listener"

            required = stream.passphrase
            if required is not None and passphrase != required:
                raise SrtError("SRT_HANDSHAKE_FAILED", "passphrase mismatch")

            stream.key_generation += 1
            stream.key = self._new_key(stream.stream_id, stream.key_generation)
            stream.state = "connected"
            stream.role = "caller"
            return self._public(stream, role="caller")

    def close_stream(self, stream_id: str) -> int:
        with self._lock:
            stream_id = self._check_stream_id(stream_id)
            stream = self._streams.get(stream_id)
            if stream is None or stream.state == "closed":
                return 0
            dropped = len(stream.sent) + len(stream.queue)
            stream.state = "closed"
            stream.role = "listener"
            stream.key = None
            stream.sent.clear()
            stream.queue.clear()
            stream.rx_buffer.clear()
            stream.rx_delivered.clear()
            stream.rx_seq_index.clear()
            return dropped

    # ------------------------------------------------------------------
    # sender side: sequence allocation and ARQ

    def submit_packet(self, stream_id: str, payload: object, *,
                      now: int = 0) -> Packet:
        with self._lock:
            stream = self._connected(stream_id)
            sequence = stream.next_seq
            index = stream.submitted_total
            packet = Packet(
                stream_id=stream.stream_id,
                sequence=sequence,
                payload=payload,
                submitted_at=now,
                retransmits=0,
                delivered=False,
            )

            stream.next_seq = (sequence + 1) % SEQ_MODULUS
            stream.submitted_total += 1
            stream.max_submitted_index = index
            if len(stream.sent) < stream.window:
                stream.sent[index] = packet
            else:
                stream.queue.append((index, packet))
                stream.queued_total += 1
                self._stats["queued"] += 1
            self._stats["submitted"] += 1
            return packet

    def handle_ack(self, stream_id: str, ack_seq: int) -> AckState:
        with self._lock:
            stream = self._connected(stream_id)
            ack_seq = self._check_seq(ack_seq, "SRT_ACK_INVALID")

            delta = (ack_seq - stream.last_ack_seq) % SEQ_MODULUS
            if delta == 0 or delta >= SEQ_HALF:
                return AckState(
                    stream_id=stream.stream_id,
                    ack_seq=ack_seq,
                    acked_packets=0,
                    pending=len(stream.sent) + len(stream.queue),
                )

            ack_index = stream.last_ack_index + delta
            if ack_index < 0 or ack_index > stream.max_submitted_index:
                raise SrtError("SRT_ACK_INVALID", ack_seq)

            removed = 0
            for index in list(stream.sent):
                if index <= ack_index:
                    del stream.sent[index]
                    removed += 1
            if stream.queue:
                remaining = []
                for index, packet in stream.queue:
                    if index <= ack_index:
                        removed += 1
                    else:
                        remaining.append((index, packet))
                stream.queue = remaining

            stream.last_ack_seq = ack_seq
            stream.last_ack_index = ack_index
            stream.acked_total += removed
            self._stats["acked"] += removed
            self._promote(stream)
            return AckState(
                stream_id=stream.stream_id,
                ack_seq=ack_seq,
                acked_packets=removed,
                pending=len(stream.sent) + len(stream.queue),
            )

    def handle_nak(self, stream_id: str, seq: int, *, now: int = 0):
        with self._lock:
            stream = self._connected(stream_id)
            seq = self._check_seq(seq)

            location = None
            packet = None
            for index, candidate in stream.sent.items():
                if candidate.sequence == seq:
                    location = ("sent", index)
                    packet = candidate
                    break
            if packet is None:
                for queue_index, (index, candidate) in enumerate(stream.queue):
                    if candidate.sequence == seq:
                        location = ("queue", queue_index)
                        packet = candidate
                        break
            if packet is None:
                return None

            kind, key = location
            if packet.retransmits >= self.max_retransmits:
                if kind == "sent":
                    del stream.sent[key]
                else:
                    stream.queue.pop(key)
                stream.too_late_total += 1
                self._stats["too_late"] += 1
                self._promote(stream)
                return None

            retransmitted = Packet(
                stream_id=packet.stream_id,
                sequence=packet.sequence,
                payload=packet.payload,
                submitted_at=packet.submitted_at,
                retransmits=packet.retransmits + 1,
                delivered=False,
            )
            if kind == "sent":
                stream.sent[key] = retransmitted
            else:
                index = stream.queue[key][0]
                stream.queue[key] = (index, retransmitted)
            stream.retransmit_total += 1
            self._stats["retransmitted"] += 1
            return retransmitted

    # ------------------------------------------------------------------
    # receiver side

    def receive_packet(self, stream_id: str, sequence: int, payload: object, *,
                       now: int = 0) -> bool:
        with self._lock:
            stream = self._connected(stream_id)
            sequence = self._check_seq(sequence)
            index = self._rx_index(stream, sequence)

            if index in stream.rx_buffer or index in stream.rx_delivered:
                return False

            old_index = stream.rx_seq_index.get(sequence)
            if (old_index is not None and old_index != index
                    and (stream.rx_high_index < 0
                         or stream.rx_high_index - old_index
                         < SEQ_MODULUS - stream.window)):
                # The same wire sequence already belonged to the current
                # sequence cycle.  Treat it as a late duplicate rather than a
                # packet from a new cycle.
                return False

            if stream.rx_high_index >= 0:
                low = stream.rx_high_index - stream.window
                high = stream.rx_high_index + stream.window
                if index < low or index > high:
                    return False
                if (index > stream.rx_high_index
                        and stream.rx_latest_time is not None
                        and now < stream.rx_latest_time):
                    # A number that looks like the future only by modulo
                    # arithmetic, but carries an older arrival timestamp, is a
                    # stale packet from before the wrap point.
                    return False

            stream.rx_buffer[index] = _RxRecord(
                index=index,
                sequence=sequence,
                payload=payload,
                arrival=now,
            )
            stream.rx_seq_index[sequence] = index
            if index > stream.rx_high_index:
                stream.rx_high_index = index
            if stream.rx_latest_time is None or now > stream.rx_latest_time:
                stream.rx_latest_time = now
            return True

    def deliver(self, stream_id: str, *, now: int = 0) -> tuple[Packet, ...]:
        with self._lock:
            stream = self._connected(stream_id)
            due = [
                record for record in stream.rx_buffer.values()
                if record.arrival + stream.latency_ms <= now
            ]
            due.sort(key=lambda record: record.index)
            delivered = []
            for record in due:
                del stream.rx_buffer[record.index]
                stream.rx_delivered[record.index] = record.arrival
                delivered.append(Packet(
                    stream_id=stream.stream_id,
                    sequence=record.sequence,
                    payload=record.payload,
                    submitted_at=record.arrival,
                    retransmits=0,
                    delivered=True,
                ))

            if stream.rx_high_index >= 0:
                floor = stream.rx_high_index - stream.window
                stream.rx_delivered = {
                    index: arrival
                    for index, arrival in stream.rx_delivered.items()
                    if index >= floor
                }
            return tuple(delivered)

    # ------------------------------------------------------------------
    # queries

    def pending_packets(self, stream_id: str) -> tuple[int, ...]:
        with self._lock:
            stream = self._get(stream_id)
            return tuple(packet.sequence for _, packet in self._pending(stream))

    def stream_state(self, stream_id: str) -> str:
        with self._lock:
            return self._get(stream_id).state

    def retransmit_count(self, stream_id: str) -> int:
        with self._lock:
            return self._get(stream_id).retransmit_total

    def too_late_count(self, stream_id: str) -> int:
        with self._lock:
            return self._get(stream_id).too_late_total

    def key_material(self, stream_id: str) -> KeyMaterial:
        with self._lock:
            stream = self._get(stream_id)
            if stream.state != "connected" or stream.key is None:
                raise SrtError("SRT_STREAM_STATE", "no active handshake")
            return stream.key

    # ------------------------------------------------------------------
    # snapshot / restore

    @staticmethod
    def _snap_int(value: object, *, minimum: int | None = None) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("expected integer")
        if minimum is not None and value < minimum:
            raise ValueError("integer below minimum")
        return value

    @staticmethod
    def _packet_state(packet: Packet) -> dict:
        return {
            "stream_id": packet.stream_id,
            "sequence": packet.sequence,
            "payload": packet.payload,
            "submitted_at": packet.submitted_at,
            "retransmits": packet.retransmits,
            "delivered": packet.delivered,
        }

    def _stream_state(self, stream: _Stream) -> dict:
        return {
            "stream_id": stream.stream_id,
            "role": stream.role,
            "state": stream.state,
            "passphrase": stream.passphrase,
            "initial_seq": stream.initial_seq,
            "next_seq": stream.next_seq,
            "window": stream.window,
            "latency_ms": stream.latency_ms,
            "key": (None if stream.key is None else {
                "key_id": stream.key.key_id,
                "salt": stream.key.salt,
            }),
            "key_generation": stream.key_generation,
            "send": {
                "submitted_total": stream.submitted_total,
                "queued_total": stream.queued_total,
                "acked_total": stream.acked_total,
                "retransmit_total": stream.retransmit_total,
                "too_late_total": stream.too_late_total,
                "last_ack_seq": stream.last_ack_seq,
                "last_ack_index": stream.last_ack_index,
                "max_submitted_index": stream.max_submitted_index,
                "sent": [
                    [index, self._packet_state(packet)]
                    for index, packet in sorted(stream.sent.items())
                ],
                "queue": [
                    [index, self._packet_state(packet)]
                    for index, packet in stream.queue
                ],
            },
            "recv": {
                "anchor_seq": stream.rx_anchor_seq,
                "high_index": stream.rx_high_index,
                "latest_time": stream.rx_latest_time,
                "buffer": [
                    [index, self._packet_state(Packet(
                        stream_id=stream.stream_id,
                        sequence=record.sequence,
                        payload=record.payload,
                        submitted_at=record.arrival,
                        retransmits=0,
                        delivered=False,
                    )), record.arrival]
                    for index, record in sorted(stream.rx_buffer.items())
                ],
                "delivered": [
                    [index, arrival]
                    for index, arrival in sorted(stream.rx_delivered.items())
                ],
                "seq_index": [
                    [sequence, index]
                    for sequence, index in sorted(stream.rx_seq_index.items())
                ],
            },
        }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "max_streams": self.max_streams,
                    "window": self.window,
                    "max_retransmits": self.max_retransmits,
                    "latency_ms": self.latency_ms,
                },
                "stats": dict(self._stats),
                "streams": [
                    self._stream_state(stream)
                    for stream in self._streams.values()
                ],
            }
            return copy.deepcopy(state)

    def _decode_packet(self, data: object, stream_id: str) -> Packet:
        if not isinstance(data, dict):
            raise ValueError("packet must be a mapping")
        if data.get("stream_id") != stream_id:
            raise ValueError("packet stream mismatch")
        sequence = self._snap_int(data.get("sequence"))
        if sequence >= SEQ_MODULUS:
            raise ValueError("packet sequence out of range")
        submitted_at = self._snap_int(data.get("submitted_at"))
        retransmits = self._snap_int(data.get("retransmits"), minimum=0)
        delivered = data.get("delivered")
        if not isinstance(delivered, bool):
            raise ValueError("invalid delivered flag")
        if "payload" not in data:
            raise ValueError("missing payload")
        return Packet(
            stream_id=stream_id,
            sequence=sequence,
            payload=data["payload"],
            submitted_at=submitted_at,
            retransmits=retransmits,
            delivered=delivered,
        )

    def _decode_stream(self, data: object) -> _Stream:
        if not isinstance(data, dict):
            raise ValueError("stream must be a mapping")
        stream_id = self._check_stream_id(data.get("stream_id"))
        role = data.get("role")
        if not isinstance(role, str):
            raise ValueError("invalid role")
        state = data.get("state")
        if state not in STREAM_STATES:
            raise ValueError("invalid stream state")
        passphrase = data.get("passphrase")
        if passphrase is not None and not isinstance(passphrase, str):
            raise ValueError("invalid passphrase")

        initial_seq = self._snap_int(data.get("initial_seq"))
        next_seq = self._snap_int(data.get("next_seq"))
        if initial_seq >= SEQ_MODULUS or next_seq >= SEQ_MODULUS:
            raise ValueError("sequence out of range")
        window = self._snap_int(data.get("window"), minimum=1)
        latency_ms = self._snap_int(data.get("latency_ms"), minimum=0)
        key_generation = self._snap_int(
            data.get("key_generation", 0), minimum=0
        )

        key_data = data.get("key")
        key = None
        if key_data is not None:
            if not isinstance(key_data, dict):
                raise ValueError("invalid key")
            key_id = self._snap_int(key_data.get("key_id"), minimum=1)
            salt = key_data.get("salt")
            if not isinstance(salt, str) or not salt:
                raise ValueError("invalid key salt")
            key = KeyMaterial(stream_id=stream_id, key_id=key_id, salt=salt)
        if state == "connected" and key is None:
            raise ValueError("connected stream has no key")
        if state != "connected" and key is not None:
            raise ValueError("inactive stream has key material")

        send = data.get("send")
        if not isinstance(send, dict):
            raise ValueError("missing send state")
        submitted_total = self._snap_int(
            send.get("submitted_total"), minimum=0
        )
        queued_total = self._snap_int(send.get("queued_total"), minimum=0)
        acked_total = self._snap_int(send.get("acked_total"), minimum=0)
        retransmit_total = self._snap_int(
            send.get("retransmit_total"), minimum=0
        )
        too_late_total = self._snap_int(
            send.get("too_late_total"), minimum=0
        )
        last_ack_seq = self._snap_int(send.get("last_ack_seq"))
        last_ack_index = self._snap_int(send.get("last_ack_index"), minimum=-1)
        max_submitted_index = self._snap_int(
            send.get("max_submitted_index"), minimum=-1
        )
        if last_ack_seq >= SEQ_MODULUS:
            raise ValueError("ack sequence out of range")
        if submitted_total > SEQ_MODULUS:
            raise ValueError("sequence space exhausted")
        if next_seq != (initial_seq + submitted_total) % SEQ_MODULUS:
            raise ValueError("next sequence does not match allocation")
        if max_submitted_index != submitted_total - 1:
            raise ValueError("invalid max submitted index")
        if queued_total > submitted_total:
            raise ValueError("invalid queued count")
        if acked_total > submitted_total or too_late_total > submitted_total:
            raise ValueError("invalid cumulative count")
        if last_ack_index > max_submitted_index:
            raise ValueError("ack index out of range")
        if last_ack_seq != (initial_seq + last_ack_index) % SEQ_MODULUS:
            raise ValueError("ack sequence does not match index")

        sent_data = send.get("sent")
        queue_data = send.get("queue")
        if not isinstance(sent_data, list) or not isinstance(queue_data, list):
            raise ValueError("invalid pending packet lists")

        sent: dict[int, Packet] = {}
        queue: list[tuple[int, Packet]] = []
        seen_indexes: set[int] = set()

        def decode_entry(entry: object) -> tuple[int, Packet]:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ValueError("invalid pending packet entry")
            index = self._snap_int(entry[0], minimum=0)
            if index >= submitted_total or index in seen_indexes:
                raise ValueError("invalid pending packet index")
            packet = self._decode_packet(entry[1], stream_id)
            expected = (initial_seq + index) % SEQ_MODULUS
            if packet.sequence != expected or packet.delivered:
                raise ValueError("pending packet mismatch")
            seen_indexes.add(index)
            return index, packet

        for entry in sent_data:
            index, packet = decode_entry(entry)
            sent[index] = packet
        for entry in queue_data:
            queue.append(decode_entry(entry))
        if len(sent) > window:
            raise ValueError("send window overflow")

        recv = data.get("recv")
        if not isinstance(recv, dict):
            raise ValueError("missing receive state")
        anchor_seq = self._snap_int(recv.get("anchor_seq"))
        if anchor_seq >= SEQ_MODULUS:
            raise ValueError("receive anchor out of range")
        high_index = self._snap_int(recv.get("high_index"), minimum=-1)
        latest_time = recv.get("latest_time")
        if latest_time is not None:
            latest_time = self._snap_int(latest_time)
        buffer_data = recv.get("buffer")
        delivered_data = recv.get("delivered")
        seq_index_data = recv.get("seq_index")
        if (not isinstance(buffer_data, list)
                or not isinstance(delivered_data, list)
                or not isinstance(seq_index_data, list)):
            raise ValueError("invalid receive buffers")

        rx_buffer: dict[int, _RxRecord] = {}
        rx_delivered: dict[int, int] = {}
        rx_seq_index: dict[int, int] = {}
        buffered_sequences: set[int] = set()

        for entry in buffer_data:
            if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                raise ValueError("invalid receive buffer entry")
            index = self._snap_int(entry[0])
            packet = self._decode_packet(entry[1], stream_id)
            arrival = self._snap_int(entry[2])
            if index in rx_buffer or index in rx_delivered:
                raise ValueError("duplicate receive index")
            if index > high_index:
                raise ValueError("receive index beyond high water mark")
            if packet.sequence != (anchor_seq + index) % SEQ_MODULUS:
                raise ValueError("receive sequence mismatch")
            if packet.delivered or packet.submitted_at != arrival:
                raise ValueError("invalid receive packet")
            rx_buffer[index] = _RxRecord(
                index=index,
                sequence=packet.sequence,
                payload=packet.payload,
                arrival=arrival,
            )
            buffered_sequences.add(packet.sequence)

        for entry in delivered_data:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ValueError("invalid delivered entry")
            index = self._snap_int(entry[0])
            arrival = self._snap_int(entry[1])
            if index in rx_delivered or index in rx_buffer:
                raise ValueError("duplicate delivered index")
            if index > high_index:
                raise ValueError("delivered index beyond high water mark")
            rx_delivered[index] = arrival

        for entry in seq_index_data:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ValueError("invalid sequence history entry")
            sequence = self._snap_int(entry[0])
            index = self._snap_int(entry[1])
            if sequence >= SEQ_MODULUS:
                raise ValueError("history sequence out of range")
            if sequence in rx_seq_index:
                raise ValueError("duplicate sequence history")
            rx_seq_index[sequence] = index
        if not buffered_sequences.issubset(rx_seq_index):
            raise ValueError("receive sequence history is incomplete")

        stream = _Stream(
            stream_id=stream_id,
            role=role,
            state=state,
            passphrase=passphrase,
            initial_seq=initial_seq,
            next_seq=next_seq,
            window=window,
            latency_ms=latency_ms,
            key=key,
            key_generation=key_generation,
            submitted_total=submitted_total,
            queued_total=queued_total,
            acked_total=acked_total,
            retransmit_total=retransmit_total,
            too_late_total=too_late_total,
            last_ack_seq=last_ack_seq,
            last_ack_index=last_ack_index,
            max_submitted_index=max_submitted_index,
            sent=sent,
            queue=queue,
            rx_anchor_seq=anchor_seq,
            rx_high_index=high_index,
            rx_latest_time=latest_time,
            rx_buffer=rx_buffer,
            rx_delivered=rx_delivered,
            rx_seq_index=rx_seq_index,
        )
        return stream

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                data = copy.deepcopy(state)
                if not isinstance(data, dict):
                    raise ValueError("snapshot must be a mapping")
                if data.get("version") != SNAPSHOT_VERSION:
                    raise ValueError("unsupported snapshot version")

                config = data.get("config")
                if not isinstance(config, dict):
                    raise ValueError("missing config")
                max_streams = self._snap_int(
                    config.get("max_streams"), minimum=1
                )
                window = self._snap_int(config.get("window"), minimum=1)
                max_retransmits = self._snap_int(
                    config.get("max_retransmits"), minimum=0
                )
                latency_ms = self._snap_int(
                    config.get("latency_ms"), minimum=0
                )

                stats_data = data.get("stats")
                if not isinstance(stats_data, dict):
                    raise ValueError("missing stats")
                stats = {}
                for key in (
                    "submitted", "queued", "acked",
                    "retransmitted", "too_late",
                ):
                    stats[key] = self._snap_int(
                        stats_data.get(key), minimum=0
                    )

                streams_data = data.get("streams")
                if not isinstance(streams_data, list):
                    raise ValueError("missing streams")
                streams: dict[str, _Stream] = {}
                for stream_data in streams_data:
                    stream = self._decode_stream(stream_data)
                    if stream.stream_id in streams:
                        raise ValueError("duplicate stream id")
                    streams[stream.stream_id] = stream
                active = sum(
                    1 for stream in streams.values()
                    if stream.state != "closed"
                )
                if active > max_streams:
                    raise ValueError("stream capacity exceeded")
            except Exception as exc:
                if isinstance(exc, SrtError):
                    detail = str(exc)
                else:
                    detail = str(exc) or "invalid snapshot"
                raise SrtError("SRT_SNAPSHOT_INVALID", detail) from None

            # Commit only after every part of the snapshot has validated.
            self.max_streams = max_streams
            self.window = window
            self.max_retransmits = max_retransmits
            self.latency_ms = latency_ms
            self._stats = stats
            self._streams = streams

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
