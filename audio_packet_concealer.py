"""Audio packet concealment: gap detection, pitch wrap fill and silence fallback."""

from __future__ import annotations

import bisect
import math
import threading
from dataclasses import dataclass, field


SNAPSHOT_VERSION = 1
DEFAULT_SAMPLE_RATE = 8000

_COUNTER_KEYS = ("injected", "concealed", "silenced", "replaced", "duplicates")
_SLOT_KINDS = ("real", "conceal", "silence")


class AudioConcealError(ValueError):
    """Raised when a concealment request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PacketSlot:
    """One slot of the reconstructed output timeline."""

    seq: int
    kind: str
    samples: tuple


@dataclass
class _StreamState:
    base: int
    highest: int
    sample_rate: int
    max_conceal: int
    slots: list = field(default_factory=list)
    history: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    seq_index: dict = field(default_factory=dict)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _empty_counters() -> dict:
    return {key: 0 for key in _COUNTER_KEYS}


class AudioPacketConcealer:
    """Detect sequence gaps per stream and fill them from a bounded history."""

    def __init__(self, *, frame_samples: int = 160, history_frames: int = 8,
                 max_conceal: int = 3, reorder_window: int = 8) -> None:
        if not _is_int(frame_samples) or frame_samples <= 0:
            raise AudioConcealError("AUDIO_BAD_FRAME", "frame_samples")
        if not _is_int(history_frames) or history_frames < 0:
            raise AudioConcealError("AUDIO_INVALID_LIMIT", "history_frames")
        if not _is_int(max_conceal) or max_conceal < 0:
            raise AudioConcealError("AUDIO_INVALID_LIMIT", "max_conceal")
        if not _is_int(reorder_window) or reorder_window < 0:
            raise AudioConcealError("AUDIO_INVALID_LIMIT", "reorder_window")
        self.frame_samples = frame_samples
        self.history_frames = history_frames
        self.max_conceal = max_conceal
        self.reorder_window = reorder_window
        self._lock = threading.RLock()
        self._streams: dict = {}

    def _check_stream(self, stream: object) -> None:
        if not isinstance(stream, str) or not stream:
            raise AudioConcealError("AUDIO_INVALID_STREAM", stream)

    def _check_seq(self, seq: object) -> None:
        if not _is_int(seq) or seq < 0:
            raise AudioConcealError("AUDIO_INVALID_SEQ", seq)

    def _check_limit(self, frames: object) -> None:
        if not _is_int(frames) or frames < 0:
            raise AudioConcealError("AUDIO_INVALID_LIMIT", frames)

    def _packet(self, samples: object) -> tuple:
        if isinstance(samples, (str, bytes, bytearray)):
            raise AudioConcealError("AUDIO_BAD_FRAME", "samples")
        try:
            values = tuple(samples)
        except TypeError as exc:
            raise AudioConcealError("AUDIO_BAD_FRAME", "samples") from exc
        if len(values) != self.frame_samples:
            raise AudioConcealError("AUDIO_BAD_FRAME", "length")
        for value in values:
            if not _is_int(value) or not -32768 <= value <= 32767:
                raise AudioConcealError("AUDIO_BAD_FRAME", value)
        return values

    def _new_state(self) -> _StreamState:
        return _StreamState(
            base=0,
            highest=-1,
            sample_rate=DEFAULT_SAMPLE_RATE,
            max_conceal=self.max_conceal,
            counters=_empty_counters(),
        )

    def _get_state(self, stream: str, create: bool = False):
        state = self._streams.get(stream)
        if state is None and create:
            state = self._new_state()
            self._streams[stream] = state
        return state

    def _add_history(self, state: _StreamState, seq: int, samples: tuple) -> None:
        limit = self.history_frames
        if limit <= 0:
            state.history = []
            return
        for index, (old_seq, _) in enumerate(state.history):
            if old_seq == seq:
                state.history[index] = (seq, samples)
                return
        position = bisect.bisect_left(
            [old_seq for old_seq, _ in state.history], seq)
        state.history.insert(position, (seq, samples))
        if len(state.history) > limit:
            del state.history[0]

    def _pitch_samples(self, source: tuple) -> tuple:
        count = self.frame_samples
        if not source:
            return (0,) * count

        low = max(1, count // 8)
        high = max(low, count // 2)
        best_lag = low
        best_score = float("-inf")
        for lag in range(low, high + 1):
            numerator = 0
            left_energy = 0
            right_energy = 0
            for index in range(lag, count):
                current = source[index]
                previous = source[index - lag]
                numerator += current * previous
                left_energy += current * current
                right_energy += previous * previous
            denominator = math.sqrt(left_energy * right_energy)
            score = numerator / denominator if denominator else 0.0
            if score > best_score and not math.isclose(
                    score, best_score, rel_tol=1e-12, abs_tol=1e-12):
                best_score = score
                best_lag = lag

        start = (count - best_lag) % count
        return tuple(source[(start + index) % count] for index in range(count))

    def push(self, stream: str, seq: int, samples) -> int:
        with self._lock:
            self._check_stream(stream)
            self._check_seq(seq)
            packet = self._packet(samples)
            state = self._get_state(stream, create=True)

            if state.highest >= 0 and seq < state.highest - self.reorder_window:
                raise AudioConcealError("AUDIO_SEQ_REGRESSION", seq)

            index = state.seq_index.get(seq)
            if index is not None and state.slots[index].kind == "real":
                state.counters["duplicates"] += 1
                return index

            if state.highest < 0:
                state.base = seq
                state.highest = seq
            else:
                state.base = min(state.base, seq)
                state.highest = max(state.highest, seq)

            slot = PacketSlot(seq, "real", packet)
            if index is not None:
                state.slots[index] = slot
                state.counters["replaced"] += 1
                position = index
            else:
                if not state.slots or seq > state.slots[-1].seq:
                    position = len(state.slots)
                    state.slots.append(slot)
                    state.seq_index[seq] = position
                else:
                    position = bisect.bisect_left(
                        [current.seq for current in state.slots], seq)
                    state.slots.insert(position, slot)
                    for offset in range(position, len(state.slots)):
                        state.seq_index[state.slots[offset].seq] = offset

            state.counters["injected"] += 1
            self._add_history(state, seq, packet)
            return position

    def gap_ranges(self, stream: str) -> tuple:
        with self._lock:
            self._check_stream(stream)
            state = self._get_state(stream)
            if state is None or state.highest < state.base:
                return ()

            present = (
                slot.seq for slot in state.slots
                if state.base <= slot.seq <= state.highest)
            ranges = []
            cursor = state.base
            for seq in present:
                if seq > cursor:
                    ranges.append((cursor, seq - 1))
                cursor = max(cursor, seq + 1)
            if cursor <= state.highest:
                ranges.append((cursor, state.highest))
            return tuple(ranges)

    def conceal(self, stream: str) -> int:
        with self._lock:
            self._check_stream(stream)
            state = self._get_state(stream)
            if state is None or state.highest < state.base:
                return 0

            missing = (state.highest - state.base + 1) - len(state.slots)
            if missing <= 0:
                return 0

            source = state.history[-1][1] if state.history else ()
            fake = self._pitch_samples(source)
            silence = (0,) * self.frame_samples

            existing = {slot.seq: slot for slot in state.slots}
            new_slots = []
            concealed = 0
            silenced = 0
            run = 0
            for seq in range(state.base, state.highest + 1):
                slot = existing.get(seq)
                if slot is not None:
                    new_slots.append(slot)
                    run = 0 if slot.kind == "real" else run + 1
                    continue
                if run < state.max_conceal:
                    new_slots.append(PacketSlot(seq, "conceal", fake))
                    concealed += 1
                else:
                    new_slots.append(PacketSlot(seq, "silence", silence))
                    silenced += 1
                run += 1

            state.slots = new_slots
            state.seq_index = {
                slot.seq: index for index, slot in enumerate(new_slots)}
            state.counters["concealed"] += concealed
            state.counters["silenced"] += silenced
            return concealed + silenced

    def set_max_conceal(self, stream: str, frames: int) -> int:
        with self._lock:
            self._check_stream(stream)
            self._check_limit(frames)
            state = self._get_state(stream, create=True)
            state.max_conceal = frames
            return frames

    def set_sample_rate(self, stream: str, rate: int) -> int:
        with self._lock:
            self._check_stream(stream)
            if not _is_int(rate) or rate <= 0:
                raise AudioConcealError("AUDIO_INVALID_RATE", rate)
            state = self._get_state(stream, create=True)
            if rate != state.sample_rate:
                state.sample_rate = rate
                state.history = []
                state.counters = _empty_counters()
            return rate

    def history(self, stream: str) -> tuple:
        with self._lock:
            self._check_stream(stream)
            state = self._get_state(stream)
            if state is None:
                return ()
            return tuple(state.history)

    def timeline(self, stream: str) -> tuple:
        with self._lock:
            self._check_stream(stream)
            state = self._get_state(stream)
            if state is None:
                return ()
            return tuple(state.slots)

    def stats(self) -> dict:
        with self._lock:
            totals = {key: 0 for key in _COUNTER_KEYS}
            for state in self._streams.values():
                for key in _COUNTER_KEYS:
                    totals[key] += state.counters[key]
            return {
                "streams": len(self._streams),
                "injected": totals["injected"],
                "concealed": totals["concealed"],
                "silenced": totals["silenced"],
                "replaced": totals["replaced"],
                "duplicates": totals["duplicates"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            streams = {}
            for name, state in self._streams.items():
                streams[name] = {
                    "base": state.base,
                    "highest": state.highest,
                    "sample_rate": state.sample_rate,
                    "max_conceal": state.max_conceal,
                    "slots": [
                        [slot.seq, slot.kind, list(slot.samples)]
                        for slot in state.slots
                    ],
                    "history": [
                        [seq, list(samples)]
                        for seq, samples in state.history
                    ],
                    "counters": dict(state.counters),
                }
            return {
                "version": SNAPSHOT_VERSION,
                "frame_samples": self.frame_samples,
                "history_frames": self.history_frames,
                "max_conceal": self.max_conceal,
                "reorder_window": self.reorder_window,
                "streams": streams,
            }

    def _invalid_snapshot(self, detail: object = None) -> AudioConcealError:
        return AudioConcealError("AUDIO_SNAPSHOT_INVALID", detail)

    def _snapshot_samples(self, raw: object, frame_samples: int) -> tuple:
        if isinstance(raw, (str, bytes, bytearray)):
            raise self._invalid_snapshot("samples")
        try:
            values = tuple(raw)
        except TypeError as exc:
            raise self._invalid_snapshot("samples") from exc
        if len(values) != frame_samples:
            raise self._invalid_snapshot("samples")
        for value in values:
            if not _is_int(value) or not -32768 <= value <= 32767:
                raise self._invalid_snapshot("samples")
        return values

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise self._invalid_snapshot("state")
        version = state.get("version")
        if not _is_int(version) or version != SNAPSHOT_VERSION:
            raise self._invalid_snapshot("version")

        frame_samples = state.get("frame_samples")
        history_frames = state.get("history_frames")
        max_conceal = state.get("max_conceal")
        reorder_window = state.get("reorder_window")
        if not _is_int(frame_samples) or frame_samples <= 0:
            raise self._invalid_snapshot("frame_samples")
        if not _is_int(history_frames) or history_frames < 0:
            raise self._invalid_snapshot("history_frames")
        if not _is_int(max_conceal) or max_conceal < 0:
            raise self._invalid_snapshot("max_conceal")
        if not _is_int(reorder_window) or reorder_window < 0:
            raise self._invalid_snapshot("reorder_window")

        raw_streams = state.get("streams")
        if not isinstance(raw_streams, dict):
            raise self._invalid_snapshot("streams")

        parsed = {}
        for name, raw_stream in raw_streams.items():
            if not isinstance(name, str) or not name:
                raise self._invalid_snapshot("stream")
            if not isinstance(raw_stream, dict):
                raise self._invalid_snapshot("stream")

            base = raw_stream.get("base")
            highest = raw_stream.get("highest")
            sample_rate = raw_stream.get("sample_rate")
            stream_limit = raw_stream.get("max_conceal")
            if not _is_int(base) or base < 0:
                raise self._invalid_snapshot("base")
            if not _is_int(highest) or highest < -1:
                raise self._invalid_snapshot("highest")
            if highest >= 0 and base > highest:
                raise self._invalid_snapshot("base")
            if not _is_int(sample_rate) or sample_rate <= 0:
                raise self._invalid_snapshot("sample_rate")
            if not _is_int(stream_limit) or stream_limit < 0:
                raise self._invalid_snapshot("max_conceal")

            raw_slots = raw_stream.get("slots")
            if not isinstance(raw_slots, (list, tuple)):
                raise self._invalid_snapshot("slots")
            slots = []
            previous = -1
            for raw_slot in raw_slots:
                if not isinstance(raw_slot, (list, tuple)) or len(raw_slot) != 3:
                    raise self._invalid_snapshot("slot")
                seq, kind, raw_samples = raw_slot
                if not _is_int(seq) or seq < 0 or seq <= previous:
                    raise self._invalid_snapshot("slot")
                if not isinstance(kind, str) or kind not in _SLOT_KINDS:
                    raise self._invalid_snapshot("slot")
                if seq < base or seq > highest:
                    raise self._invalid_snapshot("slot")
                samples = self._snapshot_samples(raw_samples, frame_samples)
                slots.append(PacketSlot(seq, kind, samples))
                previous = seq

            raw_history = raw_stream.get("history")
            if not isinstance(raw_history, (list, tuple)):
                raise self._invalid_snapshot("history")
            if len(raw_history) > history_frames:
                raise self._invalid_snapshot("history")
            history = []
            for raw_entry in raw_history:
                if not isinstance(raw_entry, (list, tuple)) or len(raw_entry) != 2:
                    raise self._invalid_snapshot("history")
                seq, raw_samples = raw_entry
                if not _is_int(seq) or seq < 0:
                    raise self._invalid_snapshot("history")
                if highest < 0 or not base <= seq <= highest:
                    raise self._invalid_snapshot("history")
                samples = self._snapshot_samples(raw_samples, frame_samples)
                history.append((seq, samples))
            history.sort(key=lambda entry: entry[0])

            raw_counters = raw_stream.get("counters")
            if not isinstance(raw_counters, dict):
                raise self._invalid_snapshot("counters")
            counters = {}
            for key in _COUNTER_KEYS:
                value = raw_counters.get(key)
                if not _is_int(value) or value < 0:
                    raise self._invalid_snapshot("counters")
                counters[key] = value

            seq_index = {
                slot.seq: index for index, slot in enumerate(slots)}
            parsed[name] = _StreamState(
                base=base,
                highest=highest,
                sample_rate=sample_rate,
                max_conceal=stream_limit,
                slots=slots,
                history=history,
                counters=counters,
                seq_index=seq_index,
            )

        return (frame_samples, history_frames, max_conceal,
                reorder_window, parsed)

    def restore(self, state: dict) -> None:
        with self._lock:
            parsed = self._parse_snapshot(state)
            frame_samples, history_frames, max_conceal, reorder_window, streams = (
                parsed)
            self.frame_samples = frame_samples
            self.history_frames = history_frames
            self.max_conceal = max_conceal
            self.reorder_window = reorder_window
            self._streams = streams

    def reset(self, stream=None) -> None:
        with self._lock:
            if stream is None:
                self._streams.clear()
                return
            self._check_stream(stream)
            self._streams.pop(stream, None)
