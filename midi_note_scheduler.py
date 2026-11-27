"""MIDI note scheduling: per-pitch pairing, sustain pedal and stuck note cleanup."""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class MidiError(ValueError):
    """Raised when a MIDI scheduling operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NoteRef:
    """One note event tracked by the scheduler."""

    note_id: int
    channel: int
    pitch: int
    velocity: int
    at_ms: int
    device: str
    state: str


class MidiNoteScheduler:
    """Track pressed notes, pedal state and pending releases per channel."""

    def __init__(self, *, max_stack: int = 4, stuck_timeout_ms: int = 5000,
                 max_pending: int = 64) -> None:
        if not self._is_int(max_stack) or max_stack < 1:
            raise MidiError("MIDI_INVALID", "max_stack")
        if not self._is_int(stuck_timeout_ms) or stuck_timeout_ms < 0:
            raise MidiError("MIDI_INVALID", "stuck_timeout_ms")
        if not self._is_int(max_pending) or max_pending < 0:
            raise MidiError("MIDI_INVALID", "max_pending")

        self.max_stack = max_stack
        self.stuck_timeout_ms = stuck_timeout_ms
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._notes: dict[int, NoteRef] = {}
        self._pedals: dict[int, bool] = {}
        self._next_id = 1
        self._serial = 0
        self._counters = {
            "note_on": 0,
            "note_off": 0,
            "sustained": 0,
            "pedal_down": 0,
            "pedal_up": 0,
            "stuck_cleaned": 0,
            "disconnect_released": 0,
            "scheduled": 0,
            "last_reason": None,
        }

    @staticmethod
    def _is_int(value: Any) -> bool:
        return type(value) is int

    @classmethod
    def _require_int(cls, value: Any, name: str, minimum: int,
                     maximum: int | None = None) -> int:
        if not cls._is_int(value):
            raise MidiError("MIDI_INVALID", name)
        if value < minimum or (maximum is not None and value > maximum):
            raise MidiError("MIDI_INVALID", name)
        return value

    @classmethod
    def _require_channel(cls, channel: Any) -> int:
        return cls._require_int(channel, "channel", 0, 15)

    @classmethod
    def _require_pitch(cls, pitch: Any) -> int:
        return cls._require_int(pitch, "pitch", 0, 127)

    @classmethod
    def _require_velocity(cls, velocity: Any) -> int:
        return cls._require_int(velocity, "velocity", 1, 127)

    @classmethod
    def _require_at_ms(cls, at_ms: Any) -> int:
        return cls._require_int(at_ms, "at_ms", 0)

    @classmethod
    def _require_device(cls, device: Any) -> str:
        if not isinstance(device, str):
            raise MidiError("MIDI_INVALID", "device")
        normalized = device.strip()
        if not normalized:
            raise MidiError("MIDI_INVALID", "device")
        return normalized

    @staticmethod
    def _snapshot_error(detail: object = None) -> MidiError:
        return MidiError("MIDI_SNAPSHOT_INVALID", detail)

    def note_on(self, *, channel: int, pitch: int, velocity: int,
                at_ms: int, device: str) -> NoteRef:
        channel = self._require_channel(channel)
        pitch = self._require_pitch(pitch)
        velocity = self._require_velocity(velocity)
        at_ms = self._require_at_ms(at_ms)
        device = self._require_device(device)

        with self._lock:
            same_pitch = sum(
                1 for note in self._notes.values()
                if note.channel == channel and note.pitch == pitch
            )
            if same_pitch >= self.max_stack:
                raise MidiError("MIDI_STACK_LIMIT", {
                    "channel": channel, "pitch": pitch,
                })
            if len(self._notes) >= self.max_pending:
                raise MidiError("MIDI_CAPACITY", len(self._notes))

            note = NoteRef(
                note_id=self._next_id,
                channel=channel,
                pitch=pitch,
                velocity=velocity,
                at_ms=at_ms,
                device=device,
                state="down",
            )
            self._notes[note.note_id] = note
            self._next_id += 1
            self._counters["note_on"] += 1
            return note

    def note_off(self, *, channel: int, pitch: int, at_ms: int,
                 device: str) -> NoteRef:
        channel = self._require_channel(channel)
        pitch = self._require_pitch(pitch)
        self._require_at_ms(at_ms)
        device = self._require_device(device)

        with self._lock:
            matches = (
                note for note in self._notes.values()
                if note.channel == channel
                and note.pitch == pitch
                and note.device == device
                and note.state == "down"
            )
            target = max(matches, key=lambda note: note.note_id, default=None)
            if target is None:
                raise MidiError("MIDI_NOT_ACTIVE", {
                    "channel": channel, "pitch": pitch, "device": device,
                })

            if self._pedals.get(channel, False):
                target = NoteRef(
                    note_id=target.note_id,
                    channel=target.channel,
                    pitch=target.pitch,
                    velocity=target.velocity,
                    at_ms=target.at_ms,
                    device=target.device,
                    state="sustained",
                )
                self._notes[target.note_id] = target
                self._counters["sustained"] += 1
            else:
                del self._notes[target.note_id]
                target = NoteRef(
                    note_id=target.note_id,
                    channel=target.channel,
                    pitch=target.pitch,
                    velocity=target.velocity,
                    at_ms=target.at_ms,
                    device=target.device,
                    state="released",
                )

            self._counters["note_off"] += 1
            return target

    def pedal(self, *, channel: int, down: bool, at_ms: int) -> bool:
        channel = self._require_channel(channel)
        if type(down) is not bool:
            raise MidiError("MIDI_INVALID", "down")
        self._require_at_ms(at_ms)

        with self._lock:
            current = self._pedals.get(channel, False)
            if current == down:
                raise MidiError("MIDI_PEDAL_STATE", {
                    "channel": channel, "down": down,
                })

            self._pedals[channel] = down
            if down:
                self._counters["pedal_down"] += 1
            else:
                for note_id, note in tuple(self._notes.items()):
                    if note.channel == channel and note.state == "sustained":
                        del self._notes[note_id]
                self._counters["pedal_up"] += 1
            return True

    def all_notes_off(self, *, at_ms: int, channel: int | None = None,
                      reason: str = "all_notes_off") -> int:
        self._require_at_ms(at_ms)
        if channel is not None:
            channel = self._require_channel(channel)
        if not isinstance(reason, str):
            raise MidiError("MIDI_INVALID", "reason")

        with self._lock:
            if channel is None:
                released = len(self._notes)
                self._notes.clear()
            else:
                released = 0
                for note_id, note in tuple(self._notes.items()):
                    if note.channel == channel:
                        del self._notes[note_id]
                        released += 1
            self._counters["last_reason"] = reason
            return released

    def tick(self, *, now_ms: int) -> tuple:
        now_ms = self._require_at_ms(now_ms)

        with self._lock:
            released = []
            for note_id in sorted(self._notes):
                note = self._notes[note_id]
                if note.at_ms + self.stuck_timeout_ms <= now_ms:
                    del self._notes[note_id]
                    released.append(NoteRef(
                        note_id=note.note_id,
                        channel=note.channel,
                        pitch=note.pitch,
                        velocity=note.velocity,
                        at_ms=note.at_ms,
                        device=note.device,
                        state="stuck",
                    ))
            self._counters["stuck_cleaned"] += len(released)
            return tuple(released)

    def device_disconnect(self, *, device: str, at_ms: int) -> int:
        device = self._require_device(device)
        self._require_at_ms(at_ms)

        with self._lock:
            released = 0
            for note_id, note in tuple(self._notes.items()):
                if note.device == device:
                    del self._notes[note_id]
                    released += 1
            self._counters["disconnect_released"] += released
            return released

    def schedule(self, *, events) -> tuple:
        if isinstance(events, (str, bytes, bytearray)):
            raise MidiError("MIDI_INVALID", "events")
        try:
            raw_events = tuple(events)
        except (TypeError, ValueError) as exc:
            raise MidiError("MIDI_INVALID", "events") from exc
        if not raw_events:
            raise MidiError("MIDI_INVALID", "events")

        validated = []
        for index, event in enumerate(raw_events):
            if not isinstance(event, Mapping) or "at_ms" not in event:
                raise MidiError("MIDI_INVALID", {"index": index})
            at_ms = event["at_ms"]
            if not self._is_int(at_ms) or at_ms < 0:
                raise MidiError("MIDI_INVALID", {
                    "index": index, "field": "at_ms",
                })
            validated.append((index, at_ms))

        with self._lock:
            first_serial = self._serial
            rows = [
                {"index": index, "at_ms": at_ms,
                 "serial": first_serial + index}
                for index, at_ms in validated
            ]
            rows.sort(key=lambda row: (row["at_ms"], row["serial"]))
            self._serial += len(rows)
            self._counters["scheduled"] += len(rows)
            return tuple(rows)

    def active_notes(self, *, channel: int | None = None) -> tuple:
        if channel is not None:
            channel = self._require_channel(channel)

        with self._lock:
            notes = self._notes.values()
            if channel is not None:
                notes = (note for note in notes if note.channel == channel)
            return tuple(sorted(notes, key=lambda note: note.note_id))

    def pedal_down(self, *, channel: int) -> bool:
        channel = self._require_channel(channel)
        with self._lock:
            return self._pedals.get(channel, False)

    def snapshot(self) -> dict:
        with self._lock:
            notes = [
                {
                    "note_id": note.note_id,
                    "channel": note.channel,
                    "pitch": note.pitch,
                    "velocity": note.velocity,
                    "at_ms": note.at_ms,
                    "device": note.device,
                    "state": note.state,
                }
                for note in sorted(
                    self._notes.values(), key=lambda item: item.note_id
                )
            ]
            return {
                "version": 1,
                "notes": notes,
                "pedals": copy.deepcopy(self._pedals),
                "next_id": self._next_id,
                "stats": self.stats(),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._validate_snapshot(state)
            except MidiError:
                raise
            except Exception as exc:
                raise self._snapshot_error() from exc

            notes, pedals, next_id, counters = restored
            self._notes = notes
            self._pedals = pedals
            self._next_id = next_id
            self._counters = counters
            self._serial = counters["scheduled"]

    def stats(self) -> dict:
        with self._lock:
            return {
                "note_on": self._counters["note_on"],
                "note_off": self._counters["note_off"],
                "sustained": self._counters["sustained"],
                "pedal_down": self._counters["pedal_down"],
                "pedal_up": self._counters["pedal_up"],
                "stuck_cleaned": self._counters["stuck_cleaned"],
                "disconnect_released": self._counters["disconnect_released"],
                "scheduled": self._counters["scheduled"],
                "pending": len(self._notes),
                "last_reason": self._counters["last_reason"],
            }

    def _validate_snapshot(
        self, state: Any
    ) -> tuple[dict[int, NoteRef], dict[int, bool], int, dict[str, Any]]:
        if not isinstance(state, Mapping):
            raise self._snapshot_error("state")
        for key in ("version", "notes", "pedals", "next_id", "stats"):
            if key not in state:
                raise self._snapshot_error(key)

        version = state["version"]
        if type(version) is not int or version != 1:
            raise self._snapshot_error("version")

        notes_raw = state["notes"]
        if not isinstance(notes_raw, list):
            raise self._snapshot_error("notes")

        notes: dict[int, NoteRef] = {}
        seen_ids = set()
        max_note_id = 0
        for index, raw in enumerate(notes_raw):
            if not isinstance(raw, Mapping):
                raise self._snapshot_error({"note": index})
            fields = (
                "note_id", "channel", "pitch", "velocity",
                "at_ms", "device", "state",
            )
            if any(field not in raw for field in fields):
                raise self._snapshot_error({"note": index})

            note_id = raw["note_id"]
            if type(note_id) is not int or note_id < 1:
                raise self._snapshot_error({"note": index, "field": "note_id"})
            if note_id in seen_ids:
                raise self._snapshot_error({"note": index, "field": "note_id"})

            channel = raw["channel"]
            pitch = raw["pitch"]
            velocity = raw["velocity"]
            at_ms = raw["at_ms"]
            device = raw["device"]
            note_state = raw["state"]
            if type(channel) is not int or not 0 <= channel <= 15:
                raise self._snapshot_error({"note": index, "field": "channel"})
            if type(pitch) is not int or not 0 <= pitch <= 127:
                raise self._snapshot_error({"note": index, "field": "pitch"})
            if type(velocity) is not int or not 1 <= velocity <= 127:
                raise self._snapshot_error({"note": index, "field": "velocity"})
            if type(at_ms) is not int or at_ms < 0:
                raise self._snapshot_error({"note": index, "field": "at_ms"})
            if not isinstance(device, str) or not device.strip():
                raise self._snapshot_error({"note": index, "field": "device"})
            if note_state not in ("down", "sustained"):
                raise self._snapshot_error({"note": index, "field": "state"})

            seen_ids.add(note_id)
            max_note_id = max(max_note_id, note_id)
            notes[note_id] = NoteRef(
                note_id=note_id,
                channel=channel,
                pitch=pitch,
                velocity=velocity,
                at_ms=at_ms,
                device=device.strip(),
                state=note_state,
            )

        next_id = state["next_id"]
        if type(next_id) is not int or next_id < 1 or next_id <= max_note_id:
            raise self._snapshot_error("next_id")

        pedals_raw = state["pedals"]
        if not isinstance(pedals_raw, Mapping):
            raise self._snapshot_error("pedals")
        pedals: dict[int, bool] = {}
        for channel, down in pedals_raw.items():
            if type(channel) is not int or not 0 <= channel <= 15:
                raise self._snapshot_error("pedals")
            if type(down) is not bool:
                raise self._snapshot_error("pedals")
            pedals[channel] = down

        sustained_channels = {
            note.channel for note in notes.values()
            if note.state == "sustained"
        }
        if any(not pedals.get(channel, False)
               for channel in sustained_channels):
            raise self._snapshot_error("notes")

        stats_raw = state["stats"]
        if not isinstance(stats_raw, Mapping):
            raise self._snapshot_error("stats")
        counter_names = (
            "note_on", "note_off", "sustained", "pedal_down",
            "pedal_up", "stuck_cleaned", "disconnect_released", "scheduled",
        )
        counters: dict[str, Any] = {}
        for name in counter_names:
            if name not in stats_raw:
                raise self._snapshot_error({"stats": name})
            value = stats_raw[name]
            if type(value) is not int or value < 0:
                raise self._snapshot_error({"stats": name})
            counters[name] = value

        if "last_reason" not in stats_raw:
            raise self._snapshot_error({"stats": "last_reason"})
        last_reason = stats_raw["last_reason"]
        if last_reason is not None and not isinstance(last_reason, str):
            raise self._snapshot_error({"stats": "last_reason"})
        counters["last_reason"] = last_reason

        if "pending" not in stats_raw:
            raise self._snapshot_error({"stats": "pending"})
        pending = stats_raw["pending"]
        if type(pending) is not int or pending < 0 or pending != len(notes):
            raise self._snapshot_error({"stats": "pending"})

        return notes, pedals, next_id, counters
