"""MIDI note scheduling: per-pitch pairing, sustain pedal and stuck note cleanup."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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
        self.max_stack = max_stack
        self.stuck_timeout_ms = stuck_timeout_ms
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._notes: dict = {}
        self._pedals: dict = {}
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

    def note_on(self, *, channel: int, pitch: int, velocity: int,
                at_ms: int, device: str) -> NoteRef:
        raise NotImplementedError

    def note_off(self, *, channel: int, pitch: int, at_ms: int,
                 device: str) -> NoteRef:
        raise NotImplementedError

    def pedal(self, *, channel: int, down: bool, at_ms: int) -> bool:
        raise NotImplementedError

    def all_notes_off(self, *, at_ms: int, channel: int | None = None,
                      reason: str = "all_notes_off") -> int:
        raise NotImplementedError

    def tick(self, *, now_ms: int) -> tuple:
        raise NotImplementedError

    def device_disconnect(self, *, device: str, at_ms: int) -> int:
        raise NotImplementedError

    def schedule(self, *, events) -> tuple:
        raise NotImplementedError

    def active_notes(self, *, channel: int | None = None) -> tuple:
        raise NotImplementedError

    def pedal_down(self, *, channel: int) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
