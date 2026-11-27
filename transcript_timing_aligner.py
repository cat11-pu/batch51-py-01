"""Transcript timing alignment: word snapping, gap distribution and drift repair."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class TranscriptError(ValueError):
    """Raised when an alignment request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SpeechSegment:
    """One span of speech with the number of words spoken inside it."""

    start_ms: int
    end_ms: int
    speaker: str
    word_count: int


@dataclass(frozen=True)
class WordTiming:
    """One word placed on the audio timeline."""

    index: int
    word: str
    start_ms: int
    end_ms: int
    speaker: str


@dataclass(frozen=True)
class Cue:
    """One subtitle line built from consecutive word timings."""

    index: int
    start_ms: int
    end_ms: int
    text: str
    speaker: str


class TranscriptTimingAligner:
    """Distribute transcript words over speech spans and export subtitle cues."""

    def __init__(self, *, max_words: int = 5000, max_segments: int = 2000,
                 cue_max_chars: int = 42,
                 cue_max_duration_ms: int = 6000,
                 cue_gap_ms: int = 700) -> None:
        self.max_words = max_words
        self.max_segments = max_segments
        self.cue_max_chars = cue_max_chars
        self.cue_max_duration_ms = cue_max_duration_ms
        self.cue_gap_ms = cue_gap_ms
        self._lock = threading.RLock()
        self._words: tuple[str, ...] | None = None
        self._segments: tuple[SpeechSegment, ...] | None = None
        self._timings: tuple[WordTiming, ...] = ()
        self._cues: tuple[Cue, ...] = ()
        self._counters = {"aligns": 0, "shifts": 0, "merges": 0, "cues": 0}

    def load_transcript(self, words) -> int:
        raise NotImplementedError

    def load_segments(self, segments) -> int:
        raise NotImplementedError

    def align(self) -> int:
        raise NotImplementedError

    def word_timings(self) -> tuple[WordTiming, ...]:
        raise NotImplementedError

    def segments(self) -> tuple[SpeechSegment, ...]:
        raise NotImplementedError

    def shift(self, offset_ms: int) -> int:
        raise NotImplementedError

    def merge_speakers(self, *, max_gap_ms: int = 0) -> int:
        raise NotImplementedError

    def drift_correct(self, anchors) -> int:
        raise NotImplementedError

    def export_cues(self, *, max_chars=None, max_duration_ms=None) -> tuple[Cue, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
