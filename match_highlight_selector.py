"""Match highlights: event dedup, window merging, per-player and per-match quotas."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass
from numbers import Real


EVENT_KINDS = ("multi_kill", "low_hp_clash", "objective")
SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = ("version", "matches", "events", "clips", "counters", "stats")
COUNTER_KEYS = ("duplicates", "merges", "evicted")
STAT_KEYS = ("matches", "events", "duplicates", "clips", "merges", "evicted")


class HighlightError(ValueError):
    """Raised when a highlight selection operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MatchInfo:
    match_id: str
    end_at: float
    merge_gap: float


@dataclass(frozen=True)
class Clip:
    clip_id: str
    match_id: str
    start: float
    end: float
    priority: int
    players: tuple[str, ...]
    events: tuple[str, ...]
    streak: int


@dataclass(frozen=True)
class _Event:
    event_id: str
    kind: str
    player: str
    at: float
    priority: int
    duration: float


def _is_number(value: object) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool) and math.isfinite(value)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _invalid_request(detail: object = None) -> HighlightError:
    return HighlightError("HL_INVALID_REQUEST", detail)


def _invalid_event(detail: object = None) -> HighlightError:
    return HighlightError("HL_INVALID_EVENT", detail)


def _snapshot_invalid(detail: object = None) -> HighlightError:
    return HighlightError("HL_SNAPSHOT_INVALID", detail)


class HighlightSelector:
    """Turn a raw match event stream into ranked highlight clips."""

    def __init__(self, *, per_player_cap: int = 2, per_match_cap: int = 12,
                 streak_window: float = 5.0) -> None:
        if not _is_int(per_player_cap) or per_player_cap < 0:
            raise _invalid_request("per_player_cap must be a non-negative integer")
        if not _is_int(per_match_cap) or per_match_cap < 0:
            raise _invalid_request("per_match_cap must be a non-negative integer")
        if not _is_number(streak_window) or streak_window < 0:
            raise _invalid_request("streak_window must be a non-negative number")
        self.per_player_cap = per_player_cap
        self.per_match_cap = per_match_cap
        self.streak_window = float(streak_window)
        self._lock = threading.RLock()
        self._matches: dict[str, MatchInfo] = {}
        self._events: dict[str, dict[str, _Event]] = {}
        self._clips: dict[str, list[Clip]] = {}
        self._match_gaps: dict[str, float] = {}
        self._counters = {"duplicates": 0, "merges": 0, "evicted": 0}

    def open_match(self, match_id: str, *, end_at: float,
                   merge_gap: float = 2.5) -> MatchInfo:
        """Register one match and the timeline boundary of its event stream."""
        if not _valid_id(match_id):
            raise _invalid_request("match_id must be a non-empty string")
        with self._lock:
            if match_id in self._matches:
                raise HighlightError("HL_MATCH_EXISTS", match_id)
            if not _is_number(end_at) or end_at <= 0:
                raise _invalid_request("end_at must be greater than zero")
            if not _is_number(merge_gap) or merge_gap < 0:
                raise _invalid_request("merge_gap must be a non-negative number")
            info = MatchInfo(match_id, float(end_at), float(merge_gap))
            self._matches[match_id] = info
            self._events[match_id] = {}
            self._clips[match_id] = []
            self._match_gaps[match_id] = info.merge_gap
            return info

    def ingest(self, match_id: str, event_id: str, *, kind: str, player: str,
               at: float, priority: int = 0, duration: float = 1.0) -> bool:
        """Record one event, returning False when the event id was already seen."""
        with self._lock:
            info = self._matches.get(match_id) if isinstance(match_id, str) else None
            if info is None:
                raise HighlightError("HL_UNKNOWN_MATCH", match_id)
            if kind not in EVENT_KINDS:
                raise _invalid_event("kind")
            if not _valid_id(event_id):
                raise _invalid_event("event_id")
            if not _valid_id(player):
                raise _invalid_event("player")
            if not _is_number(at) or at < 0 or at >= info.end_at:
                raise _invalid_event("at")
            if not _is_number(duration) or duration <= 0:
                raise _invalid_event("duration")
            if not _is_int(priority) or not 0 <= priority <= 100:
                raise _invalid_event("priority")

            events = self._events[match_id]
            if event_id in events:
                self._counters["duplicates"] += 1
                return False

            events[event_id] = _Event(
                event_id=event_id,
                kind=kind,
                player=player,
                at=float(at),
                priority=priority,
                duration=float(duration),
            )
            self._clips[match_id] = []
            return True

    def merge_window(self, match_id: str, *, gap: float | None = None) -> tuple[Clip, ...]:
        """Merge adjacent events into clips and enforce the stored quotas."""
        with self._lock:
            info = self._matches.get(match_id) if isinstance(match_id, str) else None
            if info is None:
                raise HighlightError("HL_UNKNOWN_MATCH", match_id)
            if gap is None:
                effective_gap = self._match_gaps.get(match_id, info.merge_gap)
            else:
                if not _is_number(gap) or gap < 0:
                    raise _invalid_request("gap must be a non-negative number")
                effective_gap = float(gap)

            self._match_gaps[match_id] = effective_gap
            self._clips[match_id] = self._build_clips(match_id, effective_gap)
            self._counters["merges"] += 1
            self._enforce_quotas()
            self._assign_clip_ids()
            return self._clips_in_start_order(match_id)

    def select(self, match_id: str, *, limit: int = 5) -> tuple[Clip, ...]:
        """Return the highest priority clips of one match up to limit."""
        with self._lock:
            if not isinstance(match_id, str) or match_id not in self._matches:
                raise HighlightError("HL_UNKNOWN_MATCH", match_id)
            if not _is_int(limit) or limit < 0:
                raise _invalid_request("limit must be a non-negative integer")
            self._ensure_clips(match_id)
            clips = list(self._clips[match_id])
            clips.sort(key=lambda clip: (
                -clip.priority, clip.start, clip.end, clip.clip_id, clip.events))
            return tuple(clips[:limit])

    def clips_of(self, match_id: str) -> tuple[Clip, ...]:
        """Stored clips of one match in start order."""
        with self._lock:
            if not isinstance(match_id, str) or match_id not in self._matches:
                raise HighlightError("HL_UNKNOWN_MATCH", match_id)
            self._ensure_clips(match_id)
            return self._clips_in_start_order(match_id)

    def export(self, match_id: str) -> dict:
        """Plain dictionary form of the clips for the highlight feed."""
        with self._lock:
            if not isinstance(match_id, str) or match_id not in self._matches:
                raise HighlightError("HL_UNKNOWN_MATCH", match_id)
            self._ensure_clips(match_id)
            clips = self._clips_in_start_order(match_id)
            rows = [
                {
                    "clip_id": clip.clip_id,
                    "start": clip.start,
                    "end": clip.end,
                    "priority": clip.priority,
                    "players": list(clip.players),
                    "events": list(clip.events),
                }
                for clip in clips
            ]
            return {"match_id": match_id, "count": len(rows), "clips": rows}

    def quota_of(self, player: str) -> int:
        """Number of stored clips that involve one player."""
        with self._lock:
            if not isinstance(player, str):
                return 0
            return sum(
                1
                for clips in self._clips.values()
                for clip in clips
                if player in clip.players
            )

    def remove_event(self, match_id: str, event_id: str) -> bool:
        """Delete one event and force the clips of that match to be rebuilt."""
        with self._lock:
            info = self._matches.get(match_id) if isinstance(match_id, str) else None
            if info is None:
                raise HighlightError("HL_UNKNOWN_MATCH", match_id)
            events = self._events[match_id]
            if not isinstance(event_id, str) or event_id not in events:
                return False

            del events[event_id]
            gap = self._match_gaps.get(match_id, info.merge_gap)
            self._clips[match_id] = self._build_clips(match_id, gap)
            self._counters["merges"] += 1
            self._enforce_quotas()
            self._assign_clip_ids()
            return True

    def snapshot(self) -> dict:
        """Deep copy of matches, events, clips and counters."""
        with self._lock:
            matches = {
                match_id: {
                    "match_id": info.match_id,
                    "end_at": info.end_at,
                    "merge_gap": info.merge_gap,
                }
                for match_id, info in self._matches.items()
            }
            events = {
                match_id: {
                    event_id: {
                        "event_id": event.event_id,
                        "kind": event.kind,
                        "player": event.player,
                        "at": event.at,
                        "priority": event.priority,
                        "duration": event.duration,
                    }
                    for event_id, event in match_events.items()
                }
                for match_id, match_events in self._events.items()
            }
            clips = {
                match_id: [
                    {
                        "clip_id": clip.clip_id,
                        "match_id": clip.match_id,
                        "start": clip.start,
                        "end": clip.end,
                        "priority": clip.priority,
                        "players": list(clip.players),
                        "events": list(clip.events),
                        "streak": clip.streak,
                    }
                    for clip in match_clips
                ]
                for match_id, match_clips in self._clips.items()
            }
            state = {
                "version": SNAPSHOT_VERSION,
                "matches": matches,
                "events": events,
                "clips": clips,
                "counters": dict(self._counters),
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        with self._lock:
            try:
                decoded = self._decode_snapshot(state)
            except HighlightError:
                raise
            except Exception as exc:
                raise _snapshot_invalid(repr(exc)) from exc

            matches, events, clips, match_gaps, counters = decoded
            self._matches = matches
            self._events = events
            self._clips = clips
            self._match_gaps = match_gaps
            self._counters = counters

    def stats(self) -> dict:
        """Counters exposed to the highlight operations dashboard."""
        with self._lock:
            return {
                "matches": len(self._matches),
                "events": sum(len(events) for events in self._events.values()),
                "duplicates": self._counters["duplicates"],
                "clips": sum(len(clips) for clips in self._clips.values()),
                "merges": self._counters["merges"],
                "evicted": self._counters["evicted"],
            }

    def _clips_in_start_order(self, match_id: str) -> tuple[Clip, ...]:
        return tuple(sorted(
            self._clips[match_id],
            key=lambda clip: (clip.start, clip.end, clip.clip_id, clip.events),
        ))

    def _ensure_clips(self, match_id: str) -> None:
        if not self._events[match_id] or self._clips[match_id]:
            return
        info = self._matches[match_id]
        gap = self._match_gaps.get(match_id, info.merge_gap)
        self._clips[match_id] = self._build_clips(match_id, gap)
        self._counters["merges"] += 1
        self._enforce_quotas()
        self._assign_clip_ids()

    def _build_clips(self, match_id: str, gap: float) -> list[Clip]:
        info = self._matches[match_id]
        events = sorted(
            self._events[match_id].values(),
            key=lambda event: (event.at, event.event_id),
        )
        if not events:
            return []

        groups: list[list[_Event]] = []
        current = [events[0]]
        current_end = events[0].at + events[0].duration
        for event in events[1:]:
            if event.at - current_end <= gap:
                current.append(event)
                current_end = max(current_end, event.at + event.duration)
            else:
                groups.append(current)
                current = [event]
                current_end = event.at + event.duration
        groups.append(current)

        clips: list[Clip] = []
        for group in groups:
            start = group[0].at
            end = min(
                max(event.at + event.duration for event in group),
                info.end_at,
            )
            clips.append(Clip(
                clip_id="",
                match_id=match_id,
                start=start,
                end=end,
                priority=max(event.priority for event in group),
                players=tuple(sorted({event.player for event in group})),
                events=tuple(event.event_id for event in group),
                streak=self._streak_of(group),
            ))
        return clips

    def _streak_of(self, events: list[_Event]) -> int:
        seconds_by_player: dict[str, set[int]] = {}
        for event in events:
            if event.kind == "multi_kill":
                seconds_by_player.setdefault(event.player, set()).add(
                    math.floor(event.at)
                )

        best = 0
        for seconds in seconds_by_player.values():
            ordered = sorted(seconds)
            left = 0
            for right, second in enumerate(ordered):
                while second - ordered[left] > self.streak_window:
                    left += 1
                best = max(best, right - left + 1)
        return best

    def _assign_clip_ids(self) -> None:
        for match_id, clips in self._clips.items():
            ordered = sorted(
                clips,
                key=lambda clip: (clip.start, clip.end, clip.events),
            )
            self._clips[match_id] = [
                Clip(
                    clip_id=f"c{index}",
                    match_id=clip.match_id,
                    start=clip.start,
                    end=clip.end,
                    priority=clip.priority,
                    players=clip.players,
                    events=clip.events,
                    streak=clip.streak,
                )
                for index, clip in enumerate(ordered)
            ]

    def _enforce_quotas(self) -> None:
        while True:
            candidates: list[Clip] = []

            for clips in self._clips.values():
                if len(clips) > self.per_match_cap:
                    candidates.extend(clips)

            by_player: dict[str, list[Clip]] = {}
            for clips in self._clips.values():
                for clip in clips:
                    for player in clip.players:
                        by_player.setdefault(player, []).append(clip)
            for clips in by_player.values():
                if len(clips) > self.per_player_cap:
                    candidates.extend(clips)

            if not candidates:
                return

            victim = min(candidates, key=self._eviction_key)
            clips = self._clips[victim.match_id]
            for index, clip in enumerate(clips):
                if clip is victim:
                    del clips[index]
                    break
            self._counters["evicted"] += 1

    @staticmethod
    def _eviction_key(clip: Clip) -> tuple:
        return (clip.priority, -clip.start, clip.match_id, clip.events, clip.end)

    def _decode_snapshot(self, state: object) -> tuple[
        dict[str, MatchInfo],
        dict[str, dict[str, _Event]],
        dict[str, list[Clip]],
        dict[str, float],
        dict[str, int],
    ]:
        if not isinstance(state, dict):
            raise _snapshot_invalid("snapshot must be a dictionary")
        if any(key not in state for key in SNAPSHOT_KEYS):
            raise _snapshot_invalid("missing snapshot key")
        state = copy.deepcopy(state)

        version = state["version"]
        if not _is_int(version) or version != SNAPSHOT_VERSION:
            raise _snapshot_invalid("version")

        raw_matches = state["matches"]
        raw_events = state["events"]
        raw_clips = state["clips"]
        raw_counters = state["counters"]
        raw_stats = state["stats"]
        if not isinstance(raw_matches, dict):
            raise _snapshot_invalid("matches")
        if not isinstance(raw_events, dict):
            raise _snapshot_invalid("events")
        if not isinstance(raw_clips, dict):
            raise _snapshot_invalid("clips")
        if not isinstance(raw_counters, dict):
            raise _snapshot_invalid("counters")
        if not isinstance(raw_stats, dict):
            raise _snapshot_invalid("stats")
        if any(key not in raw_counters for key in COUNTER_KEYS):
            raise _snapshot_invalid("counters")
        if any(key not in raw_stats for key in STAT_KEYS):
            raise _snapshot_invalid("stats")

        counters: dict[str, int] = {}
        for key in COUNTER_KEYS:
            value = raw_counters[key]
            if not _is_int(value) or value < 0:
                raise _snapshot_invalid(f"counters.{key}")
            counters[key] = value
        for key in STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                raise _snapshot_invalid(f"stats.{key}")

        matches: dict[str, MatchInfo] = {}
        for match_id, raw_info in raw_matches.items():
            if not _valid_id(match_id) or not isinstance(raw_info, dict):
                raise _snapshot_invalid("match entry")
            end_at = raw_info.get("end_at")
            merge_gap = raw_info.get("merge_gap")
            if not _is_number(end_at) or end_at <= 0:
                raise _snapshot_invalid("match end_at")
            if not _is_number(merge_gap) or merge_gap < 0:
                raise _snapshot_invalid("match merge_gap")
            matches[match_id] = MatchInfo(match_id, float(end_at), float(merge_gap))

        events: dict[str, dict[str, _Event]] = {}
        for match_id, raw_match_events in raw_events.items():
            if match_id not in matches:
                raise _snapshot_invalid("events match")
            if not isinstance(raw_match_events, dict):
                raise _snapshot_invalid("events entry")
            match_events: dict[str, _Event] = {}
            for event_id, raw_event in raw_match_events.items():
                if not _valid_id(event_id) or not isinstance(raw_event, dict):
                    raise _snapshot_invalid("event entry")
                kind = raw_event.get("kind")
                player = raw_event.get("player")
                at = raw_event.get("at")
                priority = raw_event.get("priority")
                duration = raw_event.get("duration")
                if kind not in EVENT_KINDS or not _valid_id(player):
                    raise _snapshot_invalid("event fields")
                if not _is_number(at) or at < 0 or at >= matches[match_id].end_at:
                    raise _snapshot_invalid("event at")
                if not _is_int(priority) or not 0 <= priority <= 100:
                    raise _snapshot_invalid("event priority")
                if not _is_number(duration) or duration <= 0:
                    raise _snapshot_invalid("event duration")
                match_events[event_id] = _Event(
                    event_id=event_id,
                    kind=kind,
                    player=player,
                    at=float(at),
                    priority=priority,
                    duration=float(duration),
                )
            events[match_id] = match_events

        clips: dict[str, list[Clip]] = {}
        for match_id, raw_match_clips in raw_clips.items():
            if match_id not in matches or not isinstance(raw_match_clips, (list, tuple)):
                raise _snapshot_invalid("clips entry")
            match_clips: list[Clip] = []
            for raw_clip in raw_match_clips:
                if not isinstance(raw_clip, dict):
                    raise _snapshot_invalid("clip entry")
                clip_id = raw_clip.get("clip_id")
                start = raw_clip.get("start")
                end = raw_clip.get("end")
                priority = raw_clip.get("priority")
                players = raw_clip.get("players")
                clip_events = raw_clip.get("events")
                streak = raw_clip.get("streak", 0)
                if not _valid_id(clip_id):
                    raise _snapshot_invalid("clip_id")
                if not _is_number(start) or start < 0:
                    raise _snapshot_invalid("clip start")
                if not _is_number(end) or end < start or end > matches[match_id].end_at:
                    raise _snapshot_invalid("clip end")
                if not _is_int(priority) or not 0 <= priority <= 100:
                    raise _snapshot_invalid("clip priority")
                if not isinstance(players, (list, tuple)) or not all(
                        _valid_id(player) for player in players):
                    raise _snapshot_invalid("clip players")
                if not isinstance(clip_events, (list, tuple)) or not all(
                        _valid_id(event_id) for event_id in clip_events):
                    raise _snapshot_invalid("clip events")
                if not _is_int(streak) or streak < 0:
                    raise _snapshot_invalid("clip streak")
                match_clips.append(Clip(
                    clip_id=clip_id,
                    match_id=match_id,
                    start=float(start),
                    end=float(end),
                    priority=priority,
                    players=tuple(sorted(set(players))),
                    events=tuple(clip_events),
                    streak=streak,
                ))
            clips[match_id] = match_clips

        for match_id in matches:
            events.setdefault(match_id, {})
            clips.setdefault(match_id, [])

        match_gaps = {
            match_id: matches[match_id].merge_gap for match_id in matches
        }
        return matches, events, clips, match_gaps, counters
