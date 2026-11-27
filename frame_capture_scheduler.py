"""GPU frame capture scheduler: pre-roll ring buffer, async export, privacy masks."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class CaptureError(ValueError):
    """Raised when a capture operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FrameMeta:
    """One frame accepted by the ring buffer."""

    frame_no: int
    payload_size: int
    captured: tuple
    added_at: str | None


@dataclass(frozen=True)
class CaptureTicket:
    """Handle for one capture request."""

    capture_id: str
    reason: str
    status: str
    trigger_frame: int
    first_frame: int
    last_frame: int


@dataclass(frozen=True)
class CaptureRecord:
    """Export result of one finalized capture."""

    capture_id: str
    reason: str
    trigger_frame: int
    first_frame: int
    last_frame: int
    frame_count: int
    bytes_total: int
    masked_regions: tuple
    masks_applied: int
    finalized_at: str | None


@dataclass
class _CaptureState:
    """Mutable capture state kept internal to the scheduler."""

    capture_id: str
    reason: str
    trigger_frame: int
    last_trigger_frame: int
    window_start: int
    window_end: int
    frames: dict
    claims: set
    status: str
    record: CaptureRecord | None = None

    @property
    def first_frame(self) -> int:
        return min(self.claims)

    @property
    def last_frame(self) -> int:
        return max(self.claims)


class FrameCaptureScheduler:
    """Keep a short pre-roll of frames and export the window around a trigger."""

    _CONFIG_KEYS = (
        "ring_size",
        "pre_frames",
        "post_frames",
        "max_active",
        "min_interval_frames",
        "max_bytes",
    )
    _COUNTER_KEYS = (
        "frames",
        "captures",
        "finalized",
        "rejected",
        "dropped_frames",
        "merged",
        "masks",
    )
    _SNAPSHOT_KEYS = {
        "version",
        "config",
        "ring",
        "captures",
        "claimed",
        "masks",
        "counters",
    }

    def __init__(self, *, ring_size: int = 64, pre_frames: int = 30,
                 post_frames: int = 10, max_active: int = 2,
                 min_interval_frames: int = 0,
                 max_bytes: int = 8_000_000) -> None:
        self._lock = threading.RLock()
        self._config = self._validated_config({
            "ring_size": ring_size,
            "pre_frames": pre_frames,
            "post_frames": post_frames,
            "max_active": max_active,
            "min_interval_frames": min_interval_frames,
            "max_bytes": max_bytes,
        })
        self._ring: dict = {}
        self._order: list = []
        self._captures: dict = {}
        self._capture_order: list = []
        self._claimed: set = set()
        self._masks: list = []
        self._counters: dict = {
            "frames": 0,
            "captures": 0,
            "finalized": 0,
            "rejected": 0,
            "dropped_frames": 0,
            "merged": 0,
            "masks": 0,
        }
        self._next_capture_no = 1
        self._latest_frame: int | None = None

    @staticmethod
    def _is_int(value: object) -> bool:
        return type(value) is int

    def _validated_config(self, config: dict) -> dict:
        if not isinstance(config, dict) or set(config) != set(self._CONFIG_KEYS):
            raise CaptureError("CAPTURE_INVALID_ARGUMENT", "invalid config")

        ring_size = config["ring_size"]
        pre_frames = config["pre_frames"]
        post_frames = config["post_frames"]
        max_active = config["max_active"]
        min_interval_frames = config["min_interval_frames"]
        max_bytes = config["max_bytes"]
        values = (ring_size, pre_frames, post_frames, max_active,
                  min_interval_frames, max_bytes)
        if not all(self._is_int(value) for value in values):
            raise CaptureError("CAPTURE_INVALID_ARGUMENT", "config must be integers")
        if ring_size <= 0 or pre_frames < 0 or post_frames < 0:
            raise CaptureError("CAPTURE_INVALID_ARGUMENT", "invalid ring/window size")
        if max_active <= 0 or min_interval_frames < 0 or max_bytes < 0:
            raise CaptureError("CAPTURE_INVALID_ARGUMENT", "invalid capture limits")
        return {key: config[key] for key in self._CONFIG_KEYS}

    def arm(self, *, pre_frames: int | None = None,
            post_frames: int | None = None,
            ring_size: int | None = None) -> dict:
        with self._lock:
            proposed = dict(self._config)
            if pre_frames is not None:
                proposed["pre_frames"] = pre_frames
            if post_frames is not None:
                proposed["post_frames"] = post_frames
            if ring_size is not None:
                proposed["ring_size"] = ring_size
            proposed = self._validated_config(proposed)

            self._config = proposed
            while len(self._order) > proposed["ring_size"]:
                evicted = self._order.pop(0)
                self._ring.pop(evicted, None)
                self._counters["dropped_frames"] += 1
            return copy.deepcopy(self._config)

    def on_frame(self, frame_no: int, *, payload_size: int = 1024,
                 now: str | None = None) -> FrameMeta:
        if not self._is_int(frame_no):
            raise CaptureError("CAPTURE_INVALID_ARGUMENT", "frame_no must be an integer")
        if not self._is_int(payload_size) or payload_size < 0:
            raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                               "payload_size must be a non-negative integer")
        if now is not None and not isinstance(now, str):
            raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                               "now must be a string or None")

        with self._lock:
            if self._latest_frame is not None and frame_no <= self._latest_frame:
                raise CaptureError(
                    "CAPTURE_FRAME_ORDER",
                    {"frame_no": frame_no, "last_frame": self._latest_frame},
                )

            meta = FrameMeta(
                frame_no=frame_no,
                payload_size=payload_size,
                captured=(),
                added_at=now,
            )
            self._ring[frame_no] = meta
            self._order.append(frame_no)
            self._latest_frame = frame_no
            if frame_no not in self._claimed:
                self._counters["frames"] += 1

            while len(self._order) > self._config["ring_size"]:
                evicted = self._order.pop(0)
                self._ring.pop(evicted, None)
                self._counters["dropped_frames"] += 1

            for capture in self._captures.values():
                if capture.record is not None:
                    continue
                if frame_no in capture.claims:
                    capture.frames[frame_no] = meta
                if capture.status == "recording" and frame_no >= capture.last_frame:
                    capture.status = "ready"
            return meta

    def trigger(self, reason: str, *, frame_no: int | None = None,
                now: str | None = None) -> CaptureTicket:
        with self._lock:
            try:
                if not isinstance(reason, str):
                    raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                                       "reason must be a string")
                if now is not None and not isinstance(now, str):
                    raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                                       "now must be a string or None")
                selected = self._select_trigger_frame(frame_no)
                prior = self._merge_candidate(selected)
                if prior is None and selected in self._claimed:
                    raise CaptureError(
                        "CAPTURE_FRAME_CLAIMED",
                        {"frame_no": selected},
                    )
                if prior is None and len(self.active_captures()) >= self._config["max_active"]:
                    raise CaptureError(
                        "CAPTURE_QUOTA_EXCEEDED",
                        {"active": len(self.active_captures()),
                         "max_active": self._config["max_active"]},
                    )

                if prior is None:
                    plan = self._plan_capture(selected)
                else:
                    plan = self._plan_merge(prior, selected)

                candidate_frames, candidate_claims, window_start, window_end = plan
                latest_payload = self._ring[self._order[-1]].payload_size
                estimated = (
                    sum(frame.payload_size for frame in candidate_frames.values())
                    + self._config["post_frames"] * latest_payload
                )
                if estimated > self._config["max_bytes"]:
                    raise CaptureError(
                        "CAPTURE_QUOTA_EXCEEDED",
                        {"estimated_bytes": estimated,
                         "max_bytes": self._config["max_bytes"]},
                    )

                if selected not in candidate_claims:
                    raise CaptureError(
                        "CAPTURE_FRAME_CLAIMED",
                        {"frame_no": selected},
                    )

                if prior is None:
                    capture_id = f"cap-{self._next_capture_no}"
                    self._next_capture_no += 1
                    capture = _CaptureState(
                        capture_id=capture_id,
                        reason=reason,
                        trigger_frame=selected,
                        last_trigger_frame=selected,
                        window_start=window_start,
                        window_end=window_end,
                        frames=candidate_frames,
                        claims=candidate_claims,
                        status=("ready" if self._latest_frame >= max(candidate_claims)
                                else "recording"),
                    )
                    self._captures[capture_id] = capture
                    self._capture_order.append(capture_id)
                    self._claimed.update(candidate_claims)
                    self._counters["captures"] += 1
                else:
                    prior.window_start = window_start
                    prior.window_end = window_end
                    prior.last_trigger_frame = selected
                    prior.frames = candidate_frames
                    prior.claims = candidate_claims
                    prior.status = (
                        "ready"
                        if self._latest_frame >= max(candidate_claims)
                        else "recording"
                    )
                    self._claimed.update(candidate_claims)
                    self._counters["merged"] += 1

                return self._ticket(
                    self._captures[
                        capture_id if prior is None else prior.capture_id
                    ]
                )
            except CaptureError:
                self._counters["rejected"] += 1
                raise

    def finalize(self, capture_id: str, *,
                 now: str | None = None) -> CaptureRecord:
        with self._lock:
            if now is not None and not isinstance(now, str):
                raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                                   "now must be a string or None")
            capture = self._captures.get(capture_id)
            if capture is None:
                raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                                   {"capture_id": capture_id})
            if capture.record is not None:
                raise CaptureError("CAPTURE_ALREADY_FINALIZED",
                                   {"capture_id": capture_id})
            if capture.status != "ready":
                raise CaptureError("CAPTURE_NOT_READY",
                                   {"capture_id": capture_id,
                                    "status": capture.status})

            masked_regions = tuple(self._masks)
            record = CaptureRecord(
                capture_id=capture.capture_id,
                reason=capture.reason,
                trigger_frame=capture.trigger_frame,
                first_frame=capture.first_frame,
                last_frame=capture.last_frame,
                frame_count=len(capture.frames),
                bytes_total=sum(frame.payload_size
                                for frame in capture.frames.values()),
                masked_regions=masked_regions,
                masks_applied=len(masked_regions),
                finalized_at=now,
            )
            capture.record = record
            self._counters["finalized"] += 1
            return record

    def mask_region(self, *, x: int, y: int, width: int, height: int) -> int:
        values = (x, y, width, height)
        if not all(self._is_int(value) for value in values):
            raise CaptureError("CAPTURE_INVALID_ARGUMENT", "mask values must be integers")
        if width <= 0 or height <= 0:
            raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                               "mask width and height must be positive")
        with self._lock:
            self._masks.append((x, y, width, height))
            self._counters["masks"] += 1
            return len(self._masks)

    def capture_of(self, capture_id: str) -> CaptureTicket:
        with self._lock:
            capture = self._captures.get(capture_id)
            if capture is None:
                raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                                   {"capture_id": capture_id})
            return self._ticket(capture)

    def captures(self) -> tuple:
        with self._lock:
            return tuple(self._ticket(self._captures[capture_id])
                         for capture_id in self._capture_order)

    def active_captures(self) -> tuple:
        with self._lock:
            return tuple(
                self._ticket(self._captures[capture_id])
                for capture_id in self._capture_order
                if self._captures[capture_id].record is None
            )

    def ring_frames(self) -> tuple:
        with self._lock:
            return tuple(self._order)

    def snapshot(self) -> dict:
        with self._lock:
            captures = {}
            for capture_id in self._capture_order:
                capture = self._captures[capture_id]
                captures[capture_id] = {
                    "capture_id": capture.capture_id,
                    "reason": capture.reason,
                    "trigger_frame": capture.trigger_frame,
                    "last_trigger_frame": capture.last_trigger_frame,
                    "window_start": capture.window_start,
                    "window_end": capture.window_end,
                    "frames": dict(capture.frames),
                    "claims": set(capture.claims),
                    "status": capture.status,
                    "finalized": capture.record is not None,
                    "record": capture.record,
                }
            return copy.deepcopy({
                "version": 1,
                "config": dict(self._config),
                "ring": dict(self._ring),
                "captures": captures,
                "claimed": set(self._claimed),
                "masks": list(self._masks),
                "counters": dict(self._counters),
            })

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, dict) or set(state) != self._SNAPSHOT_KEYS:
                raise ValueError("snapshot keys")
            if type(state.get("version")) is not int or state["version"] != 1:
                raise ValueError("snapshot version")

            snapshot = copy.deepcopy(state)
            config = self._validated_config(snapshot["config"])
            counters = self._validated_counters(snapshot["counters"])
            ring, order = self._validated_ring(snapshot["ring"], config["ring_size"])
            masks = self._validated_masks(snapshot["masks"])
            captures, capture_order, claims = self._validated_captures(
                snapshot["captures"], ring
            )
            snapshot_claims = self._validated_claims(snapshot["claimed"])
            if claims != snapshot_claims:
                raise ValueError("claimed frames do not match captures")

            next_capture_no = counters["captures"] + 1
            for capture_id in capture_order:
                prefix, separator, suffix = capture_id.partition("-")
                if prefix == "cap" and separator and suffix.isdigit():
                    next_capture_no = max(next_capture_no, int(suffix) + 1)
        except Exception as exc:
            raise CaptureError("CAPTURE_SNAPSHOT_INVALID", str(exc)) from exc

        with self._lock:
            self._config = config
            self._ring = ring
            self._order = order
            self._captures = captures
            self._capture_order = capture_order
            self._claimed = claims
            self._masks = masks
            self._counters = counters
            self._next_capture_no = next_capture_no
            self._latest_frame = order[-1] if order else None

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._counters)

    def _select_trigger_frame(self, frame_no: int | None) -> int:
        if frame_no is None:
            if not self._order:
                raise CaptureError("CAPTURE_INVALID_ARGUMENT", "ring is empty")
            return self._order[-1]
        if not self._is_int(frame_no):
            raise CaptureError("CAPTURE_INVALID_ARGUMENT",
                               "frame_no must be an integer")
        if frame_no not in self._ring:
            raise CaptureError(
                "CAPTURE_INVALID_ARGUMENT",
                {"frame_no": frame_no, "ring": tuple(self._order)},
            )
        return frame_no

    def _merge_candidate(self, frame_no: int) -> _CaptureState | None:
        interval = self._config["min_interval_frames"]
        if interval <= 0 or not self._capture_order:
            return None
        capture = self._captures[self._capture_order[-1]]
        if capture.record is not None:
            return None
        if abs(frame_no - capture.last_trigger_frame) >= interval:
            return None
        if frame_no not in capture.claims and frame_no in self._claimed:
            return None
        return capture

    def _plan_capture(self, frame_no: int) -> tuple:
        oldest = self._order[0]
        window_start = max(frame_no - self._config["pre_frames"], oldest)
        window_end = frame_no + self._config["post_frames"]
        frames = {}
        claims = set()
        for candidate in range(window_start, window_end + 1):
            if candidate in self._claimed:
                continue
            claims.add(candidate)
            if candidate in self._ring:
                frames[candidate] = self._ring[candidate]
        return frames, claims, window_start, window_end

    def _plan_merge(self, capture: _CaptureState, frame_no: int) -> tuple:
        oldest = self._order[0]
        window_start = min(capture.window_start,
                           frame_no - self._config["pre_frames"])
        window_end = max(capture.window_end,
                         frame_no + self._config["post_frames"])
        frames = dict(capture.frames)
        claims = set(capture.claims)
        for candidate in range(max(window_start, oldest), window_end + 1):
            if candidate in claims:
                if candidate in self._ring:
                    frames[candidate] = self._ring[candidate]
                continue
            if candidate in self._claimed:
                continue
            claims.add(candidate)
            if candidate in self._ring:
                frames[candidate] = self._ring[candidate]
        return frames, claims, window_start, window_end

    @staticmethod
    def _ticket(capture: _CaptureState) -> CaptureTicket:
        return CaptureTicket(
            capture_id=capture.capture_id,
            reason=capture.reason,
            status=capture.status,
            trigger_frame=capture.trigger_frame,
            first_frame=capture.first_frame,
            last_frame=capture.last_frame,
        )

    def _validated_counters(self, counters: object) -> dict:
        if not isinstance(counters, dict) or set(counters) != set(self._COUNTER_KEYS):
            raise ValueError("invalid counters")
        if not all(self._is_int(value) and value >= 0
                   for value in counters.values()):
            raise ValueError("invalid counter value")
        return {key: counters[key] for key in self._COUNTER_KEYS}

    def _validated_ring(self, ring: object, ring_size: int) -> tuple:
        if not isinstance(ring, dict):
            raise ValueError("invalid ring")
        validated = {}
        for frame_no, meta in ring.items():
            if not self._is_int(frame_no) or not isinstance(meta, FrameMeta):
                raise ValueError("invalid ring frame")
            if meta.frame_no != frame_no:
                raise ValueError("ring key mismatch")
            if not self._is_int(meta.payload_size) or meta.payload_size < 0:
                raise ValueError("invalid frame payload")
            if not isinstance(meta.captured, tuple):
                raise ValueError("invalid frame capture data")
            if meta.added_at is not None and not isinstance(meta.added_at, str):
                raise ValueError("invalid frame timestamp")
            validated[frame_no] = meta
        order = sorted(validated)
        if len(order) > ring_size:
            raise ValueError("ring is larger than configured")
        return validated, order

    def _validated_masks(self, masks: object) -> list:
        if not isinstance(masks, (list, tuple)):
            raise ValueError("invalid masks")
        validated = []
        for mask in masks:
            if not isinstance(mask, (list, tuple)) or len(mask) != 4:
                raise ValueError("invalid mask")
            if not all(self._is_int(value) for value in mask):
                raise ValueError("invalid mask value")
            x, y, width, height = mask
            if width <= 0 or height <= 0:
                raise ValueError("invalid mask size")
            validated.append((x, y, width, height))
        return validated

    def _validated_claims(self, claimed: object) -> set:
        if not isinstance(claimed, (set, list, tuple)):
            raise ValueError("invalid claims")
        if not all(self._is_int(frame_no) for frame_no in claimed):
            raise ValueError("invalid claimed frame")
        return set(claimed)

    def _validated_captures(self, captures: object,
                            ring: dict) -> tuple:
        if not isinstance(captures, dict):
            raise ValueError("invalid captures")

        validated = {}
        order = []
        all_claims = set()
        for capture_id, raw in captures.items():
            if not isinstance(capture_id, str) or not isinstance(raw, dict):
                raise ValueError("invalid capture")
            required = {
                "capture_id", "reason", "trigger_frame", "last_trigger_frame",
                "window_start", "window_end", "frames", "claims", "status",
                "finalized", "record",
            }
            if set(raw) != required:
                raise ValueError("invalid capture fields")
            if raw["capture_id"] != capture_id:
                raise ValueError("capture id mismatch")
            if not isinstance(raw["reason"], str):
                raise ValueError("invalid capture reason")

            numeric = ("trigger_frame", "last_trigger_frame",
                       "window_start", "window_end")
            if not all(self._is_int(raw[key]) for key in numeric):
                raise ValueError("invalid capture window")
            claims = self._validated_claims(raw["claims"])
            if not claims:
                raise ValueError("capture has no frames")
            if raw["window_start"] > raw["trigger_frame"]:
                raise ValueError("trigger precedes window")
            if raw["trigger_frame"] > raw["window_end"]:
                raise ValueError("trigger follows window")
            if not (raw["window_start"] <= raw["last_trigger_frame"]
                    <= raw["window_end"]):
                raise ValueError("last trigger outside window")
            if min(claims) < raw["window_start"] or max(claims) > raw["window_end"]:
                raise ValueError("claim outside window")
            if raw["trigger_frame"] not in claims:
                raise ValueError("trigger frame is not claimed")
            if raw["last_trigger_frame"] not in claims:
                raise ValueError("last trigger frame is not claimed")
            if all_claims.intersection(claims):
                raise ValueError("overlapping captures")

            if not isinstance(raw["frames"], dict):
                raise ValueError("invalid capture frames")
            frames = {}
            for frame_no, meta in raw["frames"].items():
                if frame_no not in claims or not isinstance(meta, FrameMeta):
                    raise ValueError("invalid capture frame")
                if meta.frame_no != frame_no:
                    raise ValueError("capture frame mismatch")
                if not self._is_int(meta.payload_size) or meta.payload_size < 0:
                    raise ValueError("invalid capture frame payload")
                if not isinstance(meta.captured, tuple):
                    raise ValueError("invalid capture frame data")
                if meta.added_at is not None and not isinstance(meta.added_at, str):
                    raise ValueError("invalid capture frame timestamp")
                if frame_no in ring and ring[frame_no] != meta:
                    raise ValueError("capture/ring frame mismatch")
                frames[frame_no] = meta

            status = raw["status"]
            record = raw["record"]
            if status not in {"recording", "ready"}:
                raise ValueError("invalid capture status")
            finalized = raw.get("finalized")
            if type(finalized) is not bool:
                raise ValueError("invalid finalized flag")
            if finalized:
                if not isinstance(record, CaptureRecord):
                    raise ValueError("missing capture record")
                if record.capture_id != capture_id:
                    raise ValueError("capture record mismatch")
                record_indices = (
                    record.trigger_frame,
                    record.first_frame,
                    record.last_frame,
                )
                record_counts = (
                    record.frame_count,
                    record.bytes_total,
                    record.masks_applied,
                )
                if not all(self._is_int(value) for value in record_indices):
                    raise ValueError("invalid capture record")
                if not all(self._is_int(value) and value >= 0
                           for value in record_counts):
                    raise ValueError("invalid capture record")
                if not isinstance(record.reason, str):
                    raise ValueError("invalid capture record reason")
                if not isinstance(record.masked_regions, tuple):
                    raise ValueError("invalid capture record masks")
                for mask in record.masked_regions:
                    if not isinstance(mask, tuple) or len(mask) != 4:
                        raise ValueError("invalid capture record mask")
                    if not all(self._is_int(value) for value in mask):
                        raise ValueError("invalid capture record mask")
                    if mask[2] <= 0 or mask[3] <= 0:
                        raise ValueError("invalid capture record mask")
                if (record.finalized_at is not None
                        and not isinstance(record.finalized_at, str)):
                    raise ValueError("invalid capture record timestamp")
                if record.reason != raw["reason"]:
                    raise ValueError("capture record reason mismatch")
                if (record.trigger_frame != raw["trigger_frame"]
                        or record.first_frame != min(claims)
                        or record.last_frame != max(claims)):
                    raise ValueError("capture record window mismatch")
                if record.frame_count != len(frames):
                    raise ValueError("capture record frame count mismatch")
                if record.bytes_total != sum(
                        frame.payload_size for frame in frames.values()):
                    raise ValueError("capture record byte count mismatch")
                if record.masks_applied != len(record.masked_regions):
                    raise ValueError("capture record mask count mismatch")
            elif record is not None:
                raise ValueError("active capture has a record")

            validated[capture_id] = _CaptureState(
                capture_id=capture_id,
                reason=raw["reason"],
                trigger_frame=raw["trigger_frame"],
                last_trigger_frame=raw["last_trigger_frame"],
                window_start=raw["window_start"],
                window_end=raw["window_end"],
                frames=frames,
                claims=claims,
                status=status,
                record=record,
            )
            order.append(capture_id)
            all_claims.update(claims)
        return validated, order, all_claims
