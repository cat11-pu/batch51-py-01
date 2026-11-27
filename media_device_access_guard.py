"""Session-scoped access governance for capture devices: grants, exclusive streams, privacy indicator."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, replace

CAMERA = "camera"
MICROPHONE = "microphone"
KINDS = (CAMERA, MICROPHONE)

READ = "read"
WRITE = "write"
MODES = (READ, WRITE)

SNAPSHOT_VERSION = 1
COUNTER_KEYS = (
    "grants",
    "streams_opened",
    "streams_closed",
    "streams_forced_closed",
    "sessions_ended",
)


class MediaAccessError(ValueError):
    """Raised when a device access operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceInfo:
    device_id: str
    kind: str
    present: bool


@dataclass(frozen=True)
class AccessGrant:
    session: str
    kind: str
    devices: tuple[str, ...]
    revision: int
    granted_at: str | None


@dataclass(frozen=True)
class StreamHandle:
    stream_id: str
    session: str
    device_id: str
    kind: str
    mode: str
    shared: bool
    live: bool


class MediaDeviceAccessGuard:
    """Track per-session grants, exclusive capture streams and the in-use indicator."""

    def __init__(self, *, max_streams_per_session: int = 4,
                 max_streams_total: int = 16) -> None:
        self.max_streams_per_session = max_streams_per_session
        self.max_streams_total = max_streams_total
        self._lock = threading.RLock()
        self._devices: dict[str, DeviceInfo] = {}
        self._grants: dict[tuple[str, str], AccessGrant] = {}
        self._streams: dict[str, StreamHandle] = {}
        self._next_stream_seq = 1
        self._stats = {key: 0 for key in COUNTER_KEYS}

    @staticmethod
    def _invalid(detail: object = None) -> MediaAccessError:
        return MediaAccessError("MEDIA_INVALID_REQUEST", detail)

    def _device(self, device_id: object) -> DeviceInfo:
        if not isinstance(device_id, str):
            raise MediaAccessError("MEDIA_DEVICE_UNKNOWN", device_id)
        info = self._devices.get(device_id)
        if info is None:
            raise MediaAccessError("MEDIA_DEVICE_UNKNOWN", device_id)
        return info

    def _active_streams(self) -> list[StreamHandle]:
        return [stream for stream in self._streams.values() if stream.live]

    def _force_close(self, predicate) -> int:
        closed = 0
        for stream_id, stream in list(self._streams.items()):
            if stream.live and predicate(stream):
                self._streams[stream_id] = replace(stream, live=False)
                closed += 1
        if closed:
            self._stats["streams_forced_closed"] += closed
        return closed

    def _withdraw_device(self, device_id: str) -> int:
        for key, grant in list(self._grants.items()):
            if device_id not in grant.devices:
                continue
            remaining = tuple(
                current for current in grant.devices if current != device_id
            )
            if remaining:
                self._grants[key] = replace(grant, devices=remaining)
            else:
                del self._grants[key]
        return self._force_close(lambda stream: stream.device_id == device_id)

    def register_device(self, device_id: str, kind: str, *,
                        present: bool = True) -> DeviceInfo:
        with self._lock:
            if not isinstance(device_id, str) or not device_id or kind not in KINDS:
                raise self._invalid("device")

            previous = self._devices.get(device_id)
            if previous is not None and previous.kind != kind:
                raise self._invalid("device kind mismatch")

            info = DeviceInfo(device_id, kind, bool(present))
            self._devices[device_id] = info
            if previous is not None and previous.present and not info.present:
                self._withdraw_device(device_id)
            return info

    def unplug_device(self, device_id: str) -> int:
        with self._lock:
            info = self._device(device_id)
            if not info.present:
                return 0
            self._devices[device_id] = replace(info, present=False)
            return self._withdraw_device(device_id)

    def enumerate_devices(self, *, kind: str | None = None) -> list[DeviceInfo]:
        with self._lock:
            if kind is not None and kind not in KINDS:
                raise self._invalid("kind")
            rows = [
                info for info in self._devices.values()
                if kind is None or info.kind == kind
            ]
            return sorted(rows, key=lambda info: (info.kind, info.device_id))

    def request_access(self, session: str, kind: str, devices=None, *,
                       now: str | None = None) -> AccessGrant:
        with self._lock:
            if not isinstance(session, str) or not session or kind not in KINDS:
                raise self._invalid("session or kind")

            if devices is None:
                requested = [
                    info.device_id for info in self._devices.values()
                    if info.kind == kind and info.present
                ]
            else:
                if isinstance(devices, (str, bytes)):
                    raise self._invalid("devices")
                try:
                    requested = list(devices)
                except TypeError:
                    raise self._invalid("devices") from None

            if not requested:
                raise self._invalid("devices")

            normalized: list[str] = []
            for device_id in requested:
                if not isinstance(device_id, str) or not device_id:
                    raise self._invalid("device")
                info = self._devices.get(device_id)
                if info is None:
                    raise MediaAccessError("MEDIA_DEVICE_UNKNOWN", device_id)
                if info.kind != kind:
                    raise self._invalid(device_id)
                normalized.append(device_id)

            requested_set = tuple(sorted(set(normalized)))
            key = (session, kind)
            existing = self._grants.get(key)
            if existing is None:
                grant = AccessGrant(
                    session=session,
                    kind=kind,
                    devices=requested_set,
                    revision=1,
                    granted_at=now,
                )
                self._grants[key] = grant
                self._stats["grants"] += 1
                return grant

            merged = tuple(sorted(set(existing.devices).union(requested_set)))
            if merged == existing.devices:
                return existing

            grant = replace(
                existing,
                devices=merged,
                revision=existing.revision + 1,
                granted_at=now,
            )
            self._grants[key] = grant
            return grant

    def open_stream(self, session: str, device_id: str, *, mode: str = READ,
                    shared: bool = False, now: str | None = None) -> StreamHandle:
        with self._lock:
            if mode not in MODES:
                raise self._invalid("mode")
            if not isinstance(session, str):
                raise self._invalid("session")

            info = self._device(device_id)
            if not info.present:
                raise MediaAccessError("MEDIA_DEVICE_ABSENT", device_id)

            grant = self._grants.get((session, info.kind))
            if grant is None or device_id not in grant.devices:
                raise MediaAccessError("MEDIA_ACCESS_DENIED", device_id)

            shared_read = bool(shared) and mode == READ
            active = self._active_streams()
            if not shared_read:
                if any(stream.device_id == device_id for stream in active):
                    raise MediaAccessError("MEDIA_DEVICE_BUSY", device_id)

            session_active = sum(
                1 for stream in active if stream.session == session
            )
            if (session_active >= self.max_streams_per_session
                    or len(active) >= self.max_streams_total):
                raise MediaAccessError("MEDIA_STREAM_LIMIT", device_id)

            sequence = self._next_stream_seq
            stream_id = f"{device_id}/s{sequence}"
            stream = StreamHandle(
                stream_id=stream_id,
                session=session,
                device_id=device_id,
                kind=info.kind,
                mode=mode,
                shared=shared_read,
                live=True,
            )
            self._next_stream_seq += 1
            self._streams[stream_id] = stream
            self._stats["streams_opened"] += 1
            return stream

    def close_stream(self, stream_id: str) -> bool:
        with self._lock:
            if not isinstance(stream_id, str):
                return False
            stream = self._streams.get(stream_id)
            if stream is None or not stream.live:
                return False
            self._streams[stream_id] = replace(stream, live=False)
            self._stats["streams_closed"] += 1
            return True

    def revoke(self, session: str, kind: str | None = None, *,
               now: str | None = None) -> int:
        with self._lock:
            if kind is not None and kind not in KINDS:
                raise self._invalid("kind")

            keys = [
                key for key in self._grants
                if key[0] == session and (kind is None or key[1] == kind)
            ]
            if not keys:
                return 0

            for key in keys:
                del self._grants[key]

            return self._force_close(
                lambda stream: (
                    stream.session == session
                    and (kind is None or stream.kind == kind)
                )
            )

    def end_session(self, session: str, *, now: str | None = None) -> dict:
        with self._lock:
            keys = [key for key in self._grants if key[0] == session]
            for key in keys:
                del self._grants[key]

            streams = self._force_close(
                lambda stream: stream.session == session
            )
            if keys or streams:
                self._stats["sessions_ended"] += 1
            return {"grants": len(keys), "streams": streams}

    def indicator_state(self) -> dict:
        with self._lock:
            kinds = tuple(sorted({
                stream.kind for stream in self._streams.values() if stream.live
            }))
            return {"active": bool(kinds), "kinds": kinds}

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "devices": [
                    {
                        "device_id": info.device_id,
                        "kind": info.kind,
                        "present": info.present,
                    }
                    for info in sorted(
                        self._devices.values(),
                        key=lambda item: (item.kind, item.device_id),
                    )
                ],
                "grants": [
                    {
                        "session": grant.session,
                        "kind": grant.kind,
                        "devices": list(grant.devices),
                        "revision": grant.revision,
                        "granted_at": grant.granted_at,
                    }
                    for grant in sorted(
                        self._grants.values(),
                        key=lambda item: (item.session, item.kind),
                    )
                ],
                "streams": [
                    {
                        "stream_id": stream.stream_id,
                        "session": stream.session,
                        "device_id": stream.device_id,
                        "kind": stream.kind,
                        "mode": stream.mode,
                        "shared": stream.shared,
                        "live": stream.live,
                    }
                    for stream in self._streams.values()
                ],
                "counters": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        invalid = lambda detail=None: MediaAccessError(
            "MEDIA_SNAPSHOT_INVALID", detail
        )
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise invalid("state")
                try:
                    version = state["version"]
                    raw_devices = state["devices"]
                    raw_grants = state["grants"]
                    raw_streams = state["streams"]
                    raw_counters = state["counters"]
                except KeyError as exc:
                    raise invalid(f"missing {exc.args[0]}") from None

                if type(version) is not int or version != SNAPSHOT_VERSION:
                    raise invalid("version")
                if not isinstance(raw_devices, list):
                    raise invalid("devices")
                if not isinstance(raw_grants, list):
                    raise invalid("grants")
                if not isinstance(raw_streams, list):
                    raise invalid("streams")
                if not isinstance(raw_counters, dict):
                    raise invalid("counters")

                devices: dict[str, DeviceInfo] = {}
                for row in raw_devices:
                    if not isinstance(row, dict):
                        raise invalid("device")
                    if not {"device_id", "kind", "present"} <= set(row):
                        raise invalid("device")
                    device_id = row["device_id"]
                    kind = row["kind"]
                    present = row["present"]
                    if (not isinstance(device_id, str) or not device_id
                            or kind not in KINDS or type(present) is not bool
                            or device_id in devices):
                        raise invalid("device")
                    devices[device_id] = DeviceInfo(device_id, kind, present)

                grants: dict[tuple[str, str], AccessGrant] = {}
                for row in raw_grants:
                    if not isinstance(row, dict):
                        raise invalid("grant")
                    if not {
                        "session", "kind", "devices", "revision", "granted_at"
                    } <= set(row):
                        raise invalid("grant")
                    session = row["session"]
                    kind = row["kind"]
                    raw_grant_devices = row["devices"]
                    revision = row["revision"]
                    granted_at = row["granted_at"]
                    if not isinstance(session, str) or not session:
                        raise invalid("grant session")
                    if kind not in KINDS:
                        raise invalid("grant kind")
                    if (type(revision) is not int or revision < 1
                            or not (granted_at is None
                                    or isinstance(granted_at, str))):
                        raise invalid("grant metadata")
                    if not isinstance(raw_grant_devices, (list, tuple)):
                        raise invalid("grant devices")
                    if not raw_grant_devices:
                        raise invalid("grant devices")
                    grant_devices: list[str] = []
                    for device_id in raw_grant_devices:
                        if (not isinstance(device_id, str)
                                or device_id not in devices
                                or devices[device_id].kind != kind
                                or device_id in grant_devices):
                            raise invalid("grant device")
                        grant_devices.append(device_id)
                    key = (session, kind)
                    if key in grants:
                        raise invalid("duplicate grant")
                    grants[key] = AccessGrant(
                        session=session,
                        kind=kind,
                        devices=tuple(sorted(grant_devices)),
                        revision=revision,
                        granted_at=granted_at,
                    )

                streams: dict[str, StreamHandle] = {}
                used_sequences: set[int] = set()
                for row in raw_streams:
                    if not isinstance(row, dict):
                        raise invalid("stream")
                    if not {
                        "stream_id", "session", "device_id", "kind",
                        "mode", "shared", "live",
                    } <= set(row):
                        raise invalid("stream")
                    stream_id = row["stream_id"]
                    session = row["session"]
                    device_id = row["device_id"]
                    kind = row["kind"]
                    mode = row["mode"]
                    shared = row["shared"]
                    live = row["live"]
                    if (not isinstance(stream_id, str)
                            or not isinstance(session, str) or not session
                            or not isinstance(device_id, str)
                            or device_id not in devices
                            or kind != devices[device_id].kind
                            or mode not in MODES
                            or type(shared) is not bool
                            or type(live) is not bool
                            or (shared and mode != READ)
                            or stream_id in streams):
                        raise invalid("stream")

                    prefix = f"{device_id}/s"
                    if not stream_id.startswith(prefix):
                        raise invalid("stream id")
                    suffix = stream_id[len(prefix):]
                    if not suffix.isdigit():
                        raise invalid("stream id")
                    sequence = int(suffix)
                    if (sequence < 1 or sequence in used_sequences
                            or f"{prefix}{sequence}" != stream_id):
                        raise invalid("stream sequence")
                    used_sequences.add(sequence)

                    stream = StreamHandle(
                        stream_id=stream_id,
                        session=session,
                        device_id=device_id,
                        kind=kind,
                        mode=mode,
                        shared=shared,
                        live=live,
                    )
                    streams[stream_id] = stream

                counters: dict[str, int] = {}
                for key in COUNTER_KEYS:
                    if key not in raw_counters:
                        raise invalid(f"counter {key}")
                    value = raw_counters[key]
                    if type(value) is not int or value < 0:
                        raise invalid(f"counter {key}")
                    counters[key] = value

                expected_next = max(used_sequences, default=0) + 1
                if ("next_stream_seq" in raw_counters
                        and raw_counters["next_stream_seq"] != expected_next):
                    raise invalid("next_stream_seq")

                live_streams = [stream for stream in streams.values() if stream.live]
                dead_streams = len(streams) - len(live_streams)
                if counters["streams_opened"] != len(streams):
                    raise invalid("streams_opened")
                if (counters["streams_closed"]
                        + counters["streams_forced_closed"] != dead_streams):
                    raise invalid("stream close counters")
                if counters["grants"] < len(grants):
                    raise invalid("grants")

                for stream in live_streams:
                    if not devices[stream.device_id].present:
                        raise invalid("live stream device absent")
                    grant = grants.get((stream.session, stream.kind))
                    if grant is None or stream.device_id not in grant.devices:
                        raise invalid("live stream without grant")
                exclusive_devices: set[str] = set()
                for stream in live_streams:
                    if stream.shared:
                        continue
                    if stream.device_id in exclusive_devices:
                        raise invalid("multiple exclusive streams")
                    exclusive_devices.add(stream.device_id)

                new_state = (
                    devices,
                    grants,
                    streams,
                    expected_next,
                    counters,
                )
            except MediaAccessError as exc:
                if exc.code == "MEDIA_SNAPSHOT_INVALID":
                    raise
                raise invalid(str(exc)) from None
            except Exception as exc:
                raise invalid(str(exc)) from None

            self._devices, self._grants, self._streams, self._next_stream_seq, \
                self._stats = new_state

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
