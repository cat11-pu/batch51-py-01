"""Input device grab guard.

Logical input devices are registered with their event nodes, capabilities and
physical path.  One session at a time may grab a device; grabs carry a lease
so a crashed process is reclaimed, and a hot-plugged device is rebound along
its physical path.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace

PURPOSES = ("hotkey-capture", "keyboard-capture", "pointer-capture")
STAT_KEYS = ("registered", "grabbed", "merged", "ungrabbed", "expired",
             "session_releases")
SNAPSHOT_KEYS = ("version", "devices", "grabs", "sessions", "counters")
SNAPSHOT_VERSION = 1


class InputGrabError(ValueError):
    """Refusal raised while registering devices or taking grabs."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceInfo:
    """One logical input device."""

    device_id: str
    physical_path: str
    nodes: tuple
    inode: int
    capabilities: tuple
    keyboard: bool
    present: bool


@dataclass(frozen=True)
class GrabHandle:
    """One exclusive grab of a logical device."""

    grab_id: str
    device_id: str
    session: str
    pid: int
    purpose: str
    started_at: int
    lease_expires: int
    stale: bool


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _is_int(value: object) -> bool:
    return type(value) is int


class InputDeviceGrabGuard:
    """Track /dev/input devices and exclusive grabs per session."""

    def __init__(self, *, max_devices: int = 64, max_grabs: int = 32,
                 max_grabs_per_session: int = 4,
                 lease_ttl: int = 30) -> None:
        self.max_devices = max_devices
        self.max_grabs = max_grabs
        self.max_grabs_per_session = max_grabs_per_session
        self.lease_ttl = lease_ttl
        self._lock = threading.RLock()
        self._devices = {}
        self._grabs = {}
        self._sessions = {}
        self._next_device = 1
        self._next_grab = 1
        self._stats = {key: 0 for key in STAT_KEYS}

    @staticmethod
    def _invalid(detail: object = None) -> InputGrabError:
        return InputGrabError("INPUT_INVALID_REQUEST", detail)

    @staticmethod
    def _normalise_names(value: object, field: str) -> tuple:
        if isinstance(value, str):
            values = (value,)
        else:
            try:
                values = tuple(value)
            except (TypeError, ValueError):
                raise InputGrabError(
                    "INPUT_INVALID_REQUEST", {"field": field}
                ) from None

        if not values:
            raise InputGrabError("INPUT_INVALID_REQUEST", {"field": field})

        result = []
        for item in values:
            if not _is_text(item):
                raise InputGrabError(
                    "INPUT_INVALID_REQUEST", {"field": field}
                )
            if item not in result:
                result.append(item)
        return tuple(result)

    def _device(self, device_id: str) -> DeviceInfo:
        try:
            return self._devices[device_id]
        except (KeyError, TypeError):
            raise InputGrabError(
                "INPUT_DEVICE_UNKNOWN", {"device": device_id}
            ) from None

    def _grab_for_device(self, device_id: str) -> GrabHandle | None:
        for handle in self._grabs.values():
            if handle.device_id == device_id:
                return handle
        return None

    def _session_grab_ids(self, session: str) -> tuple:
        return tuple(
            grab_id for grab_id, handle in self._grabs.items()
            if handle.session == session
        )

    def register_device(self, physical_path: str, *, event_nodes,
                        capabilities, inode: int,
                        keyboard: bool = False) -> DeviceInfo:
        """Register one logical input device and return it."""
        with self._lock:
            if not isinstance(physical_path, str) or \
                    not physical_path.startswith("/"):
                raise self._invalid({"field": "physical_path"})
            nodes = self._normalise_names(event_nodes, "event_nodes")
            caps = self._normalise_names(capabilities, "capabilities")
            if not _is_positive_int(inode):
                raise self._invalid({"field": "inode"})
            if not isinstance(keyboard, bool):
                raise self._invalid({"field": "keyboard"})
            if any(device.physical_path == physical_path
                   for device in self._devices.values()):
                raise self._invalid({"field": "physical_path",
                                     "physical_path": physical_path})
            if len(self._devices) >= self.max_devices:
                raise InputGrabError(
                    "INPUT_CAPACITY", {"limit": self.max_devices}
                )

            while f"input-{self._next_device}" in self._devices:
                self._next_device += 1
            device_id = f"input-{self._next_device}"
            self._next_device += 1
            info = DeviceInfo(
                device_id=device_id,
                physical_path=physical_path,
                nodes=nodes,
                inode=inode,
                capabilities=caps,
                keyboard=keyboard,
                present=True,
            )
            self._devices[device_id] = info
            self._stats["registered"] += 1
            return info

    def unplug(self, device_id: str) -> bool:
        """Mark a device as unplugged and report whether it was present."""
        with self._lock:
            device = self._devices.get(device_id)
            if device is None or not device.present:
                return False

            self._devices[device_id] = replace(device, present=False)
            for grab_id, handle in tuple(self._grabs.items()):
                if handle.device_id == device_id and not handle.stale:
                    self._grabs[grab_id] = replace(handle, stale=True)
            return True

    def rebind(self, device_id: str, *, event_node: str, inode: int,
               session: str, now: int = 0) -> DeviceInfo:
        """Rebind a reinserted device along its physical path."""
        with self._lock:
            device = self._device(device_id)
            if not _is_text(event_node):
                raise self._invalid({"field": "event_node"})
            if not _is_positive_int(inode):
                raise self._invalid({"field": "inode"})
            if not _is_text(session):
                raise self._invalid({"field": "session"})

            holder = self._grab_for_device(device_id)
            if holder is not None and holder.session != session:
                raise InputGrabError(
                    "INPUT_NOT_OWNER", {"session": session}
                )

            updated = replace(
                device,
                nodes=(event_node,),
                inode=inode,
                present=True,
            )
            self._devices[device_id] = updated
            for grab_id, handle in tuple(self._grabs.items()):
                if handle.device_id == device_id:
                    self._grabs[grab_id] = replace(
                        handle,
                        lease_expires=now + self.lease_ttl,
                        stale=False,
                    )
            return updated

    def grab(self, device_id: str, *, session: str, pid: int, purpose: str,
             now: int = 0, authorized: bool = False) -> GrabHandle:
        """Take an exclusive grab of ``device_id`` for ``session``."""
        with self._lock:
            device = self._device(device_id)
            if not device.present:
                raise InputGrabError(
                    "INPUT_DEVICE_ABSENT", {"device": device_id}
                )
            if not _is_text(session):
                raise self._invalid({"field": "session"})
            if purpose not in PURPOSES:
                raise self._invalid({"field": "purpose"})

            caps = device.capabilities
            if purpose == "keyboard-capture":
                capable = device.keyboard and "EV_KEY" in caps
            elif purpose == "pointer-capture":
                capable = "EV_REL" in caps or "EV_ABS" in caps
            else:
                capable = "EV_KEY" in caps
            if not capable:
                raise InputGrabError(
                    "INPUT_CAPABILITY_MISSING", {"purpose": purpose}
                )

            if device.keyboard and not authorized:
                raise InputGrabError(
                    "INPUT_AUTH_REQUIRED", {"device": device_id}
                )

            holder = self._grab_for_device(device_id)
            if holder is not None:
                if holder.session != session:
                    raise InputGrabError(
                        "INPUT_DEVICE_BUSY", {"session": holder.session}
                    )
                if holder.purpose == purpose:
                    refreshed = replace(
                        holder,
                        lease_expires=now + self._merge_lease_ttl(),
                    )
                    self._grabs[holder.grab_id] = refreshed
                    self._stats["merged"] += 1
                    return refreshed
                raise InputGrabError(
                    "INPUT_DEVICE_BUSY", {"session": holder.session}
                )

            session_grabs = self._session_grab_ids(session)
            if len(session_grabs) >= self.max_grabs_per_session:
                raise InputGrabError(
                    "INPUT_SESSION_LIMIT",
                    {"session": session, "limit": self.max_grabs_per_session},
                )
            if len(self._grabs) >= self.max_grabs:
                raise InputGrabError(
                    "INPUT_CAPACITY", {"limit": self.max_grabs}
                )

            while f"grab-{self._next_grab}" in self._grabs:
                self._next_grab += 1
            grab_id = f"grab-{self._next_grab}"
            self._next_grab += 1
            handle = GrabHandle(
                grab_id=grab_id,
                device_id=device_id,
                session=session,
                pid=pid,
                purpose=purpose,
                started_at=now,
                lease_expires=now + self.lease_ttl,
                stale=False,
            )
            self._grabs[grab_id] = handle
            self._sessions.setdefault(session, False)
            self._stats["grabbed"] += 1
            return handle

    def ungrab(self, grab_id: str, *, session: str | None = None) -> bool:
        """Release one grab and report whether it existed."""
        with self._lock:
            try:
                handle = self._grabs.get(grab_id)
            except TypeError:
                return False
            if handle is None:
                return False
            if handle.session != session:
                raise InputGrabError(
                    "INPUT_NOT_OWNER", {"session": session}
                )
            del self._grabs[grab_id]
            self._stats["ungrabbed"] += 1
            return True

    def release_session(self, session: str) -> int:
        """Release every grab owned by ``session`` and return the count."""
        with self._lock:
            grab_ids = self._session_grab_ids(session)
            for grab_id in grab_ids:
                del self._grabs[grab_id]
            if grab_ids:
                self._stats["session_releases"] += 1
            return len(grab_ids)

    def heartbeat(self, grab_id: str, *, now: int = 0) -> int:
        """Renew one grab lease and return the new expiry."""
        with self._lock:
            try:
                handle = self._grabs[grab_id]
            except (KeyError, TypeError):
                raise InputGrabError(
                    "INPUT_GRAB_UNKNOWN", {"grab": grab_id}
                ) from None
            expiry = now + self.lease_ttl
            self._grabs[grab_id] = replace(handle, lease_expires=expiry)
            return expiry

    def _merge_lease_ttl(self) -> int:
        return max(1, self.lease_ttl // 3)

    def expire(self, *, now: int = 0) -> int:
        """Reclaim grabs whose lease expired and return the count."""
        with self._lock:
            expired = [
                grab_id for grab_id, handle in self._grabs.items()
                if handle.lease_expires <= now
            ]
            for grab_id in expired:
                del self._grabs[grab_id]
            self._stats["expired"] += len(expired)
            return len(expired)

    def set_session_locked(self, session: str, locked: bool) -> None:
        """Record whether a session is currently locked."""
        with self._lock:
            if not _is_text(session):
                raise self._invalid({"field": "session"})
            if not isinstance(locked, bool):
                raise self._invalid({"field": "locked"})
            self._sessions[session] = locked

    def delivery_target(self, grab_id: str):
        """Return the session allowed to receive keys, or None."""
        with self._lock:
            try:
                handle = self._grabs.get(grab_id)
            except TypeError:
                return None
            if handle is None or handle.stale:
                return None
            device = self._devices.get(handle.device_id)
            if device is None or not device.present:
                return None
            if self._sessions.get(handle.session, False):
                return None
            return handle.session

    def device_state(self, device_id: str) -> dict:
        """Return presence and holder information for one device."""
        with self._lock:
            device = self._device(device_id)
            holder = self._grab_for_device(device_id)
            return {
                "device_id": device.device_id,
                "physical_path": device.physical_path,
                "nodes": device.nodes,
                "inode": device.inode,
                "capabilities": device.capabilities,
                "keyboard": device.keyboard,
                "present": device.present,
                "holder": None if holder is None else holder.session,
            }

    def session_state(self, session: str) -> dict:
        """Return lock state and grab ids for one session."""
        with self._lock:
            return {
                "locked": bool(self._sessions.get(session, False)),
                "grabs": self._session_grab_ids(session),
            }

    def enumerate(self) -> tuple:
        """Return the registered devices in registration order."""
        with self._lock:
            return tuple(self._devices.values())

    def grabs(self, *, session: str | None = None) -> tuple:
        """Return grab handles in grab order, optionally for one session."""
        with self._lock:
            if session is None:
                return tuple(self._grabs.values())
            return tuple(
                handle for handle in self._grabs.values()
                if handle.session == session
            )

    def snapshot(self) -> dict:
        """Return a detached snapshot of devices, grabs and counters."""
        with self._lock:
            devices = [
                {
                    "device_id": device.device_id,
                    "physical_path": device.physical_path,
                    "nodes": list(device.nodes),
                    "inode": device.inode,
                    "capabilities": list(device.capabilities),
                    "keyboard": device.keyboard,
                    "present": device.present,
                }
                for device in self._devices.values()
            ]
            grabs = [
                {
                    "grab_id": handle.grab_id,
                    "device_id": handle.device_id,
                    "session": handle.session,
                    "pid": handle.pid,
                    "purpose": handle.purpose,
                    "started_at": handle.started_at,
                    "lease_expires": handle.lease_expires,
                    "stale": handle.stale,
                }
                for handle in self._grabs.values()
            ]
            sessions = {
                session: {"locked": locked}
                for session, locked in self._sessions.items()
            }
            return {
                "version": SNAPSHOT_VERSION,
                "devices": devices,
                "grabs": grabs,
                "sessions": sessions,
                "counters": dict(self._stats),
            }

    @staticmethod
    def _snapshot_names(value: object, field: str) -> tuple:
        if not isinstance(value, (list, tuple)) or not value:
            raise ValueError(field)
        result = []
        for item in value:
            if not _is_text(item):
                raise ValueError(field)
            if item not in result:
                result.append(item)
        return tuple(result)

    @staticmethod
    def _next_id(prefix: str, identifiers) -> int:
        numbers = []
        for identifier in identifiers:
            if identifier.startswith(prefix) and \
                    identifier[len(prefix):].isdigit():
                numbers.append(int(identifier[len(prefix):]))
        candidate = max(numbers, default=0) + 1
        existing = set(identifiers)
        while f"{prefix}{candidate}" in existing:
            candidate += 1
        return candidate

    def _parse_snapshot(self, state: object) -> tuple:
        if not isinstance(state, dict) or \
                set(state) != set(SNAPSHOT_KEYS):
            raise ValueError("snapshot keys")
        if type(state["version"]) is not int or \
                state["version"] != SNAPSHOT_VERSION:
            raise ValueError("version")

        raw_devices = state["devices"]
        raw_grabs = state["grabs"]
        raw_sessions = state["sessions"]
        raw_counters = state["counters"]
        if not isinstance(raw_devices, list):
            raise ValueError("devices")
        if not isinstance(raw_grabs, list):
            raise ValueError("grabs")
        if not isinstance(raw_sessions, dict):
            raise ValueError("sessions")
        if not isinstance(raw_counters, dict) or \
                set(raw_counters) != set(STAT_KEYS):
            raise ValueError("counters")
        if len(raw_devices) > self.max_devices or \
                len(raw_grabs) > self.max_grabs:
            raise ValueError("capacity")
        if any(type(value) is not int or value < 0
               for value in raw_counters.values()):
            raise ValueError("counters")

        device_keys = {
            "device_id", "physical_path", "nodes", "inode", "capabilities",
            "keyboard", "present",
        }
        devices = {}
        physical_paths = set()
        for raw in raw_devices:
            if not isinstance(raw, dict) or set(raw) != device_keys:
                raise ValueError("device")
            device_id = raw["device_id"]
            physical_path = raw["physical_path"]
            if not _is_text(device_id) or device_id in devices:
                raise ValueError("device_id")
            if not isinstance(physical_path, str) or \
                    not physical_path.startswith("/") or \
                    physical_path in physical_paths:
                raise ValueError("physical_path")
            nodes = self._snapshot_names(raw["nodes"], "nodes")
            capabilities = self._snapshot_names(
                raw["capabilities"], "capabilities"
            )
            inode = raw["inode"]
            if not _is_positive_int(inode):
                raise ValueError("inode")
            if not isinstance(raw["keyboard"], bool) or \
                    not isinstance(raw["present"], bool):
                raise ValueError("device flags")
            devices[device_id] = DeviceInfo(
                device_id=device_id,
                physical_path=physical_path,
                nodes=nodes,
                inode=inode,
                capabilities=capabilities,
                keyboard=raw["keyboard"],
                present=raw["present"],
            )
            physical_paths.add(physical_path)

        session_keys = {"locked"}
        sessions = {}
        for session, raw in raw_sessions.items():
            if not _is_text(session) or not isinstance(raw, dict) or \
                    set(raw) != session_keys or \
                    not isinstance(raw["locked"], bool):
                raise ValueError("session")
            sessions[session] = raw["locked"]

        grab_keys = {
            "grab_id", "device_id", "session", "pid", "purpose",
            "started_at", "lease_expires", "stale",
        }
        grabs = {}
        grabbed_devices = set()
        gathered_sessions = {}
        for raw in raw_grabs:
            if not isinstance(raw, dict) or set(raw) != grab_keys:
                raise ValueError("grab")
            grab_id = raw["grab_id"]
            device_id = raw["device_id"]
            session = raw["session"]
            if not _is_text(grab_id) or grab_id in grabs:
                raise ValueError("grab_id")
            if device_id not in devices or device_id in grabbed_devices:
                raise ValueError("grab device")
            if not _is_text(session) or raw["purpose"] not in PURPOSES:
                raise ValueError("grab owner")
            if not _is_int(raw["pid"]) or \
                    not _is_int(raw["started_at"]) or \
                    not _is_int(raw["lease_expires"]) or \
                    not isinstance(raw["stale"], bool):
                raise ValueError("grab fields")
            grabs[grab_id] = GrabHandle(
                grab_id=grab_id,
                device_id=device_id,
                session=session,
                pid=raw["pid"],
                purpose=raw["purpose"],
                started_at=raw["started_at"],
                lease_expires=raw["lease_expires"],
                stale=raw["stale"],
            )
            grabbed_devices.add(device_id)
            gathered_sessions[session] = \
                gathered_sessions.get(session, 0) + 1

        if any(count > self.max_grabs_per_session
               for count in gathered_sessions.values()):
            raise ValueError("session capacity")
        for session in gathered_sessions:
            sessions.setdefault(session, False)

        next_device = self._next_id(
            "input-", (device.device_id for device in devices.values())
        )
        next_grab = self._next_id(
            "grab-", (handle.grab_id for handle in grabs.values())
        )
        return devices, grabs, sessions, dict(raw_counters), \
            next_device, next_grab

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except Exception as exc:
                raise InputGrabError(
                    "INPUT_SNAPSHOT_INVALID", {"reason": str(exc)}
                ) from None
            devices, grabs, sessions, counters, next_device, next_grab = parsed
            self._devices = devices
            self._grabs = grabs
            self._sessions = sessions
            self._stats = counters
            self._next_device = next_device
            self._next_grab = next_grab

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return {key: self._stats[key] for key in STAT_KEYS}
