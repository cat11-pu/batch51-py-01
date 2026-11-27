"""BFD session state and detection timer governance."""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass

SNAPSHOT_VERSION = 1
DOWN = "down"
INIT = "init"
UP = "up"


class BfdError(ValueError):
    """Raised when a session operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionView:
    session_id: str
    state: str
    local_discriminator: int
    remote_discriminator: int
    detection_time: int
    next_timeout_at: int | None
    auth_sequence: int


@dataclass(frozen=True)
class ReceiveResult:
    session_id: str
    accepted: bool
    reason: str
    state: str


class BfdSessionGuard:
    """Keep BFD sessions through down, init and up with detection timers."""

    _SESSION_FIELDS = {
        "local_discriminator",
        "remote_discriminator",
        "state",
        "detection_time",
        "next_timeout_at",
        "auth_sequence",
        "auth_keys",
    }

    def __init__(self, *, detection_multiplier: int = 3,
                 min_tx_interval: int = 50, auth_enabled: bool = True,
                 max_sessions: int = 64) -> None:
        self.detection_multiplier = detection_multiplier
        self.min_tx_interval = min_tx_interval
        self.auth_enabled = auth_enabled
        self.max_sessions = max_sessions
        self._lock = threading.RLock()
        self._sessions: dict[str, dict] = {}
        self._stats = {
            "created": 0,
            "transitioned": 0,
            "timeouts": 0,
            "auth_failures": 0,
            "duplicates": 0,
            "rejected": 0,
            "rebuilds": 0,
        }

    @staticmethod
    def _clock() -> float:
        return time.monotonic()

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _get_session(self, session_id: str) -> dict:
        try:
            return self._sessions[session_id]
        except (KeyError, TypeError):
            raise BfdError("BFD_UNKNOWN_SESSION", session_id) from None

    def _view(self, session_id: str, session: dict) -> SessionView:
        return SessionView(
            session_id=session_id,
            state=session["state"],
            local_discriminator=session["local_discriminator"],
            remote_discriminator=session["remote_discriminator"],
            detection_time=session["detection_time"],
            next_timeout_at=session["next_timeout_at"],
            auth_sequence=session["auth_sequence"],
        )

    def _set_down(self, session: dict) -> bool:
        if session["state"] == DOWN:
            return False
        session["state"] = DOWN
        self._stats["transitioned"] += 1
        return True

    def _expire(self, session: dict, now) -> bool:
        deadline = session["next_timeout_at"]
        if deadline is None or now < deadline:
            return False
        self._set_down(session)
        session["next_timeout_at"] = None
        self._stats["timeouts"] += 1
        return True

    def _validate_auth(self, session: dict, packet: dict) -> str:
        keys = session["auth_keys"]
        key_id = packet.get("auth_key")
        sequence = packet.get("auth_seq")
        if key_id not in keys or not self._is_int(sequence):
            self._stats["auth_failures"] += 1
            return "failure"
        current = session["auth_sequence"]
        if sequence == current:
            self._stats["duplicates"] += 1
            return "duplicate"
        if sequence < current:
            self._stats["auth_failures"] += 1
            return "failure"
        session["auth_sequence"] = sequence
        return "ok"

    def create_session(self, session_id: str, local_discriminator: int,
                       remote_discriminator: int = 0,
                       now=None) -> SessionView:
        with self._lock:
            if session_id in self._sessions:
                raise BfdError("BFD_SESSION_EXISTS", session_id)
            for existing in self._sessions.values():
                if existing["local_discriminator"] == local_discriminator:
                    raise BfdError(
                        "BFD_DISCRIMINATOR_TAKEN", local_discriminator
                    )
            if len(self._sessions) >= self.max_sessions:
                raise BfdError("BFD_SESSION_LIMIT", self.max_sessions)
            session = {
                "local_discriminator": local_discriminator,
                "remote_discriminator": remote_discriminator,
                "state": DOWN,
                "detection_time": (
                    self.detection_multiplier * self.min_tx_interval
                ),
                "next_timeout_at": None,
                "auth_sequence": 0,
                "auth_keys": {},
            }
            self._sessions[session_id] = session
            self._stats["created"] += 1
            return self._view(session_id, session)

    def session_view(self, session_id: str) -> SessionView:
        with self._lock:
            return self._view(session_id, self._get_session(session_id))

    def receive(self, session_id: str, packet, now=None) -> ReceiveResult:
        with self._lock:
            session = self._get_session(session_id)
            try:
                packet_local = packet["local_discriminator"]
            except (KeyError, TypeError):
                packet_local = None
            if packet_local != session["local_discriminator"]:
                self._stats["rejected"] += 1
                return ReceiveResult(
                    session_id, False, "local_discriminator_mismatch",
                    session["state"],
                )

            current = self._clock() if now is None else now
            self._expire(session, current)

            try:
                packet_remote = packet.get(
                    "remote_discriminator",
                    session["remote_discriminator"],
                )
            except AttributeError:
                packet_remote = session["remote_discriminator"]

            learn_remote = False
            if packet_remote != session["remote_discriminator"]:
                if (
                    session["remote_discriminator"] == 0
                    and session["state"] == DOWN
                ):
                    learn_remote = True
                else:
                    self._set_down(session)
                    session["next_timeout_at"] = None
                    self._stats["rejected"] += 1
                    return ReceiveResult(
                        session_id, False, "remote_discriminator_mismatch",
                        session["state"],
                    )

            if self.auth_enabled:
                auth_result = self._validate_auth(session, packet)
                if auth_result == "duplicate":
                    return ReceiveResult(
                        session_id, False, "duplicate", session["state"]
                    )
                if auth_result == "failure":
                    return ReceiveResult(
                        session_id, False, "authentication_failed",
                        session["state"],
                    )

            if learn_remote:
                session["remote_discriminator"] = packet_remote
            if session["state"] == DOWN:
                session["state"] = INIT
                self._stats["transitioned"] += 1
            elif session["state"] == INIT:
                session["state"] = UP
                self._stats["transitioned"] += 1
            session["next_timeout_at"] = current + session["detection_time"]
            return ReceiveResult(
                session_id, True, "accepted", session["state"]
            )

    def advance(self, now) -> tuple[str, ...]:
        with self._lock:
            current = self._clock() if now is None else now
            due = []
            for session_id, session in self._sessions.items():
                deadline = session["next_timeout_at"]
                if deadline is not None and deadline <= current:
                    due.append((deadline, session_id))
            due.sort(key=lambda item: (item[0], item[1]))
            timed_out = []
            for _, session_id in due:
                session = self._sessions[session_id]
                self._expire(session, current)
                timed_out.append(session_id)
            return tuple(timed_out)

    def authenticate(self, session_id: str, packet) -> bool:
        with self._lock:
            session = self._get_session(session_id)
            if not isinstance(packet, dict):
                self._stats["auth_failures"] += 1
                return False
            return self._validate_auth(session, packet) == "ok"

    def set_auth_keys(self, session_id: str, key_id: int, secret: str) -> None:
        with self._lock:
            session = self._get_session(session_id)
            session["auth_keys"][key_id] = secret

    def rebuild(self, session_id: str, remote_discriminator: int,
                now=None) -> SessionView:
        with self._lock:
            session = self._get_session(session_id)
            self._set_down(session)
            session["remote_discriminator"] = remote_discriminator
            session["auth_sequence"] = 0
            session["next_timeout_at"] = None
            self._stats["rebuilds"] += 1
            return self._view(session_id, session)

    def session_state(self, session_id: str) -> str:
        with self._lock:
            return self._get_session(session_id)["state"]

    def peer(self, session_id: str) -> int:
        with self._lock:
            return self._get_session(session_id)["remote_discriminator"]

    def timers(self, session_id: str) -> dict:
        with self._lock:
            session = self._get_session(session_id)
            return {
                "detection_time": session["detection_time"],
                "next_timeout_at": session["next_timeout_at"],
            }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "sessions": copy.deepcopy(self._sessions),
                "stats": dict(self._stats),
            }

    def restore(self, state) -> None:
        with self._lock:
            sessions, stats = self._validated_snapshot(state)
            self._sessions = sessions
            self._stats = stats

    def _validated_snapshot(self, state) -> tuple[dict[str, dict], dict]:
        if not isinstance(state, dict):
            raise BfdError("BFD_SNAPSHOT_INVALID", "snapshot must be a dict")
        if set(state) != {"version", "sessions", "stats"}:
            raise BfdError("BFD_SNAPSHOT_INVALID", "snapshot keys")
        version = state["version"]
        if not self._is_int(version) or version != SNAPSHOT_VERSION:
            raise BfdError("BFD_SNAPSHOT_INVALID", "snapshot version")
        raw_sessions = state["sessions"]
        raw_stats = state["stats"]
        if not isinstance(raw_sessions, dict) or not isinstance(raw_stats, dict):
            raise BfdError("BFD_SNAPSHOT_INVALID", "snapshot container type")

        if set(raw_stats) != set(self._stats):
            raise BfdError("BFD_SNAPSHOT_INVALID", "stats keys")
        stats = {}
        for key, value in raw_stats.items():
            if not self._is_int(value) or value < 0:
                raise BfdError("BFD_SNAPSHOT_INVALID", f"stats.{key}")
            stats[key] = value

        sessions = {}
        locals_seen = set()
        for session_id, raw in raw_sessions.items():
            if not isinstance(session_id, str) or not isinstance(raw, dict):
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID", "session entry type"
                )
            if set(raw) != self._SESSION_FIELDS:
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID", f"session {session_id} keys"
                )
            local = raw["local_discriminator"]
            remote = raw["remote_discriminator"]
            detection = raw["detection_time"]
            deadline = raw["next_timeout_at"]
            sequence = raw["auth_sequence"]
            keys = raw["auth_keys"]
            if not self._is_int(local) or not self._is_int(remote):
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID",
                    f"session {session_id} discriminator",
                )
            if local in locals_seen:
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID",
                    f"session {session_id} duplicate local discriminator",
                )
            if raw["state"] not in (DOWN, INIT, UP):
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID", f"session {session_id} state"
                )
            if not self._is_int(detection) or detection < 0:
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID",
                    f"session {session_id} detection time",
                )
            if deadline is not None and (
                isinstance(deadline, bool)
                or not isinstance(deadline, (int, float))
            ):
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID",
                    f"session {session_id} timeout",
                )
            if not self._is_int(sequence) or sequence < 0:
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID",
                    f"session {session_id} auth sequence",
                )
            if not isinstance(keys, dict):
                raise BfdError(
                    "BFD_SNAPSHOT_INVALID",
                    f"session {session_id} auth keys",
                )
            for secret in keys.values():
                if not isinstance(secret, str):
                    raise BfdError(
                        "BFD_SNAPSHOT_INVALID",
                        f"session {session_id} auth secret",
                    )
            locals_seen.add(local)
            sessions[session_id] = {
                "local_discriminator": local,
                "remote_discriminator": remote,
                "state": raw["state"],
                "detection_time": detection,
                "next_timeout_at": deadline,
                "auth_sequence": sequence,
                "auth_keys": copy.deepcopy(keys),
            }
        return sessions, stats
