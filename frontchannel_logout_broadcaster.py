"""Front-channel logout broadcaster: per-session fan-out, acks and fallback."""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class FrontchannelError(ValueError):
    """Raised when a logout broadcast step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Participant:
    session_id: str
    participant_id: str
    url: str
    registered_at: str


@dataclass(frozen=True)
class LogoutEntry:
    participant_id: str
    url: str
    token: str
    status: str


@dataclass(frozen=True)
class Broadcast:
    session_id: str
    started_at: str
    entries: tuple[LogoutEntry, ...]


_STAT_KEYS = (
    "broadcasts",
    "entries",
    "confirmed",
    "failed",
    "fallbacks",
    "attempts",
    "closed",
    "duplicates",
)

_ENTRY_STATUSES = ("pending", "confirmed", "failed", "exhausted")

_SNAPSHOT_VERSION = 1


def _error(code: str, detail: object = None) -> FrontchannelError:
    return FrontchannelError("FRONTCHANNEL_" + code, detail)


def _parse_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class _BroadcastState:
    __slots__ = ("started_at", "deadline", "urls", "tokens", "statuses",
                 "attempts")

    def __init__(self, started_at, deadline, urls, tokens, statuses,
                 attempts):
        self.started_at = started_at
        self.deadline = deadline
        self.urls = urls
        self.tokens = tokens
        self.statuses = statuses
        self.attempts = attempts


class _SessionState:
    __slots__ = ("participants", "broadcast")

    def __init__(self):
        self.participants = {}
        self.broadcast = None


class FrontchannelLogoutBroadcaster:
    """Fan logout calls out to the participants bound to one session."""

    def __init__(self, *, timeout_ms: int = 800, max_attempts: int = 3,
                 clock=None) -> None:
        self.timeout_ms = timeout_ms
        self.max_attempts = max_attempts
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def _now_string(self, now: str | None) -> str:
        if now is not None:
            if not isinstance(now, str) or not now.strip():
                raise _error("REQUEST_INVALID", {"now": now})
            return now
        if self._clock is not None:
            value = self._clock() if callable(self._clock) else self._clock
            if isinstance(value, datetime):
                return _format_time(value)
            if isinstance(value, str) and value.strip():
                return value
            raise _error("REQUEST_INVALID", {"clock": value})
        return _format_time(datetime.now(timezone.utc))

    @staticmethod
    def _token(signer_key: str, session_id: str, participant_id: str) -> str:
        payload = f"{signer_key}|{session_id}|{participant_id}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _fanout_url(url: str, session_id: str, token: str) -> str:
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}session={session_id}&sig={token}"

    def _session_or_raise(self, session_id: str) -> _SessionState:
        session = self._sessions.get(session_id)
        if session is None:
            raise _error("SESSION_UNKNOWN", {"session_id": session_id})
        return session

    def register_participant(self, *, session_id: str, participant_id: str,
                             url: str, now: str | None = None) -> Participant:
        if not isinstance(session_id, str) or not session_id.strip():
            raise _error("REQUEST_INVALID", {"session_id": session_id})
        if not isinstance(participant_id, str) or not participant_id.strip():
            raise _error("REQUEST_INVALID", {"participant_id": participant_id})
        if (not isinstance(url, str) or not url.strip()
                or not (url.startswith("http://")
                        or url.startswith("https://"))):
            raise _error("REQUEST_INVALID", {"url": url})
        registered_at = self._now_string(now)
        participant = Participant(session_id=session_id,
                                  participant_id=participant_id,
                                  url=url, registered_at=registered_at)
        with self._lock:
            session = self._sessions.setdefault(session_id, _SessionState())
            session.participants[participant_id] = participant
        return participant

    def participants_for(self, session_id: str) -> tuple[str, ...]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return ()
            return tuple(sorted(session.participants))

    def broadcast(self, *, session_id: str, signer_key: str,
                  now: str | None = None) -> Broadcast:
        if not isinstance(signer_key, str) or not signer_key:
            raise _error("REQUEST_INVALID", {"signer_key": signer_key})
        started_at = self._now_string(now)
        with self._lock:
            session = self._session_or_raise(session_id)
            if session.broadcast is None:
                urls = {}
                tokens = {}
                statuses = {}
                attempts = {}
                for pid in sorted(session.participants):
                    token = self._token(signer_key, session_id, pid)
                    participant = session.participants[pid]
                    urls[pid] = self._fanout_url(participant.url,
                                                 session_id, token)
                    tokens[pid] = token
                    statuses[pid] = "pending"
                    attempts[pid] = 0
                deadline = _format_time(
                    _parse_time(started_at)
                    + timedelta(milliseconds=self.timeout_ms))
                session.broadcast = _BroadcastState(
                    started_at, deadline, urls, tokens, statuses, attempts)
                self._stats["broadcasts"] += 1
                self._stats["entries"] += len(urls)
            state = session.broadcast
            entries = tuple(
                LogoutEntry(participant_id=pid, url=state.urls[pid],
                            token=state.tokens[pid],
                            status=state.statuses[pid])
                for pid in sorted(state.tokens))
            return Broadcast(session_id=session_id,
                             started_at=state.started_at, entries=entries)

    def collect(self, *, session_id: str, participant_id: str, token: str,
                ok: bool = True, now: str | None = None) -> str:
        self._now_string(now)
        with self._lock:
            session = self._session_or_raise(session_id)
            state = session.broadcast
            if state is None:
                raise _error("NOT_BROADCAST", {"session_id": session_id})
            if participant_id not in state.tokens:
                raise _error("PARTICIPANT_UNKNOWN",
                             {"participant_id": participant_id})
            if token != state.tokens[participant_id]:
                raise _error("BAD_TOKEN", {"participant_id": participant_id})
            if state.statuses[participant_id] != "pending":
                self._stats["duplicates"] += 1
                raise _error("DUPLICATE_ACK",
                             {"participant_id": participant_id})
            outcome = "confirmed" if ok else "failed"
            state.statuses[participant_id] = outcome
            self._stats[outcome] += 1
            return outcome

    def fallback(self, *, session_id: str,
                 now: str | None = None) -> tuple[str, ...]:
        moment = self._now_string(now)
        with self._lock:
            session = self._session_or_raise(session_id)
            state = session.broadcast
            if state is None:
                return ()
            if _parse_time(moment) < _parse_time(state.deadline):
                return ()
            retried = []
            for pid in sorted(state.tokens):
                if state.statuses[pid] != "pending":
                    continue
                state.attempts[pid] += 1
                self._stats["attempts"] += 1
                retried.append(pid)
                if state.attempts[pid] >= self.max_attempts:
                    state.statuses[pid] = "exhausted"
            if retried:
                self._stats["fallbacks"] += 1
            return tuple(retried)

    def pending_for(self, session_id: str) -> tuple[str, ...]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.broadcast is None:
                return ()
            state = session.broadcast
            return tuple(pid for pid in sorted(state.tokens)
                         if state.statuses[pid] == "pending")

    def attempts_for(self, *, session_id: str, participant_id: str) -> int:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.broadcast is None:
                return 0
            return session.broadcast.attempts.get(participant_id, 0)

    def close_session(self, session_id: str) -> int:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return 0
            self._stats["closed"] += 1
            return len(session.participants)

    def snapshot(self) -> dict:
        with self._lock:
            sessions = {}
            for session_id, session in self._sessions.items():
                record = {
                    "participants": {
                        pid: {
                            "session_id": p.session_id,
                            "participant_id": p.participant_id,
                            "url": p.url,
                            "registered_at": p.registered_at,
                        }
                        for pid, p in session.participants.items()
                    },
                    "broadcast": None,
                }
                state = session.broadcast
                if state is not None:
                    record["broadcast"] = {
                        "started_at": state.started_at,
                        "deadline": state.deadline,
                        "urls": dict(state.urls),
                        "tokens": dict(state.tokens),
                        "statuses": dict(state.statuses),
                        "attempts": dict(state.attempts),
                    }
                sessions[session_id] = record
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "sessions": sessions,
                "stats": dict(self._stats),
            })

    @staticmethod
    def _validate_snapshot(state: object) -> None:
        def invalid(detail: object) -> FrontchannelError:
            return _error("SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            raise invalid(state)
        if state.get("version") != _SNAPSHOT_VERSION:
            raise invalid(state.get("version"))
        sessions = state.get("sessions")
        stats = state.get("stats")
        if not isinstance(sessions, dict) or not isinstance(stats, dict):
            raise invalid("structure")
        if set(stats) != set(_STAT_KEYS) or not all(
                _is_int(stats[key]) and stats[key] >= 0 for key in _STAT_KEYS):
            raise invalid("stats")
        for session_id, record in sessions.items():
            if not isinstance(session_id, str) or not isinstance(record, dict):
                raise invalid("session")
            participants = record.get("participants")
            broadcast = record.get("broadcast")
            if not isinstance(participants, dict):
                raise invalid("participants")
            for pid, participant in participants.items():
                if not isinstance(pid, str) or not isinstance(participant, dict):
                    raise invalid("participant")
                if (participant.get("session_id") != session_id
                        or participant.get("participant_id") != pid
                        or not isinstance(participant.get("url"), str)
                        or not isinstance(participant.get("registered_at"),
                                          str)):
                    raise invalid("participant")
            if broadcast is None:
                continue
            if not isinstance(broadcast, dict):
                raise invalid("broadcast")
            if (not isinstance(broadcast.get("started_at"), str)
                    or not isinstance(broadcast.get("deadline"), str)):
                raise invalid("broadcast")
            urls = broadcast.get("urls")
            tokens = broadcast.get("tokens")
            statuses = broadcast.get("statuses")
            attempts = broadcast.get("attempts")
            if not all(isinstance(section, dict)
                       for section in (urls, tokens, statuses, attempts)):
                raise invalid("broadcast")
            if not (set(urls) == set(tokens) == set(statuses) == set(attempts)):
                raise invalid("broadcast")
            for pid in tokens:
                if not isinstance(pid, str):
                    raise invalid("broadcast")
                if not isinstance(urls[pid], str) or not isinstance(
                        tokens[pid], str):
                    raise invalid("broadcast")
                if statuses[pid] not in _ENTRY_STATUSES:
                    raise invalid("broadcast")
                if not _is_int(attempts[pid]) or attempts[pid] < 0:
                    raise invalid("broadcast")

    def restore(self, state: dict) -> None:
        self._validate_snapshot(state)
        sessions = {}
        for session_id, record in state["sessions"].items():
            session = _SessionState()
            for pid, participant in record["participants"].items():
                session.participants[pid] = Participant(
                    session_id=participant["session_id"],
                    participant_id=participant["participant_id"],
                    url=participant["url"],
                    registered_at=participant["registered_at"])
            broadcast = record["broadcast"]
            if broadcast is not None:
                session.broadcast = _BroadcastState(
                    broadcast["started_at"], broadcast["deadline"],
                    dict(broadcast["urls"]), dict(broadcast["tokens"]),
                    dict(broadcast["statuses"]), dict(broadcast["attempts"]))
            sessions[session_id] = session
        stats = {key: state["stats"][key] for key in _STAT_KEYS}
        with self._lock:
            self._sessions = sessions
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
