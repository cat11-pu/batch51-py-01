"""Session fixation defence: identifier rotation, cookie scope checks, session caps."""

from __future__ import annotations

import copy
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


_SID_RE = re.compile(r"[0-9a-f]{32}\Z")
_COOKIE_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_COOKIE_ATTRIBUTES = {"secure", "httponly", "path", "domain", "samesite", "max-age"}
_SNAPSHOT_VERSION = 1
_COUNTER_NAMES = (
    "created", "rejected", "rotated", "elevated", "logged_in",
    "revoked", "expired", "restored", "evicted",
)


class SessionError(ValueError):
    """Raised when a session or cookie operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionRecord:
    sid: str
    user: str | None
    auth_level: int
    generation: int
    fingerprint: str | None
    created_at: str
    rotated_at: str


@dataclass(frozen=True)
class CookieSpec:
    name: str
    value: str
    secure: bool
    http_only: bool
    path: str
    domain: str | None
    same_site: str
    max_age: int | None


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    event: str
    subject: str
    code: str | None


def _parse_time(value: str | datetime) -> datetime:
    """Parse an ISO timestamp, treating naive values as UTC."""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp(now: str | datetime | None) -> str:
    if now is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(now, datetime):
        return now.isoformat()
    return now


class SessionFixationGuard:
    """Keep session identifiers rotating and cookie scopes inside policy."""

    def __init__(self, *, max_sessions_per_user: int = 5,
                 max_sessions_total: int = 1000, idle_timeout: int = 1800,
                 cookie_name: str = "__Host-SID") -> None:
        self._lock = threading.RLock()
        self._max_sessions_per_user = max_sessions_per_user
        self._max_sessions_total = max_sessions_total
        self._idle_timeout = idle_timeout
        self._cookie_name = cookie_name
        self._sessions: dict[str, dict] = {}
        self._audit: list[AuditEntry] = []
        self._counters = {name: 0 for name in _COUNTER_NAMES}
        self._seq = 0

    # ------------------------------------------------------------------
    # Internal helpers.  Helpers ending in "_locked" require self._lock.
    # ------------------------------------------------------------------

    def _audit_locked(self, event: str, subject: object,
                      code: str | None = None) -> None:
        self._seq += 1
        self._audit.append(AuditEntry(self._seq, event, str(subject), code))

    def _reject_locked(self, code: str, event: str, subject: object,
                       detail: object = None) -> None:
        self._counters["rejected"] += 1
        self._audit_locked(event, subject, code)
        raise SessionError(code, detail)

    def _expired_locked(self, record: dict, now: datetime) -> bool:
        return now - _parse_time(record["last_seen"]) > timedelta(
            seconds=self._idle_timeout)

    def _check_fingerprint_locked(self, record: dict, fingerprint: str | None,
                                  event: str) -> None:
        bound = record["fingerprint"]
        if bound is not None and bound != fingerprint:
            self._reject_locked(
                "SESSION_FINGERPRINT_MISMATCH", event, record["sid"],
                {"sid": record["sid"]},
            )

    def _require_locked(self, sid: str, *, fingerprint: str | None,
                        now: datetime, event: str,
                        check_fingerprint: bool = True) -> dict:
        record = self._sessions.get(sid)
        if record is None:
            self._reject_locked("SESSION_UNKNOWN", event, sid, {"sid": sid})
        if self._expired_locked(record, now):
            self._reject_locked("SESSION_EXPIRED", event, sid, {"sid": sid})
        if check_fingerprint:
            self._check_fingerprint_locked(record, fingerprint, event)
        return record

    def _new_sid_locked(self) -> str:
        while True:
            sid = secrets.token_hex(16)
            if sid not in self._sessions:
                return sid

    @staticmethod
    def _sort_key(record: dict) -> tuple[datetime, str]:
        return (_parse_time(record["created_at"]), record["sid"])

    def _enforce_user_cap_locked(self, user: str | None, *,
                                 exclude: str | None, event: str,
                                 subject: object) -> None:
        if user is None:
            return
        if self._max_sessions_per_user < 1:
            self._reject_locked(
                "SESSION_LIMIT_EXCEEDED", event, subject,
                {"reason": "max_sessions_per_user", "user": user},
            )
        candidates = sorted(
            (sid for sid, record in self._sessions.items()
             if record["user"] == user and sid != exclude),
            key=lambda sid: self._sort_key(self._sessions[sid]),
        )
        while len(candidates) >= self._max_sessions_per_user:
            victim = candidates.pop(0)
            self._sessions.pop(victim, None)
            self._counters["revoked"] += 1
            self._counters["evicted"] += 1
            self._audit_locked("evict", victim, "SESSION_EVICTED")

    def _rotate_locked(self, record: dict, *, now_text: str,
                       user: str | None, auth_level: int,
                       fingerprint: str | None) -> str:
        old_sid = record["sid"]
        new_sid = self._new_sid_locked()
        new_fingerprint = (record["fingerprint"]
                           if record["fingerprint"] is not None
                           else fingerprint)
        replacement = {
            "sid": new_sid,
            "user": user,
            "auth_level": auth_level,
            "generation": record["generation"] + 1,
            "fingerprint": new_fingerprint,
            "created_at": record["created_at"],
            "rotated_at": now_text,
            "last_seen": now_text,
        }
        self._sessions.pop(old_sid, None)
        self._sessions[new_sid] = replacement
        return new_sid

    @staticmethod
    def _public_record(record: dict) -> SessionRecord:
        return SessionRecord(
            sid=record["sid"],
            user=record["user"],
            auth_level=record["auth_level"],
            generation=record["generation"],
            fingerprint=record["fingerprint"],
            created_at=record["created_at"],
            rotated_at=record["rotated_at"],
        )

    # ------------------------------------------------------------------
    # Session lifecycle.
    # ------------------------------------------------------------------

    def create_session(self, *, user: str | None = None,
                       fingerprint: str | None = None,
                       now: str | None = None) -> str:
        now_text = _timestamp(now)
        with self._lock:
            if len(self._sessions) >= self._max_sessions_total:
                self._reject_locked(
                    "SESSION_LIMIT_EXCEEDED", "create", "",
                    {"reason": "max_sessions_total"},
                )
            self._enforce_user_cap_locked(
                user, exclude=None, event="create", subject="")
            sid = self._new_sid_locked()
            self._sessions[sid] = {
                "sid": sid,
                "user": user,
                "auth_level": 0 if user is None else 1,
                "generation": 0,
                "fingerprint": fingerprint,
                "created_at": now_text,
                "rotated_at": now_text,
                "last_seen": now_text,
            }
            self._counters["created"] += 1
            self._audit_locked("create", sid)
            return sid

    def login(self, sid: str, *, user: str,
              fingerprint: str | None = None,
              now: str | None = None) -> str:
        now_text = _timestamp(now)
        now_dt = _parse_time(now_text)
        with self._lock:
            record = self._require_locked(
                sid, fingerprint=fingerprint, now=now_dt, event="login")
            self._enforce_user_cap_locked(
                user, exclude=sid, event="login", subject=sid)
            new_sid = self._rotate_locked(
                record, now_text=now_text, user=user, auth_level=1,
                fingerprint=fingerprint)
            self._counters["logged_in"] += 1
            self._audit_locked("login", new_sid)
            return new_sid

    def elevate(self, sid: str, *, level: int,
                fingerprint: str | None = None,
                now: str | None = None) -> str:
        now_text = _timestamp(now)
        now_dt = _parse_time(now_text)
        with self._lock:
            record = self._require_locked(
                sid, fingerprint=fingerprint, now=now_dt, event="elevate")
            if (not isinstance(level, int) or isinstance(level, bool)
                    or level < 1 or level > 3):
                self._reject_locked(
                    "SESSION_INVALID_LEVEL", "elevate", sid,
                    {"level": level},
                )
            if level <= record["auth_level"]:
                self._reject_locked(
                    "SESSION_LEVEL_NOT_RAISED", "elevate", sid,
                    {"current": record["auth_level"], "requested": level},
                )
            new_sid = self._rotate_locked(
                record, now_text=now_text, user=record["user"],
                auth_level=level, fingerprint=fingerprint)
            self._counters["elevated"] += 1
            self._audit_locked("elevate", new_sid)
            return new_sid

    def rotate(self, sid: str, *, fingerprint: str | None = None,
               now: str | None = None) -> str:
        now_text = _timestamp(now)
        now_dt = _parse_time(now_text)
        with self._lock:
            record = self._require_locked(
                sid, fingerprint=fingerprint, now=now_dt, event="rotate")
            new_sid = self._rotate_locked(
                record, now_text=now_text, user=record["user"],
                auth_level=record["auth_level"], fingerprint=fingerprint)
            self._counters["rotated"] += 1
            self._audit_locked("rotate", new_sid)
            return new_sid

    def logout(self, sid: str, *, now: str | None = None) -> bool:
        del now
        with self._lock:
            if self._sessions.pop(sid, None) is None:
                return False
            self._counters["revoked"] += 1
            self._audit_locked("logout", sid)
            return True

    def revoke_user(self, user: str, *, now: str | None = None) -> int:
        del now
        with self._lock:
            victims = sorted(
                (sid for sid, record in self._sessions.items()
                 if record["user"] == user),
                key=lambda sid: self._sort_key(self._sessions[sid]),
            )
            for sid in victims:
                self._sessions.pop(sid, None)
                self._counters["revoked"] += 1
                self._audit_locked("revoke", sid)
            return len(victims)

    def revoke_expired(self, now: str | None = None) -> int:
        now_text = _timestamp(now)
        now_dt = _parse_time(now_text)
        with self._lock:
            victims = sorted(
                (sid for sid, record in self._sessions.items()
                 if self._expired_locked(record, now_dt)),
                key=lambda sid: self._sort_key(self._sessions[sid]),
            )
            for sid in victims:
                self._sessions.pop(sid, None)
                self._counters["expired"] += 1
                self._audit_locked("expired", sid)
            return len(victims)

    def session_record(self, sid: str, *, fingerprint: str | None = None,
                       now: str | None = None) -> SessionRecord:
        now_text = _timestamp(now)
        now_dt = _parse_time(now_text)
        with self._lock:
            record = self._require_locked(
                sid, fingerprint=fingerprint, now=now_dt,
                event="session_record")
            record["last_seen"] = now_text
            return self._public_record(record)

    def sessions_for(self, user: str) -> tuple[SessionRecord, ...]:
        with self._lock:
            records = sorted(
                (record for record in self._sessions.values()
                 if record["user"] == user),
                key=self._sort_key,
            )
            return tuple(self._public_record(record) for record in records)

    def sessions(self) -> tuple[SessionRecord, ...]:
        with self._lock:
            records = sorted(self._sessions.values(), key=self._sort_key)
            return tuple(self._public_record(record) for record in records)

    # ------------------------------------------------------------------
    # Cookies.
    # ------------------------------------------------------------------

    def issue_cookie(self, sid: str, *, now: str | None = None) -> CookieSpec:
        now_text = _timestamp(now)
        now_dt = _parse_time(now_text)
        with self._lock:
            record = self._require_locked(
                sid, fingerprint=None, now=now_dt, event="issue_cookie",
                check_fingerprint=False)
            record["last_seen"] = now_text
            return CookieSpec(
                name=self._cookie_name,
                value=sid,
                secure=True,
                http_only=True,
                path="/",
                domain=None,
                same_site="Lax",
                max_age=None,
            )

    def validate_cookie(self, raw: str) -> CookieSpec:
        with self._lock:
            try:
                return self._parse_cookie(raw)
            except SessionError as exc:
                self._counters["rejected"] += 1
                self._audit_locked("cookie", raw, exc.code)
                raise

    @staticmethod
    def _parse_cookie(raw: str) -> CookieSpec:
        if not isinstance(raw, str) or not raw.strip():
            raise SessionError("COOKIE_MALFORMED", raw)

        parts = raw.split(";")
        head = parts[0].strip()
        if "=" not in head:
            raise SessionError("COOKIE_MALFORMED", raw)
        name, _, value = head.partition("=")
        name = name.strip()
        value = value.strip()
        if not name or not _COOKIE_NAME_RE.fullmatch(name):
            raise SessionError("COOKIE_MALFORMED", raw)
        if not _SID_RE.fullmatch(value):
            raise SessionError("COOKIE_INVALID_VALUE", value)

        attributes: dict[str, str | None] = {}
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                key, _, attr_value = part.partition("=")
                key = key.strip().lower()
                attr_value = attr_value.strip()
            else:
                key = part.strip().lower()
                attr_value = None
            if not key:
                raise SessionError("COOKIE_MALFORMED", raw)
            if key in attributes:
                raise SessionError("COOKIE_DUPLICATE_ATTRIBUTE", key)
            attributes[key] = attr_value

        for key in attributes:
            if key not in _COOKIE_ATTRIBUTES:
                raise SessionError("COOKIE_UNKNOWN_ATTRIBUTE", key)

        for flag in ("secure", "httponly"):
            if flag in attributes and attributes[flag] is not None:
                raise SessionError("COOKIE_MALFORMED", flag)

        secure = "secure" in attributes
        http_only = "httponly" in attributes
        domain_present = "domain" in attributes
        path_present = "path" in attributes

        if name.startswith("__Host-"):
            if not secure or domain_present:
                raise SessionError("COOKIE_INSECURE_PREFIX", name)
        elif name.startswith("__Secure-"):
            if not secure:
                raise SessionError("COOKIE_INSECURE_PREFIX", name)

        path = "/"
        if path_present:
            raw_path = attributes["path"]
            if (raw_path is None or not raw_path.startswith("/")
                    or any(ch.isspace() or ord(ch) < 0x20 for ch in raw_path)):
                raise SessionError("COOKIE_INVALID_PATH", raw_path)
            path = raw_path
        if name.startswith("__Host-") and (not path_present or path != "/"):
            raise SessionError("COOKIE_INVALID_PATH", path)

        domain = None
        if domain_present:
            raw_domain = attributes["domain"]
            if (raw_domain is None or not raw_domain
                    or "/" in raw_domain
                    or any(ch.isspace() or ord(ch) < 0x20 for ch in raw_domain)):
                raise SessionError("COOKIE_INVALID_VALUE", raw_domain)
            domain = raw_domain

        same_site = "Lax"
        if "samesite" in attributes:
            raw_same_site = attributes["samesite"]
            if raw_same_site is None:
                raise SessionError("COOKIE_INVALID_VALUE", raw_same_site)
            same_site_values = {
                "strict": "Strict", "lax": "Lax", "none": "None",
            }
            canonical = same_site_values.get(raw_same_site.strip().lower())
            if canonical is None:
                raise SessionError("COOKIE_INVALID_VALUE", raw_same_site)
            same_site = canonical

        max_age = None
        if "max-age" in attributes:
            raw_max_age = attributes["max-age"]
            if raw_max_age is None:
                raise SessionError("COOKIE_INVALID_VALUE", raw_max_age)
            try:
                max_age = int(raw_max_age, 10)
            except (TypeError, ValueError):
                raise SessionError("COOKIE_INVALID_VALUE", raw_max_age) from None
            if max_age < 0:
                raise SessionError("COOKIE_INVALID_VALUE", raw_max_age)

        if same_site == "None" and not secure:
            raise SessionError("COOKIE_SAMESITE_NONE_REQUIRES_SECURE", name)

        return CookieSpec(
            name=name,
            value=value,
            secure=secure,
            http_only=http_only,
            path=path,
            domain=domain,
            same_site=same_site,
            max_age=max_age,
        )

    # ------------------------------------------------------------------
    # Observations and persistence.
    # ------------------------------------------------------------------

    def audit_log(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._audit)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            records = sorted(self._sessions.values(), key=self._sort_key)
            return {
                "version": _SNAPSHOT_VERSION,
                "sessions": [copy.deepcopy(record) for record in records],
                "audit": [
                    {"seq": entry.seq, "event": entry.event,
                     "subject": entry.subject, "code": entry.code}
                    for entry in self._audit
                ],
                "counters": dict(self._counters),
                "seq": self._seq,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            sessions, audit, counters, seq = self._validate_snapshot(state)
            self._sessions = sessions
            self._audit = audit
            self._counters = counters
            self._seq = seq
            self._counters["restored"] += 1
            self._audit_locked("restore", "", None)

    def _validate_snapshot(
            self, state: object) -> tuple[dict[str, dict], list[AuditEntry],
                                          dict[str, int], int]:
        invalid = "SESSION_SNAPSHOT_INVALID"
        if not isinstance(state, dict):
            raise SessionError(invalid, "state must be a mapping")
        required = {"version", "sessions", "audit", "counters", "seq"}
        if not required.issubset(state):
            raise SessionError(invalid, "missing snapshot fields")
        if type(state["version"]) is not int or state["version"] != _SNAPSHOT_VERSION:
            raise SessionError(invalid, "unsupported snapshot version")

        raw_sessions = state["sessions"]
        if not isinstance(raw_sessions, (list, tuple)):
            raise SessionError(invalid, "sessions must be a sequence")

        session_fields = {
            "sid", "user", "auth_level", "generation", "fingerprint",
            "created_at", "rotated_at", "last_seen",
        }
        sessions: dict[str, dict] = {}
        per_user: dict[str | None, int] = {}
        for raw_record in raw_sessions:
            if not isinstance(raw_record, dict):
                raise SessionError(invalid, "session record must be a mapping")
            if not session_fields.issubset(raw_record):
                raise SessionError(invalid, "session record missing fields")
            record = {key: copy.deepcopy(raw_record[key])
                      for key in session_fields}
            sid = record["sid"]
            if not isinstance(sid, str) or not _SID_RE.fullmatch(sid):
                raise SessionError(invalid, "invalid session identifier")
            if sid in sessions:
                raise SessionError(invalid, "duplicate session identifier")
            if record["user"] is not None and not isinstance(record["user"], str):
                raise SessionError(invalid, "invalid session user")
            if (type(record["auth_level"]) is not int
                    or not 0 <= record["auth_level"] <= 3):
                raise SessionError(invalid, "invalid auth level")
            if type(record["generation"]) is not int or record["generation"] < 0:
                raise SessionError(invalid, "invalid generation")
            if (record["fingerprint"] is not None
                    and not isinstance(record["fingerprint"], str)):
                raise SessionError(invalid, "invalid fingerprint")
            for field in ("created_at", "rotated_at", "last_seen"):
                if not isinstance(record[field], str):
                    raise SessionError(invalid, f"invalid {field}")
                try:
                    _parse_time(record[field])
                except (TypeError, ValueError):
                    raise SessionError(invalid, f"invalid {field}") from None
            sessions[sid] = record
            per_user[record["user"]] = per_user.get(record["user"], 0) + 1

        if len(sessions) > self._max_sessions_total:
            raise SessionError(invalid, "session total exceeds cap")
        for user, count in per_user.items():
            if user is not None and count > self._max_sessions_per_user:
                raise SessionError(invalid, "user session count exceeds cap")

        raw_audit = state["audit"]
        if not isinstance(raw_audit, (list, tuple)):
            raise SessionError(invalid, "audit must be a sequence")
        audit: list[AuditEntry] = []
        seen_seq: set[int] = set()
        for raw_entry in raw_audit:
            if not isinstance(raw_entry, dict):
                raise SessionError(invalid, "audit entry must be a mapping")
            if not {"seq", "event", "subject", "code"}.issubset(raw_entry):
                raise SessionError(invalid, "audit entry missing fields")
            entry_seq = raw_entry["seq"]
            if type(entry_seq) is not int or entry_seq < 1:
                raise SessionError(invalid, "invalid audit sequence")
            if entry_seq in seen_seq:
                raise SessionError(invalid, "duplicate audit sequence")
            if not isinstance(raw_entry["event"], str):
                raise SessionError(invalid, "invalid audit event")
            if not isinstance(raw_entry["subject"], str):
                raise SessionError(invalid, "invalid audit subject")
            code = raw_entry["code"]
            if code is not None and not isinstance(code, str):
                raise SessionError(invalid, "invalid audit code")
            seen_seq.add(entry_seq)
            audit.append(AuditEntry(entry_seq, raw_entry["event"],
                                    raw_entry["subject"], code))

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise SessionError(invalid, "counters must be a mapping")
        counters = {name: 0 for name in _COUNTER_NAMES}
        for key, value in raw_counters.items():
            if not isinstance(key, str):
                raise SessionError(invalid, "invalid counter name")
            if type(value) is not int or value < 0:
                raise SessionError(invalid, "invalid counter value")
            counters[key] = value

        seq = state["seq"]
        if type(seq) is not int or seq < 0:
            raise SessionError(invalid, "invalid sequence")
        if seen_seq and seq < max(seen_seq):
            raise SessionError(invalid, "sequence behind audit log")

        return sessions, audit, counters, seq
