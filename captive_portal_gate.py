"""Captive portal pre-authentication gate: allowlist, per-client budget, expiry settlement."""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass, fields, replace


class CaptiveError(ValueError):
    """Raised when a pre-authentication request cannot be served."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PreauthSession:
    mac: str
    addr: str
    state: str
    started_at: float
    expires_at: float
    bytes_used: int
    bytes_limit: int
    authenticated_at: float | None


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str
    host: str


class CaptivePortalGate:
    """Decide what a client may reach before it finishes portal authentication."""

    def __init__(self, *, session_ttl: float = 600.0, byte_budget: int = 1_000_000,
                 max_sessions: int = 128, portal_hosts=(), clock=None) -> None:
        self._validate_constructor(session_ttl, byte_budget, max_sessions)
        self.session_ttl = session_ttl
        self.byte_budget = byte_budget
        self.max_sessions = max_sessions
        self.portal_hosts = tuple(portal_hosts)
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, PreauthSession] = {}
        self._allowlist: dict[str, dict] = {}
        self._stats = {
            "registered": 0,
            "authorized": 0,
            "allowed": 0,
            "denied": 0,
            "expired": 0,
            "bytes_consumed": 0,
        }

    _SNAPSHOT_VERSION = 1
    _STATS_KEYS = ("registered", "authorized", "allowed", "denied", "expired", "bytes_consumed")
    _SESSION_STATES = ("preauth", "authorized", "expired")

    @staticmethod
    def _invalid(detail: str) -> None:
        raise CaptiveError("CAPTIVE_INVALID_ARGUMENT", detail)

    @classmethod
    def _validate_constructor(cls, session_ttl, byte_budget, max_sessions) -> None:
        if isinstance(session_ttl, bool) or not isinstance(session_ttl, (int, float)):
            cls._invalid("session_ttl must be a positive number")
        if session_ttl != session_ttl or session_ttl <= 0:
            cls._invalid("session_ttl must be a positive number")
        if isinstance(byte_budget, bool) or not isinstance(byte_budget, (int, float)):
            cls._invalid("byte_budget must be a non-negative number")
        if byte_budget != byte_budget or byte_budget < 0:
            cls._invalid("byte_budget must be a non-negative number")
        if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions <= 0:
            cls._invalid("max_sessions must be a positive integer")

    @classmethod
    def _normalize_mac(cls, mac) -> str:
        if not isinstance(mac, str) or not mac.strip():
            cls._invalid("mac must be a non-empty hardware address")
        return mac.strip().lower()

    def _now(self, now) -> float:
        if now is not None:
            return now
        if self._clock is not None:
            return self._clock()
        return time.monotonic()

    @staticmethod
    def _is_number(value) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and value == value

    def register_client(self, mac: str, addr: str, *, now: float | None = None) -> PreauthSession:
        key = self._normalize_mac(mac)
        if not isinstance(addr, str) or not addr.strip():
            self._invalid("addr must be a non-empty address")
        current = self._now(now)
        with self._lock:
            existing = self._sessions.get(key)
            if existing is not None:
                if existing.addr != addr:
                    existing = replace(existing, addr=addr)
                    self._sessions[key] = existing
                return existing
            active_preauth = sum(1 for session in self._sessions.values()
                                 if session.state == "preauth")
            if active_preauth >= self.max_sessions:
                raise CaptiveError(
                    "CAPTIVE_CAPACITY_EXCEEDED",
                    f"pre-auth session limit {self.max_sessions} reached",
                )
            session = PreauthSession(
                mac=key,
                addr=addr,
                state="preauth",
                started_at=current,
                expires_at=current + self.session_ttl,
                bytes_used=0,
                bytes_limit=self.byte_budget,
                authenticated_at=None,
            )
            self._sessions[key] = session
            self._stats["registered"] += 1
            return session

    def complete_auth(self, mac: str, *, now: float | None = None) -> PreauthSession:
        key = self._normalize_mac(mac)
        current = self._now(now)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                raise CaptiveError("CAPTIVE_UNKNOWN_CLIENT", f"no session for {key}")
            if session.state == "authorized":
                return session
            authorized = replace(session, state="authorized", authenticated_at=current)
            self._sessions[key] = authorized
            self._stats["authorized"] += 1
            return authorized

    def authorize(self, mac: str, addr: str, host: str, *, now: float | None = None) -> AccessDecision:
        key = mac.strip().lower() if isinstance(mac, str) else mac
        current = self._now(now)
        with self._lock:
            if host in self.portal_hosts:
                self._stats["allowed"] += 1
                return AccessDecision(True, "portal", host)
            session = self._sessions.get(key)
            if session is None:
                return self._deny(host, "unregistered")
            if session.state == "expired":
                return self._deny(host, "expired")
            if session.state == "authorized":
                self._stats["allowed"] += 1
                return AccessDecision(True, "authorized", host)
            if session.bytes_used >= session.bytes_limit:
                return self._deny(host, "quota_exhausted")
            if self._allowlisted(host, current):
                self._stats["allowed"] += 1
                return AccessDecision(True, "allowlist", host)
            return self._deny(host, "blocked")

    def _deny(self, host: str, reason: str) -> AccessDecision:
        self._stats["denied"] += 1
        return AccessDecision(False, reason, host)

    def _allowlisted(self, host: str, now: float) -> bool:
        for entry in self._allowlist.values():
            if now < entry["expires_at"] and host in entry["addresses"]:
                return True
        return False

    def session_for(self, mac: str) -> PreauthSession | None:
        key = mac.strip().lower() if isinstance(mac, str) else mac
        with self._lock:
            return self._sessions.get(key)

    def sessions(self) -> list[PreauthSession]:
        with self._lock:
            return list(self._sessions.values())

    def consume_bytes(self, mac: str, count: int, *, now: float | None = None) -> int:
        key = self._normalize_mac(mac)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            self._invalid("count must be a non-negative integer")
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                raise CaptiveError("CAPTIVE_UNKNOWN_CLIENT", f"no session for {key}")
            remaining = session.bytes_limit - session.bytes_used
            applied = min(count, remaining)
            if applied:
                session = replace(session, bytes_used=session.bytes_used + applied)
                self._sessions[key] = session
                self._stats["bytes_consumed"] += applied
            return session.bytes_limit - session.bytes_used

    def settle_expired(self, *, now: float | None = None) -> int:
        current = self._now(now)
        settled = 0
        with self._lock:
            for key, session in self._sessions.items():
                if session.state == "preauth" and current >= session.expires_at:
                    self._sessions[key] = replace(session, state="expired")
                    settled += 1
            self._stats["expired"] += settled
            return settled

    def update_allowlist(self, host: str, *, addresses, ttl: float = 30.0,
                         now: float | None = None) -> tuple[str, ...]:
        if not isinstance(host, str) or not host.strip():
            self._invalid("host must be a non-empty name")
        if isinstance(ttl, bool) or not self._is_number(ttl) or ttl <= 0:
            self._invalid("ttl must be a positive number")
        try:
            published = tuple(addresses)
        except TypeError:
            self._invalid("addresses must be an iterable of addresses")
        current = self._now(now)
        with self._lock:
            self._allowlist[host] = {
                "addresses": published,
                "expires_at": current + ttl,
            }
            return published

    def allowlist_addresses(self, host: str, *, now: float | None = None) -> tuple[str, ...]:
        current = self._now(now)
        with self._lock:
            entry = self._allowlist.get(host)
            if entry is None or current >= entry["expires_at"]:
                return ()
            return tuple(entry["addresses"])

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self._SNAPSHOT_VERSION,
                "sessions": [
                    {field.name: copy.deepcopy(getattr(session, field.name))
                     for field in fields(PreauthSession)}
                    for session in self._sessions.values()
                ],
                "allowlist": {
                    host: {
                        "addresses": tuple(entry["addresses"]),
                        "expires_at": entry["expires_at"],
                    }
                    for host, entry in self._allowlist.items()
                },
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        sessions, allowlist, stats = self._parse_snapshot(state)
        with self._lock:
            self._sessions = sessions
            self._allowlist = allowlist
            self._stats = stats

    @classmethod
    def _parse_snapshot(cls, state):
        if not isinstance(state, dict):
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "state must be a dict")
        if set(state.keys()) != {"version", "sessions", "allowlist", "stats"}:
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "unexpected snapshot keys")
        if state.get("version") != cls._SNAPSHOT_VERSION:
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "unsupported snapshot version")
        raw_sessions = state["sessions"]
        raw_allowlist = state["allowlist"]
        raw_stats = state["stats"]
        if isinstance(raw_sessions, str) or not isinstance(raw_sessions, (list, tuple)):
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "sessions must be a list")
        if not isinstance(raw_allowlist, dict):
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "allowlist must be a dict")
        if not isinstance(raw_stats, dict) or set(raw_stats.keys()) != set(cls._STATS_KEYS):
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "stats keys do not match")

        session_keys = {field.name for field in fields(PreauthSession)}
        sessions: dict[str, PreauthSession] = {}
        for item in raw_sessions:
            if not isinstance(item, dict) or set(item.keys()) != session_keys:
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed session entry")
            if not isinstance(item["mac"], str) or not item["mac"].strip():
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed session mac")
            if not isinstance(item["addr"], str) or not item["addr"].strip():
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed session addr")
            if item["state"] not in cls._SESSION_STATES:
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed session state")
            numeric_fields = ("started_at", "expires_at", "bytes_used", "bytes_limit")
            if any(not cls._is_number(item[name]) for name in numeric_fields):
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed session numbers")
            authenticated_at = item["authenticated_at"]
            if authenticated_at is not None and not cls._is_number(authenticated_at):
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed authenticated_at")
            if item["mac"] in sessions:
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "duplicate session mac")
            sessions[item["mac"]] = PreauthSession(
                mac=item["mac"],
                addr=item["addr"],
                state=item["state"],
                started_at=item["started_at"],
                expires_at=item["expires_at"],
                bytes_used=item["bytes_used"],
                bytes_limit=item["bytes_limit"],
                authenticated_at=authenticated_at,
            )

        allowlist: dict[str, dict] = {}
        for host, entry in raw_allowlist.items():
            if not isinstance(host, str) or not isinstance(entry, dict):
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed allowlist entry")
            if set(entry.keys()) != {"addresses", "expires_at"}:
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed allowlist entry")
            addresses = entry["addresses"]
            if isinstance(addresses, str) or not isinstance(addresses, (list, tuple)):
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed allowlist addresses")
            if any(not isinstance(address, str) for address in addresses):
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed allowlist addresses")
            if not cls._is_number(entry["expires_at"]):
                raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed allowlist expiry")
            allowlist[host] = {
                "addresses": tuple(copy.deepcopy(addresses)),
                "expires_at": entry["expires_at"],
            }

        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0
               for value in raw_stats.values()):
            raise CaptiveError("CAPTIVE_SNAPSHOT_INVALID", "malformed stats values")
        stats = {key: raw_stats[key] for key in cls._STATS_KEYS}
        return sessions, allowlist, stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
