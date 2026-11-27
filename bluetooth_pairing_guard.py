"""Bluetooth pairing governance: IO capability matrix, MITM downgrade guard, bond overwrite."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass

LE = "le"
CLASSIC = "classic"
TRANSPORTS = (CLASSIC, LE)

JUST_WORKS = "just_works"
NUMERIC_COMPARISON = "numeric_comparison"
PASSKEY_DISPLAY = "passkey_display"
PASSKEY_ENTRY = "passkey_entry"
METHODS = (JUST_WORKS, NUMERIC_COMPARISON, PASSKEY_DISPLAY, PASSKEY_ENTRY)

DISPLAY = "display"
KEYBOARD = "keyboard"
IO_CAPABILITIES = (DISPLAY, KEYBOARD)

PAIRING_INVALID_REQUEST = "PAIRING_INVALID_REQUEST"
PAIRING_ADAPTER_OFFLINE = "PAIRING_ADAPTER_OFFLINE"
PAIRING_ADAPTER_UNKNOWN = "PAIRING_ADAPTER_UNKNOWN"
PAIRING_IO_INSUFFICIENT = "PAIRING_IO_INSUFFICIENT"
PAIRING_MITM_REQUIRED = "PAIRING_MITM_REQUIRED"
PAIRING_SESSION_EXISTS = "PAIRING_SESSION_EXISTS"
PAIRING_SESSION_LIMIT = "PAIRING_SESSION_LIMIT"
PAIRING_PASSKEY_MISMATCH = "PAIRING_PASSKEY_MISMATCH"
PAIRING_ATTEMPTS_EXHAUSTED = "PAIRING_ATTEMPTS_EXHAUSTED"
PAIRING_COOLDOWN = "PAIRING_COOLDOWN"
PAIRING_NOT_CONFIRMED = "PAIRING_NOT_CONFIRMED"
PAIRING_SESSION_EXPIRED = "PAIRING_SESSION_EXPIRED"
PAIRING_BOND_LIMIT = "PAIRING_BOND_LIMIT"
PAIRING_SNAPSHOT_INVALID = "PAIRING_SNAPSHOT_INVALID"

_SESSION_ID_RE = re.compile(r"s[1-9][0-9]*\Z")
_PASSKEY_RE = re.compile(r"[0-9]{6}\Z")


class PairingError(ValueError):
    """Raised when a pairing operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AdapterInfo:
    adapter_id: str
    powered: bool
    io_caps: tuple[str, ...]
    max_bonds: int


@dataclass(frozen=True)
class PairingSession:
    session_id: str
    adapter_id: str
    address: str
    transport: str
    method: str
    passkey: str
    requires_mitm: bool
    attempts: int
    deadline: int


@dataclass(frozen=True)
class BondRecord:
    adapter_id: str
    address: str
    transport: str
    key: str
    method: str
    created_at: int


@dataclass
class _Session:
    session_id: str
    adapter_id: str
    address: str
    transport: str
    method: str
    passkey: str
    requires_mitm: bool
    attempts: int
    deadline: int
    confirmed: bool = False

    def public(self) -> PairingSession:
        return PairingSession(
            session_id=self.session_id,
            adapter_id=self.adapter_id,
            address=self.address,
            transport=self.transport,
            method=self.method,
            passkey=self.passkey,
            requires_mitm=self.requires_mitm,
            attempts=self.attempts,
            deadline=self.deadline,
        )


class BluetoothPairingGuard:
    """Choose pairing methods from both ends' IO capabilities and keep per-adapter bonds."""

    def __init__(self, *, pairing_window: int = 60, max_attempts: int = 3,
                 cooldown: int = 30, max_sessions: int = 32) -> None:
        if pairing_window < 0:
            raise ValueError("pairing_window must be non-negative")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if cooldown < 0:
            raise ValueError("cooldown must be non-negative")
        if max_sessions < 0:
            raise ValueError("max_sessions must be non-negative")
        self.pairing_window = pairing_window
        self.max_attempts = max_attempts
        self.cooldown = cooldown
        self.max_sessions = max_sessions
        self._lock = threading.RLock()
        self._adapters: dict[str, AdapterInfo] = {}
        self._sessions: dict[str, _Session] = {}
        self._bonds: dict[tuple[str, str, str], BondRecord] = {}
        self._cooldowns: dict[tuple[str, str, str], int] = {}
        self._session_seq = 0
        self._confirmed = 0
        self._removed = 0
        self._rejected = 0

    def _now(self, now: int | None) -> int:
        if now is None:
            return int(time.time())
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            self._reject(PAIRING_INVALID_REQUEST)
        try:
            return int(now)
        except (OverflowError, ValueError):
            self._reject(PAIRING_INVALID_REQUEST)

    @staticmethod
    def _normalize_caps(io_caps) -> tuple[str, ...]:
        if io_caps is None:
            return ()
        if isinstance(io_caps, dict):
            raw = [str(cap) for cap, enabled in io_caps.items() if enabled]
        elif isinstance(io_caps, str):
            raw = [io_caps]
        else:
            try:
                raw = [str(cap) for cap in io_caps]
            except TypeError:
                raise ValueError("invalid io capabilities") from None
        caps = set(raw)
        if not caps <= set(IO_CAPABILITIES):
            raise ValueError("unknown io capability")
        return tuple(cap for cap in IO_CAPABILITIES if cap in caps)

    def _reject(self, code: str, detail: object = None) -> None:
        self._rejected += 1
        raise PairingError(code, detail)

    def _caps_or_reject(self, io_caps) -> tuple[str, ...]:
        try:
            return self._normalize_caps(io_caps)
        except (TypeError, ValueError):
            self._reject(PAIRING_INVALID_REQUEST)

    def _adapter(self, adapter_id: str, *, powered: bool = False) -> AdapterInfo:
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            self._reject(PAIRING_ADAPTER_UNKNOWN)
        info = self._adapters.get(adapter_id)
        if info is None:
            self._reject(PAIRING_ADAPTER_UNKNOWN)
        if powered and not info.powered:
            self._reject(PAIRING_ADAPTER_OFFLINE)
        return info

    def _address_or_reject(self, address: str) -> str:
        if not isinstance(address, str) or not address.strip():
            self._reject(PAIRING_INVALID_REQUEST)
        return address.strip()

    def _transport_or_reject(self, transport: str) -> str:
        if transport not in TRANSPORTS:
            self._reject(PAIRING_INVALID_REQUEST)
        return transport

    @staticmethod
    def _method(local_caps: tuple[str, ...], peer_caps: tuple[str, ...]) -> str:
        local_display = DISPLAY in local_caps
        local_keyboard = KEYBOARD in local_caps
        peer_display = DISPLAY in peer_caps
        peer_keyboard = KEYBOARD in peer_caps

        if local_display and local_keyboard and peer_display and peer_keyboard:
            return NUMERIC_COMPARISON
        if local_display and peer_keyboard:
            return PASSKEY_DISPLAY
        if local_keyboard and peer_display:
            return PASSKEY_ENTRY
        if not (local_display or local_keyboard or peer_display or peer_keyboard):
            return JUST_WORKS
        raise PairingError(PAIRING_IO_INSUFFICIENT)

    @staticmethod
    def _passkey(address: str) -> str:
        digest = hashlib.sha256(address.encode("utf-8")).digest()
        return f"{int.from_bytes(digest[:8], 'big') % 1_000_000:06d}"

    @staticmethod
    def _bond_key(adapter_id: str, address: str, transport: str) -> tuple[str, str, str]:
        return (adapter_id, address, transport)

    @staticmethod
    def _snapshot_key(adapter_id: str, address: str, transport: str) -> str:
        return json.dumps([adapter_id, address, transport], ensure_ascii=False,
                          separators=(",", ":"))

    def register_adapter(self, adapter_id: str, *, powered: bool = True,
                         io_caps=None, max_bonds: int = 8) -> AdapterInfo:
        with self._lock:
            if not isinstance(adapter_id, str) or not adapter_id.strip():
                self._reject(PAIRING_INVALID_REQUEST)
            caps = self._caps_or_reject(io_caps)
            if (isinstance(max_bonds, bool) or not isinstance(max_bonds, int)
                    or max_bonds < 0):
                self._reject(PAIRING_INVALID_REQUEST)
            info = AdapterInfo(adapter_id, bool(powered), caps, max_bonds)
            self._adapters[adapter_id] = info
            return info

    def set_powered(self, adapter_id: str, powered: bool) -> AdapterInfo:
        with self._lock:
            info = self._adapter(adapter_id)
            updated = AdapterInfo(info.adapter_id, bool(powered), info.io_caps,
                                  info.max_bonds)
            self._adapters[adapter_id] = updated
            return updated

    def pair_request(self, adapter_id: str, address: str, *, transport: str = LE,
                     peer_caps=None, requires_mitm: bool = False,
                     now: int | None = None) -> PairingSession:
        with self._lock:
            timestamp = self._now(now)
            info = self._adapter(adapter_id, powered=True)
            address = self._address_or_reject(address)
            transport = self._transport_or_reject(transport)
            peer = self._caps_or_reject(peer_caps)
            key = self._bond_key(adapter_id, address, transport)

            until = self._cooldowns.get(key)
            if until is not None:
                if timestamp < until:
                    self._reject(PAIRING_COOLDOWN,
                                 {"retry_after": until - timestamp})
                del self._cooldowns[key]

            for session_id, session in list(self._sessions.items()):
                if (session.adapter_id, session.address, session.transport) == key:
                    if timestamp > session.deadline:
                        del self._sessions[session_id]
                    else:
                        self._reject(PAIRING_SESSION_EXISTS)

            try:
                method = self._method(info.io_caps, peer)
            except PairingError as exc:
                self._reject(exc.code)
            if requires_mitm and method == JUST_WORKS:
                self._reject(PAIRING_MITM_REQUIRED)
            active_sessions = sum(
                1 for session in self._sessions.values()
                if timestamp <= session.deadline
            )
            if active_sessions >= self.max_sessions:
                self._reject(PAIRING_SESSION_LIMIT)

            self._session_seq += 1
            session_id = f"s{self._session_seq}"
            session = _Session(
                session_id=session_id,
                adapter_id=adapter_id,
                address=address,
                transport=transport,
                method=method,
                passkey=self._passkey(address),
                requires_mitm=bool(requires_mitm),
                attempts=0,
                deadline=timestamp + self.pairing_window,
            )
            self._sessions[session_id] = session
            return session.public()

    def confirm_passkey(self, session_id: str, value: str, *,
                        now: int | None = None) -> dict:
        with self._lock:
            timestamp = self._now(now)
            session = self._sessions.get(session_id)
            if session is None:
                self._reject(PAIRING_INVALID_REQUEST)
            self._adapter(session.adapter_id, powered=True)

            if timestamp > session.deadline:
                del self._sessions[session_id]
                self._reject(PAIRING_SESSION_EXPIRED)

            if session.confirmed:
                return {"status": "confirmed", "attempts": session.attempts}

            if str(value) == session.passkey:
                session.confirmed = True
                self._confirmed += 1
                return {"status": "confirmed", "attempts": session.attempts}

            session.attempts += 1
            if session.attempts >= self.max_attempts:
                del self._sessions[session_id]
                key = self._bond_key(session.adapter_id, session.address,
                                     session.transport)
                self._cooldowns[key] = timestamp + self.cooldown
                self._reject(PAIRING_ATTEMPTS_EXHAUSTED,
                             {"attempts": session.attempts})

            self._reject(PAIRING_PASSKEY_MISMATCH,
                         {"attempts": session.attempts,
                          "remaining": self.max_attempts - session.attempts})

    def complete_pairing(self, session_id: str, *, confirm: bool = True,
                         now: int | None = None) -> BondRecord:
        with self._lock:
            timestamp = self._now(now)
            session = self._sessions.get(session_id)
            if session is None:
                self._reject(PAIRING_INVALID_REQUEST)
            info = self._adapter(session.adapter_id, powered=True)

            if timestamp > session.deadline:
                del self._sessions[session_id]
                self._reject(PAIRING_SESSION_EXPIRED)
            if not confirm or (session.method != JUST_WORKS and not session.confirmed):
                self._reject(PAIRING_NOT_CONFIRMED)

            key = self._bond_key(session.adapter_id, session.address,
                                 session.transport)
            if key not in self._bonds:
                adapter_bonds = sum(1 for bond_key in self._bonds
                                    if bond_key[0] == session.adapter_id)
                if adapter_bonds >= info.max_bonds:
                    self._reject(PAIRING_BOND_LIMIT)

            bond = BondRecord(
                adapter_id=session.adapter_id,
                address=session.address,
                transport=session.transport,
                key=f"key-{session.adapter_id}-{uuid.uuid4().hex}",
                method=session.method,
                created_at=timestamp,
            )
            self._bonds[key] = bond
            del self._sessions[session_id]
            self._cooldowns.pop(key, None)
            return bond

    def remove_bond(self, adapter_id: str, address: str, *,
                    transport: str | None = None) -> int:
        with self._lock:
            self._adapter(adapter_id, powered=True)
            address = self._address_or_reject(address)
            if transport is not None:
                transport = self._transport_or_reject(transport)

            keys = [
                key for key in self._bonds
                if key[0] == adapter_id and key[1] == address
                and (transport is None or key[2] == transport)
            ]
            for key in keys:
                del self._bonds[key]
            self._removed += len(keys)
            return len(keys)

    def bond_for(self, adapter_id: str, address: str, *,
                 transport: str = LE) -> BondRecord | None:
        with self._lock:
            self._adapter(adapter_id)
            address = self._address_or_reject(address)
            transport = self._transport_or_reject(transport)
            return self._bonds.get(self._bond_key(adapter_id, address, transport))

    def bonds(self, adapter_id: str) -> list[BondRecord]:
        with self._lock:
            self._adapter(adapter_id)
            rows = [bond for key, bond in self._bonds.items()
                    if key[0] == adapter_id]
            return sorted(rows, key=lambda bond: (bond.address, bond.transport))

    def pending_sessions(self) -> list[PairingSession]:
        with self._lock:
            rows = sorted(
                self._sessions.values(),
                key=lambda session: int(session.session_id[1:]),
            )
            return [session.public() for session in rows]

    def snapshot(self) -> dict:
        with self._lock:
            adapters = {
                adapter_id: {
                    "powered": info.powered,
                    "io_caps": list(info.io_caps),
                    "max_bonds": info.max_bonds,
                }
                for adapter_id, info in self._adapters.items()
            }
            sessions = {
                session_id: {
                    "adapter_id": session.adapter_id,
                    "address": session.address,
                    "transport": session.transport,
                    "method": session.method,
                    "passkey": session.passkey,
                    "requires_mitm": session.requires_mitm,
                    "attempts": session.attempts,
                    "deadline": session.deadline,
                    "confirmed": session.confirmed,
                }
                for session_id, session in self._sessions.items()
            }
            bonds = {
                self._snapshot_key(*key): {
                    "adapter_id": bond.adapter_id,
                    "address": bond.address,
                    "transport": bond.transport,
                    "key": bond.key,
                    "method": bond.method,
                    "created_at": bond.created_at,
                }
                for key, bond in self._bonds.items()
            }
            cooldowns = {
                self._snapshot_key(*key): {
                    "adapter_id": key[0],
                    "address": key[1],
                    "transport": key[2],
                    "deadline": deadline,
                }
                for key, deadline in self._cooldowns.items()
            }
            return {
                "version": 1,
                "adapters": adapters,
                "sessions": sessions,
                "bonds": bonds,
                "cooldowns": cooldowns,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except PairingError as exc:
                if exc.code == PAIRING_SNAPSHOT_INVALID:
                    raise
                raise PairingError(PAIRING_SNAPSHOT_INVALID) from None
            except Exception:
                raise PairingError(PAIRING_SNAPSHOT_INVALID) from None

            (self._adapters, self._sessions, self._bonds, self._cooldowns,
             self._session_seq, confirmed) = restored
            self._confirmed = confirmed
            self._removed = 0
            self._rejected = 0

    @staticmethod
    def _invalid_snapshot() -> None:
        raise PairingError(PAIRING_SNAPSHOT_INVALID)

    @classmethod
    def _snapshot_int(cls, value: object, *, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            cls._invalid_snapshot()
        return value

    @classmethod
    def _snapshot_bool(cls, value: object) -> bool:
        if type(value) is not bool:
            cls._invalid_snapshot()
        return value

    @classmethod
    def _snapshot_string(cls, value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            cls._invalid_snapshot()
        return value

    @classmethod
    def _snapshot_transport(cls, value: object) -> str:
        if value not in TRANSPORTS:
            cls._invalid_snapshot()
        return value

    @classmethod
    def _snapshot_method(cls, value: object) -> str:
        if value not in METHODS:
            cls._invalid_snapshot()
        return value

    @classmethod
    def _snapshot_table(cls, value: object) -> dict:
        if not isinstance(value, dict):
            cls._invalid_snapshot()
        return value

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            self._invalid_snapshot()
        if set(state) != {"version", "adapters", "sessions", "bonds", "cooldowns"}:
            self._invalid_snapshot()
        version = state["version"]
        if isinstance(version, bool) or version != 1:
            self._invalid_snapshot()

        raw_adapters = self._snapshot_table(state["adapters"])
        raw_sessions = self._snapshot_table(state["sessions"])
        raw_bonds = self._snapshot_table(state["bonds"])
        raw_cooldowns = self._snapshot_table(state["cooldowns"])

        adapters: dict[str, AdapterInfo] = {}
        for adapter_id, row in raw_adapters.items():
            if not isinstance(adapter_id, str) or not adapter_id.strip():
                self._invalid_snapshot()
            if not isinstance(row, dict) or set(row) != {
                    "powered", "io_caps", "max_bonds"}:
                self._invalid_snapshot()
            powered = self._snapshot_bool(row["powered"])
            caps_raw = row["io_caps"]
            if not isinstance(caps_raw, (list, tuple)):
                self._invalid_snapshot()
            try:
                caps = self._normalize_caps(caps_raw)
            except (TypeError, ValueError):
                self._invalid_snapshot()
            max_bonds = self._snapshot_int(row["max_bonds"])
            adapters[adapter_id] = AdapterInfo(adapter_id, powered, caps, max_bonds)

        sessions: dict[str, _Session] = {}
        session_peers: set[tuple[str, str, str]] = set()
        for session_id, row in raw_sessions.items():
            if not isinstance(session_id, str) or not _SESSION_ID_RE.fullmatch(session_id):
                self._invalid_snapshot()
            if not isinstance(row, dict):
                self._invalid_snapshot()
            allowed = {"adapter_id", "address", "transport", "method", "passkey",
                       "requires_mitm", "attempts", "deadline"}
            if not set(row) <= allowed | {"confirmed"} or not allowed <= set(row):
                self._invalid_snapshot()

            adapter_id = self._snapshot_string(row["adapter_id"])
            if adapter_id not in adapters:
                self._invalid_snapshot()
            address = self._snapshot_string(row["address"])
            transport = self._snapshot_transport(row["transport"])
            method = self._snapshot_method(row["method"])
            passkey = row["passkey"]
            if not isinstance(passkey, str) or not _PASSKEY_RE.fullmatch(passkey):
                self._invalid_snapshot()
            requires_mitm = self._snapshot_bool(row["requires_mitm"])
            attempts = self._snapshot_int(row["attempts"])
            if attempts > self.max_attempts:
                self._invalid_snapshot()
            deadline = self._snapshot_int(row["deadline"])
            confirmed = self._snapshot_bool(row.get("confirmed", False))
            if method == JUST_WORKS and requires_mitm:
                self._invalid_snapshot()

            peer = (adapter_id, address, transport)
            if peer in session_peers:
                self._invalid_snapshot()
            session_peers.add(peer)
            sessions[session_id] = _Session(
                session_id=session_id,
                adapter_id=adapter_id,
                address=address,
                transport=transport,
                method=method,
                passkey=passkey,
                requires_mitm=requires_mitm,
                attempts=attempts,
                deadline=deadline,
                confirmed=confirmed,
            )

        bonds: dict[tuple[str, str, str], BondRecord] = {}
        for row_key, row in raw_bonds.items():
            if not isinstance(row_key, str):
                self._invalid_snapshot()
            if not isinstance(row, dict) or set(row) != {
                    "adapter_id", "address", "transport", "key", "method",
                    "created_at"}:
                self._invalid_snapshot()
            adapter_id = self._snapshot_string(row["adapter_id"])
            if adapter_id not in adapters:
                self._invalid_snapshot()
            address = self._snapshot_string(row["address"])
            transport = self._snapshot_transport(row["transport"])
            bond_key = self._snapshot_string(row["key"])
            method = self._snapshot_method(row["method"])
            created_at = self._snapshot_int(row["created_at"])
            key = (adapter_id, address, transport)
            if key in bonds:
                self._invalid_snapshot()
            bonds[key] = BondRecord(adapter_id, address, transport, bond_key,
                                    method, created_at)

        cooldowns: dict[tuple[str, str, str], int] = {}
        for row_key, row in raw_cooldowns.items():
            if not isinstance(row_key, str):
                self._invalid_snapshot()
            if not isinstance(row, dict) or set(row) != {
                    "adapter_id", "address", "transport", "deadline"}:
                self._invalid_snapshot()
            adapter_id = self._snapshot_string(row["adapter_id"])
            if adapter_id not in adapters:
                self._invalid_snapshot()
            address = self._snapshot_string(row["address"])
            transport = self._snapshot_transport(row["transport"])
            deadline = self._snapshot_int(row["deadline"])
            key = (adapter_id, address, transport)
            if key in cooldowns:
                self._invalid_snapshot()
            cooldowns[key] = deadline

        session_seq = 0
        for session_id in sessions:
            session_seq = max(session_seq, int(session_id[1:]))
        confirmed = sum(1 for session in sessions.values() if session.confirmed)
        return adapters, sessions, bonds, cooldowns, session_seq, confirmed

    def stats(self) -> dict:
        with self._lock:
            return {
                "adapters": len(self._adapters),
                "sessions": len(self._sessions),
                "confirmed": self._confirmed,
                "bonds": len(self._bonds),
                "removed": self._removed,
                "cooldowns": len(self._cooldowns),
                "rejected": self._rejected,
            }
