"""Bluetooth pairing governance: IO capability matrix, MITM downgrade guard, bond overwrite."""

from __future__ import annotations

import threading
from dataclasses import dataclass

LE = "le"
CLASSIC = "classic"
TRANSPORTS = (CLASSIC, LE)

JUST_WORKS = "just_works"
NUMERIC_COMPARISON = "numeric_comparison"
PASSKEY_DISPLAY = "passkey_display"
PASSKEY_ENTRY = "passkey_entry"
METHODS = (JUST_WORKS, NUMERIC_COMPARISON, PASSKEY_DISPLAY, PASSKEY_ENTRY)


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


class BluetoothPairingGuard:
    """Choose pairing methods from both ends' IO capabilities and keep per-adapter bonds."""

    def __init__(self, *, pairing_window: int = 60, max_attempts: int = 3,
                 cooldown: int = 30, max_sessions: int = 32) -> None:
        self.pairing_window = pairing_window
        self.max_attempts = max_attempts
        self.cooldown = cooldown
        self.max_sessions = max_sessions
        self._lock = threading.RLock()

    def register_adapter(self, adapter_id: str, *, powered: bool = True,
                         io_caps=None, max_bonds: int = 8) -> AdapterInfo:
        raise NotImplementedError

    def set_powered(self, adapter_id: str, powered: bool) -> AdapterInfo:
        raise NotImplementedError

    def pair_request(self, adapter_id: str, address: str, *, transport: str = LE,
                     peer_caps=None, requires_mitm: bool = False,
                     now: int | None = None) -> PairingSession:
        raise NotImplementedError

    def confirm_passkey(self, session_id: str, value: str, *,
                        now: int | None = None) -> dict:
        raise NotImplementedError

    def complete_pairing(self, session_id: str, *, confirm: bool = True,
                         now: int | None = None) -> BondRecord:
        raise NotImplementedError

    def remove_bond(self, adapter_id: str, address: str, *,
                    transport: str | None = None) -> int:
        raise NotImplementedError

    def bond_for(self, adapter_id: str, address: str, *,
                 transport: str = LE) -> BondRecord | None:
        raise NotImplementedError

    def bonds(self, adapter_id: str) -> list[BondRecord]:
        raise NotImplementedError

    def pending_sessions(self) -> list[PairingSession]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
