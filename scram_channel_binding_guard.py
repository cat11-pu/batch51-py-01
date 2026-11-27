"""SCRAM channel binding guard: mechanism policy, downgrade refusal, binding check."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ScramError(ValueError):
    """Raised when a negotiation step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Offer:
    session_id: str
    mechanisms: tuple[str, ...]
    has_binding: bool
    state: str


@dataclass(frozen=True)
class BindingVerdict:
    session_id: str
    mechanism: str
    status: str
    digest: str


class ScramChannelBindingGuard:
    """Decide whether a session may continue with its actual binding data."""

    def __init__(self, *, policy: str = "require", supported=None,
                 clock=None) -> None:
        self.policy = policy
        self.supported = supported
        self._clock = clock
        self._lock = threading.RLock()

    def offer(self, *, session_id: str, mechanisms,
              binding_data: str | None = None) -> Offer:
        raise NotImplementedError

    def select_mechanism(self, *, session_id: str,
                         mechanism: str | None = None) -> str:
        raise NotImplementedError

    def bind_channel(self, *, session_id: str, channel_digest: str) -> None:
        raise NotImplementedError

    def verify_binding(self, *, session_id: str,
                       binding_data: str | None) -> BindingVerdict:
        raise NotImplementedError

    def reject_downgrade(self, *, session_id: str, mechanism: str) -> str:
        raise NotImplementedError

    def session_state(self, session_id: str) -> str:
        raise NotImplementedError

    def close_session(self, session_id: str) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
