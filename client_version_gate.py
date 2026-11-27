"""Client version admission: numeric version comparison, channel policies, gray release."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GateError(ValueError):
    """Raised when a version gate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VersionPolicy:
    platform: str
    channel: str
    min_version: str
    recommended_version: str
    protocol_min: int
    protocol_max: int
    allow_prerelease: bool
    version: int


@dataclass(frozen=True)
class Admission:
    account: str
    platform: str
    channel: str
    client_version: str
    protocol_version: int
    allowed: bool
    gray: bool
    reason: str
    policy_version: int
    at: str | None = None


@dataclass(frozen=True)
class Negotiation:
    accepted_protocol: int | None
    allowed: bool
    reason: str
    policy_version: int


class ClientVersionGate:
    """Admit clients by platform and channel while tracking policy generations."""

    def __init__(self, *, max_history: int = 200) -> None:
        self.max_history = max_history
        self._lock = threading.RLock()

    def set_policy(self, platform: str, channel: str, *, min_version: str,
                   recommended_version: str | None = None,
                   protocol_min: int = 1, protocol_max: int = 1,
                   allow_prerelease: bool = False) -> int:
        """Install or replace the policy of one platform/channel pair."""
        raise NotImplementedError

    def drop_policy(self, platform: str, channel: str) -> int:
        """Remove one platform/channel policy and return the new generation."""
        raise NotImplementedError

    def policy_of(self, platform: str, channel: str) -> VersionPolicy:
        """Return the policy currently installed for one platform/channel pair."""
        raise NotImplementedError

    def admit(self, account: str, *, platform: str, channel: str,
              client_version: str, protocol_version: int,
              now: str | None = None) -> Admission:
        """Decide whether one client handshake may enter the current server."""
        raise NotImplementedError

    def negotiate(self, account: str, *, platform: str, channel: str,
                  client_version: str, protocol_versions,
                  now: str | None = None) -> Negotiation:
        """Pick the highest accepted protocol version from the client offer list."""
        raise NotImplementedError

    def grant_gray(self, account: str, platform: str, channel: str, *,
                   note: str = "") -> bool:
        """Put one account on the early-access list of a policy generation."""
        raise NotImplementedError

    def revoke_gray(self, account: str, platform: str, channel: str) -> bool:
        """Remove one account from the early-access list."""
        raise NotImplementedError

    def gray_bucket(self, account: str, client_version: str) -> int:
        """Stable early-access bucket derived from the account and prerelease tag."""
        raise NotImplementedError

    def reason_of(self, account: str) -> str | None:
        """Reason of the most recent admission attempt of one account."""
        raise NotImplementedError

    def history_of(self, account: str) -> list[Admission]:
        """Admission attempts of one account in chronological order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of policies, gray list, history and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Counters exposed to the login operations dashboard."""
        raise NotImplementedError
