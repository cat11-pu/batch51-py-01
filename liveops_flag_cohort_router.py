"""Live-ops flag routing: stable cohorts, targeting, dependency order, config generations."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class FlagError(ValueError):
    """Raised when a flag operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FlagSpec:
    name: str
    enabled: bool
    rollout_bps: int
    regions: tuple[str, ...]
    platforms: tuple[str, ...]
    versions: tuple[str, ...]
    whitelist: tuple[str, ...]
    depends_on: tuple[str, ...]
    version: int


@dataclass(frozen=True)
class Decision:
    flag: str
    enabled: bool
    reason: str
    source: str
    version: int


class FlagCohortRouter:
    """Decide flag state per account with sticky cohorts and dependency ordering."""

    def __init__(self, *, max_flags: int = 128, max_audit: int = 256,
                 salt: str = "cohort-v1") -> None:
        self.max_flags = max_flags
        self.max_audit = max_audit
        self.salt = salt
        self._lock = threading.RLock()

    def define_flag(self, name: str, *, enabled: bool = False,
                    rollout_bps: int = 0, regions=(), platforms=(),
                    versions=(), whitelist=(), depends_on=()) -> int:
        """Create a flag and return the new configuration version."""
        raise NotImplementedError

    def set_rollout(self, name: str, bps: int) -> int:
        """Change the rollout percentage and return the new configuration version."""
        raise NotImplementedError

    def set_dependencies(self, name: str, flags) -> int:
        """Replace the parent list of a flag, refusing unknown parents and cycles."""
        raise NotImplementedError

    def remove_flag(self, name: str) -> int:
        """Drop a flag and return the new configuration version."""
        raise NotImplementedError

    def evaluate(self, account: str, flag: str, *, region: str | None = None,
                 platform: str | None = None,
                 version: str | None = None) -> Decision:
        """Resolve one flag for one account at the current configuration version."""
        raise NotImplementedError

    def bulk_evaluate(self, account: str, flags, *, region: str | None = None,
                      platform: str | None = None,
                      version: str | None = None) -> list[Decision]:
        """Resolve several flags in dependency topological order."""
        raise NotImplementedError

    def audit_of(self, flag: str | None = None) -> list[dict]:
        """Configuration changes ordered by sequence, optionally scoped to one flag."""
        raise NotImplementedError

    def spec_of(self, name: str) -> FlagSpec:
        """Current definition of one flag."""
        raise NotImplementedError

    def config_version(self) -> int:
        """Current configuration generation number."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of flags, audit trail and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live configuration from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the counters exposed to the operations dashboard."""
        raise NotImplementedError
