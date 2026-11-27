"""Item instance provenance ledger: source events, holder chains, duplicate quarantine."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class LedgerError(ValueError):
    """Raised when a provenance operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProvenanceEvent:
    seq: int
    kind: str
    instance: str
    actor: str
    qty: int
    at: str | None
    note: str = ""


@dataclass(frozen=True)
class Conflict:
    instance: str
    holders: tuple[str, ...]
    events: tuple[int, ...]


class ItemProvenanceLedger:
    """Track every item instance from its source event down to the current holder."""

    SOURCE_KINDS = ("drop", "craft", "trade", "mail")

    def __init__(self, *, max_chain: int = 64, max_quarantine: int = 32) -> None:
        self.max_chain = max_chain
        self.max_quarantine = max_quarantine
        self._lock = threading.RLock()

    def ingest_event(self, kind: str, instance: str, *, actor: str,
                     qty: int = 1, event_key: str | None = None,
                     at: str | None = None) -> int:
        """Append one source event, or drop it when the event key was seen."""
        raise NotImplementedError

    def transfer(self, instance: str, from_owner: str, to_owner: str, *,
                 event_key: str | None = None, at: str | None = None) -> int:
        """Append a holder change and return the assigned global event number."""
        raise NotImplementedError

    def owner_of(self, instance: str) -> str:
        """Current holder of a live instance."""
        raise NotImplementedError

    def qty_of(self, instance: str) -> int:
        """Stack size of a live instance."""
        raise NotImplementedError

    def holdings_of(self, owner: str) -> list[str]:
        """Live instances of one holder, sorted by instance id."""
        raise NotImplementedError

    def chain_of(self, instance: str) -> list[ProvenanceEvent]:
        """Full event chain in ascending event-number order."""
        raise NotImplementedError

    def segments_of(self, instance: str) -> list[tuple[str, int]]:
        """Source segments still carried by the instance."""
        raise NotImplementedError

    def split(self, instance: str, qty: int, *, new_instance: str,
              at: str | None = None) -> str:
        """Split a stack into a child instance that inherits the parent chain."""
        raise NotImplementedError

    def merge(self, target: str, sources: list[str], *,
              at: str | None = None) -> int:
        """Merge source stacks into the target and archive the sources."""
        raise NotImplementedError

    def destroy(self, instance: str, *, at: str | None = None) -> bool:
        """Mark an instance as destroyed without dropping its chain."""
        raise NotImplementedError

    def recover(self, instance: str, *, at: str | None = None) -> bool:
        """Append a recovery event to a destroyed instance."""
        raise NotImplementedError

    def scan_duplicates(self, observed: dict[str, list[str]] | None = None) -> list[Conflict]:
        """Detect instances reported under more than one holder."""
        raise NotImplementedError

    def quarantine(self) -> list[Conflict]:
        """Conflicts currently parked in the quarantine area."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Deep copy of instances, chains, counters and stats."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the counters exposed to the item operations dashboard."""
        raise NotImplementedError
