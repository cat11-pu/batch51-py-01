"""Honeypot hit ledger: source fingerprint clustering, window dedupe, payload caps."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class HoneypotError(ValueError):
    """Raised when a ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class HitRecord:
    fingerprint: str
    subnet: str
    client: str
    window_start: int
    hits: int
    first_seen: int
    last_seen: int
    path: str
    sources: tuple[str, ...]
    folded: bool


@dataclass(frozen=True)
class ClusterView:
    fingerprint: str
    subnet: str
    client: str
    window_start: int
    sources: tuple[str, ...]
    hits: int


@dataclass(frozen=True)
class WindowSummary:
    window_start: int
    records: int
    hits: int
    folded: int


@dataclass(frozen=True)
class ArchiveResult:
    fingerprint: str
    at: int
    digest: str
    stored_bytes: int
    status: str
    truncated: bool


@dataclass(frozen=True)
class TrailLink:
    fingerprint: str
    window_start: int
    client: str
    hits: int


class HoneypotHitLedger:
    """Cluster honeypot interactions by source fingerprint and archive payloads."""

    def __init__(self, *, window_seconds: int = 60, max_entries: int = 64,
                 max_payload_bytes: int = 256,
                 max_total_payload: int = 1024) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self.max_payload_bytes = max_payload_bytes
        self.max_total_payload = max_total_payload
        self._lock = threading.RLock()

    def record_hit(self, source_ip: str, *, client: str = "",
                   path: str = "/", at: int = 0) -> HitRecord:
        raise NotImplementedError

    def fingerprint_for(self, source_ip: str, *, client: str = "",
                        at: int = 0) -> str:
        raise NotImplementedError

    def cluster_by_fingerprint(self, *, window_start: int | None = None) -> tuple[ClusterView, ...]:
        raise NotImplementedError

    def dedupe_window(self, at: int) -> WindowSummary:
        raise NotImplementedError

    def archive_payload(self, fingerprint: str, payload: bytes, *,
                        at: int = 0) -> ArchiveResult:
        raise NotImplementedError

    def payload_for(self, fingerprint: str) -> bytes | None:
        raise NotImplementedError

    def source_trail(self, source_ip: str) -> tuple[TrailLink, ...]:
        raise NotImplementedError

    def entries(self) -> tuple[HitRecord, ...]:
        raise NotImplementedError

    def lookup(self, fingerprint: str) -> HitRecord | None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
