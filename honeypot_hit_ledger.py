"""Honeypot hit ledger: source fingerprint clustering, window dedupe, payload caps."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
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


@dataclass(frozen=True)
class _ArchiveEntry:
    fingerprint: str
    at: int
    digest: str
    stored_bytes: int
    status: str
    truncated: bool
    overflow: bool
    payload: bytes | None


_SNAPSHOT_KEYS = {"version", "window_seconds", "records", "archives", "stats"}
_STATS_KEYS = {
    "hits",
    "records",
    "sources",
    "folded",
    "payloads",
    "payload_overflow",
    "restores",
}
_RECORD_KEYS = {
    "fingerprint",
    "subnet",
    "client",
    "window_start",
    "hits",
    "first_seen",
    "last_seen",
    "path",
    "sources",
    "folded",
}
_ARCHIVE_KEYS = {
    "fingerprint",
    "at",
    "digest",
    "stored_bytes",
    "status",
    "truncated",
    "overflow",
    "payload",
}
_SNAPSHOT_VERSION = 1


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonnegative_int(value: object) -> bool:
    return _is_int(value) and value >= 0


def _snapshot_error(detail: object) -> HoneypotError:
    return HoneypotError("HONEY_SNAPSHOT_INVALID", detail)


class HoneypotHitLedger:
    """Cluster honeypot interactions by source fingerprint and archive payloads."""

    def __init__(self, *, window_seconds: int = 60, max_entries: int = 64,
                 max_payload_bytes: int = 256,
                 max_total_payload: int = 1024) -> None:
        if not _is_int(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be a positive integer")
        if not _is_int(max_entries) or max_entries < 0:
            raise ValueError("max_entries must be a non-negative integer")
        if not _is_int(max_payload_bytes) or max_payload_bytes < 0:
            raise ValueError("max_payload_bytes must be a non-negative integer")
        if not _is_int(max_total_payload) or max_total_payload < 0:
            raise ValueError("max_total_payload must be a non-negative integer")

        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self.max_payload_bytes = max_payload_bytes
        self.max_total_payload = max_total_payload
        self._lock = threading.RLock()
        self._clear_state()

    def _clear_state(self) -> None:
        self._records: dict[str, HitRecord] = {}
        self._trails: dict[str, list[tuple[int, str]]] = {}
        self._next_trail_sequence = 0
        self._archives: list[_ArchiveEntry] = []
        self._latest_payloads: dict[str, bytes] = {}
        self._stored_total = 0
        self._restores = 0

    def _validated_source(self, source_ip: object) -> str:
        if not isinstance(source_ip, str) or not source_ip.strip():
            raise HoneypotError(
                "HONEY_INVALID_HIT", {"field": "source_ip", "value": source_ip}
            )
        return source_ip.strip()

    @staticmethod
    def _validated_at(at: object) -> int:
        if not _is_nonnegative_int(at):
            raise HoneypotError("HONEY_INVALID_HIT", {"field": "at", "value": at})
        return at

    @staticmethod
    def _normalized_client(client: object) -> str:
        if not isinstance(client, str):
            raise HoneypotError(
                "HONEY_INVALID_HIT", {"field": "client", "value": client}
            )
        normalized = client.strip().lower()
        return normalized or "anon"

    def _subnet_for(self, source: str) -> str:
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return source.lower()
        if isinstance(address, ipaddress.IPv4Address):
            return ".".join(str(address).split(".")[:3])
        return source.lower()

    def _window_for(self, at: int) -> int:
        return (at // self.window_seconds) * self.window_seconds

    def _fingerprint_parts(self, source_ip: object, client: object,
                           at: object) -> tuple[str, str, str, int, str]:
        source = self._validated_source(source_ip)
        normalized_at = self._validated_at(at)
        subnet = self._subnet_for(source)
        normalized_client = self._normalized_client(client)
        window_start = self._window_for(normalized_at)
        fingerprint = f"{subnet}|{normalized_client}|{window_start}"
        return source, subnet, normalized_client, window_start, fingerprint

    def _link_source(self, source: str, fingerprint: str) -> None:
        links = self._trails.setdefault(source, [])
        if any(link_fingerprint == fingerprint
               for _, link_fingerprint in links):
            return
        links.append((self._next_trail_sequence, fingerprint))
        self._next_trail_sequence += 1

    def _stats_locked(self) -> dict:
        records = tuple(self._records.values())
        sources = {
            source
            for record in records
            for source in record.sources
        }
        return {
            "hits": sum(record.hits for record in records),
            "records": len(records),
            "sources": len(sources),
            "folded": sum(record.hits - 1 for record in records),
            "payloads": len(self._archives),
            "payload_overflow": sum(
                1 for archive in self._archives if archive.overflow
            ),
            "restores": self._restores,
        }

    def record_hit(self, source_ip: str, *, client: str = "",
                   path: str = "/", at: int = 0) -> HitRecord:
        with self._lock:
            source, subnet, normalized_client, window_start, fingerprint = (
                self._fingerprint_parts(source_ip, client, at)
            )
            existing = self._records.get(fingerprint)
            if existing is not None:
                sources = tuple(sorted(set(existing.sources) | {source}))
                record = HitRecord(
                    fingerprint=fingerprint,
                    subnet=subnet,
                    client=normalized_client,
                    window_start=window_start,
                    hits=existing.hits + 1,
                    first_seen=existing.first_seen,
                    last_seen=at,
                    path=path,
                    sources=sources,
                    folded=True,
                )
                self._records[fingerprint] = record
                if source not in existing.sources:
                    self._link_source(source, fingerprint)
                return record

            if len(self._records) >= self.max_entries:
                raise HoneypotError(
                    "HONEY_CAPACITY_EXCEEDED",
                    {"max_entries": self.max_entries},
                )

            record = HitRecord(
                fingerprint=fingerprint,
                subnet=subnet,
                client=normalized_client,
                window_start=window_start,
                hits=1,
                first_seen=at,
                last_seen=at,
                path=path,
                sources=(source,),
                folded=False,
            )
            self._records[fingerprint] = record
            self._link_source(source, fingerprint)
            return record

    def fingerprint_for(self, source_ip: str, *, client: str = "",
                        at: int = 0) -> str:
        with self._lock:
            return self._fingerprint_parts(source_ip, client, at)[4]

    def cluster_by_fingerprint(
            self, *, window_start: int | None = None) -> tuple[ClusterView, ...]:
        if window_start is not None:
            if not _is_nonnegative_int(window_start):
                raise HoneypotError(
                    "HONEY_INVALID_HIT",
                    {"field": "window_start", "value": window_start},
                )

        with self._lock:
            clusters = [
                ClusterView(
                    fingerprint=record.fingerprint,
                    subnet=record.subnet,
                    client=record.client,
                    window_start=record.window_start,
                    sources=record.sources,
                    hits=record.hits,
                )
                for record in self._records.values()
                if window_start is None or record.window_start == window_start
            ]
        return tuple(sorted(clusters, key=lambda cluster: cluster.fingerprint))

    def dedupe_window(self, at: int) -> WindowSummary:
        normalized_at = self._validated_at(at)
        with self._lock:
            window_start = self._window_for(normalized_at)
            records = [
                record
                for record in self._records.values()
                if record.window_start == window_start
            ]
            hits = sum(record.hits for record in records)
            return WindowSummary(
                window_start=window_start,
                records=len(records),
                hits=hits,
                folded=hits - len(records),
            )

    def archive_payload(self, fingerprint: str, payload: bytes, *,
                        at: int = 0) -> ArchiveResult:
        normalized_at = self._validated_at(at)
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload must be bytes-like")
        body = bytes(payload)
        digest = hashlib.sha256(body).hexdigest()

        with self._lock:
            if fingerprint not in self._records:
                raise HoneypotError(
                    "HONEY_UNKNOWN_FINGERPRINT", fingerprint
                )

            if len(body) > self.max_payload_bytes:
                status = "digest_only"
                stored_bytes = 0
                truncated = True
                overflow = False
                stored_payload: bytes | None = None
            elif self._stored_total + len(body) > self.max_total_payload:
                status = "digest_only"
                stored_bytes = 0
                truncated = True
                overflow = True
                stored_payload = None
            else:
                status = "stored"
                stored_bytes = len(body)
                truncated = False
                overflow = False
                stored_payload = body
                self._stored_total += stored_bytes
                self._latest_payloads[fingerprint] = body

            entry = _ArchiveEntry(
                fingerprint=fingerprint,
                at=normalized_at,
                digest=digest,
                stored_bytes=stored_bytes,
                status=status,
                truncated=truncated,
                overflow=overflow,
                payload=stored_payload,
            )
            self._archives.append(entry)
            return ArchiveResult(
                fingerprint=fingerprint,
                at=normalized_at,
                digest=digest,
                stored_bytes=stored_bytes,
                status=status,
                truncated=truncated,
            )

    def payload_for(self, fingerprint: str) -> bytes | None:
        with self._lock:
            return self._latest_payloads.get(fingerprint)

    def source_trail(self, source_ip: str) -> tuple[TrailLink, ...]:
        if not isinstance(source_ip, str) or not source_ip.strip():
            raise HoneypotError(
                "HONEY_INVALID_HIT", {"field": "source_ip", "value": source_ip}
            )
        source = source_ip.strip()
        with self._lock:
            links = sorted(self._trails.get(source, ()))
            trail: list[TrailLink] = []
            for _, fingerprint in links:
                record = self._records.get(fingerprint)
                if record is None:
                    continue
                trail.append(
                    TrailLink(
                        fingerprint=record.fingerprint,
                        window_start=record.window_start,
                        client=record.client,
                        hits=record.hits,
                    )
                )
            return tuple(trail)

    def entries(self) -> tuple[HitRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def lookup(self, fingerprint: str) -> HitRecord | None:
        with self._lock:
            return self._records.get(fingerprint)

    def snapshot(self) -> dict:
        with self._lock:
            record_links: dict[str, list[list[object]]] = {}
            for source, links in self._trails.items():
                for sequence, fingerprint in links:
                    record_links.setdefault(fingerprint, []).append(
                        [source, sequence]
                    )

            records = []
            for record in self._records.values():
                links = sorted(
                    record_links.get(record.fingerprint, ()),
                    key=lambda link: link[1],
                )
                records.append({
                    "fingerprint": record.fingerprint,
                    "subnet": record.subnet,
                    "client": record.client,
                    "window_start": record.window_start,
                    "hits": record.hits,
                    "first_seen": record.first_seen,
                    "last_seen": record.last_seen,
                    "path": record.path,
                    "sources": list(record.sources),
                    "folded": record.folded,
                    "source_links": links,
                })

            archives = [
                {
                    "fingerprint": archive.fingerprint,
                    "at": archive.at,
                    "digest": archive.digest,
                    "stored_bytes": archive.stored_bytes,
                    "status": archive.status,
                    "truncated": archive.truncated,
                    "overflow": archive.overflow,
                    "payload": archive.payload,
                }
                for archive in self._archives
            ]
            state = {
                "version": _SNAPSHOT_VERSION,
                "window_seconds": self.window_seconds,
                "records": records,
                "archives": archives,
                "stats": self._stats_locked(),
            }
            return copy.deepcopy(state)

    def _restore_candidate(self, state: object) -> tuple:
        try:
            state_copy = copy.deepcopy(state)
        except Exception as exc:
            raise _snapshot_error("state is not copyable") from exc

        if not isinstance(state_copy, dict) or set(state_copy) != _SNAPSHOT_KEYS:
            raise _snapshot_error("snapshot must contain exactly five fields")

        version = state_copy["version"]
        if not _is_int(version) or version != _SNAPSHOT_VERSION:
            raise _snapshot_error("unsupported version")

        window_seconds = state_copy["window_seconds"]
        if not _is_int(window_seconds) or window_seconds <= 0:
            raise _snapshot_error("invalid window_seconds")

        raw_records = state_copy["records"]
        raw_archives = state_copy["archives"]
        raw_stats = state_copy["stats"]
        if not isinstance(raw_records, list):
            raise _snapshot_error("records must be a list")
        if not isinstance(raw_archives, list):
            raise _snapshot_error("archives must be a list")
        if not isinstance(raw_stats, dict) or set(raw_stats) != _STATS_KEYS:
            raise _snapshot_error("invalid stats")
        for name, value in raw_stats.items():
            if not _is_nonnegative_int(value):
                raise _snapshot_error(f"invalid stats.{name}")

        records: dict[str, HitRecord] = {}
        provided_links: dict[str, list[tuple[int, str]]] = {}
        next_sequence = 0

        for index, raw in enumerate(raw_records):
            if not isinstance(raw, dict):
                raise _snapshot_error(f"records[{index}] must be a mapping")
            if not _RECORD_KEYS.issubset(raw):
                raise _snapshot_error(f"records[{index}] is incomplete")

            fingerprint = raw["fingerprint"]
            subnet = raw["subnet"]
            client = raw["client"]
            window_start = raw["window_start"]
            hits = raw["hits"]
            first_seen = raw["first_seen"]
            last_seen = raw["last_seen"]
            path = raw["path"]
            sources = raw["sources"]
            folded = raw["folded"]

            if not isinstance(fingerprint, str) or not fingerprint:
                raise _snapshot_error(f"records[{index}].fingerprint is invalid")
            if not isinstance(subnet, str) or not subnet:
                raise _snapshot_error(f"records[{index}].subnet is invalid")
            if not isinstance(client, str) or not client:
                raise _snapshot_error(f"records[{index}].client is invalid")
            if client != self._normalized_client(client):
                raise _snapshot_error(
                    f"records[{index}].client is not normalized"
                )
            if not isinstance(window_start, int) or isinstance(window_start, bool):
                raise _snapshot_error(
                    f"records[{index}].window_start is invalid"
                )
            if window_start < 0 or window_start % window_seconds:
                raise _snapshot_error(
                    f"records[{index}].window_start is invalid"
                )
            if not _is_int(hits) or hits < 1:
                raise _snapshot_error(f"records[{index}].hits is invalid")
            if not _is_nonnegative_int(first_seen):
                raise _snapshot_error(
                    f"records[{index}].first_seen is invalid"
                )
            if not _is_nonnegative_int(last_seen):
                raise _snapshot_error(
                    f"records[{index}].last_seen is invalid"
                )
            window_end = window_start + window_seconds
            if not (window_start <= first_seen <= last_seen < window_end):
                raise _snapshot_error(
                    f"records[{index}] timestamps fall outside its window"
                )
            if not isinstance(path, str):
                raise _snapshot_error(f"records[{index}].path is invalid")
            if not isinstance(sources, (list, tuple)) or not sources:
                raise _snapshot_error(f"records[{index}].sources is invalid")
            if not all(isinstance(source, str) and source
                       for source in sources):
                raise _snapshot_error(f"records[{index}].sources is invalid")
            if list(sources) != sorted(set(sources)):
                raise _snapshot_error(
                    f"records[{index}].sources must be unique and sorted"
                )
            if any(self._subnet_for(source) != subnet for source in sources):
                raise _snapshot_error(
                    f"records[{index}].sources do not match its subnet"
                )
            if not isinstance(folded, bool) or folded != (hits > 1):
                raise _snapshot_error(f"records[{index}].folded is invalid")
            if fingerprint != f"{subnet}|{client}|{window_start}":
                raise _snapshot_error(
                    f"records[{index}].fingerprint is inconsistent"
                )
            if fingerprint in records:
                raise _snapshot_error("duplicate fingerprint")

            records[fingerprint] = HitRecord(
                fingerprint=fingerprint,
                subnet=subnet,
                client=client,
                window_start=window_start,
                hits=hits,
                first_seen=first_seen,
                last_seen=last_seen,
                path=path,
                sources=tuple(sources),
                folded=folded,
            )

            links = raw.get("source_links", [])
            if not isinstance(links, (list, tuple)):
                raise _snapshot_error(
                    f"records[{index}].source_links is invalid"
                )
            seen_link_sources: set[str] = set()
            for link in links:
                if not isinstance(link, (list, tuple)) or len(link) != 2:
                    raise _snapshot_error(
                        f"records[{index}].source_links is invalid"
                    )
                source, sequence = link
                if not isinstance(source, str) or source not in sources:
                    raise _snapshot_error(
                        f"records[{index}].source_links is invalid"
                    )
                if source in seen_link_sources:
                    raise _snapshot_error(
                        f"records[{index}].source_links has duplicates"
                    )
                if not _is_nonnegative_int(sequence):
                    raise _snapshot_error(
                        f"records[{index}].source_links is invalid"
                    )
                seen_link_sources.add(source)
                provided_links.setdefault(source, []).append(
                    (sequence, fingerprint)
                )
                next_sequence = max(next_sequence, sequence + 1)

        for source, links in provided_links.items():
            links.sort()
            provided_links[source] = links

        # Older or hand-built snapshots may omit the internal source sequence
        # metadata. In that case, use record order as a deterministic fallback.
        for record in records.values():
            for source in record.sources:
                links = provided_links.setdefault(source, [])
                if not any(fp == record.fingerprint for _, fp in links):
                    links.append((next_sequence, record.fingerprint))
                    next_sequence += 1

        archives: list[_ArchiveEntry] = []
        latest_payloads: dict[str, bytes] = {}
        stored_total = 0
        for index, raw in enumerate(raw_archives):
            if not isinstance(raw, dict):
                raise _snapshot_error(f"archives[{index}] must be a mapping")
            if not _ARCHIVE_KEYS.issubset(raw):
                raise _snapshot_error(f"archives[{index}] is incomplete")

            fingerprint = raw["fingerprint"]
            at = raw["at"]
            digest = raw["digest"]
            stored_bytes = raw["stored_bytes"]
            status = raw["status"]
            truncated = raw["truncated"]
            overflow = raw["overflow"]
            payload = raw["payload"]

            if not isinstance(fingerprint, str) or fingerprint not in records:
                raise _snapshot_error(
                    f"archives[{index}].fingerprint is unknown"
                )
            if not _is_nonnegative_int(at):
                raise _snapshot_error(f"archives[{index}].at is invalid")
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise _snapshot_error(f"archives[{index}].digest is invalid")
            if not _is_nonnegative_int(stored_bytes):
                raise _snapshot_error(
                    f"archives[{index}].stored_bytes is invalid"
                )
            if status not in {"stored", "digest_only"}:
                raise _snapshot_error(f"archives[{index}].status is invalid")
            if not isinstance(truncated, bool):
                raise _snapshot_error(
                    f"archives[{index}].truncated is invalid"
                )
            if not isinstance(overflow, bool):
                raise _snapshot_error(
                    f"archives[{index}].overflow is invalid"
                )

            stored_payload: bytes | None
            if status == "stored":
                if (not isinstance(payload, bytes) or truncated or overflow
                        or stored_bytes != len(payload)):
                    raise _snapshot_error(
                        f"archives[{index}] stored payload is invalid"
                    )
                if hashlib.sha256(payload).hexdigest() != digest:
                    raise _snapshot_error(
                        f"archives[{index}].digest does not match payload"
                    )
                stored_payload = payload
                latest_payloads[fingerprint] = payload
                stored_total += stored_bytes
            else:
                if payload is not None or stored_bytes != 0 or not truncated:
                    raise _snapshot_error(
                        f"archives[{index}] digest-only payload is invalid"
                    )
                stored_payload = None

            archives.append(
                _ArchiveEntry(
                    fingerprint=fingerprint,
                    at=at,
                    digest=digest,
                    stored_bytes=stored_bytes,
                    status=status,
                    truncated=truncated,
                    overflow=overflow,
                    payload=stored_payload,
                )
            )

        expected_stats = {
            "hits": sum(record.hits for record in records.values()),
            "records": len(records),
            "sources": len({
                source for record in records.values()
                for source in record.sources
            }),
            "folded": sum(
                record.hits - 1 for record in records.values()
            ),
            "payloads": len(archives),
            "payload_overflow": sum(
                1 for archive in archives if archive.overflow
            ),
            "restores": raw_stats["restores"],
        }
        if raw_stats != expected_stats:
            raise _snapshot_error("stats do not match records or archives")

        return (
            window_seconds,
            records,
            provided_links,
            archives,
            latest_payloads,
            stored_total,
            next_sequence,
            raw_stats["restores"],
        )

    def restore(self, state: dict) -> None:
        with self._lock:
            (
                window_seconds,
                records,
                trails,
                archives,
                latest_payloads,
                stored_total,
                next_sequence,
                restores,
            ) = self._restore_candidate(state)

            self.window_seconds = window_seconds
            self._records = records
            self._trails = trails
            self._archives = archives
            self._latest_payloads = latest_payloads
            self._stored_total = stored_total
            self._next_trail_sequence = next_sequence
            self._restores = restores + 1

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()

    def reset(self) -> None:
        with self._lock:
            self._clear_state()
