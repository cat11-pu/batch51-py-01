"""Signature counter watermark tracking and authenticator clone quarantine."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CloneDetectorError(ValueError):
    """Refusal raised by the authenticator clone detector."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CredentialView:
    account: str
    credential_id: str
    status: str
    counter_capable: bool
    watermark: int
    regressions: int


@dataclass(frozen=True)
class ObservationVerdict:
    status: str
    code: str
    watermark: int
    regressions: int
    quarantined: bool


@dataclass(frozen=True)
class ReviewRecord:
    credential_id: str
    reviewer: str
    at: int


class CloneDetector:
    """Track per credential signature counters and isolate cloned authenticators."""

    _STATUSES = ("active", "quarantined", "revoked")
    _SNAPSHOT_VERSION = 1
    _STAT_KEYS = ("credentials", "observations", "regressions",
                  "quarantines", "releases", "revocations")

    def __init__(self, *, quarantine_after: int = 2) -> None:
        self.quarantine_after = quarantine_after
        self._lock = threading.RLock()
        self._credentials = {}
        self._reviews = {}
        self._stats = {key: 0 for key in self._STAT_KEYS}

    @staticmethod
    def _is_valid_counter(counter: object) -> bool:
        return isinstance(counter, int) and not isinstance(counter, bool) \
            and counter >= 0

    def _lookup(self, account, credential_id):
        record = self._credentials.get(credential_id)
        if record is None or record["account"] != account:
            raise CloneDetectorError("CTR_UNKNOWN_CREDENTIAL",
                                     {"credential_id": credential_id})
        return record

    def _lookup_by_id(self, credential_id):
        record = self._credentials.get(credential_id)
        if record is None:
            raise CloneDetectorError("CTR_UNKNOWN_CREDENTIAL",
                                     {"credential_id": credential_id})
        return record

    @staticmethod
    def _view(record):
        return CredentialView(
            account=record["account"],
            credential_id=record["credential_id"],
            status=record["status"],
            counter_capable=record["counter_capable"],
            watermark=record["watermark"],
            regressions=record["regressions"],
        )

    def _apply_quarantine(self, record, *, source, reason, at):
        record["status"] = "quarantined"
        record["quarantine"] = {"source": source, "reason": reason, "at": at}
        self._stats["quarantines"] += 1

    def register_credential(self, account: str, *, credential_id: str,
                            counter_capable: bool = True,
                            at: int = 0) -> CredentialView:
        with self._lock:
            if credential_id in self._credentials:
                raise CloneDetectorError("CTR_CREDENTIAL_EXISTS",
                                         {"credential_id": credential_id})
            record = {
                "account": account,
                "credential_id": credential_id,
                "status": "active",
                "counter_capable": bool(counter_capable),
                "watermark": 0,
                "regressions": 0,
                "registered_at": at,
                "quarantine": None,
            }
            self._credentials[credential_id] = record
            self._reviews.setdefault(credential_id, [])
            self._stats["credentials"] += 1
            return self._view(record)

    def observe(self, account: str, *, credential_id: str, counter: int,
                at: int) -> ObservationVerdict:
        with self._lock:
            record = self._lookup(account, credential_id)
            if not self._is_valid_counter(counter):
                raise CloneDetectorError("CTR_INVALID_COUNTER",
                                         {"counter": counter})
            self._stats["observations"] += 1
            if record["status"] == "revoked":
                return ObservationVerdict(
                    status="deny", code="CTR_CREDENTIAL_REVOKED",
                    watermark=record["watermark"],
                    regressions=record["regressions"], quarantined=False)
            if record["status"] == "quarantined":
                return ObservationVerdict(
                    status="deny", code="CTR_QUARANTINED",
                    watermark=record["watermark"],
                    regressions=record["regressions"], quarantined=True)
            if not record["counter_capable"]:
                return ObservationVerdict(
                    status="pass", code="CTR_NOT_APPLICABLE",
                    watermark=record["watermark"],
                    regressions=record["regressions"], quarantined=False)
            if counter > record["watermark"]:
                record["watermark"] = counter
                return ObservationVerdict(
                    status="pass", code="CTR_OK",
                    watermark=record["watermark"],
                    regressions=record["regressions"], quarantined=False)
            record["regressions"] += 1
            self._stats["regressions"] += 1
            if record["regressions"] >= self.quarantine_after:
                self._apply_quarantine(record, source="auto",
                                       reason="repeated counter regression",
                                       at=at)
                return ObservationVerdict(
                    status="quarantine", code="CTR_REPEAT_REGRESSION",
                    watermark=record["watermark"],
                    regressions=record["regressions"], quarantined=True)
            return ObservationVerdict(
                status="warn", code="CTR_ROLLBACK",
                watermark=record["watermark"],
                regressions=record["regressions"], quarantined=False)

    def credential_state(self, credential_id: str) -> CredentialView:
        with self._lock:
            return self._view(self._lookup_by_id(credential_id))

    def list_credentials(self, account: str) -> tuple:
        with self._lock:
            rows = [self._view(record) for record in self._credentials.values()
                    if record["account"] == account]
            rows.sort(key=lambda view: view.credential_id)
            return tuple(rows)

    def quarantine(self, credential_id: str, *, reason: str, at: int = 0) -> bool:
        with self._lock:
            record = self._lookup_by_id(credential_id)
            if record["status"] != "active":
                return False
            self._apply_quarantine(record, source="manual", reason=reason,
                                   at=at)
            return True

    def release_after_review(self, credential_id: str, *, reviewer: str,
                             at: int) -> CredentialView:
        with self._lock:
            record = self._lookup_by_id(credential_id)
            if record["status"] != "quarantined":
                raise CloneDetectorError("CTR_NOT_QUARANTINED",
                                         {"credential_id": credential_id})
            record["status"] = "active"
            self._reviews.setdefault(credential_id, []).append(
                ReviewRecord(credential_id=credential_id, reviewer=reviewer,
                             at=at))
            self._stats["releases"] += 1
            return self._view(record)

    def revoke_credential(self, credential_id: str) -> bool:
        with self._lock:
            record = self._lookup_by_id(credential_id)
            if record["status"] == "revoked":
                return False
            record["status"] = "revoked"
            self._stats["revocations"] += 1
            return True

    def login_allowed(self, account: str, *, credential_id: str) -> bool:
        with self._lock:
            record = self._lookup(account, credential_id)
            return record["status"] == "active"

    def account_summary(self, account: str) -> dict:
        with self._lock:
            summary = {"credentials": 0, "active": 0, "quarantined": 0,
                       "revoked": 0, "regressions": 0}
            for record in self._credentials.values():
                if record["account"] != account:
                    continue
                summary["credentials"] += 1
                summary[record["status"]] += 1
                summary["regressions"] += record["regressions"]
            return summary

    def reviews(self, credential_id: str) -> tuple:
        with self._lock:
            self._lookup_by_id(credential_id)
            return tuple(self._reviews.get(credential_id, ()))

    def snapshot(self) -> dict:
        with self._lock:
            credentials = []
            for record in self._credentials.values():
                entry = {
                    "account": record["account"],
                    "credential_id": record["credential_id"],
                    "status": record["status"],
                    "counter_capable": record["counter_capable"],
                    "watermark": record["watermark"],
                    "regressions": record["regressions"],
                    "registered_at": record["registered_at"],
                    "quarantine": (dict(record["quarantine"])
                                   if record["quarantine"] else None),
                }
                credentials.append(entry)
            reviews = [
                {"credential_id": item.credential_id, "reviewer": item.reviewer,
                 "at": item.at}
                for items in self._reviews.values() for item in items
            ]
            return {
                "version": self._SNAPSHOT_VERSION,
                "credentials": credentials,
                "reviews": reviews,
                "stats": dict(self._stats),
            }

    def _validate_snapshot(self, state):
        def fail(detail):
            raise CloneDetectorError("CTR_INVALID_SNAPSHOT", detail)

        if not isinstance(state, dict):
            fail("snapshot must be a mapping")
        if set(state) != {"version", "credentials", "reviews", "stats"}:
            fail("snapshot keys must be version/credentials/reviews/stats")
        if state["version"] != self._SNAPSHOT_VERSION:
            fail("unsupported snapshot version")
        credentials = state["credentials"]
        reviews = state["reviews"]
        stats = state["stats"]
        if not isinstance(credentials, list) or not isinstance(reviews, list) \
                or not isinstance(stats, dict):
            fail("malformed snapshot sections")
        if set(stats) != set(self._STAT_KEYS) or any(
                not self._is_valid_counter(stats[key]) for key in stats):
            fail("malformed stats counters")
        seen = set()
        for entry in credentials:
            if not isinstance(entry, dict):
                fail("credential entries must be mappings")
            if not isinstance(entry.get("account"), str) \
                    or not isinstance(entry.get("credential_id"), str):
                fail("credential identity must be strings")
            if entry["credential_id"] in seen:
                fail("duplicate credential in snapshot")
            seen.add(entry["credential_id"])
            if entry.get("status") not in self._STATUSES:
                fail("unknown credential status")
            if not isinstance(entry.get("counter_capable"), bool):
                fail("counter_capable must be a boolean")
            if not self._is_valid_counter(entry.get("watermark")) \
                    or not self._is_valid_counter(entry.get("regressions")):
                fail("watermark and regressions must be non-negative ints")
            quarantine = entry.get("quarantine")
            if quarantine is not None:
                if not isinstance(quarantine, dict) \
                        or quarantine.get("source") not in ("auto", "manual"):
                    fail("malformed quarantine provenance")
        for entry in reviews:
            if not isinstance(entry, dict) \
                    or entry.get("credential_id") not in seen \
                    or not isinstance(entry.get("reviewer"), str) \
                    or not self._is_valid_counter(entry.get("at")):
                fail("malformed review record")
        if stats["credentials"] != len(credentials):
            fail("stats inconsistent with credential roster")
        if stats["regressions"] != sum(entry["regressions"]
                                       for entry in credentials):
            fail("stats inconsistent with credential regressions")

    def restore(self, state: dict) -> None:
        with self._lock:
            self._validate_snapshot(state)
            credentials = {}
            reviews = {}
            for entry in state["credentials"]:
                record = {
                    "account": entry["account"],
                    "credential_id": entry["credential_id"],
                    "status": entry["status"],
                    "counter_capable": entry["counter_capable"],
                    "watermark": entry["watermark"],
                    "regressions": entry["regressions"],
                    "registered_at": entry.get("registered_at", 0),
                    "quarantine": (dict(entry["quarantine"])
                                   if entry.get("quarantine") else None),
                }
                credentials[record["credential_id"]] = record
                reviews[record["credential_id"]] = []
            for entry in state["reviews"]:
                reviews[entry["credential_id"]].append(ReviewRecord(
                    credential_id=entry["credential_id"],
                    reviewer=entry["reviewer"], at=entry["at"]))
            self._credentials = credentials
            self._reviews = reviews
            self._stats = dict(state["stats"])

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
