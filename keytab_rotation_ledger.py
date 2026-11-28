"""Keytab rotation ledger: monotonic versions, replica confirmation, retention."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


_SCHEMA_VERSION = 1
_STAT_KEYS = {
    "rotations",
    "activations",
    "retired",
    "idempotent_hits",
    "confirm_failures",
}
_VERSION_STATES = {
    "distributing",
    "distributed",
    "active",
    "retained",
    "aborted",
}
_REPLICA_STATUSES = {"pending", "distributed", "confirmed", "failed"}
_IN_FLIGHT_STATES = {"distributing", "distributed"}
_UNSET = object()


class KeytabError(ValueError):
    """Raised when a rotation step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ReplicaState:
    replica_id: str
    status: str


@dataclass(frozen=True)
class KeyVersion:
    principal: str
    version: int
    state: str
    request_id: str | None
    replicas: tuple[ReplicaState, ...]
    created_at: str
    retained_at: str | None


class KeytabRotationLedger:
    """Track one key version at a time per principal and its replica rollout."""

    def __init__(self, *, retention: int = 3600, clock=None) -> None:
        if (
            isinstance(retention, bool)
            or not isinstance(retention, int)
            or retention < 0
        ):
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "retention must be a non-negative integer"
            )
        if clock is not None and not callable(clock) and not hasattr(clock, "now"):
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "clock must be callable or provide now()"
            )

        self.retention = retention
        self._clock = clock
        self._lock = threading.RLock()
        self._principals: dict[str, dict] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def register_principal(self, *, principal: str, replicas) -> None:
        principal = self._require_text(principal, "principal")
        with self._lock:
            if principal in self._principals:
                raise KeytabError(
                    "KEYTAB_PRINCIPAL_EXISTS", {"principal": principal}
                )

            replica_ids = self._normalize_replicas(replicas)
            self._principals[principal] = {
                "replicas": replica_ids,
                "next_version": 1,
                "active_version": None,
                "requests": {},
                "versions": {},
            }

    def rotate(
        self,
        *,
        principal: str,
        request_id: str | None | object = _UNSET,
        now: str | None = None,
    ) -> KeyVersion:
        principal = self._require_text(principal, "principal")
        request_supplied = request_id is not _UNSET
        if not request_supplied:
            request_id = None
        if request_id is not None:
            request_id = self._require_text(request_id, "request_id")

        with self._lock:
            state = self._principal(principal)

            if request_id is not None:
                existing_version = state["requests"].get(request_id)
                if existing_version is not None:
                    self._stats["idempotent_hits"] += 1
                    return self._version_view(
                        principal, state, state["versions"][existing_version]
                    )

            in_flight = self._in_flight_version(state)
            if in_flight is not None:
                if (
                    request_id is not None
                    and in_flight["request_id"] == request_id
                ) or (
                    request_supplied
                    and request_id is None
                    and in_flight["request_id"] is None
                ):
                    self._stats["idempotent_hits"] += 1
                    return self._version_view(principal, state, in_flight)
                raise KeytabError(
                    "KEYTAB_ROTATION_IN_FLIGHT",
                    {
                        "principal": principal,
                        "version": in_flight["version"],
                    },
                )

            created_at = self._resolve_now(now)
            version = state["next_version"]
            state["next_version"] += 1
            record = {
                "version": version,
                "state": "distributing",
                "request_id": request_id,
                "replica_status": {
                    replica_id: "pending" for replica_id in state["replicas"]
                },
                "created_at": created_at,
                "retained_at": None,
            }
            state["versions"][version] = record
            if request_id is not None:
                state["requests"][request_id] = version
            self._stats["rotations"] += 1
            return self._version_view(principal, state, record)

    def distribute(
        self, *, principal: str, version: int, now: str | None = None
    ) -> tuple[ReplicaState, ...]:
        principal = self._require_text(principal, "principal")
        version = self._require_version_number(version)

        with self._lock:
            state = self._principal(principal)
            record = self._version(state, version)
            self._resolve_now(now)

            if record["state"] != "distributing":
                raise KeytabError(
                    "KEYTAB_STATE_INVALID",
                    {"version": version, "state": record["state"]},
                )

            record["state"] = "distributed"
            for replica_id in state["replicas"]:
                record["replica_status"][replica_id] = "distributed"

            return tuple(
                ReplicaState(replica_id, record["replica_status"][replica_id])
                for replica_id in sorted(state["replicas"])
            )

    def confirm(
        self,
        *,
        principal: str,
        version: int,
        replica_id: str,
        ok: bool = True,
        now: str | None = None,
    ) -> KeyVersion:
        principal = self._require_text(principal, "principal")
        version = self._require_version_number(version)
        replica_id = self._require_text(replica_id, "replica_id")
        if not isinstance(ok, bool):
            raise KeytabError("KEYTAB_REQUEST_INVALID", "ok must be a boolean")

        with self._lock:
            state = self._principal(principal)
            record = self._version(state, version)
            self._resolve_now(now)

            if record["state"] == "distributing":
                raise KeytabError(
                    "KEYTAB_NOT_DISTRIBUTED", {"version": version}
                )
            if record["state"] != "distributed":
                raise KeytabError(
                    "KEYTAB_STATE_INVALID",
                    {"version": version, "state": record["state"]},
                )
            if replica_id not in record["replica_status"]:
                raise KeytabError(
                    "KEYTAB_REPLICA_UNKNOWN",
                    {"version": version, "replica_id": replica_id},
                )
            if record["replica_status"][replica_id] != "distributed":
                raise KeytabError(
                    "KEYTAB_STATE_INVALID",
                    {
                        "version": version,
                        "replica_id": replica_id,
                        "status": record["replica_status"][replica_id],
                    },
                )

            if not ok:
                record["replica_status"][replica_id] = "failed"
                record["state"] = "aborted"
                self._stats["confirm_failures"] += 1
                return self._version_view(principal, state, record)

            record["replica_status"][replica_id] = "confirmed"
            if all(
                status == "confirmed"
                for status in record["replica_status"].values()
            ):
                previous_version = state["active_version"]
                if previous_version is not None:
                    previous = state["versions"].get(previous_version)
                    if previous is not None and previous["state"] == "active":
                        previous["state"] = "retained"
                        previous["retained_at"] = previous["created_at"]

                record["state"] = "active"
                state["active_version"] = version
                self._stats["activations"] += 1

            return self._version_view(principal, state, record)

    def retire(
        self,
        *,
        principal: str,
        version: int | None = None,
        now: str | None = None,
    ) -> int:
        principal = self._require_text(principal, "principal")
        if version is not None:
            version = self._require_version_number(version)

        with self._lock:
            state = self._principal(principal)
            retired_at = self._resolve_now(now)

            if version is not None:
                record = self._version(state, version)
                if record["state"] == "active":
                    raise KeytabError(
                        "KEYTAB_ACTIVE_RETIRE", {"version": version}
                    )
                if record["state"] != "retained":
                    raise KeytabError(
                        "KEYTAB_STATE_INVALID",
                        {"version": version, "state": record["state"]},
                    )
                self._drop_version(state, version)
                self._stats["retired"] += 1
                return 1

            now_dt = self._parse_timestamp(retired_at)
            expired = [
                number
                for number, record in state["versions"].items()
                if record["state"] == "retained"
                and self._is_expired(record, now_dt)
            ]
            for number in expired:
                self._drop_version(state, number)
            self._stats["retired"] += len(expired)
            return len(expired)

    def active_version(self, principal: str) -> int | None:
        principal = self._require_text(principal, "principal")
        with self._lock:
            return self._principal(principal)["active_version"]

    def issuable_versions(self, principal: str) -> tuple[int, ...]:
        principal = self._require_text(principal, "principal")
        with self._lock:
            state = self._principal(principal)
            active = state["active_version"]
            if active is None:
                return ()
            record = state["versions"].get(active)
            if record is None or record["state"] != "active":
                return ()
            return (active,)

    def verifiable_versions(self, principal: str) -> tuple[int, ...]:
        principal = self._require_text(principal, "principal")
        with self._lock:
            state = self._principal(principal)
            now_dt = self._parse_timestamp(self._resolve_now(None))
            versions = []
            for number in sorted(state["versions"]):
                record = state["versions"][number]
                if record["state"] == "active":
                    versions.append(number)
                elif record["state"] == "retained" and not self._is_expired(
                    record, now_dt
                ):
                    versions.append(number)
            return tuple(versions)

    def snapshot(self) -> dict:
        with self._lock:
            principals = {}
            for principal, state in self._principals.items():
                versions = {}
                for number, record in sorted(state["versions"].items()):
                    versions[str(number)] = {
                        "version": number,
                        "state": record["state"],
                        "request_id": record["request_id"],
                        "replicas": [
                            {
                                "replica_id": replica_id,
                                "status": record["replica_status"][replica_id],
                            }
                            for replica_id in state["replicas"]
                        ],
                        "created_at": record["created_at"],
                        "retained_at": record["retained_at"],
                    }
                principals[principal] = {
                    "replicas": list(state["replicas"]),
                    "next_version": state["next_version"],
                    "active_version": state["active_version"],
                    "requests": dict(state["requests"]),
                    "versions": versions,
                    "retention": self.retention,
                }
            return {
                "version": _SCHEMA_VERSION,
                "principals": principals,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            principals, stats, retention = self._validated_snapshot(state)
        except KeytabError as exc:
            if exc.code == "KEYTAB_SNAPSHOT_INVALID":
                raise
            raise KeytabError(
                "KEYTAB_SNAPSHOT_INVALID", exc.detail or exc.code
            ) from None
        except Exception as exc:
            raise KeytabError("KEYTAB_SNAPSHOT_INVALID", str(exc)) from None

        with self._lock:
            self._principals = principals
            self._stats = stats
            if retention is not None:
                self.retention = retention

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _principal(self, principal: str) -> dict:
        try:
            return self._principals[principal]
        except KeyError:
            raise KeytabError(
                "KEYTAB_PRINCIPAL_UNKNOWN", {"principal": principal}
            ) from None

    def _version(self, state: dict, version: int) -> dict:
        try:
            return state["versions"][version]
        except KeyError:
            raise KeytabError(
                "KEYTAB_VERSION_UNKNOWN", {"version": version}
            ) from None

    @staticmethod
    def _in_flight_version(state: dict) -> dict | None:
        for record in state["versions"].values():
            if record["state"] in _IN_FLIGHT_STATES:
                return record
        return None

    @staticmethod
    def _version_view(principal: str, state: dict, record: dict) -> KeyVersion:
        return KeyVersion(
            principal=principal,
            version=record["version"],
            state=record["state"],
            request_id=record["request_id"],
            replicas=tuple(
                ReplicaState(replica_id, record["replica_status"][replica_id])
                for replica_id in state["replicas"]
            ),
            created_at=record["created_at"],
            retained_at=record["retained_at"],
        )

    def _drop_version(self, state: dict, version: int) -> None:
        record = state["versions"].pop(version)
        request_id = record["request_id"]
        if (
            request_id is not None
            and state["requests"].get(request_id) == version
        ):
            del state["requests"][request_id]

    def _is_expired(self, record: dict, now_dt: datetime) -> bool:
        retained_at = record["retained_at"]
        if retained_at is None:
            return False
        expires_at = self._parse_timestamp(retained_at) + timedelta(
            seconds=self.retention
        )
        return now_dt >= expires_at

    def _resolve_now(self, now: str | None) -> str:
        if now is not None:
            if not isinstance(now, str):
                raise KeytabError(
                    "KEYTAB_REQUEST_INVALID", "now must be an ISO 8601 string"
                )
            self._parse_timestamp(now)
            return now

        if self._clock is None:
            value = datetime.now(timezone.utc)
        else:
            if callable(self._clock):
                value = self._clock()
            else:
                value = self._clock.now
            if callable(value):
                value = value()

        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc).isoformat(timespec="seconds")
        if isinstance(value, str):
            self._parse_timestamp(value)
            return value
        raise KeytabError(
            "KEYTAB_REQUEST_INVALID", "clock must return an ISO 8601 string"
        )

    @staticmethod
    def _parse_timestamp(value: object) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value:
            text = value[:-1] + "+00:00" if value.endswith("Z") else value
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                raise KeytabError(
                    "KEYTAB_REQUEST_INVALID",
                    {"timestamp": value},
                ) from None
        else:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", {"timestamp": value}
            )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    @staticmethod
    def _require_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", f"{field} must be a non-empty string"
            )
        return value

    @staticmethod
    def _require_version_number(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "version must be an integer"
            )
        return value

    @classmethod
    def _normalize_replicas(cls, replicas) -> list[str]:
        if replicas is None or isinstance(replicas, (str, bytes)):
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "replicas must be a non-empty iterable"
            )
        try:
            values = list(replicas)
        except TypeError:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "replicas must be a non-empty iterable"
            ) from None
        if not values:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "replicas must not be empty"
            )

        result = []
        seen = set()
        for replica in values:
            replica_id = cls._require_text(replica, "replica_id")
            if replica_id in seen:
                raise KeytabError(
                    "KEYTAB_REQUEST_INVALID",
                    {"replica_id": replica_id, "reason": "duplicate"},
                )
            seen.add(replica_id)
            result.append(replica_id)
        return result

    def _validated_snapshot(
        self, snapshot: object
    ) -> tuple[dict[str, dict], dict[str, int], int | None]:
        if not isinstance(snapshot, dict) or set(snapshot) != {
            "version",
            "principals",
            "stats",
        }:
            self._snapshot_invalid("invalid top-level snapshot structure")

        schema_version = snapshot["version"]
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != _SCHEMA_VERSION
        ):
            self._snapshot_invalid("unsupported snapshot version")
        principals_raw = snapshot["principals"]
        stats_raw = snapshot["stats"]
        if not isinstance(principals_raw, dict):
            self._snapshot_invalid("principals must be an object")
        if not isinstance(stats_raw, dict) or set(stats_raw) != _STAT_KEYS:
            self._snapshot_invalid("stats has an invalid structure")

        stats = {}
        for name in _STAT_KEYS:
            value = stats_raw[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                self._snapshot_invalid(f"stats.{name} must be non-negative")
            stats[name] = value
        if (
            stats["activations"] > stats["rotations"]
            or stats["retired"] > stats["rotations"]
            or stats["confirm_failures"] > stats["rotations"]
        ):
            self._snapshot_invalid("stats counters are inconsistent")

        principals: dict[str, dict] = {}
        snapshot_retentions = set()
        for principal_raw, principal_state_raw in principals_raw.items():
            principal = self._snapshot_text(
                principal_raw, "principal", "KEYTAB_REQUEST_INVALID"
            )
            if principal in principals:
                self._snapshot_invalid("duplicate principal")
            if not isinstance(principal_state_raw, dict) or set(
                principal_state_raw
            ) != {
                "replicas",
                "next_version",
                "active_version",
                "requests",
                "versions",
                "retention",
            }:
                self._snapshot_invalid(
                    f"invalid state for principal {principal}"
                )

            replicas_raw = principal_state_raw["replicas"]
            if not isinstance(replicas_raw, list) or not replicas_raw:
                self._snapshot_invalid("replicas must be a non-empty list")
            replicas = []
            replica_set = set()
            for replica_raw in replicas_raw:
                replica_id = self._snapshot_text(
                    replica_raw, "replica_id", "KEYTAB_REQUEST_INVALID"
                )
                if replica_id in replica_set:
                    self._snapshot_invalid("duplicate replica")
                replica_set.add(replica_id)
                replicas.append(replica_id)

            next_version = self._snapshot_positive_int(
                principal_state_raw["next_version"], "next_version"
            )
            active_version = principal_state_raw["active_version"]
            if active_version is not None:
                active_version = self._snapshot_positive_int(
                    active_version, "active_version"
                )
            retention = principal_state_raw["retention"]
            if (
                isinstance(retention, bool)
                or not isinstance(retention, int)
                or retention < 0
            ):
                self._snapshot_invalid(
                    "retention must be a non-negative integer"
                )
            snapshot_retentions.add(retention)

            requests_raw = principal_state_raw["requests"]
            if not isinstance(requests_raw, dict):
                self._snapshot_invalid("requests must be an object")
            requests = {}
            for request_raw, version_raw in requests_raw.items():
                request_id = self._snapshot_text(
                    request_raw, "request_id", "KEYTAB_REQUEST_INVALID"
                )
                requests[request_id] = self._snapshot_positive_int(
                    version_raw, "request version"
                )

            versions_raw = principal_state_raw["versions"]
            if not isinstance(versions_raw, dict):
                self._snapshot_invalid("versions must be an object")
            versions = {}
            active_records = []
            in_flight_records = []
            for version_key, version_raw in versions_raw.items():
                version_number = self._snapshot_version_key(version_key)
                if version_number in versions:
                    self._snapshot_invalid("duplicate version")
                if not 1 <= version_number < next_version:
                    self._snapshot_invalid("version is outside the version range")
                if not isinstance(version_raw, dict) or set(version_raw) != {
                    "version",
                    "state",
                    "request_id",
                    "replicas",
                    "created_at",
                    "retained_at",
                }:
                    self._snapshot_invalid("invalid version record")
                raw_version_number = version_raw["version"]
                if (
                    isinstance(raw_version_number, bool)
                    or not isinstance(raw_version_number, int)
                    or raw_version_number != version_number
                ):
                    self._snapshot_invalid("version number does not match key")

                version_state = version_raw["state"]
                if version_state not in _VERSION_STATES:
                    self._snapshot_invalid("invalid version state")
                request_id = version_raw["request_id"]
                if request_id is not None:
                    request_id = self._snapshot_text(
                        request_id, "request_id", "KEYTAB_REQUEST_INVALID"
                    )

                replica_rows = version_raw["replicas"]
                if not isinstance(replica_rows, list):
                    self._snapshot_invalid("replica rows must be a list")
                replica_status = {}
                for row in replica_rows:
                    if not isinstance(row, dict) or set(row) != {
                        "replica_id",
                        "status",
                    }:
                        self._snapshot_invalid("invalid replica row")
                    replica_id = self._snapshot_text(
                        row["replica_id"], "replica_id", "KEYTAB_REQUEST_INVALID"
                    )
                    if replica_id in replica_status:
                        self._snapshot_invalid("duplicate replica row")
                    status = row["status"]
                    if status not in _REPLICA_STATUSES:
                        self._snapshot_invalid("invalid replica status")
                    replica_status[replica_id] = status
                if set(replica_status) != replica_set:
                    self._snapshot_invalid(
                        "replica rows do not match the principal replicas"
                    )

                created_at = self._snapshot_text(
                    version_raw["created_at"],
                    "created_at",
                    "KEYTAB_REQUEST_INVALID",
                )
                self._parse_timestamp(created_at)
                retained_at = version_raw["retained_at"]
                if retained_at is not None:
                    retained_at = self._snapshot_text(
                        retained_at,
                        "retained_at",
                        "KEYTAB_REQUEST_INVALID",
                    )
                    self._parse_timestamp(retained_at)

                if version_state == "retained":
                    if retained_at is None:
                        self._snapshot_invalid(
                            "retained version has no retained_at"
                        )
                elif retained_at is not None:
                    self._snapshot_invalid(
                        "non-retained version has retained_at"
                    )

                statuses = set(replica_status.values())
                if version_state == "distributing" and statuses != {"pending"}:
                    self._snapshot_invalid(
                        "distributing version has non-pending replicas"
                    )
                if version_state == "distributed":
                    if not statuses <= {"distributed", "confirmed"}:
                        self._snapshot_invalid(
                            "distributed version has invalid replica states"
                        )
                    if "distributed" not in statuses:
                        self._snapshot_invalid(
                            "distributed version is fully confirmed"
                        )
                if version_state == "active" and statuses != {"confirmed"}:
                    self._snapshot_invalid(
                        "active version has unconfirmed replicas"
                    )
                if version_state == "aborted" and "failed" not in statuses:
                    self._snapshot_invalid(
                        "aborted version has no failed replica"
                    )
                if version_state == "retained" and statuses != {"confirmed"}:
                    self._snapshot_invalid(
                        "retained version has unconfirmed replicas"
                    )

                if version_state == "active":
                    active_records.append(version_number)
                if version_state in _IN_FLIGHT_STATES:
                    in_flight_records.append(version_number)
                if (
                    request_id is not None
                    and requests.get(request_id) != version_number
                ):
                    self._snapshot_invalid(
                        "request index does not match version"
                    )

                versions[version_number] = {
                    "version": version_number,
                    "state": version_state,
                    "request_id": request_id,
                    "replica_status": replica_status,
                    "created_at": created_at,
                    "retained_at": retained_at,
                }

            if len(active_records) > 1:
                self._snapshot_invalid("multiple active versions")
            if len(in_flight_records) > 1:
                self._snapshot_invalid("multiple in-flight versions")
            for request_id, version_number in requests.items():
                record = versions.get(version_number)
                if record is None or record["request_id"] != request_id:
                    self._snapshot_invalid(
                        "request index points to an unknown version"
                    )
            if active_version is None:
                if active_records:
                    self._snapshot_invalid(
                        "active version is not indexed by the principal"
                    )
            elif active_records != [active_version]:
                self._snapshot_invalid(
                    "active version index does not match version state"
                )

            principals[principal] = {
                "replicas": replicas,
                "next_version": next_version,
                "active_version": active_version,
                "requests": requests,
                "versions": versions,
            }

        if len(snapshot_retentions) > 1:
            self._snapshot_invalid("retention differs between principals")
        retention = (
            next(iter(snapshot_retentions)) if snapshot_retentions else None
        )
        return principals, stats, retention

    @staticmethod
    def _snapshot_text(value: object, field: str, code: str) -> str:
        if not isinstance(value, str) or not value:
            raise KeytabError(
                code, f"{field} must be a non-empty string"
            )
        return value

    @staticmethod
    def _snapshot_positive_int(value: object, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID",
                f"{field} must be a positive integer",
            )
        return value

    @staticmethod
    def _snapshot_version_key(value: object) -> int:
        if isinstance(value, bool):
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "version key must be an integer"
            )
        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and value.isdigit():
            number = int(value)
        else:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "version key must be an integer"
            )
        if number < 1:
            raise KeytabError(
                "KEYTAB_REQUEST_INVALID", "version key must be positive"
            )
        return number

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise KeytabError("KEYTAB_SNAPSHOT_INVALID", detail)
