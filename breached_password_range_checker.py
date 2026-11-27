"""k-anonymity prefix lookup against a breached password range service."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping


_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_OFFLINE_MODES = frozenset({"block", "allow"})
_BUCKET_SOURCES = frozenset({"network", "cache"})
_STAT_KEYS = (
    "fetches",
    "cache_hits",
    "budget_exhausted",
    "breaches",
    "clears",
    "undetermined",
)
_LOGIN_FAILURE_LIMIT = 5


class BreachError(ValueError):
    """Refusal raised by the breach range checker."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TenantPolicy:
    tenant: str
    budget: int
    offline_mode: str


@dataclass(frozen=True)
class BucketView:
    prefix: str
    version: int
    suffix_count: int
    source: str
    fetched_at: int


@dataclass(frozen=True)
class BreachVerdict:
    status: str
    reason: str
    prefix: str
    bucket_version: int
    allowed: bool
    tenant: str = field(default="", compare=False)


@dataclass(frozen=True)
class ChangeOutcome:
    status: str
    code: str
    allowed: bool
    tenant: str = field(default="", compare=False)
    prefix: str = field(default="", compare=False)
    bucket_version: int = field(default=0, compare=False)


@dataclass
class _TenantState:
    policy: TenantPolicy
    remaining: int


@dataclass(frozen=True)
class _Bucket:
    prefix: str
    version: int
    suffixes: tuple[str, ...]
    fetched_at: int
    source: str = "network"


class _Flight:
    __slots__ = ("done", "result", "bucket", "error")

    def __init__(self) -> None:
        self.done = False
        self.result: BucketView | None = None
        self.bucket: _Bucket | None = None
        self.error: BreachError | None = None


class BreachRangeChecker:
    """Resolve password digests against a breached range service by prefix."""

    def __init__(self, *, fetcher, prefix_length: int = 5, bucket_limit: int = 64,
                 cache_ttl: int = 3600) -> None:
        self.fetcher = fetcher
        self.prefix_length = prefix_length
        self.bucket_limit = bucket_limit
        self.cache_ttl = cache_ttl
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._tenants: dict[str, _TenantState] = {}
        self._buckets: dict[str, _Bucket] = {}
        self._inflight: dict[str, _Flight] = {}
        self._login_failures: dict[str, int] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------
    def _normalize_prefix(self, prefix: object) -> str:
        if not isinstance(prefix, str) or len(prefix) != self.prefix_length:
            raise BreachError("BREACH_INVALID_DIGEST", "invalid prefix")
        if not prefix or any(char not in _HEX_DIGITS for char in prefix):
            raise BreachError("BREACH_INVALID_DIGEST", "invalid prefix")
        return prefix.upper()

    def _normalize_digest(self, digest: object) -> str:
        if not isinstance(digest, str) or len(digest) <= self.prefix_length:
            raise BreachError("BREACH_INVALID_DIGEST", "invalid digest")
        if not digest or any(char not in _HEX_DIGITS for char in digest):
            raise BreachError("BREACH_INVALID_DIGEST", "invalid digest")
        return digest.upper()

    def _tenant_locked(self, tenant: object) -> _TenantState:
        if not isinstance(tenant, str):
            raise BreachError("BREACH_UNKNOWN_TENANT", tenant)
        state = self._tenants.get(tenant)
        if state is None:
            raise BreachError("BREACH_UNKNOWN_TENANT", tenant)
        return state

    def _normalize_bucket(self, raw: object) -> tuple[str, ...]:
        if not isinstance(raw, (list, tuple)):
            raise BreachError("BREACH_BUCKET_INVALID", "response must be a list")
        if len(raw) > self.bucket_limit:
            raise BreachError("BREACH_BUCKET_INVALID", "bucket limit exceeded")
        suffixes: list[str] = []
        for entry in raw:
            if (not isinstance(entry, str) or not entry
                    or any(char not in _HEX_DIGITS for char in entry)):
                raise BreachError("BREACH_BUCKET_INVALID", "invalid bucket entry")
            suffixes.append(entry.upper())
        return tuple(suffixes)

    def _fresh(self, bucket: _Bucket, now: int) -> bool:
        return now - bucket.fetched_at < self.cache_ttl

    @staticmethod
    def _view(bucket: _Bucket, source: str) -> BucketView:
        return BucketView(
            prefix=bucket.prefix,
            version=bucket.version,
            suffix_count=len(bucket.suffixes),
            source=source,
            fetched_at=bucket.fetched_at,
        )

    @staticmethod
    def _copy_error(error: BreachError) -> BreachError:
        return BreachError(error.code, error.detail)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def register_tenant(self, tenant: str, *, budget: int = 10,
                        offline_mode: str = "block") -> TenantPolicy:
        if (not isinstance(tenant, str) or not tenant
                or type(budget) is not int or budget < 0
                or offline_mode not in _OFFLINE_MODES):
            raise BreachError("BREACH_INVALID_POLICY", "invalid tenant policy")
        with self._lock:
            if tenant in self._tenants:
                raise BreachError("BREACH_TENANT_EXISTS", tenant)
            policy = TenantPolicy(tenant=tenant, budget=budget,
                                  offline_mode=offline_mode)
            self._tenants[tenant] = _TenantState(policy=policy, remaining=budget)
            return policy

    def tenant_policy(self, tenant: str) -> TenantPolicy:
        with self._lock:
            return self._tenant_locked(tenant).policy

    def _resolve_bucket(self, tenant: str, prefix: str,
                        now: int) -> tuple[BucketView, _Bucket | None]:
        prefix = self._normalize_prefix(prefix)
        with self._condition:
            tenant_state = self._tenant_locked(tenant)
            bucket = self._buckets.get(prefix)
            if bucket is not None and self._fresh(bucket, now):
                self._stats["cache_hits"] += 1
                return self._view(bucket, "cache"), bucket

            flight = self._inflight.get(prefix)
            if flight is not None:
                while not flight.done:
                    self._condition.wait()
                if flight.error is not None:
                    raise self._copy_error(flight.error)
                if flight.bucket is None or flight.result is None:
                    raise BreachError("BREACH_BUCKET_INVALID",
                                      "missing in-flight result")
                self._stats["cache_hits"] += 1
                return self._view(flight.bucket, "cache"), flight.bucket

            if tenant_state.remaining <= 0:
                self._stats["budget_exhausted"] += 1
                return BucketView(prefix=prefix, version=0, suffix_count=0,
                                  source="offline", fetched_at=now), None

            tenant_state.remaining -= 1
            self._stats["fetches"] += 1
            version = bucket.version + 1 if bucket is not None else 1
            flight = _Flight()
            self._inflight[prefix] = flight

        try:
            suffixes = self._normalize_bucket(self.fetcher(prefix))
        except BreachError as exc:
            error = exc
        except Exception as exc:  # pragma: no cover - defensive service failure
            error = BreachError("BREACH_FETCH_FAILED", repr(exc))
        else:
            error = None

        with self._condition:
            if error is not None:
                self._buckets.pop(prefix, None)
                flight.error = error
            else:
                bucket = _Bucket(prefix=prefix, version=version,
                                 suffixes=suffixes, fetched_at=now)
                self._buckets[prefix] = bucket
                flight.bucket = bucket
                flight.result = self._view(bucket, "network")
            if self._inflight.get(prefix) is flight:
                del self._inflight[prefix]
            flight.done = True
            self._condition.notify_all()
            if error is not None:
                raise self._copy_error(error)
            assert bucket is not None and flight.result is not None
            return flight.result, bucket

    def query_prefix(self, tenant: str, *, prefix: str, now: int) -> BucketView:
        view, _ = self._resolve_bucket(tenant, prefix, now)
        return view

    def check_password(self, tenant: str, *, digest: str, now: int) -> BreachVerdict:
        normalized = self._normalize_digest(digest)
        prefix = normalized[:self.prefix_length]
        with self._lock:
            policy = self._tenant_locked(tenant).policy
            allowed_when_unknown = policy.offline_mode == "allow"
            tenant_name = policy.tenant

        try:
            view, bucket = self._resolve_bucket(tenant, prefix, now)
        except BreachError as exc:
            if exc.code in {"BREACH_BUCKET_INVALID", "BREACH_FETCH_FAILED"}:
                with self._lock:
                    self._stats["undetermined"] += 1
                return BreachVerdict(
                    status="undetermined",
                    reason=exc.code,
                    prefix=prefix,
                    bucket_version=0,
                    allowed=allowed_when_unknown,
                    tenant=tenant_name,
                )
            raise

        if view.source == "offline":
            with self._lock:
                self._stats["undetermined"] += 1
            return BreachVerdict(
                status="undetermined",
                reason="BREACH_BUDGET_EXHAUSTED",
                prefix=prefix,
                bucket_version=0,
                allowed=allowed_when_unknown,
                tenant=tenant_name,
            )

        assert bucket is not None
        suffix = normalized[self.prefix_length:]
        if suffix in bucket.suffixes:
            with self._lock:
                self._stats["breaches"] += 1
            return BreachVerdict(
                status="breached",
                reason="BREACH_HIT",
                prefix=prefix,
                bucket_version=bucket.version,
                allowed=False,
                tenant=tenant_name,
            )

        with self._lock:
            self._stats["clears"] += 1
        return BreachVerdict(
            status="clear",
            reason="BREACH_CLEAR",
            prefix=prefix,
            bucket_version=bucket.version,
            allowed=True,
            tenant=tenant_name,
        )

    def submit_change(self, tenant: str, account: str, *, digest: str,
                      now: int) -> ChangeOutcome:
        verdict = self.check_password(tenant, digest=digest, now=now)
        if verdict.status == "breached":
            return ChangeOutcome(
                status="rejected",
                code="PASSWORD_BREACHED",
                allowed=False,
                tenant=verdict.tenant,
                prefix=verdict.prefix,
                bucket_version=verdict.bucket_version,
            )
        if verdict.status == "clear":
            return ChangeOutcome(
                status="accepted",
                code="PASSWORD_ACCEPTED",
                allowed=True,
                tenant=verdict.tenant,
                prefix=verdict.prefix,
                bucket_version=verdict.bucket_version,
            )
        return ChangeOutcome(
            status="undetermined",
            code=verdict.reason,
            allowed=verdict.allowed,
            tenant=verdict.tenant,
            prefix=verdict.prefix,
            bucket_version=verdict.bucket_version,
        )

    def prewarm(self, tenant: str, prefixes: Iterable[str], *,
                now: int | None = None) -> int:
        with self._lock:
            self._tenant_locked(tenant)
        timestamp = int(time.time()) if now is None else now
        warmed = 0
        seen: set[str] = set()
        for prefix in prefixes:
            normalized = self._normalize_prefix(prefix)
            if normalized in seen:
                continue
            seen.add(normalized)
            view = self.query_prefix(tenant, prefix=normalized, now=timestamp)
            if view.source == "offline":
                break
            if view.source == "network":
                warmed += 1
        return warmed

    def budget_remaining(self, tenant: str) -> int:
        with self._lock:
            return self._tenant_locked(tenant).remaining

    def reset_budget(self, tenant: str) -> int:
        with self._lock:
            state = self._tenant_locked(tenant)
            state.remaining = state.policy.budget
            return state.remaining

    def bucket_state(self, prefix: str):
        normalized = self._normalize_prefix(prefix)
        with self._lock:
            bucket = self._buckets.get(normalized)
            if bucket is None:
                return None
            return {
                "prefix": bucket.prefix,
                "version": bucket.version,
                "suffix_count": len(bucket.suffixes),
                "source": bucket.source,
                "fetched_at": bucket.fetched_at,
            }

    def purge_cache(self, now: int) -> int:
        with self._lock:
            expired = [
                prefix for prefix, bucket in self._buckets.items()
                if not self._fresh(bucket, now)
            ]
            for prefix in expired:
                del self._buckets[prefix]
            return len(expired)

    def mark_login_failure(self, account: str) -> int:
        with self._lock:
            count = self._login_failures.get(account, 0) + 1
            self._login_failures[account] = count
            return count

    def mark_login_success(self, account: str) -> int:
        with self._lock:
            self._login_failures.pop(account, None)
            return 0

    def login_locked(self, account: str) -> bool:
        with self._lock:
            return self._login_failures.get(account, 0) >= _LOGIN_FAILURE_LIMIT

    def snapshot(self) -> dict:
        with self._lock:
            tenants = {
                name: {
                    "budget": state.remaining,
                    "limit": state.policy.budget,
                    "offline_mode": state.policy.offline_mode,
                }
                for name, state in self._tenants.items()
            }
            buckets = {
                prefix: {
                    "prefix": bucket.prefix,
                    "version": bucket.version,
                    "suffix_count": len(bucket.suffixes),
                    "source": bucket.source,
                    "fetched_at": bucket.fetched_at,
                    "suffixes": list(bucket.suffixes),
                }
                for prefix, bucket in self._buckets.items()
            }
            return {
                "version": 1,
                "tenants": tenants,
                "buckets": buckets,
                "login_failures": dict(self._login_failures),
                "stats": dict(self._stats),
            }

    def _parse_snapshot(self, state: object):
        invalid = BreachError("BREACH_SNAPSHOT_INVALID", "malformed snapshot")
        if not isinstance(state, Mapping):
            raise invalid
        version = state.get("version")
        if type(version) is not int or version != 1:
            raise invalid

        raw_tenants = state.get("tenants")
        raw_buckets = state.get("buckets")
        raw_failures = state.get("login_failures")
        raw_stats = state.get("stats")
        if (not isinstance(raw_tenants, Mapping)
                or not isinstance(raw_buckets, Mapping)
                or not isinstance(raw_failures, Mapping)
                or not isinstance(raw_stats, Mapping)):
            raise invalid

        tenants: dict[str, _TenantState] = {}
        for name, entry in raw_tenants.items():
            if not isinstance(name, str) or not name or not isinstance(entry, Mapping):
                raise invalid
            offline_mode = entry.get("offline_mode")
            budget = entry.get("budget", entry.get("remaining"))
            if (offline_mode not in _OFFLINE_MODES
                    or type(budget) is not int or budget < 0):
                raise invalid
            limit = entry.get("limit", budget)
            remaining = entry.get("remaining", budget)
            if (type(limit) is not int or type(remaining) is not int
                    or limit < 0 or remaining < 0 or remaining > limit):
                raise invalid
            policy = TenantPolicy(tenant=name, budget=limit,
                                  offline_mode=offline_mode)
            tenants[name] = _TenantState(policy=policy, remaining=remaining)

        buckets: dict[str, _Bucket] = {}
        for key, entry in raw_buckets.items():
            if not isinstance(key, str) or not key or not isinstance(entry, Mapping):
                raise invalid
            prefix = entry.get("prefix", key)
            if not isinstance(prefix, str) or prefix.upper() != key.upper():
                raise invalid
            try:
                normalized = self._normalize_prefix(prefix)
            except BreachError as exc:
                raise BreachError("BREACH_SNAPSHOT_INVALID", exc.detail) from exc
            if normalized in buckets:
                raise invalid
            bucket_version = entry.get("version")
            fetched_at = entry.get("fetched_at")
            source = entry.get("source", "network")
            raw_suffixes = entry.get("suffixes")
            if (type(bucket_version) is not int or bucket_version < 1
                    or type(fetched_at) is not int
                    or source not in _BUCKET_SOURCES
                    or not isinstance(raw_suffixes, (list, tuple))):
                raise invalid
            try:
                suffixes = self._normalize_bucket(raw_suffixes)
            except BreachError as exc:
                raise BreachError("BREACH_SNAPSHOT_INVALID", exc.detail) from exc
            suffix_count = entry.get("suffix_count", len(suffixes))
            if (type(suffix_count) is not int or suffix_count < 0
                    or suffix_count != len(suffixes)):
                raise invalid
            buckets[normalized] = _Bucket(
                prefix=normalized,
                version=bucket_version,
                suffixes=suffixes,
                fetched_at=fetched_at,
                source=source,
            )

        failures: dict[str, int] = {}
        for account, count in raw_failures.items():
            if (not isinstance(account, str) or type(count) is not int
                    or count < 0):
                raise invalid
            failures[account] = count

        stats: dict[str, int] = {}
        for stat in _STAT_KEYS:
            if stat not in raw_stats:
                raise invalid
            value = raw_stats[stat]
            if type(value) is not int or value < 0:
                raise invalid
            stats[stat] = value

        return tenants, buckets, failures, stats

    def restore(self, state: dict) -> None:
        tenants, buckets, failures, stats = self._parse_snapshot(state)
        with self._lock:
            self._tenants = tenants
            self._buckets = buckets
            self._login_failures = failures
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
