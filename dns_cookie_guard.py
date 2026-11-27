"""DNS Cookie transaction guard: server cookie rotation, missing-cookie downgrade, amplification quota."""

from __future__ import annotations

import hashlib
import hmac
import math
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass


_INVALID_ARGUMENT = "DNS_COOKIE_INVALID_ARGUMENT"
_INVALID_SNAPSHOT = "DNS_COOKIE_SNAPSHOT_INVALID"
_MIN_SECRET_BYTES = 16
_SNAPSHOT_VERSION = 1
_STAT_KEYS = (
    "queries",
    "answered",
    "retried",
    "dropped",
    "truncated",
    "missing_client",
    "bad_server",
    "rotations",
)
_SNAPSHOT_KEYS = {
    "version",
    "generation",
    "active",
    "policies",
    "windows",
    "stats",
}
_POLICY_KEYS = {
    "cookie_required",
    "missing_budget",
    "amplification_budget",
}
_WINDOW_KEYS = {
    "started_at",
    "missing_used",
    "amplification_used",
}
_HEX_DIGITS = frozenset("0123456789abcdef")


class DnsCookieError(ValueError):
    """Raised when a cookie operation cannot be carried out."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CookieVerdict:
    action: str
    server_cookie: str | None
    reason: str


@dataclass(frozen=True)
class SourcePolicy:
    source: str
    cookie_required: bool
    missing_budget: int
    amplification_budget: int


class DnsCookieGuard:
    """Validate client and server cookies for a recursive DNS front end."""

    def __init__(self, secret: bytes, *, generation: int = 1,
                 overlap_generations: int = 1, window: float = 60.0,
                 default_missing_budget: int = 3,
                 default_amplification_budget: int = 4096) -> None:
        if not isinstance(secret, (bytes, bytearray, memoryview)):
            raise DnsCookieError(_INVALID_ARGUMENT, "secret must be bytes")
        normalized_secret = bytes(secret)
        if len(normalized_secret) < _MIN_SECRET_BYTES:
            raise DnsCookieError(_INVALID_ARGUMENT, "secret is too short")

        self._validate_int("generation", generation, minimum=1)
        self._validate_int("overlap_generations", overlap_generations, minimum=0)
        self._validate_int(
            "default_missing_budget", default_missing_budget, minimum=0
        )
        self._validate_int(
            "default_amplification_budget",
            default_amplification_budget,
            minimum=0,
        )
        if isinstance(window, bool) or not isinstance(window, (int, float)):
            raise DnsCookieError(_INVALID_ARGUMENT, "window must be positive")
        try:
            normalized_window = float(window)
        except (OverflowError, ValueError) as exc:
            raise DnsCookieError(
                _INVALID_ARGUMENT, "window must be positive"
            ) from exc
        if not math.isfinite(normalized_window) or normalized_window <= 0:
            raise DnsCookieError(_INVALID_ARGUMENT, "window must be positive")

        self._secret = normalized_secret
        self.generation = generation
        self.overlap_generations = overlap_generations
        self.window = normalized_window
        self.default_missing_budget = default_missing_budget
        self.default_amplification_budget = default_amplification_budget
        self._lock = threading.RLock()
        self._active = [generation]
        self._last_rotation_at: float | None = None
        self._rotation_times: set[float] = set()
        self._policies: dict[str, SourcePolicy] = {}
        self._windows: dict[str, dict[str, float | int]] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _validate_int(name: str, value: object, *, minimum: int) -> int:
        if type(value) is not int or value < minimum:
            raise DnsCookieError(
                _INVALID_ARGUMENT,
                f"{name} must be an integer >= {minimum}",
            )
        return value

    @staticmethod
    def _validate_source(source: object) -> str:
        if not isinstance(source, str) or not source.strip():
            raise DnsCookieError(_INVALID_ARGUMENT, "source must be non-empty")
        return source

    @staticmethod
    def _coerce_now(now: float | None) -> float:
        if now is None:
            return time.monotonic()
        if isinstance(now, bool) or not isinstance(now, (int, float)):
            raise DnsCookieError(_INVALID_ARGUMENT, "now must be a finite number")
        try:
            timestamp = float(now)
        except (OverflowError, ValueError) as exc:
            raise DnsCookieError(
                _INVALID_ARGUMENT, "now must be a finite number"
            ) from exc
        if not math.isfinite(timestamp):
            raise DnsCookieError(_INVALID_ARGUMENT, "now must be a finite number")
        return timestamp

    @staticmethod
    def _is_valid_hex(cookie: str, length: int) -> bool:
        return len(cookie) == length and all(char in _HEX_DIGITS for char in cookie)

    def _derive(self, label: bytes, source: str, generation: int | None = None) -> str:
        source_bytes = source.encode("utf-8")
        message = bytearray(label)
        message.extend(len(source_bytes).to_bytes(8, "big"))
        message.extend(source_bytes)
        if generation is not None:
            generation_bytes = generation.to_bytes(
                max(1, (generation.bit_length() + 7) // 8),
                "big",
            )
            message.extend(generation_bytes)
        return hmac.new(self._secret, bytes(message), hashlib.sha256).hexdigest()

    def _client_cookie_for(self, source: str) -> str:
        return self._derive(b"client\x00", source)[:16]

    def _server_cookie_for(self, source: str, generation: int) -> str:
        return self._derive(b"server\x00", source, generation)[:32]

    def _effective_policy(self, source: str) -> SourcePolicy:
        policy = self._policies.get(source)
        if policy is None:
            return SourcePolicy(
                source,
                True,
                self.default_missing_budget,
                self.default_amplification_budget,
            )
        return policy

    def _window_for(self, source: str, now: float) -> dict[str, float | int]:
        window = self._windows.get(source)
        if window is None or now - float(window["started_at"]) >= self.window:
            window = {
                "started_at": now,
                "missing_used": 0,
                "amplification_used": 0,
            }
            self._windows[source] = window
        return window

    @staticmethod
    def _parse_query_cookie(
        query_cookie: object,
    ) -> tuple[str, str | None, bool]:
        if query_cookie is None:
            return "", None, False
        if isinstance(query_cookie, (bytes, bytearray, memoryview)):
            try:
                query_cookie = bytes(query_cookie).decode("ascii")
            except UnicodeDecodeError:
                return "", None, False
        if not isinstance(query_cookie, str):
            return "", None, False

        parts = query_cookie.strip().split()
        if not parts:
            return "", None, False
        if len(parts) == 1:
            return parts[0], None, False

        server = parts[1]
        return parts[0], server, len(parts) > 2

    def _is_active_server_cookie(self, source: str, cookie: str) -> bool:
        if not self._is_valid_hex(cookie, 32):
            return False
        accepted = set(self._active)
        accepted.update(
            range(
                max(1, self.generation - self.overlap_generations),
                self.generation + 1,
            )
        )
        for generation in accepted:
            expected = self._server_cookie_for(source, generation)
            if hmac.compare_digest(cookie, expected):
                return True
        return False

    def client_cookie(self, source: str) -> str:
        source = self._validate_source(source)
        return self._client_cookie_for(source)

    def issue_server_cookie(self, source: str, *, generation: int | None = None) -> str:
        source = self._validate_source(source)
        if generation is not None:
            self._validate_int("generation", generation, minimum=1)
        with self._lock:
            selected_generation = self.generation if generation is None else generation
            return self._server_cookie_for(source, selected_generation)

    def verify(self, query_cookie: str, source: str, *, now: float | None = None) -> CookieVerdict:
        source = self._validate_source(source)
        timestamp = self._coerce_now(now)
        with self._lock:
            self._stats["queries"] += 1
            policy = self._effective_policy(source)
            window = self._window_for(source, timestamp)
            client_cookie, server_cookie, extra_tokens = self._parse_query_cookie(
                query_cookie
            )

            client_valid = False
            if len(client_cookie) != 16:
                self._stats["missing_client"] += 1
                missing_available = (
                    int(window["missing_used"]) < policy.missing_budget
                )
                if missing_available:
                    window["missing_used"] = int(window["missing_used"]) + 1

                if policy.cookie_required:
                    if missing_available:
                        self._stats["retried"] += 1
                        return CookieVerdict(
                            "retry_with_cookie",
                            self._server_cookie_for(source, self.generation),
                            "client_cookie_missing",
                        )
                    self._stats["dropped"] += 1
                    return CookieVerdict(
                        "drop",
                        None,
                        "missing_budget_exhausted",
                    )
            elif not hmac.compare_digest(
                client_cookie, self._client_cookie_for(source)
            ):
                self._stats["dropped"] += 1
                return CookieVerdict("drop", None, "client_cookie_forged")
            else:
                client_valid = True

            server_valid = False
            if server_cookie is not None:
                server_valid = (
                    not extra_tokens
                    and self._is_active_server_cookie(source, server_cookie)
                )
                if not server_valid:
                    self._stats["bad_server"] += 1

            remaining = max(
                0,
                policy.amplification_budget
                - int(window["amplification_used"]),
            )
            if remaining == 0:
                self._stats["truncated"] += 1
                if server_valid:
                    replacement_cookie = server_cookie
                else:
                    replacement_cookie = self._server_cookie_for(
                        source, self.generation
                    )
                return CookieVerdict(
                    "truncate",
                    replacement_cookie,
                    "amplification_budget_exhausted",
                )

            if client_valid:
                if server_cookie is None:
                    self._stats["answered"] += 1
                    return CookieVerdict(
                        "answer_with_cookie",
                        self._server_cookie_for(source, self.generation),
                        "server_cookie_missing",
                    )
                if not server_valid:
                    self._stats["answered"] += 1
                    return CookieVerdict(
                        "answer_with_cookie",
                        self._server_cookie_for(source, self.generation),
                        "server_cookie_invalid",
                    )
                self._stats["answered"] += 1
                return CookieVerdict("answer", None, "valid")

            self._stats["answered"] += 1
            if server_valid:
                return CookieVerdict("answer", None, "cookie_not_required")
            return CookieVerdict(
                "answer_with_cookie",
                self._server_cookie_for(source, self.generation),
                "cookie_not_required",
            )

    def rotate_key(self, *, now: float | None = None) -> int:
        timestamp = self._coerce_now(now)
        with self._lock:
            if (
                self._last_rotation_at is not None
                and timestamp in self._rotation_times
            ):
                if timestamp == self._last_rotation_at:
                    self._active = [self.generation]
                return self.generation

            self._rotation_times.add(timestamp)
            self.generation += 1
            self._active.append(self.generation)
            self._active.sort()
            self._last_rotation_at = timestamp
            self._stats["rotations"] += 1
            return self.generation

    def active_generations(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(self._active)

    def sweep(self, *, now: float | None = None) -> int:
        if now is not None:
            self._coerce_now(now)
        with self._lock:
            oldest_allowed = self.generation - self.overlap_generations
            retained = [
                generation
                for generation in self._active
                if generation >= oldest_allowed
            ]
            retired = len(self._active) - len(retained)
            self._active = retained
            return retired

    def set_source_policy(
        self,
        source: str,
        *,
        cookie_required: bool | None = None,
        missing_budget: int | None = None,
        amplification_budget: int | None = None,
    ) -> SourcePolicy:
        source = self._validate_source(source)
        if cookie_required is not None and type(cookie_required) is not bool:
            raise DnsCookieError(
                _INVALID_ARGUMENT, "cookie_required must be a boolean"
            )
        if missing_budget is not None:
            self._validate_int("missing_budget", missing_budget, minimum=0)
        if amplification_budget is not None:
            self._validate_int(
                "amplification_budget", amplification_budget, minimum=0
            )

        with self._lock:
            current = self._effective_policy(source)
            policy = SourcePolicy(
                source,
                current.cookie_required
                if cookie_required is None
                else cookie_required,
                current.missing_budget
                if missing_budget is None
                else missing_budget,
                current.amplification_budget
                if amplification_budget is None
                else amplification_budget,
            )
            self._policies[source] = policy
            return policy

    def policy_for(self, source: str) -> SourcePolicy:
        source = self._validate_source(source)
        with self._lock:
            return self._effective_policy(source)

    def note_amplification(
        self,
        source: str,
        response_bytes: int,
        *,
        now: float | None = None,
    ) -> int:
        source = self._validate_source(source)
        self._validate_int("response_bytes", response_bytes, minimum=0)
        timestamp = self._coerce_now(now)
        with self._lock:
            policy = self._effective_policy(source)
            window = self._window_for(source, timestamp)
            used = int(window["amplification_used"])
            available = max(0, policy.amplification_budget - used)
            deducted = min(response_bytes, available)
            window["amplification_used"] = used + deducted
            return deducted

    def quota_remaining(
        self, source: str, *, now: float | None = None
    ) -> int:
        source = self._validate_source(source)
        timestamp = self._coerce_now(now)
        with self._lock:
            policy = self._effective_policy(source)
            window = self._windows.get(source)
            if (
                window is None
                or timestamp - float(window["started_at"]) >= self.window
            ):
                return policy.amplification_budget
            return max(
                0,
                policy.amplification_budget
                - int(window["amplification_used"]),
            )

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "generation": self.generation,
                "active": list(self._active),
                "policies": {
                    source: {
                        "cookie_required": policy.cookie_required,
                        "missing_budget": policy.missing_budget,
                        "amplification_budget": policy.amplification_budget,
                    }
                    for source, policy in self._policies.items()
                },
                "windows": {
                    source: {
                        "started_at": window["started_at"],
                        "missing_used": window["missing_used"],
                        "amplification_used": window["amplification_used"],
                    }
                    for source, window in self._windows.items()
                },
                "stats": dict(self._stats),
            }

    @staticmethod
    def _snapshot_error(detail: object) -> DnsCookieError:
        return DnsCookieError(_INVALID_SNAPSHOT, detail)

    @classmethod
    def _validate_snapshot_source(cls, source: object) -> str:
        if not isinstance(source, str) or not source.strip():
            raise cls._snapshot_error("snapshot source must be non-empty")
        return source

    @classmethod
    def _validate_snapshot_count(cls, name: str, value: object) -> int:
        if type(value) is not int or value < 0:
            raise cls._snapshot_error(f"{name} must be a non-negative integer")
        return value

    def _validated_snapshot(
        self, state: object
    ) -> tuple[
        int,
        list[int],
        dict[str, SourcePolicy],
        dict[str, dict[str, float | int]],
        dict[str, int],
    ]:
        if not isinstance(state, Mapping):
            raise self._snapshot_error("state must be a mapping")
        if set(state.keys()) != _SNAPSHOT_KEYS:
            raise self._snapshot_error("snapshot keys are invalid")
        if type(state["version"]) is not int or state["version"] != _SNAPSHOT_VERSION:
            raise self._snapshot_error("snapshot version is invalid")

        generation = state["generation"]
        if type(generation) is not int or generation < 1:
            raise self._snapshot_error("generation must be a positive integer")

        active_state = state["active"]
        if not isinstance(active_state, (list, tuple)):
            raise self._snapshot_error("active must be a sequence")
        active: list[int] = []
        for item in active_state:
            if type(item) is not int or item < 1:
                raise self._snapshot_error(
                    "active generations must be positive integers"
                )
            if item in active:
                raise self._snapshot_error("active generations must be unique")
            active.append(item)
        active.sort()
        if not active or active[-1] != generation:
            raise self._snapshot_error(
                "active generations must contain the current generation"
            )

        policies_state = state["policies"]
        if not isinstance(policies_state, Mapping):
            raise self._snapshot_error("policies must be a mapping")
        policies: dict[str, SourcePolicy] = {}
        for raw_source, raw_policy in policies_state.items():
            source = self._validate_snapshot_source(raw_source)
            if not isinstance(raw_policy, Mapping):
                raise self._snapshot_error("policy entries must be mappings")
            if set(raw_policy.keys()) != _POLICY_KEYS:
                raise self._snapshot_error("policy entry keys are invalid")
            cookie_required = raw_policy["cookie_required"]
            if type(cookie_required) is not bool:
                raise self._snapshot_error(
                    "cookie_required must be a boolean"
                )
            policies[source] = SourcePolicy(
                source,
                cookie_required,
                self._validate_snapshot_count(
                    "missing_budget", raw_policy["missing_budget"]
                ),
                self._validate_snapshot_count(
                    "amplification_budget",
                    raw_policy["amplification_budget"],
                ),
            )

        windows_state = state["windows"]
        if not isinstance(windows_state, Mapping):
            raise self._snapshot_error("windows must be a mapping")
        windows: dict[str, dict[str, float | int]] = {}
        for raw_source, raw_window in windows_state.items():
            source = self._validate_snapshot_source(raw_source)
            if not isinstance(raw_window, Mapping):
                raise self._snapshot_error("window entries must be mappings")
            if set(raw_window.keys()) != _WINDOW_KEYS:
                raise self._snapshot_error("window entry keys are invalid")
            started_at = raw_window["started_at"]
            if isinstance(started_at, bool) or not isinstance(
                started_at, (int, float)
            ):
                raise self._snapshot_error("window start must be a finite number")
            try:
                started_at_value = float(started_at)
            except (OverflowError, ValueError) as exc:
                raise self._snapshot_error(
                    "window start must be a finite number"
                ) from exc
            if not math.isfinite(started_at_value):
                raise self._snapshot_error("window start must be a finite number")
            windows[source] = {
                "started_at": started_at_value,
                "missing_used": self._validate_snapshot_count(
                    "missing_used", raw_window["missing_used"]
                ),
                "amplification_used": self._validate_snapshot_count(
                    "amplification_used",
                    raw_window["amplification_used"],
                ),
            }

        stats_state = state["stats"]
        if not isinstance(stats_state, Mapping):
            raise self._snapshot_error("stats must be a mapping")
        if set(stats_state.keys()) != set(_STAT_KEYS):
            raise self._snapshot_error("stats keys are invalid")
        stats = {
            key: self._validate_snapshot_count(key, stats_state[key])
            for key in _STAT_KEYS
        }
        return generation, active, policies, windows, stats

    def restore(self, state: dict) -> None:
        generation, active, policies, windows, stats = self._validated_snapshot(
            state
        )
        with self._lock:
            self.generation = generation
            self._active = active
            self._policies = policies
            self._windows = windows
            self._stats = stats
            self._last_rotation_at = None
            self._rotation_times = set()

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
