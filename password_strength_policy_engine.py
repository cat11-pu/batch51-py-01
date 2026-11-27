"""Layered password strength policy: baseline, tenant rules, scenario exceptions, scoring."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


RULE_ORDER = ("length", "classes", "repeat", "dictionary", "username")

DEFAULT_RULES = {
    "min_length": 12,
    "min_classes": 3,
    "max_repeats": 2,
    "min_score": 60,
}

PENALTIES = {
    "length": 25,
    "classes": 20,
    "repeat": 15,
    "dictionary": 30,
    "username": 40,
}

_POLICY_KEYS = tuple(DEFAULT_RULES)
_STATS_KEYS = ("evaluations", "failures", "exemptions_applied", "reloads")
_EXCEPTION_FIELDS = ("tenant", "scenario", "overrides", "exempt")


class PolicyError(ValueError):
    """Raised when policy composition or evaluation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CompositePolicy:
    tenant: str
    scenario: str | None
    version: int
    min_length: int
    min_classes: int
    max_repeats: int
    min_score: int
    exempted: tuple[str, ...]


@dataclass(frozen=True)
class Evaluation:
    passed: bool
    score: int
    failed: tuple[str, ...]
    exempted: tuple[str, ...]
    version: int


def _is_valid_value(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_overrides(overrides: object, code: str) -> None:
    if not isinstance(overrides, dict):
        raise PolicyError(code, "overrides must be a mapping of rule keys to values")
    for key, value in overrides.items():
        if key not in _POLICY_KEYS:
            raise PolicyError(code, f"unknown rule key: {key!r}")
        if not _is_valid_value(value):
            raise PolicyError(code, f"invalid value for {key!r}: {value!r}")


def _validate_exempt(exempt: object, code: str) -> None:
    if not isinstance(exempt, (list, tuple)):
        raise PolicyError(code, "exempt must be a list of rule names")
    for name in exempt:
        if name not in RULE_ORDER:
            raise PolicyError(code, f"unknown rule name in exempt: {name!r}")


def _validate_tenant(tenant: object, code: str) -> None:
    if not isinstance(tenant, str) or not tenant.strip():
        raise PolicyError(code, "tenant must be a non-empty string")


def _validate_scenario(scenario: object, code: str) -> None:
    if not isinstance(scenario, str) or not scenario.strip():
        raise PolicyError(code, "scenario must be a non-empty string")


def _tighten(base: dict, overrides: dict) -> dict:
    """Merge two layers keeping the stricter value for every key."""
    merged = dict(base)
    for key, value in overrides.items():
        if key == "max_repeats":
            merged[key] = min(merged[key], value)
        else:
            merged[key] = max(merged[key], value)
    return merged


def _parse_baseline(baseline: object, code: str) -> dict:
    if not isinstance(baseline, dict) or set(baseline) != set(_POLICY_KEYS):
        raise PolicyError(code, "baseline must define exactly the four policy keys")
    _validate_overrides(baseline, code)
    return dict(baseline)


def _parse_tenants(tenants: object, code: str) -> dict:
    if not isinstance(tenants, dict):
        raise PolicyError(code, "tenants must be a mapping of tenant to overrides")
    parsed = {}
    for tenant, overrides in tenants.items():
        _validate_tenant(tenant, code)
        _validate_overrides(overrides, code)
        parsed[tenant] = dict(overrides)
    return parsed


def _parse_exceptions(exceptions: object, code: str) -> list:
    if not isinstance(exceptions, list):
        raise PolicyError(code, "exceptions must be a list of records")
    parsed = []
    for record in exceptions:
        if not isinstance(record, dict) or set(record) != set(_EXCEPTION_FIELDS):
            raise PolicyError(
                code, "exception records need tenant, scenario, overrides, exempt")
        _validate_tenant(record["tenant"], code)
        _validate_scenario(record["scenario"], code)
        _validate_overrides(record["overrides"], code)
        _validate_exempt(record["exempt"], code)
        parsed.append({
            "tenant": record["tenant"],
            "scenario": record["scenario"],
            "overrides": dict(record["overrides"]),
            "exempt": tuple(record["exempt"]),
        })
    return parsed


def _character_classes(password: str) -> int:
    classes = 0
    if any(ch.islower() for ch in password):
        classes += 1
    if any(ch.isupper() for ch in password):
        classes += 1
    if any(ch.isdigit() for ch in password):
        classes += 1
    if any(not ch.isalnum() for ch in password):
        classes += 1
    return classes


def _longest_run(password: str) -> int:
    longest = 1
    current = 1
    for index in range(1, len(password)):
        if password[index] == password[index - 1]:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
    return longest


class StrengthPolicyEngine:
    """Compose strength rules from layers and evaluate passwords deterministically."""

    def __init__(self, *, dictionary=("password", "letmein", "qwerty")) -> None:
        self._dictionary = tuple(
            word.lower() for word in dictionary
            if isinstance(word, str) and word
        )
        self._lock = threading.RLock()
        self._baseline = dict(DEFAULT_RULES)
        self._tenants: dict[str, dict] = {}
        self._exceptions: list[dict] = []
        self._version = 1
        self._stats = {key: 0 for key in _STATS_KEYS}

    def set_baseline(self, overrides: dict) -> int:
        with self._lock:
            _validate_overrides(overrides, "POLICY_INVALID_REQUEST")
            self._baseline.update(overrides)
            self._version += 1
            return self._version

    def set_tenant_policy(self, tenant: str, overrides: dict) -> int:
        with self._lock:
            _validate_tenant(tenant, "POLICY_INVALID_REQUEST")
            _validate_overrides(overrides, "POLICY_INVALID_REQUEST")
            self._tenants[tenant] = dict(overrides)
            self._version += 1
            return self._version

    def register_exception(self, tenant: str, scenario: str, overrides: dict,
                           *, exempt=()) -> int:
        with self._lock:
            _validate_tenant(tenant, "POLICY_INVALID_REQUEST")
            _validate_scenario(scenario, "POLICY_INVALID_REQUEST")
            _validate_overrides(overrides, "POLICY_INVALID_REQUEST")
            _validate_exempt(exempt, "POLICY_INVALID_REQUEST")
            self._exceptions.append({
                "tenant": tenant,
                "scenario": scenario,
                "overrides": dict(overrides),
                "exempt": tuple(exempt),
            })
            self._version += 1
            return self._version

    def _compose_locked(self, tenant: str, scenario: str | None) -> CompositePolicy:
        _validate_tenant(tenant, "POLICY_INVALID_REQUEST")
        if scenario is not None:
            _validate_scenario(scenario, "POLICY_INVALID_REQUEST")
        merged = dict(self._baseline)
        tenant_overrides = self._tenants.get(tenant)
        if tenant_overrides:
            merged = _tighten(merged, tenant_overrides)
        exempted: set[str] = set()
        if scenario is not None:
            records = [record for record in self._exceptions
                       if record["tenant"] == tenant
                       and record["scenario"] == scenario]
            if not records:
                raise PolicyError(
                    "POLICY_SCENARIO_UNKNOWN",
                    f"no exception registered for tenant={tenant!r} scenario={scenario!r}",
                )
            listed: dict[str, list[int]] = {}
            for record in records:
                for key, value in record["overrides"].items():
                    listed.setdefault(key, []).append(value)
                exempted.update(record["exempt"])
            for key, values in listed.items():
                if key == "max_repeats":
                    merged[key] = min(values)
                else:
                    merged[key] = max(values)
        return CompositePolicy(
            tenant=tenant,
            scenario=scenario,
            version=self._version,
            min_length=merged["min_length"],
            min_classes=merged["min_classes"],
            max_repeats=merged["max_repeats"],
            min_score=merged["min_score"],
            exempted=tuple(rule for rule in RULE_ORDER if rule in exempted),
        )

    def compose(self, tenant: str, *, scenario: str | None = None) -> CompositePolicy:
        with self._lock:
            return self._compose_locked(tenant, scenario)

    def explain(self, tenant: str, *, scenario: str | None = None) -> dict:
        with self._lock:
            policy = self._compose_locked(tenant, scenario)
            return {
                "version": policy.version,
                "tenant": policy.tenant,
                "scenario": policy.scenario,
                "min_length": policy.min_length,
                "min_classes": policy.min_classes,
                "max_repeats": policy.max_repeats,
                "min_score": policy.min_score,
                "exempted": list(policy.exempted),
            }

    def evaluate(self, password, *, tenant: str, username: str | None = None,
                 scenario: str | None = None) -> Evaluation:
        if not isinstance(password, str) or not password:
            raise PolicyError(
                "POLICY_INVALID_REQUEST", "password must be a non-empty string")
        if username is not None and not isinstance(username, str):
            raise PolicyError(
                "POLICY_INVALID_REQUEST", "username must be a string or None")
        with self._lock:
            policy = self._compose_locked(tenant, scenario)
            exempted = set(policy.exempted)
            lowered = password.lower()
            failures = {
                "length": len(password) < policy.min_length,
                "classes": _character_classes(password) < policy.min_classes,
                "repeat": _longest_run(password) > policy.max_repeats,
                "dictionary": any(word in lowered for word in self._dictionary),
                "username": self._username_hit(lowered, username),
            }
            failed = []
            applied = 0
            score = 100
            for rule in RULE_ORDER:
                if not failures[rule]:
                    continue
                if rule in exempted and rule != "username":
                    applied += 1
                    continue
                failed.append(rule)
                score -= PENALTIES[rule]
            score = max(0, score)
            passed = not failed and score >= policy.min_score
            self._stats["evaluations"] += 1
            if not passed:
                self._stats["failures"] += 1
            self._stats["exemptions_applied"] += applied
            return Evaluation(
                passed=passed,
                score=score,
                failed=tuple(failed),
                exempted=policy.exempted,
                version=policy.version,
            )

    @staticmethod
    def _username_hit(lowered_password: str, username: str | None) -> bool:
        if not username:
            return False
        lowered_username = username.lower()
        if not lowered_username:
            return False
        return (lowered_username in lowered_password
                or lowered_username[::-1] in lowered_password)

    def reload(self, payload: dict) -> int:
        with self._lock:
            code = "POLICY_PAYLOAD_INVALID"
            if not isinstance(payload, dict) or set(payload) != {
                    "baseline", "tenants", "exceptions"}:
                raise PolicyError(
                    code, "payload must contain baseline, tenants, exceptions")
            baseline = _parse_baseline(payload["baseline"], code)
            tenants = _parse_tenants(payload["tenants"], code)
            exceptions = _parse_exceptions(payload["exceptions"], code)
            self._baseline = baseline
            self._tenants = tenants
            self._exceptions = exceptions
            self._version += 1
            self._stats["reloads"] += 1
            return self._version

    def policy_version(self) -> int:
        with self._lock:
            return self._version

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self._version,
                "baseline": copy.deepcopy(self._baseline),
                "tenants": copy.deepcopy(self._tenants),
                "exceptions": [
                    {
                        "tenant": record["tenant"],
                        "scenario": record["scenario"],
                        "overrides": dict(record["overrides"]),
                        "exempt": list(record["exempt"]),
                    }
                    for record in self._exceptions
                ],
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            code = "POLICY_SNAPSHOT_INVALID"
            if not isinstance(state, dict) or set(state) != {
                    "version", "baseline", "tenants", "exceptions", "stats"}:
                raise PolicyError(
                    code, "state must contain version, baseline, tenants, exceptions, stats")
            version = state["version"]
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise PolicyError(code, "version must be a positive integer")
            baseline = _parse_baseline(state["baseline"], code)
            tenants = _parse_tenants(state["tenants"], code)
            exceptions = _parse_exceptions(state["exceptions"], code)
            stats = state["stats"]
            if not isinstance(stats, dict) or set(stats) != set(_STATS_KEYS):
                raise PolicyError(code, "stats must define the four counters")
            for key, value in stats.items():
                if not _is_valid_value(value):
                    raise PolicyError(code, f"invalid stats counter {key!r}: {value!r}")
            self._version = version
            self._baseline = baseline
            self._tenants = tenants
            self._exceptions = exceptions
            self._stats = dict(stats)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
