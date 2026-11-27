"""Live-ops flag routing: stable cohorts, targeting, dependency order, config generations."""

from __future__ import annotations

import copy
import hashlib
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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class FlagCohortRouter:
    """Decide flag state per account with sticky cohorts and dependency ordering."""

    def __init__(self, *, max_flags: int = 128, max_audit: int = 256,
                 salt: str = "cohort-v1") -> None:
        self.max_flags = max_flags
        self.max_audit = max_audit
        self.salt = salt
        self._lock = threading.RLock()
        self._version = 0
        self._flags: dict[str, FlagSpec] = {}
        self._audit: list[dict] = []
        self._seq = 0
        self._evaluations = 0

    @staticmethod
    def _new_flag_name(name: object) -> str:
        if not isinstance(name, str):
            raise FlagError("FLAG_INVALID_NAME", name)
        clean = name.strip()
        if not clean:
            raise FlagError("FLAG_INVALID_NAME", name)
        return clean

    @staticmethod
    def _lookup_name(name: object) -> str:
        if not isinstance(name, str) or not name.strip():
            raise FlagError("FLAG_UNKNOWN", name)
        return name.strip()

    @staticmethod
    def _valid_rollout(bps: object) -> bool:
        return _is_int(bps) and 0 <= bps <= 10000

    @staticmethod
    def _as_tuple(values: object) -> tuple:
        if values is None:
            return ()
        if isinstance(values, str):
            return (values,)
        return tuple(values)

    @classmethod
    def _dependency_names(cls, flags: object) -> tuple[str, ...]:
        if flags is None:
            return ()
        if isinstance(flags, str):
            values = (flags,)
        else:
            values = tuple(flags)
        result = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise FlagError("FLAG_UNKNOWN_DEPENDENCY", value)
            clean = value.strip()
            if clean not in result:
                result.append(clean)
        return tuple(result)

    def _record_locked(self, flag: str, kind: str, version: int,
                       detail: object) -> None:
        self._seq += 1
        self._audit.append({
            "seq": self._seq,
            "flag": flag,
            "kind": kind,
            "version": version,
            "detail": copy.deepcopy(detail),
        })
        if self.max_audit <= 0:
            self._audit.clear()
        elif len(self._audit) > self.max_audit:
            del self._audit[:-self.max_audit]

    def _require_locked(self, name: object) -> tuple[str, FlagSpec]:
        clean = self._lookup_name(name)
        spec = self._flags.get(clean)
        if spec is None:
            raise FlagError("FLAG_UNKNOWN", clean)
        return clean, spec

    def _dependencies_would_cycle(self, target: str,
                                  parents: tuple[str, ...]) -> bool:
        pending = list(parents)
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current in seen:
                continue
            seen.add(current)
            spec = self._flags.get(current)
            if spec is not None:
                pending.extend(spec.depends_on)
        return False

    def define_flag(self, name: str, *, enabled: bool = False,
                    rollout_bps: int = 0, regions=(), platforms=(),
                    versions=(), whitelist=(), depends_on=()) -> int:
        """Create a flag and return the new configuration version."""
        clean = self._new_flag_name(name)
        with self._lock:
            if clean in self._flags:
                raise FlagError("FLAG_ALREADY_DEFINED", clean)
            if len(self._flags) >= self.max_flags:
                raise FlagError("FLAG_CAPACITY_EXCEEDED", clean)
            if not self._valid_rollout(rollout_bps):
                raise FlagError("FLAG_INVALID_ROLLOUT", rollout_bps)

            parents = self._dependency_names(depends_on)
            for parent in parents:
                if parent == clean:
                    raise FlagError("FLAG_DEPENDENCY_CYCLE", parent)
                if parent not in self._flags:
                    raise FlagError("FLAG_UNKNOWN_DEPENDENCY", parent)

            new_version = self._version + 1
            spec = FlagSpec(
                name=clean,
                enabled=bool(enabled),
                rollout_bps=rollout_bps,
                regions=self._as_tuple(regions),
                platforms=self._as_tuple(platforms),
                versions=self._as_tuple(versions),
                whitelist=self._as_tuple(whitelist),
                depends_on=parents,
                version=new_version,
            )
            self._flags[clean] = spec
            self._version = new_version
            self._record_locked(clean, "define", new_version, {
                "enabled": spec.enabled,
                "rollout_bps": spec.rollout_bps,
                "depends_on": list(spec.depends_on),
            })
            return new_version

    def set_rollout(self, name: str, bps: int) -> int:
        """Change the rollout percentage and return the new configuration version."""
        with self._lock:
            clean, spec = self._require_locked(name)
            if not self._valid_rollout(bps):
                raise FlagError("FLAG_INVALID_ROLLOUT", bps)

            new_version = self._version + 1
            updated = FlagSpec(
                name=spec.name,
                enabled=spec.enabled,
                rollout_bps=bps,
                regions=spec.regions,
                platforms=spec.platforms,
                versions=spec.versions,
                whitelist=spec.whitelist,
                depends_on=spec.depends_on,
                version=new_version,
            )
            self._flags[clean] = updated
            self._version = new_version
            self._record_locked(clean, "rollout", new_version, {
                "from": spec.rollout_bps,
                "to": bps,
            })
            return new_version

    def set_dependencies(self, name: str, flags) -> int:
        """Replace the parent list of a flag, refusing unknown parents and cycles."""
        with self._lock:
            clean, spec = self._require_locked(name)
            parents = self._dependency_names(flags)
            for parent in parents:
                if parent not in self._flags:
                    raise FlagError("FLAG_UNKNOWN_DEPENDENCY", parent)
            if self._dependencies_would_cycle(clean, parents):
                raise FlagError("FLAG_DEPENDENCY_CYCLE", clean)

            new_version = self._version + 1
            updated = FlagSpec(
                name=spec.name,
                enabled=spec.enabled,
                rollout_bps=spec.rollout_bps,
                regions=spec.regions,
                platforms=spec.platforms,
                versions=spec.versions,
                whitelist=spec.whitelist,
                depends_on=parents,
                version=new_version,
            )
            self._flags[clean] = updated
            self._version = new_version
            self._record_locked(clean, "dependencies", new_version, {
                "from": list(spec.depends_on),
                "to": list(parents),
            })
            return new_version

    def remove_flag(self, name: str) -> int:
        """Drop a flag and return the new configuration version."""
        with self._lock:
            clean, spec = self._require_locked(name)
            new_version = self._version + 1
            del self._flags[clean]
            self._version = new_version
            self._record_locked(clean, "remove", new_version, {
                "enabled": spec.enabled,
                "rollout_bps": spec.rollout_bps,
            })
            return new_version

    def _bucket(self, account: object) -> int:
        material = f"{self.salt}\x1f{account}".encode("utf-8")
        digest = hashlib.sha256(material).digest()
        return int.from_bytes(digest[:8], "big") % 10000

    @staticmethod
    def _target_matches(spec: FlagSpec, region: str | None,
                        platform: str | None,
                        version: str | None) -> bool:
        checks = (
            (spec.regions, region),
            (spec.platforms, platform),
            (spec.versions, version),
        )
        for allowed, actual in checks:
            if allowed and actual not in allowed:
                return False
        return True

    def _evaluate_locked(self, account: object, name: str,
                         region: str | None, platform: str | None,
                         version: str | None, memo: dict[str, Decision],
                         trail: set[str]) -> Decision:
        cached = memo.get(name)
        if cached is not None:
            return cached
        if name in trail:
            raise FlagError("FLAG_DEPENDENCY_CYCLE", name)

        spec = self._flags.get(name)
        if spec is None:
            raise FlagError("FLAG_UNKNOWN", name)
        trail.add(name)

        if not spec.enabled:
            decision = Decision(name, False, "FLAG_DISABLED", "switch",
                                self._version)
        elif account in spec.whitelist:
            decision = Decision(name, True, "WHITELIST", "whitelist",
                                self._version)
        elif not self._target_matches(spec, region, platform, version):
            decision = Decision(name, False, "TARGET_MISS", "target",
                                self._version)
        elif self._bucket(account) < spec.rollout_bps:
            decision = Decision(name, True, "COHORT_HIT", "rollout",
                                self._version)
        else:
            decision = Decision(name, False, "COHORT_MISS", "rollout",
                                self._version)

        if decision.enabled:
            for parent in spec.depends_on:
                parent_decision = self._evaluate_locked(
                    account, parent, region, platform, version, memo, trail)
                if not parent_decision.enabled:
                    decision = Decision(
                        name, False, "DEPENDENCY_BLOCKED", "dependency",
                        self._version)
                    break

        trail.remove(name)
        memo[name] = decision
        return decision

    def evaluate(self, account: str, flag: str, *, region: str | None = None,
                 platform: str | None = None,
                 version: str | None = None) -> Decision:
        """Resolve one flag for one account at the current configuration version."""
        with self._lock:
            clean, _ = self._require_locked(flag)
            decision = self._evaluate_locked(
                account, clean, region, platform, version, {}, set())
            self._evaluations += 1
            return decision

    def bulk_evaluate(self, account: str, flags, *, region: str | None = None,
                      platform: str | None = None,
                      version: str | None = None) -> list[Decision]:
        """Resolve several flags in dependency topological order."""
        with self._lock:
            if isinstance(flags, str):
                requested_values = (flags,)
            else:
                requested_values = tuple(flags)

            requested: list[str] = []
            for item in requested_values:
                clean = self._lookup_name(item)
                if clean not in self._flags:
                    raise FlagError("FLAG_UNKNOWN", clean)
                if clean not in requested:
                    requested.append(clean)

            ordered: list[str] = []
            seen: set[str] = set()

            def visit(name: str) -> None:
                if name in seen:
                    return
                seen.add(name)
                spec = self._flags.get(name)
                if spec is None:
                    raise FlagError("FLAG_UNKNOWN_DEPENDENCY", name)
                for parent in spec.depends_on:
                    visit(parent)
                ordered.append(name)

            for name in requested:
                visit(name)

            requested_set = set(requested)
            ordered = [name for name in ordered if name in requested_set]
            memo: dict[str, Decision] = {}
            results = [
                self._evaluate_locked(
                    account, name, region, platform, version, memo, set())
                for name in ordered
            ]
            self._evaluations += len(results)
            return results

    def audit_of(self, flag: str | None = None) -> list[dict]:
        """Configuration changes ordered by sequence, optionally scoped to one flag."""
        with self._lock:
            if flag is None:
                rows = self._audit
            else:
                clean = self._lookup_name(flag)
                rows = [row for row in self._audit if row["flag"] == clean]
                if clean not in self._flags and not rows:
                    raise FlagError("FLAG_UNKNOWN", clean)
            return copy.deepcopy(rows)

    def spec_of(self, name: str) -> FlagSpec:
        """Current definition of one flag."""
        with self._lock:
            _, spec = self._require_locked(name)
            return spec

    def config_version(self) -> int:
        """Current configuration generation number."""
        with self._lock:
            return self._version

    def _stats_locked(self) -> dict:
        return {
            "flags": len(self._flags),
            "evaluations": self._evaluations,
            "audit": len(self._audit),
            "version": self._version,
        }

    def snapshot(self) -> dict:
        """Deep copy of flags, audit trail and counters."""
        with self._lock:
            flags = {}
            for name, spec in self._flags.items():
                flags[name] = {
                    "name": spec.name,
                    "enabled": spec.enabled,
                    "rollout_bps": spec.rollout_bps,
                    "regions": spec.regions,
                    "platforms": spec.platforms,
                    "versions": spec.versions,
                    "whitelist": spec.whitelist,
                    "depends_on": spec.depends_on,
                    "version": spec.version,
                }
            return {
                "version": self._version,
                "flags": flags,
                "audit": copy.deepcopy(self._audit),
                "counters": {
                    "seq": self._seq,
                    "evaluations": self._evaluations,
                },
                "stats": self._stats_locked(),
            }

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> None:
        raise FlagError("FLAG_SNAPSHOT_INVALID", detail)

    @classmethod
    def _snapshot_tuple(cls, value: object) -> tuple:
        if value is None:
            return ()
        if isinstance(value, str):
            return (value,)
        if not isinstance(value, (list, tuple)):
            cls._snapshot_invalid(value)
        return tuple(value)

    @classmethod
    def _parse_snapshot_flags(cls, raw_flags: dict) -> dict[str, FlagSpec]:
        flags: dict[str, FlagSpec] = {}
        for raw_name, raw_spec in raw_flags.items():
            if not isinstance(raw_name, str) or not raw_name.strip():
                cls._snapshot_invalid(raw_name)
            name = raw_name.strip()
            if name in flags:
                cls._snapshot_invalid(raw_name)

            if isinstance(raw_spec, FlagSpec):
                spec_name = raw_spec.name
                enabled = raw_spec.enabled
                rollout_bps = raw_spec.rollout_bps
                regions = raw_spec.regions
                platforms = raw_spec.platforms
                versions = raw_spec.versions
                whitelist = raw_spec.whitelist
                depends_on = raw_spec.depends_on
                flag_version = raw_spec.version
            elif isinstance(raw_spec, dict):
                required = {
                    "enabled", "rollout_bps", "regions", "platforms",
                    "versions", "whitelist", "depends_on", "version",
                }
                if not required.issubset(raw_spec):
                    cls._snapshot_invalid(raw_name)
                spec_name = raw_spec.get("name", name)
                enabled = raw_spec["enabled"]
                rollout_bps = raw_spec["rollout_bps"]
                regions = raw_spec["regions"]
                platforms = raw_spec["platforms"]
                versions = raw_spec["versions"]
                whitelist = raw_spec["whitelist"]
                depends_on = raw_spec["depends_on"]
                flag_version = raw_spec["version"]
            else:
                cls._snapshot_invalid(raw_name)

            if spec_name != name or not isinstance(enabled, bool):
                cls._snapshot_invalid(raw_name)
            if not cls._valid_rollout(rollout_bps):
                cls._snapshot_invalid(raw_name)
            if not _is_int(flag_version) or flag_version < 0:
                cls._snapshot_invalid(raw_name)

            parent_values = cls._snapshot_tuple(depends_on)
            parents = []
            for parent in parent_values:
                if not isinstance(parent, str) or not parent.strip():
                    cls._snapshot_invalid(parent)
                clean_parent = parent.strip()
                if clean_parent not in parents:
                    parents.append(clean_parent)

            flags[name] = FlagSpec(
                name=name,
                enabled=enabled,
                rollout_bps=rollout_bps,
                regions=cls._snapshot_tuple(regions),
                platforms=cls._snapshot_tuple(platforms),
                versions=cls._snapshot_tuple(versions),
                whitelist=cls._snapshot_tuple(whitelist),
                depends_on=tuple(parents),
                version=flag_version,
            )
        return flags

    @classmethod
    def _validate_snapshot_graph(cls, flags: dict[str, FlagSpec],
                                 version: int) -> None:
        for name, spec in flags.items():
            if spec.version > version:
                cls._snapshot_invalid(name)
            for parent in spec.depends_on:
                if parent not in flags:
                    cls._snapshot_invalid(parent)

        state: dict[str, int] = {}

        def visit(name: str) -> None:
            marker = state.get(name, 0)
            if marker == 1:
                cls._snapshot_invalid(name)
            if marker == 2:
                return
            state[name] = 1
            for parent in flags[name].depends_on:
                visit(parent)
            state[name] = 2

        for name in flags:
            visit(name)

    def restore(self, state: dict) -> None:
        """Replace live configuration from a snapshot, refusing malformed input."""
        if not isinstance(state, dict):
            self._snapshot_invalid(state)
        required = {"version", "flags", "audit", "counters", "stats"}
        if not required.issubset(state):
            self._snapshot_invalid(state)

        version = state["version"]
        raw_flags = state["flags"]
        raw_audit = state["audit"]
        counters = state["counters"]
        stats = state["stats"]
        if not _is_int(version) or version < 0:
            self._snapshot_invalid(version)
        if not isinstance(raw_flags, dict):
            self._snapshot_invalid(raw_flags)
        if not isinstance(raw_audit, list):
            self._snapshot_invalid(raw_audit)
        if not isinstance(counters, dict):
            self._snapshot_invalid(counters)
        if not isinstance(stats, dict):
            self._snapshot_invalid(stats)

        flags = self._parse_snapshot_flags(raw_flags)
        if len(flags) > self.max_flags:
            self._snapshot_invalid(raw_flags)
        self._validate_snapshot_graph(flags, version)

        audit: list[dict] = []
        for raw_row in raw_audit:
            if not isinstance(raw_row, dict):
                self._snapshot_invalid(raw_row)
            if not {"seq", "flag", "kind", "version", "detail"}.issubset(raw_row):
                self._snapshot_invalid(raw_row)
            seq = raw_row["seq"]
            row_flag = raw_row["flag"]
            kind = raw_row["kind"]
            row_version = raw_row["version"]
            if not _is_int(seq) or seq < 0:
                self._snapshot_invalid(raw_row)
            if not isinstance(row_flag, str) or not row_flag.strip():
                self._snapshot_invalid(raw_row)
            if not isinstance(kind, str) or not kind:
                self._snapshot_invalid(raw_row)
            if not _is_int(row_version) or row_version < 0:
                self._snapshot_invalid(raw_row)
            audit.append({
                "seq": seq,
                "flag": row_flag.strip(),
                "kind": kind,
                "version": row_version,
                "detail": copy.deepcopy(raw_row["detail"]),
            })
        audit.sort(key=lambda row: row["seq"])
        if any(audit[index]["seq"] >= audit[index + 1]["seq"]
               for index in range(len(audit) - 1)):
            self._snapshot_invalid(raw_audit)

        seq = counters.get("seq", audit[-1]["seq"] if audit else 0)
        if not _is_int(seq) or seq < 0:
            self._snapshot_invalid(counters)
        if audit:
            seq = max(seq, audit[-1]["seq"])

        if "evaluations" in counters:
            evaluations = counters["evaluations"]
        elif "evaluations" in stats:
            evaluations = stats["evaluations"]
        else:
            evaluations = 0
        if not _is_int(evaluations) or evaluations < 0:
            self._snapshot_invalid(evaluations)
        if "evaluations" in stats:
            stats_evaluations = stats["evaluations"]
            if not _is_int(stats_evaluations) or stats_evaluations < 0:
                self._snapshot_invalid(stats_evaluations)

        with self._lock:
            self._version = version
            self._flags = flags
            self._audit = audit
            self._seq = seq
            self._evaluations = evaluations

    def stats(self) -> dict:
        """Return the counters exposed to the operations dashboard."""
        with self._lock:
            return self._stats_locked()
