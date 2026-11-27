"""Render target load/store operation planning and bandwidth accounting."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class LoadOpError(ValueError):
    """Raised when a load/store plan is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TargetState:
    """Declared render target."""

    name: str
    bytes_per_frame: int
    samples: int
    persistent: bool
    external_read: bool


@dataclass(frozen=True)
class UsePlan:
    """One decided use of a render target inside the frame."""

    target: str
    pass_index: int
    kind: str
    load_op: str
    store_op: str
    resolve: bool
    sampled: bool


@dataclass(frozen=True)
class Use:
    """A declared use of a render target."""

    target: str
    pass_index: int
    kind: str
    resolve: bool
    sampled: bool


class LoadOpOptimizer:
    """Pick clear/load/discard per render target use and account the saved bandwidth."""

    _KINDS = frozenset(("write", "read", "read_write"))
    _SAMPLES = frozenset((1, 2, 4, 8))
    _SNAPSHOT_VERSION = 1
    _COUNTER_KEYS = ("targets", "uses", "plans", "rejected")

    def __init__(self, *, max_targets: int = 64,
                 max_uses_per_target: int = 64) -> None:
        self._lock = threading.RLock()
        self._config = {"max_targets": max_targets,
                        "max_uses_per_target": max_uses_per_target}
        self._targets: dict = {}
        self._uses: dict = {}
        self._counters: dict = {
            "targets": 0,
            "uses": 0,
            "plans": 0,
            "rejected": 0,
        }

    def declare_target(self, name: str, *, bytes_per_frame: int,
                       samples: int = 1, persistent: bool = False,
                       external_read: bool = False) -> TargetState:
        with self._lock:
            self._check_target_fields(name, bytes_per_frame, samples)
            if name in self._targets:
                self._reject("LOADOP_TARGET_EXISTS", name)
            if len(self._targets) >= self._config["max_targets"]:
                self._reject("LOADOP_CAPACITY_EXCEEDED", {
                    "max_targets": self._config["max_targets"],
                    "target": name,
                })

            state = TargetState(
                name=name,
                bytes_per_frame=bytes_per_frame,
                samples=samples,
                persistent=bool(persistent),
                external_read=bool(external_read),
            )
            self._targets[name] = state
            self._uses[name] = []
            self._counters["targets"] += 1
            return state

    def declare_external_read(self, name: str) -> TargetState:
        with self._lock:
            if not isinstance(name, str) or name not in self._targets:
                self._reject("LOADOP_NO_SUCH_TARGET", name)
            current = self._targets[name]
            if current.external_read:
                return current
            updated = TargetState(
                name=current.name,
                bytes_per_frame=current.bytes_per_frame,
                samples=current.samples,
                persistent=current.persistent,
                external_read=True,
            )
            self._targets[name] = updated
            return updated

    def declare_use(self, target: str, pass_index: int, kind: str, *,
                    resolve: bool = False, sampled: bool = False) -> None:
        with self._lock:
            if not isinstance(target, str) or target not in self._targets:
                self._reject("LOADOP_NO_SUCH_TARGET", target)
            if (not isinstance(pass_index, int)
                    or isinstance(pass_index, bool)
                    or pass_index < 0
                    or not isinstance(kind, str)
                    or kind not in self._KINDS):
                self._reject("LOADOP_INVALID_USE", {
                    "target": target,
                    "pass_index": pass_index,
                    "kind": kind,
                })

            uses = self._uses[target]
            if any(use.pass_index == pass_index for use in uses):
                self._reject("LOADOP_PASS_CONFLICT", {
                    "target": target,
                    "pass_index": pass_index,
                })
            if len(uses) >= self._config["max_uses_per_target"]:
                self._reject("LOADOP_USE_LIMIT", {
                    "target": target,
                    "max_uses_per_target":
                        self._config["max_uses_per_target"],
                })

            uses.append(Use(
                target=target,
                pass_index=pass_index,
                kind=kind,
                resolve=bool(resolve),
                sampled=bool(sampled),
            ))
            self._counters["uses"] += 1

    def plan(self) -> tuple:
        with self._lock:
            result = self._build_plan()
            self._counters["plans"] += 1
            return result

    def load_op_of(self, target: str, pass_index: int) -> str:
        with self._lock:
            return self._op_of(target, pass_index, "load_op")

    def store_op_of(self, target: str, pass_index: int) -> str:
        with self._lock:
            return self._op_of(target, pass_index, "store_op")

    def bandwidth_saved(self) -> dict:
        with self._lock:
            plan = self._build_plan()
            baseline = 0
            planned = 0
            per_target = {}
            costs = {name: 0 for name in self._targets}

            for name in sorted(self._targets):
                state = self._targets[name]
                target_baseline = (
                    len(self._uses[name]) * 2 * state.bytes_per_frame)
                baseline += target_baseline

            for item in plan:
                state = self._targets[item.target]
                size = state.bytes_per_frame
                if item.load_op == "load":
                    costs[item.target] += size
                if item.store_op in ("store", "resolve"):
                    costs[item.target] += size

            for name in sorted(self._targets):
                state = self._targets[name]
                target_baseline = (
                    len(self._uses[name]) * 2 * state.bytes_per_frame)
                planned += costs[name]
                per_target[name] = target_baseline - costs[name]

            return {
                "baseline_bytes": baseline,
                "planned_bytes": planned,
                "saved_bytes": baseline - planned,
                "per_target": per_target,
            }

    def target_state(self, name: str) -> TargetState:
        with self._lock:
            if not isinstance(name, str) or name not in self._targets:
                self._reject("LOADOP_NO_SUCH_TARGET", name)
            return self._targets[name]

    def uses_of(self, target: str) -> tuple:
        with self._lock:
            if not isinstance(target, str) or target not in self._targets:
                self._reject("LOADOP_NO_SUCH_TARGET", target)
            return tuple(sorted(self._uses[target],
                                key=lambda use: use.pass_index))

    def snapshot(self) -> dict:
        with self._lock:
            targets = {}
            uses = {}
            for name in sorted(self._targets):
                state = self._targets[name]
                targets[name] = {
                    "name": state.name,
                    "bytes_per_frame": state.bytes_per_frame,
                    "samples": state.samples,
                    "persistent": state.persistent,
                    "external_read": state.external_read,
                }
                uses[name] = [
                    {
                        "target": use.target,
                        "pass_index": use.pass_index,
                        "kind": use.kind,
                        "resolve": use.resolve,
                        "sampled": use.sampled,
                    }
                    for use in sorted(self._uses[name],
                                      key=lambda item: item.pass_index)
                ]
            return copy.deepcopy({
                "version": self._SNAPSHOT_VERSION,
                "targets": targets,
                "uses": uses,
                "counters": dict(self._counters),
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            targets, uses, counters = self._parse_snapshot(state)
            self._targets = targets
            self._uses = uses
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def _reject(self, code: str, detail: object = None) -> None:
        self._counters["rejected"] += 1
        raise LoadOpError(code, detail)

    def _check_target_fields(self, name: object, bytes_per_frame: object,
                             samples: object) -> None:
        valid = (
            isinstance(name, str)
            and bool(name)
            and isinstance(bytes_per_frame, int)
            and not isinstance(bytes_per_frame, bool)
            and bytes_per_frame > 0
            and isinstance(samples, int)
            and not isinstance(samples, bool)
            and samples in self._SAMPLES
        )
        if valid:
            return
        self._reject("LOADOP_INVALID_TARGET", {
            "name": name,
            "bytes_per_frame": bytes_per_frame,
            "samples": samples,
        })

    def _build_plan(self) -> tuple:
        result = []
        for name in sorted(self._targets):
            uses = sorted(self._uses[name], key=lambda use: use.pass_index)
            result.extend(self._plan_target(self._targets[name], uses))
        return tuple(result)

    def _plan_target(self, target: TargetState, uses: list) -> list:
        if target.samples == 1 and any(use.resolve for use in uses):
            self._reject("LOADOP_RESOLVE_NOT_MSAA", {
                "target": target.name,
                "samples": target.samples,
            })

        planned = []
        last_index = len(uses) - 1
        for index, use in enumerate(uses):
            needs_previous = (
                use.kind in ("read", "read_write") or use.resolve)

            if index == 0:
                load_op = "load" if needs_previous else "clear"
            elif needs_previous:
                previous = planned[-1]
                if previous.store_op == "discard":
                    if use.resolve:
                        self._reject("LOADOP_RESOLVE_AFTER_DISCARD", {
                            "target": target.name,
                            "pass_index": use.pass_index,
                            "previous_pass": previous.pass_index,
                        })
                    self._reject("LOADOP_CONTENT_DISCARDED", {
                        "target": target.name,
                        "pass_index": use.pass_index,
                        "previous_pass": previous.pass_index,
                    })
                load_op = "load"
            else:
                load_op = "discard"

            if use.resolve:
                store_op = "resolve"
            elif index < last_index:
                following = uses[index + 1]
                following_needs_previous = (
                    following.kind in ("read", "read_write")
                    or following.resolve)
                store_op = (
                    "store" if following_needs_previous else "discard")
            else:
                store_op = (
                    "store"
                    if target.persistent or target.external_read
                    else "discard")

            planned.append(UsePlan(
                target=target.name,
                pass_index=use.pass_index,
                kind=use.kind,
                load_op=load_op,
                store_op=store_op,
                resolve=use.resolve,
                sampled=use.sampled,
            ))
        return planned

    def _op_of(self, target: str, pass_index: int, field: str) -> str:
        if not isinstance(target, str) or target not in self._targets:
            self._reject("LOADOP_NO_SUCH_TARGET", target)
        for item in self._build_plan():
            if item.target == target and item.pass_index == pass_index:
                return getattr(item, field)
        self._reject("LOADOP_NO_SUCH_USE", {
            "target": target,
            "pass_index": pass_index,
        })

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise LoadOpError("LOADOP_SNAPSHOT_INVALID", state)
        if set(state) != {"version", "targets", "uses", "counters"}:
            raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                "keys": list(state),
            })
        if (state["version"] != self._SNAPSHOT_VERSION
                or isinstance(state["version"], bool)
                or not isinstance(state["version"], int)):
            raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                "version": state["version"],
            })

        raw_targets = state["targets"]
        raw_uses = state["uses"]
        raw_counters = state["counters"]
        if (not isinstance(raw_targets, dict)
                or not isinstance(raw_uses, dict)
                or not isinstance(raw_counters, dict)):
            raise LoadOpError("LOADOP_SNAPSHOT_INVALID", state)
        if len(raw_targets) > self._config["max_targets"]:
            raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                "targets": len(raw_targets),
                "max_targets": self._config["max_targets"],
            })
        if set(raw_counters) != set(self._COUNTER_KEYS):
            raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                "counters": raw_counters,
            })

        counters = {}
        for key in self._COUNTER_KEYS:
            value = raw_counters[key]
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < 0):
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                    "counter": key,
                    "value": value,
                })
            counters[key] = value

        targets = {}
        for name, raw in raw_targets.items():
            if not isinstance(name, str) or not name or not isinstance(raw, dict):
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", name)
            allowed = {
                "name", "bytes_per_frame", "samples",
                "persistent", "external_read",
            }
            if set(raw) - allowed or not {
                    "bytes_per_frame", "samples",
                    "persistent", "external_read"}.issubset(raw):
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)
            if "name" in raw and raw["name"] != name:
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)

            bytes_per_frame = raw["bytes_per_frame"]
            samples = raw["samples"]
            persistent = raw["persistent"]
            external_read = raw["external_read"]
            if (not isinstance(bytes_per_frame, int)
                    or isinstance(bytes_per_frame, bool)
                    or bytes_per_frame <= 0
                    or not isinstance(samples, int)
                    or isinstance(samples, bool)
                    or samples not in self._SAMPLES
                    or not isinstance(persistent, bool)
                    or not isinstance(external_read, bool)):
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)
            targets[name] = TargetState(
                name=name,
                bytes_per_frame=bytes_per_frame,
                samples=samples,
                persistent=persistent,
                external_read=external_read,
            )

        for name, raw in raw_uses.items():
            if name not in targets:
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                    "unknown_target": name,
                })
            if not isinstance(raw, (list, tuple)):
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)
            if len(raw) > self._config["max_uses_per_target"]:
                raise LoadOpError("LOADOP_SNAPSHOT_INVALID", {
                    "target": name,
                    "uses": len(raw),
                })

        uses = {}
        for name in targets:
            parsed = []
            seen_passes = set()
            for raw in raw_uses.get(name, ()):
                if not isinstance(raw, dict):
                    raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)
                allowed = {
                    "target", "pass_index", "kind", "resolve", "sampled",
                }
                if set(raw) - allowed or not {
                        "pass_index", "kind"}.issubset(raw):
                    raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)
                if "target" in raw and raw["target"] != name:
                    raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)

                pass_index = raw["pass_index"]
                kind = raw["kind"]
                resolve = raw.get("resolve", False)
                sampled = raw.get("sampled", False)
                if (not isinstance(pass_index, int)
                        or isinstance(pass_index, bool)
                        or pass_index < 0
                        or not isinstance(kind, str)
                        or kind not in self._KINDS
                        or not isinstance(resolve, bool)
                        or not isinstance(sampled, bool)
                        or pass_index in seen_passes):
                    raise LoadOpError("LOADOP_SNAPSHOT_INVALID", raw)
                seen_passes.add(pass_index)
                parsed.append(Use(
                    target=name,
                    pass_index=pass_index,
                    kind=kind,
                    resolve=resolve,
                    sampled=sampled,
                ))
            parsed.sort(key=lambda use: use.pass_index)
            uses[name] = parsed

        return targets, uses, counters
