"""Udev rule synthesizer: ordered rules, specificity tie-break, hotplug apply."""

from __future__ import annotations

import copy
import json
import re
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass

_MODE_PATTERN = re.compile(r"^0[0-7]{3}$")
_PLAIN_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_{}.:-]+$")

DEFAULT_MODE = "0600"
DEFAULT_OWNER = "root"
DEFAULT_GROUP = "root"

_RULE_FIELDS = ("rule_id", "match", "mode", "owner", "group", "priority")
_NODE_FIELDS = ("device", "mode", "owner", "group", "rule_id")
_STAT_KEYS = ("added", "removed", "synthesized", "hotplugged", "skipped",
              "refused")
_RESERVED_KEYS = {"MODE", "OWNER", "GROUP", "PRIORITY", "RULE_ID"}


class UdevError(ValueError):
    """Raised when a rule or a synthesis request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceRule:
    rule_id: str
    match: tuple[tuple[str, str], ...]
    mode: str
    owner: str
    group: str
    priority: int


@dataclass(frozen=True)
class NodeSpec:
    device: str
    mode: str
    owner: str
    group: str
    rule_id: str


def _invalid(detail: object = None) -> UdevError:
    return UdevError("UDEV_INVALID_RULE", detail)


def _validate_mode(mode: object) -> None:
    if not isinstance(mode, str) or _MODE_PATTERN.fullmatch(mode) is None:
        raise _invalid("mode")


def _validate_owner(owner: object) -> None:
    if not isinstance(owner, str) or not owner.strip():
        raise _invalid("owner")


def _validate_group(group: object) -> None:
    if (not isinstance(group, str) or not group
            or any(char.isspace() for char in group)):
        raise _invalid("group")


def _validate_priority(priority: object) -> None:
    if (not isinstance(priority, int) or isinstance(priority, bool)
            or priority < 0):
        raise _invalid("priority")


def _validate_rule_id(rule_id: object) -> None:
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise _invalid("rule_id")


def _normalize_match(match: object) -> tuple[tuple[str, str], ...]:
    if isinstance(match, Mapping):
        items = list(match.items())
    else:
        if isinstance(match, (str, bytes)):
            raise _invalid("match")
        try:
            items = list(match)
        except TypeError as exc:
            raise _invalid("match") from exc

    if not items:
        raise _invalid("match")

    normalized: dict[str, str] = {}
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise _invalid("match")
        key, value = item
        if not isinstance(key, str) or not key or not isinstance(value, str):
            raise _invalid("match")
        normalized[key] = value

    if not normalized:
        raise _invalid("match")
    return tuple(sorted(normalized.items(), key=lambda pair: pair[0]))


def _normalize_match_state(match: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(match, (tuple, list)) or not match:
        raise _invalid("match")

    pairs: list[tuple[str, str]] = []
    for item in match:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise _invalid("match")
        key, value = item
        if not isinstance(key, str) or not key or not isinstance(value, str):
            raise _invalid("match")
        pairs.append((key, value))

    keys = [key for key, _ in pairs]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise _invalid("match")
    return tuple(pairs)


def _rule_sort_key(rule: DeviceRule) -> tuple[int, int, str]:
    return (rule.priority, len(rule.match), rule.rule_id)


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_key(key: str) -> str:
    if (_PLAIN_KEY_PATTERN.fullmatch(key)
            and key.upper() not in _RESERVED_KEYS):
        return key
    return f"MATCH[{_quote(key)}]"


def _split_assignments(text: str) -> list[str]:
    tokens: list[str] = []
    start = 0
    quote = False
    escaped = False
    depth = 0
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote and char == "\\":
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if quote:
            continue
        if char == "[":
            depth += 1
        elif char == "]" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            tokens.append(text[start:index].strip())
            start = index + 1
    tokens.append(text[start:].strip())
    return [token for token in tokens if token]


def _parse_value(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    if raw[0] == '"':
        try:
            value = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise _invalid("value") from exc
        if not isinstance(value, str):
            raise _invalid("value")
        return value
    return raw


def _find_assignment(token: str) -> tuple[int, int]:
    quote = False
    escaped = False
    depth = 0
    for index, char in enumerate(token):
        if escaped:
            escaped = False
            continue
        if quote and char == "\\":
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if quote:
            continue
        if char == "[":
            depth += 1
            continue
        if char == "]" and depth:
            depth -= 1
            continue
        if depth == 0 and char == "=":
            if index + 1 < len(token) and token[index + 1] == "=":
                return index, 2
            return index, 1
    return -1, 0


class UdevRuleSynthesizer:
    """Keep device rules and derive ordered node permissions from them."""

    def __init__(self, *, max_rules: int = 64) -> None:
        self.max_rules = int(max_rules)
        self._lock = threading.RLock()
        self._rules: dict[str, DeviceRule] = {}
        self._next_id = 1
        self._synth: dict[str, NodeSpec] = {}
        self._stats = {
            "added": 0,
            "removed": 0,
            "synthesized": 0,
            "hotplugged": 0,
            "skipped": 0,
            "refused": 0,
        }

    def add_rule(self, match, *, mode: str = "0660", owner: str = "root",
                 group: str = "root", priority: int = 50,
                 rule_id: str | None = None) -> DeviceRule:
        with self._lock:
            try:
                normalized = _normalize_match(match)
                _validate_mode(mode)
                _validate_owner(owner)
                _validate_group(group)
                _validate_priority(priority)
                if rule_id is not None:
                    _validate_rule_id(rule_id)

                if rule_id is not None and rule_id in self._rules:
                    raise UdevError("UDEV_RULE_EXISTS", rule_id)
                if len(self._rules) >= self.max_rules:
                    raise UdevError("UDEV_RULE_LIMIT", self.max_rules)

                if rule_id is None:
                    while True:
                        candidate = f"rule-{self._next_id:04d}"
                        self._next_id += 1
                        if candidate not in self._rules:
                            rule_id = candidate
                            break

                rule = DeviceRule(
                    rule_id=rule_id,
                    match=normalized,
                    mode=mode,
                    owner=owner,
                    group=group,
                    priority=priority,
                )
            except UdevError:
                self._stats["refused"] += 1
                raise

            self._rules[rule_id] = rule
            self._stats["added"] += 1
            self._synth.clear()
            return rule

    def rule(self, rule_id: str) -> DeviceRule | None:
        with self._lock:
            try:
                return self._rules.get(rule_id)
            except TypeError:
                return None

    def rules(self) -> tuple[DeviceRule, ...]:
        with self._lock:
            return tuple(sorted(self._rules.values(), key=_rule_sort_key))

    def remove_rule(self, rule_id: str) -> bool:
        with self._lock:
            try:
                exists = rule_id in self._rules
            except TypeError:
                return False
            if not exists:
                return False
            del self._rules[rule_id]
            self._stats["removed"] += 1
            self._synth.clear()
            return True

    def _effective_unlocked(self, device: str, attrs) -> NodeSpec:
        winner = None
        for rule in sorted(self._rules.values(), key=_rule_sort_key):
            if all(attrs.get(key) == value for key, value in rule.match):
                winner = rule

        if winner is None:
            return NodeSpec(
                device=device,
                mode=DEFAULT_MODE,
                owner=DEFAULT_OWNER,
                group=DEFAULT_GROUP,
                rule_id="",
            )
        return NodeSpec(
            device=device,
            mode=winner.mode,
            owner=winner.owner,
            group=winner.group,
            rule_id=winner.rule_id,
        )

    def effective(self, device: str, attrs) -> NodeSpec:
        with self._lock:
            return self._effective_unlocked(device, attrs)

    def synthesize(self, devices) -> tuple[NodeSpec, ...]:
        with self._lock:
            names = sorted(devices)
            result = tuple(
                self._effective_unlocked(name, devices[name]) for name in names
            )
            previous = set(self._synth)
            self._synth = {spec.device: spec for spec in result}
            self._stats["synthesized"] += len(set(names) - previous)
            return result

    @staticmethod
    def _actual_permissions(value) -> tuple[str, str, str, str | None] | None:
        if value is None:
            return None
        if isinstance(value, NodeSpec):
            return (value.mode, value.owner, value.group, value.rule_id)
        if isinstance(value, Mapping):
            try:
                mode = value["mode"]
                owner = value["owner"]
                group = value["group"]
            except KeyError:
                return None
            rule_id = value.get("rule_id")
            if not all(isinstance(item, str) for item in (mode, owner, group)):
                return None
            if rule_id is not None and not isinstance(rule_id, str):
                return None
            return (mode, owner, group, rule_id)
        if isinstance(value, (tuple, list)) and len(value) >= 3:
            mode, owner, group = value[:3]
            if not all(isinstance(item, str) for item in (mode, owner, group)):
                return None
            return (mode, owner, group, None)
        return None

    def reconcile(self, devices, actual) -> tuple[str, ...]:
        with self._lock:
            mismatched: list[str] = []
            for name in sorted(devices):
                expected = self._effective_unlocked(name, devices[name])
                found = self._actual_permissions(actual.get(name))
                if found is None:
                    mismatched.append(name)
                    continue
                mode, owner, group, rule_id = found
                if (expected.mode, expected.owner, expected.group) != (
                        mode, owner, group):
                    mismatched.append(name)
                elif rule_id is not None and expected.rule_id != rule_id:
                    mismatched.append(name)
            return tuple(mismatched)

    def apply_hotplug(self, devices, *, existing=()) -> tuple[NodeSpec, ...]:
        with self._lock:
            existing_names = set(existing)
            applied: list[NodeSpec] = []
            for name in sorted(devices):
                if name in existing_names or name in self._synth:
                    self._stats["skipped"] += 1
                    continue
                spec = self._effective_unlocked(name, devices[name])
                self._synth[name] = spec
                applied.append(spec)
                self._stats["hotplugged"] += 1
            return tuple(applied)

    def render_rule(self, rule_id: str) -> str:
        with self._lock:
            try:
                rule = self._rules.get(rule_id)
            except TypeError:
                rule = None
            if rule is None:
                raise UdevError("UDEV_RULE_UNKNOWN", rule_id)

            parts = [
                f"{_render_key(key)}=={_quote(value)}"
                for key, value in rule.match
            ]
            parts.extend((
                f"MODE={_quote(rule.mode)}",
                f"OWNER={_quote(rule.owner)}",
                f"GROUP={_quote(rule.group)}",
                f"PRIORITY={_quote(str(rule.priority))}",
            ))
            return ", ".join(parts)

    def parse_rule(self, text: str, *,
                   rule_id: str = "rule-parsed") -> DeviceRule:
        if not isinstance(text, str) or not text.strip():
            raise _invalid("text")
        _validate_rule_id(rule_id)

        stripped = text.strip()
        if stripped.startswith("{"):
            try:
                payload = json.loads(stripped)
            except (TypeError, ValueError) as exc:
                raise _invalid("text") from exc
            if not isinstance(payload, Mapping):
                raise _invalid("text")
            match = payload.get("match")
            if isinstance(match, Mapping):
                match = list(match.items())
            normalized = _normalize_match(match)
            mode = payload.get("mode", "0660")
            owner = payload.get("owner", "root")
            group = payload.get("group", "root")
            priority = payload.get("priority", 50)
            return self._build_parsed_rule(
                rule_id, normalized, mode, owner, group, priority
            )

        conditions: list[tuple[str, str]] = []
        mode = "0660"
        owner = "root"
        group = "root"
        priority = 50
        for token in _split_assignments(stripped):
            separator, width = _find_assignment(token)
            if separator <= 0:
                raise _invalid("text")
            key = token[:separator].strip()
            value = _parse_value(token[separator + width:])
            if not key:
                raise _invalid("text")

            if key.startswith("MATCH[") and key.endswith("]"):
                try:
                    match_key = json.loads(key[6:-1])
                except (TypeError, ValueError) as exc:
                    raise _invalid("text") from exc
                if not isinstance(match_key, str) or not match_key:
                    raise _invalid("text")
                conditions.append((match_key, value))
                continue

            upper_key = key.upper()
            if upper_key == "MODE":
                mode = value
            elif upper_key == "OWNER":
                owner = value
            elif upper_key == "GROUP":
                group = value
            elif upper_key == "PRIORITY":
                try:
                    priority = int(value)
                except (TypeError, ValueError) as exc:
                    raise _invalid("priority") from exc
            elif upper_key == "RULE_ID":
                continue
            else:
                conditions.append((key, value))

        return self._build_parsed_rule(
            rule_id, _normalize_match(conditions), mode, owner, group, priority
        )

    @staticmethod
    def _build_parsed_rule(rule_id: str,
                           match: tuple[tuple[str, str], ...],
                           mode: object, owner: object, group: object,
                           priority: object) -> DeviceRule:
        _validate_mode(mode)
        _validate_owner(owner)
        _validate_group(group)
        _validate_priority(priority)
        return DeviceRule(
            rule_id=rule_id,
            match=match,
            mode=mode,
            owner=owner,
            group=group,
            priority=priority,
        )

    @staticmethod
    def _rule_from_state(rule_id: object, raw: object) -> DeviceRule:
        if isinstance(raw, DeviceRule):
            if raw.rule_id != rule_id:
                raise _invalid("rule_id")
            _validate_rule_id(raw.rule_id)
            _validate_mode(raw.mode)
            _validate_owner(raw.owner)
            _validate_group(raw.group)
            _validate_priority(raw.priority)
            return DeviceRule(
                rule_id=raw.rule_id,
                match=_normalize_match_state(raw.match),
                mode=raw.mode,
                owner=raw.owner,
                group=raw.group,
                priority=raw.priority,
            )
        if not isinstance(raw, Mapping):
            raise _invalid("rule")
        if any(field not in raw for field in _RULE_FIELDS):
            raise _invalid("rule")
        if raw["rule_id"] != rule_id:
            raise _invalid("rule_id")
        _validate_rule_id(raw["rule_id"])
        _validate_mode(raw["mode"])
        _validate_owner(raw["owner"])
        _validate_group(raw["group"])
        _validate_priority(raw["priority"])
        return DeviceRule(
            rule_id=raw["rule_id"],
            match=_normalize_match_state(raw["match"]),
            mode=raw["mode"],
            owner=raw["owner"],
            group=raw["group"],
            priority=raw["priority"],
        )

    @staticmethod
    def _node_from_state(device: object, raw: object) -> NodeSpec:
        if isinstance(raw, NodeSpec):
            node = raw
        elif isinstance(raw, Mapping):
            if any(field not in raw for field in _NODE_FIELDS):
                raise _invalid("synth")
            node = NodeSpec(
                device=raw["device"],
                mode=raw["mode"],
                owner=raw["owner"],
                group=raw["group"],
                rule_id=raw["rule_id"],
            )
        else:
            raise _invalid("synth")

        if not isinstance(device, str) or node.device != device:
            raise _invalid("synth")
        _validate_mode(node.mode)
        _validate_owner(node.owner)
        _validate_group(node.group)
        if not isinstance(node.rule_id, str):
            raise _invalid("synth")
        return node

    def snapshot(self) -> dict:
        with self._lock:
            rules = {
                rule.rule_id: asdict(rule)
                for rule in sorted(self._rules.values(), key=_rule_sort_key)
            }
            synth = {
                device: asdict(self._synth[device])
                for device in sorted(self._synth)
            }
            return copy.deepcopy({
                "version": 1,
                "rules": rules,
                "next_id": self._next_id,
                "synth": synth,
                "stats": dict(self._stats),
            })

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, Mapping):
                raise _invalid("state")
            required = {"version", "rules", "next_id", "synth", "stats"}
            if not required.issubset(state):
                raise _invalid("state")
            version = state["version"]
            if (not isinstance(version, int) or isinstance(version, bool)
                    or version != 1):
                raise _invalid("version")

            raw_rules = state["rules"]
            if not isinstance(raw_rules, Mapping):
                raise _invalid("rules")
            if len(raw_rules) > self.max_rules:
                raise _invalid("rules")

            rules: dict[str, DeviceRule] = {}
            for rule_id, raw in raw_rules.items():
                rules[rule_id] = self._rule_from_state(rule_id, raw)

            next_id = state["next_id"]
            if (not isinstance(next_id, int) or isinstance(next_id, bool)
                    or next_id < 1):
                raise _invalid("next_id")

            raw_synth = state["synth"]
            if not isinstance(raw_synth, Mapping):
                raise _invalid("synth")
            synth: dict[str, NodeSpec] = {}
            for device, raw in raw_synth.items():
                node = self._node_from_state(device, raw)
                if node.rule_id and node.rule_id not in rules:
                    raise _invalid("synth")
                synth[device] = node

            raw_stats = state["stats"]
            if not isinstance(raw_stats, Mapping) or set(raw_stats) != set(
                    _STAT_KEYS):
                raise _invalid("stats")
            stats: dict[str, int] = {}
            for key in _STAT_KEYS:
                value = raw_stats[key]
                if (not isinstance(value, int) or isinstance(value, bool)
                        or value < 0):
                    raise _invalid("stats")
                stats[key] = value
        except UdevError as exc:
            raise UdevError("UDEV_SNAPSHOT_INVALID", exc.detail) from exc
        except (TypeError, ValueError) as exc:
            raise UdevError("UDEV_SNAPSHOT_INVALID", None) from exc

        with self._lock:
            self._rules = rules
            self._next_id = next_id
            self._synth = synth
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
