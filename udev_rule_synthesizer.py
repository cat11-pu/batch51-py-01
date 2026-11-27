"""Udev rule synthesizer: ordered rules, specificity tie-break, hotplug apply."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

_MODE_PATTERN = re.compile(r"^0[0-7]{3}$")

DEFAULT_MODE = "0600"
DEFAULT_OWNER = "root"
DEFAULT_GROUP = "root"


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
        raise NotImplementedError

    def rule(self, rule_id: str) -> DeviceRule | None:
        raise NotImplementedError

    def rules(self) -> tuple[DeviceRule, ...]:
        raise NotImplementedError

    def remove_rule(self, rule_id: str) -> bool:
        raise NotImplementedError

    def effective(self, device: str, attrs) -> NodeSpec:
        raise NotImplementedError

    def synthesize(self, devices) -> tuple[NodeSpec, ...]:
        raise NotImplementedError

    def reconcile(self, devices, actual) -> tuple[str, ...]:
        raise NotImplementedError

    def apply_hotplug(self, devices, *, existing=()) -> tuple[NodeSpec, ...]:
        raise NotImplementedError

    def render_rule(self, rule_id: str) -> str:
        raise NotImplementedError

    def parse_rule(self, text: str, *, rule_id: str = "rule-parsed") -> DeviceRule:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
