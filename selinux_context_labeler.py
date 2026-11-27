"""SELinux file context labeling.

Rules are regular expressions installed in two blocks (distribution defaults
and local overrides).  Resolution prefers the local block, then the most
specific rule inside a block, then the last declaration.  Equivalence classes
share one label across several paths.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

FILE_TYPES = ("--", "-d", "-l", "-c", "-s", "-p", "-b")
SOURCES = ("distro", "local")
STAT_KEYS = ("loaded", "rejected", "resolved", "planned", "applied",
             "unchanged", "restores")
_META = set("\\^$.[]()*+?{}|")
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_LEVEL = re.compile(r"^[A-Za-z0-9_.,:-]+$")


class LabelError(ValueError):
    """Refusal raised while loading rules, planning or applying labels."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FileContextRule:
    """One installed file context rule."""

    pattern: str
    context: str
    file_type: str
    source: str
    seq: int
    specificity: int


@dataclass(frozen=True)
class PathState:
    """What the guard knows about one path."""

    path: str
    file_type: str
    exists: bool
    current: str | None


@dataclass(frozen=True)
class LabelPlanEntry:
    """One line of a relabel plan."""

    path: str
    context: str
    action: str
    detail: str
    version: int


class SelinuxContextLabeler:
    """Resolve SELinux contexts and plan relabels for filesystem paths."""

    def __init__(self, *, max_rules: int = 512,
                 max_plan_entries: int = 4096,
                 default_mls: str = "s0") -> None:
        self.max_rules = max_rules
        self.max_plan_entries = max_plan_entries
        self.default_mls = default_mls
        self._lock = threading.RLock()
        self._version = 0
        self._seq = 0
        self._rules = {"distro": [], "local": []}
        self._equivalences = {}
        self._paths = {}
        self._watermark = set()
        self._stats = {key: 0 for key in STAT_KEYS}

    def load_rules(self, rules, *, source: str = "distro") -> int:
        """Validate and install ``rules`` into ``source``; return accepted count."""
        raise NotImplementedError

    def remove_rule(self, pattern: str, *, source: str = "distro") -> bool:
        """Remove one rule by exact pattern and report whether it existed."""
        raise NotImplementedError

    def rules(self, *, source: str | None = None) -> tuple:
        """Return installed rules in declaration order."""
        raise NotImplementedError

    def add_equivalence(self, primary: str, *members: str) -> None:
        """Map ``members`` onto the context of ``primary``."""
        raise NotImplementedError

    def equivalence_of(self, path: str) -> str:
        """Return the class representative for ``path``."""
        raise NotImplementedError

    def observe_path(self, path: str, *, file_type: str = "-d",
                     exists: bool = True,
                     current: str | None = None) -> PathState:
        """Record the file type, existence and current label of ``path``."""
        raise NotImplementedError

    def resolve_context(self, path: str, *, file_type: str | None = None):
        """Return the context for ``path`` or None when no rule matches."""
        raise NotImplementedError

    def plan_relabel(self, paths) -> tuple:
        """Build a relabel plan for ``paths`` without touching any label."""
        raise NotImplementedError

    def apply(self, entries) -> int:
        """Apply a plan and return how many paths were written."""
        raise NotImplementedError

    def verify(self, paths) -> tuple:
        """Compare the expected context with the label currently recorded."""
        raise NotImplementedError

    def watermark(self) -> int:
        """Return how many distinct paths have been written by ``apply``."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of rules, classes, paths and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the operation counters."""
        raise NotImplementedError
