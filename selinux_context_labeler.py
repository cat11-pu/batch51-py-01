"""SELinux file context labeling.

Rules are regular expressions installed in two blocks (distribution defaults
and local overrides).  Resolution prefers the local block, then the most
specific rule inside a block, then the last declaration.  Equivalence classes
share one label across several paths.
"""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass
from collections.abc import Mapping

FILE_TYPES = ("--", "-d", "-l", "-c", "-s", "-p", "-b")
SOURCES = ("distro", "local")
STAT_KEYS = ("loaded", "rejected", "resolved", "planned", "applied",
             "unchanged", "restores")
_META = set("\\^$.[]()*+?{}|")
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_LEVEL = re.compile(r"^[A-Za-z0-9_.,:-]+$")


def _split_context(context):
    """Return ``(user, role, type, level|None)`` for a valid context."""
    if not isinstance(context, str):
        return None
    parts = context.split(":", 3)
    if len(parts) not in (3, 4):
        return None
    user, role, role_type = parts[:3]
    if not all(_NAME.fullmatch(value) for value in (user, role, role_type)):
        return None
    if len(parts) == 4:
        if not _LEVEL.fullmatch(parts[3]):
            return None
        return user, role, role_type, parts[3]
    return user, role, role_type, None


def _literal_prefix_length(pattern: str) -> int:
    """Count literal characters before the first regular-expression token."""
    length = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 >= len(pattern):
                break
            escaped = pattern[index + 1]
            if escaped.isalnum():
                break
            length += 1
            index += 2
            continue
        if char in _META:
            break
        length += 1
        index += 1
    return length


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
        if (not isinstance(max_rules, int) or isinstance(max_rules, bool)
                or max_rules < 0):
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"max_rules": max_rules})
        if (not isinstance(max_plan_entries, int)
                or isinstance(max_plan_entries, bool)
                or max_plan_entries < 0):
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"max_plan_entries": max_plan_entries})
        if (not isinstance(default_mls, str)
                or not _LEVEL.fullmatch(default_mls)):
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"default_mls": default_mls})
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
        with self._lock:
            self._check_source(source)
            try:
                candidates = list(rules)
            except TypeError as exc:
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"rules": repr(rules)}) from exc

            parsed = []
            rejected = 0
            for item in candidates:
                rule = self._parse_rule(item)
                if rule is None:
                    rejected += 1
                else:
                    parsed.append(rule)

            current_count = len(self._rules["distro"]) + \
                len(self._rules["local"])
            if current_count + len(parsed) > self.max_rules:
                raise LabelError("LABEL_CAPACITY_EXCEEDED",
                                 {"limit": self.max_rules})

            next_seq = self._seq
            installed = []
            for pattern, context, file_type in parsed:
                installed.append(FileContextRule(
                    pattern=pattern,
                    context=context,
                    file_type=file_type,
                    source=source,
                    seq=next_seq,
                    specificity=_literal_prefix_length(pattern),
                ))
                next_seq += 1

            self._rules[source].extend(installed)
            self._seq = next_seq
            self._stats["loaded"] += len(installed)
            self._stats["rejected"] += rejected
            self._version += 1
            return len(installed)

    def remove_rule(self, pattern: str, *, source: str = "distro") -> bool:
        """Remove one rule by exact pattern and report whether it existed."""
        with self._lock:
            self._check_source(source)
            if not isinstance(pattern, str):
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"pattern": pattern})
            block = self._rules[source]
            kept = [rule for rule in block if rule.pattern != pattern]
            if len(kept) == len(block):
                return False
            self._rules[source] = kept
            self._version += 1
            return True

    def rules(self, *, source: str | None = None) -> tuple:
        """Return installed rules in declaration order."""
        with self._lock:
            if source is not None:
                self._check_source(source)
                return tuple(self._rules[source])
            merged = self._rules["distro"] + self._rules["local"]
            return tuple(sorted(merged, key=lambda rule: rule.seq))

    def add_equivalence(self, primary: str, *members: str) -> None:
        """Map ``members`` onto the context of ``primary``."""
        with self._lock:
            if not isinstance(primary, str) or not primary:
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"primary": primary})
            for member in members:
                if not isinstance(member, str) or not member:
                    raise LabelError("LABEL_INVALID_REQUEST",
                                     {"member": member})

            representative = self._equivalence(primary)
            changed = False
            for member in members:
                member_rep = self._equivalence(member)
                if member_rep == representative:
                    continue
                for alias, target in list(self._equivalences.items()):
                    if self._equivalence(target) == member_rep:
                        self._equivalences[alias] = representative
                self._equivalences[member_rep] = representative
                changed = True
            if changed:
                self._version += 1

    def equivalence_of(self, path: str) -> str:
        """Return the class representative for ``path``."""
        with self._lock:
            if not isinstance(path, str) or not path:
                raise LabelError("LABEL_INVALID_REQUEST", {"path": path})
            return self._equivalence(path)

    def observe_path(self, path: str, *, file_type: str = "-d",
                     exists: bool = True,
                     current: str | None = None) -> PathState:
        """Record the file type, existence and current label of ``path``."""
        with self._lock:
            if not isinstance(path, str) or not path:
                raise LabelError("LABEL_INVALID_REQUEST", {"path": path})
            self._check_file_type(file_type)
            if not isinstance(exists, bool):
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"exists": exists})
            if current is not None and not isinstance(current, str):
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"current": current})
            state = PathState(path=path, file_type=file_type,
                              exists=exists, current=current)
            self._paths[path] = state
            return state

    def resolve_context(self, path: str, *, file_type: str | None = None):
        """Return the context for ``path`` or None when no rule matches."""
        with self._lock:
            if not isinstance(path, str) or not path:
                raise LabelError("LABEL_INVALID_REQUEST", {"path": path})
            effective_type = self._effective_file_type(path, file_type)
            context, _ = self._resolve_with_equivalence(
                path, effective_type)
            return context

    def plan_relabel(self, paths) -> tuple:
        """Build a relabel plan for ``paths`` without touching any label."""
        with self._lock:
            requested = self._unique_paths(paths)
            if len(requested) > self.max_plan_entries:
                raise LabelError("LABEL_PLAN_TOO_LARGE",
                                 {"limit": self.max_plan_entries})

            primary_cache = {}
            plan = []
            for path in requested:
                representative = self._equivalence(path)
                if representative not in primary_cache:
                    primary_type = self._effective_file_type(
                        representative, None)
                    primary_context, _ = self._resolve_direct(
                        representative, primary_type)
                    primary_cache[representative] = (
                        primary_context, primary_type)
                primary_context, primary_type = primary_cache[representative]

                path_state = self._paths.get(path)
                path_type = path_state.file_type if path_state else "-d"
                direct_context = None
                if path == representative:
                    target = primary_context
                else:
                    direct_context, _ = self._resolve_direct(
                        path, path_type)
                    if (direct_context is not None
                            and direct_context != primary_context):
                        target = direct_context
                    else:
                        target = primary_context

                if target is not None:
                    self._stats["resolved"] += 1

                exists = path_state.exists if path_state else True
                current = path_state.current if path_state else None
                if not exists:
                    action = "pending"
                    detail = "missing"
                    context = target if target is not None else ""
                elif target is None:
                    action = "unlabeled"
                    detail = "no matching rule"
                    context = ""
                elif current == target:
                    action = "unchanged"
                    detail = ""
                    context = target
                    self._stats["unchanged"] += 1
                elif (path != representative
                      and target == primary_context):
                    action = "alias"
                    detail = representative
                    context = target
                else:
                    action = "relabel"
                    detail = ""
                    context = target

                if action == "relabel":
                    self._stats["planned"] += 1
                plan.append(LabelPlanEntry(
                    path=path,
                    context=context,
                    action=action,
                    detail=detail,
                    version=self._version,
                ))
            return tuple(plan)

    def apply(self, entries) -> int:
        """Apply a plan and return how many paths were written."""
        with self._lock:
            try:
                rows = [self._coerce_entry(entry) for entry in entries]
            except TypeError as exc:
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"entries": repr(entries)}) from exc

            for path, context, action, detail, version in rows:
                if (not isinstance(version, int)
                        or isinstance(version, bool)
                        or version != self._version):
                    raise LabelError("LABEL_STALE_PLAN", {
                        "expected": self._version,
                        "found": version,
                    })

            written = 0
            seen = set()
            for path, context, action, _detail, _version in rows:
                if path in seen:
                    continue
                seen.add(path)
                if action not in ("relabel", "alias"):
                    continue
                state = self._paths.get(path)
                if state is not None and not state.exists:
                    continue
                if not isinstance(context, str) or not context:
                    continue
                current = state.current if state is not None else None
                if current == context:
                    continue
                file_type = state.file_type if state is not None else "-d"
                self._paths[path] = PathState(
                    path=path,
                    file_type=file_type,
                    exists=True,
                    current=context,
                )
                self._watermark.add(path)
                self._stats["applied"] += 1
                written += 1
            return written

    def verify(self, paths) -> tuple:
        """Compare the expected context with the label currently recorded."""
        with self._lock:
            requested = self._unique_paths(paths)
            checks = []
            for path in requested:
                effective_type = self._effective_file_type(path, None)
                expected, _ = self._resolve_with_equivalence(
                    path, effective_type)
                if expected is not None:
                    self._stats["resolved"] += 1
                state = self._paths.get(path)
                actual = state.current if (
                    state is not None and state.exists) else None
                ok = expected is not None and actual == expected
                checks.append({
                    "path": path,
                    "expected": expected,
                    "actual": actual,
                    "ok": ok,
                })
            return tuple(checks)

    def watermark(self) -> int:
        """Return how many distinct paths have been written by ``apply``."""
        with self._lock:
            return len(self._watermark)

    def snapshot(self) -> dict:
        """Return a detached snapshot of rules, classes, paths and counters."""
        with self._lock:
            state = {
                "version": self._version,
                "distro": [self._rule_snapshot(rule)
                           for rule in self._rules["distro"]],
                "local": [self._rule_snapshot(rule)
                          for rule in self._rules["local"]],
                "equivalences": dict(self._equivalences),
                "paths": {
                    path: self._path_snapshot(path_state)
                    for path, path_state in self._paths.items()
                },
                "watermark": sorted(self._watermark),
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        with self._lock:
            restored = self._validate_snapshot(state)
            self._version = restored["version"]
            self._seq = restored["seq"]
            self._rules = restored["rules"]
            self._equivalences = restored["equivalences"]
            self._paths = restored["paths"]
            self._watermark = restored["watermark"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return dict(self._stats)

    def _check_source(self, source: str) -> None:
        if source not in SOURCES:
            raise LabelError("LABEL_INVALID_REQUEST", {"source": source})

    def _check_file_type(self, file_type: str) -> None:
        if file_type not in FILE_TYPES:
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"file_type": file_type})

    def _parse_rule(self, item):
        if isinstance(item, FileContextRule):
            pattern = item.pattern
            context = item.context
            file_type = item.file_type
        elif isinstance(item, Mapping):
            if "pattern" not in item or "context" not in item:
                return None
            pattern = item.get("pattern")
            context = item.get("context")
            if "type" in item:
                file_type = item.get("type")
            else:
                file_type = item.get("file_type")
        else:
            return None

        if not isinstance(pattern, str) or not pattern:
            return None
        if not isinstance(context, str) or _split_context(context) is None:
            return None
        if file_type not in FILE_TYPES:
            return None
        try:
            re.compile(pattern)
        except (re.error, TypeError):
            return None
        return pattern, context, file_type

    def _equivalence(self, path: str) -> str:
        seen = set()
        current = path
        while current in self._equivalences:
            if current in seen:
                break
            seen.add(current)
            current = self._equivalences[current]
        return current

    def _effective_file_type(self, path: str,
                             file_type: str | None) -> str:
        if file_type is not None:
            self._check_file_type(file_type)
            return file_type
        state = self._paths.get(path)
        return state.file_type if state is not None else "-d"

    def _best_direct_rule(self, block: str, path: str,
                          file_type: str):
        best = None
        for rule in self._rules[block]:
            if rule.file_type != file_type:
                continue
            try:
                matched = re.fullmatch(rule.pattern, path)
            except re.error:
                continue
            if matched is None:
                continue
            if (best is None
                    or (rule.specificity, rule.seq)
                    >= (best.specificity, best.seq)):
                best = rule
        return best

    def _resolve_direct(self, path: str, file_type: str):
        rule = self._best_direct_rule("local", path, file_type)
        if rule is None:
            rule = self._best_direct_rule("distro", path, file_type)
            if rule is None:
                return None, None
            return rule.context, rule

        local = _split_context(rule.context)
        distro_rule = self._best_direct_rule("distro", path, file_type)
        distro = (_split_context(distro_rule.context)
                  if distro_rule is not None else None)
        local_level = local[3]
        distro_level = distro[3] if distro is not None else None

        if local_level is not None:
            if (distro_level is not None
                    and local_level != distro_level):
                raise LabelError("LABEL_MLS_WIDENED", {
                    "path": path,
                    "local": local_level,
                    "distro": distro_level,
                })
            return rule.context, rule

        level = distro_level if distro_level is not None \
            else self.default_mls
        return ":".join((*local[:3], level)), rule

    def _resolve_with_equivalence(self, path: str, file_type: str):
        context, rule = self._resolve_direct(path, file_type)
        if context is not None:
            return context, rule
        representative = self._equivalence(path)
        if representative != path:
            return self._resolve_direct(representative, file_type)
        return None, None

    def _unique_paths(self, paths) -> list[str]:
        if isinstance(paths, str):
            paths = [paths]
        try:
            source = list(paths)
        except TypeError as exc:
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"paths": repr(paths)}) from exc
        unique = []
        seen = set()
        for path in source:
            if not isinstance(path, str) or not path:
                raise LabelError("LABEL_INVALID_REQUEST",
                                 {"path": path})
            if path not in seen:
                seen.add(path)
                unique.append(path)
        return unique

    @staticmethod
    def _coerce_entry(entry):
        if isinstance(entry, Mapping):
            path = entry.get("path")
            context = entry.get("context")
            action = entry.get("action")
            detail = entry.get("detail")
            version = entry.get("version")
        else:
            path = getattr(entry, "path", None)
            context = getattr(entry, "context", None)
            action = getattr(entry, "action", None)
            detail = getattr(entry, "detail", None)
            version = getattr(entry, "version", None)
        if not isinstance(path, str) or not path:
            raise LabelError("LABEL_INVALID_REQUEST", {"path": path})
        if not isinstance(context, str):
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"context": context})
        if not isinstance(action, str):
            raise LabelError("LABEL_INVALID_REQUEST",
                             {"action": action})
        if detail is None:
            detail = ""
        return path, context, action, detail, version

    @staticmethod
    def _rule_snapshot(rule: FileContextRule) -> dict:
        return {
            "pattern": rule.pattern,
            "context": rule.context,
            "file_type": rule.file_type,
            "source": rule.source,
            "seq": rule.seq,
            "specificity": rule.specificity,
        }

    @staticmethod
    def _path_snapshot(state: PathState) -> dict:
        return {
            "path": state.path,
            "file_type": state.file_type,
            "exists": state.exists,
            "current": state.current,
        }

    def _validate_snapshot(self, state):
        required = {"version", "distro", "local", "equivalences",
                    "paths", "watermark", "stats"}
        if not isinstance(state, Mapping) or set(state) != required:
            raise LabelError("LABEL_SNAPSHOT_INVALID",
                             {"reason": "shape"})

        version = state["version"]
        if (not isinstance(version, int) or isinstance(version, bool)
                or version < 0):
            raise LabelError("LABEL_SNAPSHOT_INVALID",
                             {"reason": "version"})

        rules = {}
        sequences = set()
        for source in SOURCES:
            snapshot_rules = state[source]
            if not isinstance(snapshot_rules, (list, tuple)):
                raise LabelError("LABEL_SNAPSHOT_INVALID",
                                 {"reason": source})
            restored_rules = []
            for item in snapshot_rules:
                if not isinstance(item, Mapping):
                    raise LabelError("LABEL_SNAPSHOT_INVALID",
                                     {"reason": source})
                pattern = item.get("pattern")
                context = item.get("context")
                file_type = item.get("file_type", item.get("type"))
                item_source = item.get("source", source)
                seq = item.get("seq")
                if (not isinstance(pattern, str) or not pattern
                        or not isinstance(context, str)
                        or _split_context(context) is None
                        or file_type not in FILE_TYPES
                        or item_source not in SOURCES
                        or (item_source != source)
                        or not isinstance(seq, int)
                        or isinstance(seq, bool)
                        or seq < 0
                        or seq in sequences):
                    raise LabelError("LABEL_SNAPSHOT_INVALID",
                                     {"reason": source})
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise LabelError("LABEL_SNAPSHOT_INVALID",
                                     {"reason": source}) from exc
                sequences.add(seq)
                restored_rules.append(FileContextRule(
                    pattern=pattern,
                    context=context,
                    file_type=file_type,
                    source=source,
                    seq=seq,
                    specificity=_literal_prefix_length(pattern),
                ))
            rules[source] = restored_rules

        equivalences_raw = state["equivalences"]
        if not isinstance(equivalences_raw, Mapping):
            raise LabelError("LABEL_SNAPSHOT_INVALID",
                             {"reason": "equivalences"})
        equivalences = {}
        for alias, target in equivalences_raw.items():
            if (not isinstance(alias, str) or not alias
                    or not isinstance(target, str) or not target):
                raise LabelError("LABEL_SNAPSHOT_INVALID",
                                 {"reason": "equivalences"})
            equivalences[alias] = target
        for start in equivalences:
            seen = set()
            current = start
            while current in equivalences:
                if current in seen:
                    raise LabelError("LABEL_SNAPSHOT_INVALID",
                                     {"reason": "equivalences"})
                seen.add(current)
                current = equivalences[current]

        paths_raw = state["paths"]
        if not isinstance(paths_raw, Mapping):
            raise LabelError("LABEL_SNAPSHOT_INVALID",
                             {"reason": "paths"})
        paths = {}
        for path, value in paths_raw.items():
            if not isinstance(path, str) or not path \
                    or not isinstance(value, Mapping):
                raise LabelError("LABEL_SNAPSHOT_INVALID",
                                 {"reason": "paths"})
            stored_path = value.get("path", path)
            file_type = value.get("file_type")
            exists = value.get("exists")
            current = value.get("current")
            if (stored_path != path
                    or file_type not in FILE_TYPES
                    or not isinstance(exists, bool)
                    or (current is not None
                        and not isinstance(current, str))):
                raise LabelError("LABEL_SNAPSHOT_INVALID",
                                 {"reason": "paths"})
            paths[path] = PathState(
                path=path,
                file_type=file_type,
                exists=exists,
                current=current,
            )

        watermark_raw = state["watermark"]
        if (not isinstance(watermark_raw, (list, tuple, set))
                or isinstance(watermark_raw, (str, bytes))):
            raise LabelError("LABEL_SNAPSHOT_INVALID",
                             {"reason": "watermark"})
        watermark = set()
        for path in watermark_raw:
            if not isinstance(path, str) or not path:
                raise LabelError("LABEL_SNAPSHOT_INVALID",
                                 {"reason": "watermark"})
            watermark.add(path)

        stats_raw = state["stats"]
        if not isinstance(stats_raw, Mapping) \
                or set(stats_raw) != set(STAT_KEYS):
            raise LabelError("LABEL_SNAPSHOT_INVALID",
                             {"reason": "stats"})
        stats = {}
        for key in STAT_KEYS:
            value = stats_raw[key]
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                raise LabelError("LABEL_SNAPSHOT_INVALID",
                                 {"reason": "stats"})
            stats[key] = value

        next_seq = max(sequences, default=-1) + 1
        return {
            "version": version,
            "seq": next_seq,
            "rules": rules,
            "equivalences": equivalences,
            "paths": paths,
            "watermark": watermark,
            "stats": stats,
        }
