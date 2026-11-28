"""Commit graph sweeper for secrets in blob objects with rename tracking."""

from __future__ import annotations

import copy
import difflib
import re
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


SECRET_KINDS = (
    "aws_access_key_id",
    "private_key_block",
    "hex_secret_assignment",
)

_STAT_KEYS = (
    "commits",
    "objects",
    "cached",
    "findings",
    "scans",
    "restores",
)

_SNAPSHOT_VERSION = 1

_AWS_RE = re.compile(r"(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN[^\r\n]*?PRIVATE KEY-----")
_HEX_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+_)*(?:secret|token)"
    r"(?:_[A-Za-z0-9]+)*\b"
    r"\s*[:=]\s*[\"']?[0-9a-f]{16,}\b"
)


class SweepError(ValueError):
    """Raised when the sweeper refuses a commit, object or cursor."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class _Finding:
    kind: str
    line: int


@dataclass(frozen=True)
class _ScanResult:
    findings: tuple[_Finding, ...]
    bytes: int


@dataclass(frozen=True)
class _Commit:
    commit_id: str
    parents: tuple[str, ...]
    objects: tuple[tuple[str, str], ...]


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class GitBlobSecretSweeper:
    """Walk commits, scan each blob once and keep results per path."""

    def __init__(
        self, *, max_objects: int = 500, rename_threshold: float = 0.6
    ) -> None:
        self.max_objects = max_objects
        self.rename_threshold = rename_threshold
        self._lock = threading.RLock()

        self._commits: dict[str, _Commit] = {}
        self._commit_order: list[str] = []
        self._last_registered: str | None = None

        self._blobs: dict[str, str | bytes] = {}
        self._scans: dict[str, _ScanResult] = {}
        self._path_results: dict[str, tuple[str, ...]] = {}

        self._scanned_commits: set[str] = set()
        self._scanned_order: list[str] = []
        self._last_scanned: str | None = None

        self._stats = {key: 0 for key in _STAT_KEYS}

    def add_commit(self, commit_id: str, *, parents=(), objects=()) -> dict:
        with self._lock:
            if not isinstance(commit_id, str) or not commit_id:
                raise SweepError("SWEEP_INVALID_COMMIT", commit_id)
            if commit_id in self._commits:
                raise SweepError("SWEEP_DUPLICATE_COMMIT", commit_id)

            parent_ids = self._normalize_parents(parents)
            object_pairs = self._normalize_objects(objects)

            missing_parents = tuple(
                parent for parent in parent_ids if parent not in self._commits
            )
            commit = _Commit(commit_id, parent_ids, object_pairs)
            self._commits[commit_id] = commit
            self._commit_order.append(commit_id)
            self._last_registered = commit_id
            return {
                "commit": commit_id,
                "objects": len(object_pairs),
                "parents": len(parent_ids),
                "missing_parents": missing_parents,
            }

    def register_blob(self, oid: str, *, content) -> int:
        with self._lock:
            if not isinstance(oid, str) or not oid:
                raise SweepError("SWEEP_INVALID_OBJECT", oid)
            _text, size = self._normalized_content(content)
            if isinstance(content, (bytes, bytearray, memoryview)):
                self._blobs[oid] = bytes(content)
            else:
                self._blobs[oid] = content
            return size

    def walk_commits(self, *, from_commit: str | None = None) -> tuple:
        with self._lock:
            if from_commit is None:
                start = self._last_registered
            else:
                start = from_commit
            if (
                not isinstance(start, str)
                or not start
                or start not in self._commits
            ):
                raise SweepError("SWEEP_UNKNOWN_COMMIT", start)

            result: list[str] = []
            visited: set[str] = set()
            stack = [start]
            while stack:
                commit_id = stack.pop()
                if commit_id in visited or commit_id not in self._commits:
                    continue
                visited.add(commit_id)
                result.append(commit_id)
                parents = self._commits[commit_id].parents
                for parent in reversed(parents):
                    if parent not in visited:
                        stack.append(parent)
            return tuple(result)

    def scan_object(self, oid: str, *, content=None) -> dict:
        with self._lock:
            if not isinstance(oid, str) or not oid:
                raise SweepError("SWEEP_UNKNOWN_OBJECT", oid)

            if content is not None:
                text, size = self._normalized_content(content)
            elif oid in self._blobs:
                text, size = self._normalized_content(self._blobs[oid])
            else:
                raise SweepError("SWEEP_UNKNOWN_OBJECT", oid)

            result, cached = self._scan_locked(oid, text, size)
            self._backfill_scanned_oid(oid)
            return {
                "oid": oid,
                "findings": self._findings_to_dicts(result.findings),
                "cached": cached,
                "bytes": result.bytes,
            }

    def sweep(self, from_commit: str | None = None) -> dict:
        with self._lock:
            commits = self.walk_commits(from_commit=from_commit)
            return self._process_commits(commits)

    def resume(self, cursor: dict) -> int:
        with self._lock:
            cursor_commit, cursor_objects = self._validated_cursor(cursor)
            if cursor_commit not in self._scanned_commits:
                raise SweepError("SWEEP_INVALID_CURSOR", cursor)
            if not _is_nonnegative_int(cursor_objects):
                raise SweepError("SWEEP_INVALID_CURSOR", cursor)

            pending_commits = [
                commit_id
                for commit_id in self.walk_commits()
                if commit_id not in self._scanned_commits
            ]
            queued = set(pending_commits)
            for commit_id in self._commit_order:
                if (
                    commit_id not in self._scanned_commits
                    and commit_id not in queued
                ):
                    pending_commits.append(commit_id)
                    queued.add(commit_id)
            return self._process_commits(pending_commits)["commits"]

    def checkpoint(self) -> dict:
        with self._lock:
            return {
                "commit": self._last_scanned,
                "objects": self._stats["objects"],
            }

    def follow_renames(self, commit_id: str) -> dict:
        with self._lock:
            commit = self._require_commit(commit_id)
            current = {path: oid for path, oid in commit.objects}

            parent_paths: dict[str, str] = {}
            parent_order: list[str] = []
            for parent_id in commit.parents:
                parent = self._commits.get(parent_id)
                if parent is None:
                    continue
                for path, oid in parent.objects:
                    if path not in parent_paths:
                        parent_paths[path] = oid
                        parent_order.append(path)

            deleted = [
                (path, parent_paths[path])
                for path in parent_order
                if path not in current
            ]
            added = [
                (path, oid)
                for path, oid in commit.objects
                if path not in parent_paths
            ]

            paired: dict[str, str] = {}
            used_new: set[int] = set()

            # Identical object ids are authoritative rename evidence.
            for old_path, old_oid in deleted:
                for index, (new_path, new_oid) in enumerate(added):
                    if index not in used_new and new_oid == old_oid:
                        paired[old_path] = new_path
                        used_new.add(index)
                        break

            remaining_old = [
                item for item in deleted if item[0] not in paired
            ]
            candidates: list[tuple[float, int, int, str, str]] = []
            for old_index, (old_path, _old_oid) in enumerate(remaining_old):
                for new_index, (new_path, _new_oid) in enumerate(added):
                    if new_index in used_new:
                        continue
                    score = difflib.SequenceMatcher(
                        None, old_path, new_path
                    ).ratio()
                    if score >= self.rename_threshold:
                        candidates.append(
                            (-score, old_index, new_index, old_path, new_path)
                        )

            candidates.sort(key=lambda item: (item[0], item[1], item[2]))
            for (
                _negative_score,
                _old_index,
                new_index,
                old_path,
                new_path,
            ) in candidates:
                if old_path in paired or new_index in used_new:
                    continue
                paired[old_path] = new_path
                used_new.add(new_index)

            return {
                old_path: paired[old_path]
                for old_path, _oid in deleted
                if old_path in paired
            }

    def results_for_path(self, path: str) -> tuple:
        with self._lock:
            return self._path_results.get(path, ())

    def describe_commit(self, commit_id: str) -> dict:
        with self._lock:
            commit = self._require_commit(commit_id)
            return {
                "commit": commit.commit_id,
                "parents": commit.parents,
                "objects": len(commit.objects),
                "paths": tuple(path for path, _oid in commit.objects),
            }

    def snapshot(self) -> dict:
        with self._lock:
            commits = {}
            for commit_id in self._commit_order:
                commit = self._commits[commit_id]
                commits[commit_id] = {
                    "parents": list(commit.parents),
                    "objects": [
                        [path, oid] for path, oid in commit.objects
                    ],
                }

            scans = {}
            for oid, result in self._scans.items():
                scans[oid] = {
                    "findings": [
                        {"kind": finding.kind, "line": finding.line}
                        for finding in result.findings
                    ],
                    "bytes": result.bytes,
                }

            return {
                "version": _SNAPSHOT_VERSION,
                "commits": commits,
                "commit_order": list(self._commit_order),
                "default_start": self._last_registered,
                "blobs": copy.deepcopy(self._blobs),
                "scans": scans,
                "results": {
                    path: list(kinds)
                    for path, kinds in self._path_results.items()
                },
                "cursor": {
                    "commit": self._last_scanned,
                    "objects": self._stats["objects"],
                    "commits": list(self._scanned_order),
                },
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = self._validated_snapshot(state)
            except SweepError:
                raise
            except Exception as exc:
                raise SweepError(
                    "SWEEP_SNAPSHOT_INVALID", {"reason": str(exc)}
                ) from exc

            self._commits = candidate["commits"]
            self._commit_order = candidate["commit_order"]
            self._last_registered = candidate["default_start"]
            self._blobs = candidate["blobs"]
            self._scans = candidate["scans"]
            self._path_results = candidate["results"]
            self._scanned_order = candidate["scanned_order"]
            self._scanned_commits = set(candidate["scanned_order"])
            self._last_scanned = candidate["last_scanned"]
            self._stats = candidate["stats"]
            self._stats["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset(self) -> None:
        with self._lock:
            self._scans.clear()
            self._path_results.clear()
            self._scanned_commits.clear()
            self._scanned_order.clear()
            self._last_scanned = None
            self._stats = {key: 0 for key in _STAT_KEYS}

    # ------------------------------------------------------------------
    # Internal helpers

    @staticmethod
    def _normalize_parents(parents) -> tuple[str, ...]:
        if isinstance(parents, str):
            raw_parents = [parents]
        else:
            try:
                raw_parents = list(parents)
            except TypeError as exc:
                raise SweepError("SWEEP_INVALID_COMMIT", parents) from exc

        result = []
        for parent in raw_parents:
            if not isinstance(parent, str) or not parent:
                raise SweepError("SWEEP_INVALID_COMMIT", parent)
            result.append(parent)
        return tuple(result)

    @staticmethod
    def _normalize_objects(objects) -> tuple[tuple[str, str], ...]:
        if isinstance(objects, (str, bytes, bytearray)):
            raise SweepError("SWEEP_INVALID_OBJECT", objects)
        try:
            raw_objects = list(objects)
        except TypeError as exc:
            raise SweepError("SWEEP_INVALID_OBJECT", objects) from exc

        result: list[tuple[str, str]] = []
        seen_paths: set[str] = set()
        for entry in raw_objects:
            if (
                not isinstance(entry, (tuple, list))
                or len(entry) != 2
            ):
                raise SweepError("SWEEP_INVALID_OBJECT", entry)
            path, oid = entry
            if (
                not isinstance(path, str)
                or not path
                or not isinstance(oid, str)
                or not oid
            ):
                raise SweepError("SWEEP_INVALID_OBJECT", entry)
            if path in seen_paths:
                raise SweepError("SWEEP_DUPLICATE_PATH", path)
            seen_paths.add(path)
            result.append((path, oid))
        return tuple(result)

    @staticmethod
    def _normalized_content(content) -> tuple[str, int]:
        if isinstance(content, str):
            return content, len(content.encode("utf-8"))
        if isinstance(content, (bytes, bytearray, memoryview)):
            raw = bytes(content)
            return raw.decode("utf-8", errors="replace"), len(raw)
        raise SweepError("SWEEP_INVALID_OBJECT", content)

    @staticmethod
    def _findings_to_dicts(
        findings: Sequence[_Finding],
    ) -> tuple[dict, ...]:
        return tuple(
            {"kind": finding.kind, "line": finding.line}
            for finding in findings
        )

    @classmethod
    def _detect_findings(cls, text: str) -> tuple[_Finding, ...]:
        matches: list[tuple[int, _Finding]] = []

        for match in _AWS_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            matches.append(
                (match.start(), _Finding("aws_access_key_id", line))
            )

        for match in _PRIVATE_KEY_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            matches.append(
                (match.start(), _Finding("private_key_block", line))
            )

        for match in _HEX_ASSIGNMENT_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            matches.append(
                (match.start(), _Finding("hex_secret_assignment", line))
            )

        matches.sort(key=lambda item: item[0])
        return tuple(finding for _position, finding in matches)

    def _scan_locked(
        self, oid: str, text: str, size: int
    ) -> tuple[_ScanResult, bool]:
        cached = self._scans.get(oid)
        if cached is not None:
            self._stats["cached"] += 1
            return cached, True

        if self._stats["objects"] >= self.max_objects:
            raise SweepError("SWEEP_OBJECT_LIMIT", oid)

        findings = self._detect_findings(text)
        result = _ScanResult(findings=findings, bytes=size)
        self._scans[oid] = result
        self._stats["objects"] += 1
        self._stats["scans"] += 1
        self._stats["findings"] += len(findings)
        return result, False

    def _record_path(
        self, path: str, findings: Sequence[_Finding]
    ) -> None:
        if not findings:
            self._path_results.setdefault(path, ())
            return
        kind = findings[0].kind
        current = self._path_results.get(path, ())
        if kind not in current:
            self._path_results[path] = current + (kind,)

    def _backfill_scanned_oid(self, oid: str) -> None:
        result = self._scans.get(oid)
        if result is None:
            return
        for commit_id in self._scanned_order:
            commit = self._commits.get(commit_id)
            if commit is None:
                continue
            for path, referenced_oid in commit.objects:
                if referenced_oid == oid:
                    self._record_path(path, result.findings)

    def _process_commits(self, commit_ids: Sequence[str]) -> dict:
        processed = 0
        cached_hits = 0
        report_objects: set[str] = set()
        pending_objects: set[str] = set()
        finding_count = 0

        for commit_id in commit_ids:
            commit = self._commits[commit_id]
            if commit_id not in self._scanned_commits:
                self._scanned_commits.add(commit_id)
                self._scanned_order.append(commit_id)
                self._stats["commits"] += 1
            self._last_scanned = commit_id
            processed += 1

            for path, oid in commit.objects:
                if oid not in self._blobs:
                    pending_objects.add(oid)
                result = self._scans.get(oid)
                if result is not None:
                    self._stats["cached"] += 1
                    cached_hits += 1
                elif oid in self._blobs:
                    text, size = self._normalized_content(self._blobs[oid])
                    result, was_cached = self._scan_locked(oid, text, size)
                    if was_cached:
                        cached_hits += 1
                else:
                    continue

                if oid not in report_objects:
                    report_objects.add(oid)
                    finding_count += len(result.findings)
                self._record_path(path, result.findings)

        return {
            "commits": processed,
            "objects": len(report_objects),
            "cached": cached_hits,
            "findings": finding_count,
            "pending": len(pending_objects),
        }

    def _require_commit(self, commit_id: str) -> _Commit:
        commit = (
            self._commits.get(commit_id)
            if isinstance(commit_id, str)
            else None
        )
        if commit is None:
            raise SweepError("SWEEP_UNKNOWN_COMMIT", commit_id)
        return commit

    @staticmethod
    def _validated_cursor(cursor: dict) -> tuple[str, int]:
        if not isinstance(cursor, Mapping):
            raise SweepError("SWEEP_INVALID_CURSOR", cursor)
        if "commit" not in cursor or "objects" not in cursor:
            raise SweepError("SWEEP_INVALID_CURSOR", cursor)
        commit = cursor["commit"]
        objects = cursor["objects"]
        if not isinstance(commit, str) or not commit:
            raise SweepError("SWEEP_INVALID_CURSOR", cursor)
        if not _is_nonnegative_int(objects):
            raise SweepError("SWEEP_INVALID_CURSOR", cursor)
        return commit, objects

    def _validated_snapshot(self, state: object) -> dict:
        if not isinstance(state, Mapping):
            self._snapshot_error("snapshot must be a mapping")

        required = {
            "version",
            "commits",
            "commit_order",
            "default_start",
            "blobs",
            "scans",
            "results",
            "cursor",
            "stats",
        }
        if set(state.keys()) != required:
            self._snapshot_error("snapshot fields do not match")

        version = state["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != _SNAPSHOT_VERSION
        ):
            self._snapshot_error("unsupported snapshot version")

        raw_commits = state["commits"]
        if not isinstance(raw_commits, Mapping):
            self._snapshot_error("commits must be a mapping")
        commits: dict[str, _Commit] = {}
        for commit_id, raw_commit in raw_commits.items():
            if not isinstance(commit_id, str) or not commit_id:
                self._snapshot_error("invalid commit id")
            if not isinstance(raw_commit, Mapping):
                self._snapshot_error("commit record must be a mapping")
            if set(raw_commit.keys()) != {"parents", "objects"}:
                self._snapshot_error("commit record fields do not match")
            parents, objects = self._snapshot_commit_parts(raw_commit)
            commits[commit_id] = _Commit(commit_id, parents, objects)

        raw_order = state["commit_order"]
        if not self._is_sequence(raw_order):
            self._snapshot_error("commit_order must be a sequence")
        commit_order = list(raw_order)
        if (
            any(not isinstance(item, str) for item in commit_order)
            or len(set(commit_order)) != len(commit_order)
            or set(commit_order) != set(commits)
        ):
            self._snapshot_error("commit_order does not match commits")

        default_start = state["default_start"]
        if default_start is not None:
            if (
                not isinstance(default_start, str)
                or default_start not in commits
            ):
                self._snapshot_error("invalid default_start")
        elif commits:
            self._snapshot_error("default_start is required")

        raw_blobs = state["blobs"]
        if not isinstance(raw_blobs, Mapping):
            self._snapshot_error("blobs must be a mapping")
        blobs: dict[str, str | bytes] = {}
        for oid, content in raw_blobs.items():
            if not isinstance(oid, str) or not oid:
                self._snapshot_error("invalid blob id")
            if isinstance(content, str):
                blobs[oid] = content
            elif isinstance(content, (bytes, bytearray, memoryview)):
                blobs[oid] = bytes(content)
            else:
                self._snapshot_error("invalid blob content")

        raw_scans = state["scans"]
        if not isinstance(raw_scans, Mapping):
            self._snapshot_error("scans must be a mapping")
        scans: dict[str, _ScanResult] = {}
        for oid, raw_scan in raw_scans.items():
            if not isinstance(oid, str) or not oid:
                self._snapshot_error("invalid scan id")
            if not isinstance(raw_scan, Mapping):
                self._snapshot_error("scan record must be a mapping")
            if set(raw_scan.keys()) != {"findings", "bytes"}:
                self._snapshot_error("scan record fields do not match")
            raw_findings = raw_scan["findings"]
            if not self._is_sequence(raw_findings):
                self._snapshot_error("findings must be a sequence")
            findings = []
            for raw_finding in raw_findings:
                if not isinstance(raw_finding, Mapping):
                    self._snapshot_error("finding must be a mapping")
                if set(raw_finding.keys()) != {"kind", "line"}:
                    self._snapshot_error("finding fields do not match")
                kind = raw_finding["kind"]
                line = raw_finding["line"]
                if kind not in SECRET_KINDS:
                    self._snapshot_error("invalid finding kind")
                if not _is_nonnegative_int(line) or line < 1:
                    self._snapshot_error("invalid finding line")
                findings.append(_Finding(kind, line))
            scan_bytes = raw_scan["bytes"]
            if not _is_nonnegative_int(scan_bytes):
                self._snapshot_error("invalid scan byte count")
            scans[oid] = _ScanResult(tuple(findings), scan_bytes)

        raw_results = state["results"]
        if not isinstance(raw_results, Mapping):
            self._snapshot_error("results must be a mapping")
        results: dict[str, tuple[str, ...]] = {}
        for path, raw_kinds in raw_results.items():
            if not isinstance(path, str) or not path:
                self._snapshot_error("invalid result path")
            if not self._is_sequence(raw_kinds):
                self._snapshot_error("result kinds must be a sequence")
            kinds = tuple(raw_kinds)
            if any(kind not in SECRET_KINDS for kind in kinds):
                self._snapshot_error("invalid result kind")
            results[path] = kinds

        raw_cursor = state["cursor"]
        if not isinstance(raw_cursor, Mapping):
            self._snapshot_error("cursor must be a mapping")
        if set(raw_cursor.keys()) != {"commit", "objects", "commits"}:
            self._snapshot_error("cursor fields do not match")
        last_scanned = raw_cursor["commit"]
        cursor_objects = raw_cursor["objects"]
        raw_scanned = raw_cursor["commits"]
        if last_scanned is not None:
            if not isinstance(last_scanned, str):
                self._snapshot_error("invalid cursor commit")
        if not _is_nonnegative_int(cursor_objects):
            self._snapshot_error("invalid cursor object count")
        if not self._is_sequence(raw_scanned):
            self._snapshot_error("cursor commits must be a sequence")
        scanned_order = list(raw_scanned)
        if (
            any(not isinstance(item, str) for item in scanned_order)
            or len(set(scanned_order)) != len(scanned_order)
            or any(item not in commits for item in scanned_order)
        ):
            self._snapshot_error("invalid scanned commit list")
        if last_scanned is not None and last_scanned not in scanned_order:
            self._snapshot_error("cursor commit was not scanned")
        if last_scanned is None and scanned_order:
            self._snapshot_error("cursor commit is missing")

        raw_stats = state["stats"]
        if not isinstance(raw_stats, Mapping):
            self._snapshot_error("stats must be a mapping")
        if set(raw_stats.keys()) != set(_STAT_KEYS):
            self._snapshot_error("stats fields do not match")
        stats = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if not _is_nonnegative_int(value):
                self._snapshot_error("invalid statistic")
            stats[key] = value
        if stats["commits"] != len(scanned_order):
            self._snapshot_error("commit count does not match cursor")
        if stats["objects"] != len(scans) or stats["scans"] != len(scans):
            self._snapshot_error("object scan counts do not match cache")
        if cursor_objects != stats["objects"]:
            self._snapshot_error("cursor object count does not match stats")
        if stats["findings"] != sum(
            len(result.findings) for result in scans.values()
        ):
            self._snapshot_error("finding count does not match cache")

        return {
            "commits": commits,
            "commit_order": commit_order,
            "default_start": default_start,
            "blobs": blobs,
            "scans": scans,
            "results": results,
            "scanned_order": scanned_order,
            "last_scanned": last_scanned,
            "stats": stats,
        }

    def _snapshot_commit_parts(
        self, raw_commit: Mapping
    ) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
        raw_parents = raw_commit["parents"]
        raw_objects = raw_commit["objects"]
        if not self._is_sequence(raw_parents):
            self._snapshot_error("commit parents must be a sequence")
        parents = []
        for parent in raw_parents:
            if not isinstance(parent, str) or not parent:
                self._snapshot_error("invalid commit parent")
            parents.append(parent)

        if not self._is_sequence(raw_objects):
            self._snapshot_error("commit objects must be a sequence")
        objects = []
        paths = set()
        for entry in raw_objects:
            if (
                not isinstance(entry, (tuple, list))
                or len(entry) != 2
                or not isinstance(entry[0], str)
                or not entry[0]
                or not isinstance(entry[1], str)
                or not entry[1]
            ):
                self._snapshot_error("invalid commit object")
            path, oid = entry
            if path in paths:
                self._snapshot_error("duplicate path in snapshot commit")
            paths.add(path)
            objects.append((path, oid))
        return tuple(parents), tuple(objects)

    @staticmethod
    def _is_sequence(value: object) -> bool:
        return (
            isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray))
        )

    @staticmethod
    def _snapshot_error(detail: object) -> None:
        raise SweepError("SWEEP_SNAPSHOT_INVALID", detail)
