"""Log rotation permission guard.

Rotation plans derive the owner, group and mode of the replacement file,
refuse symbolic links, keep archive files no looser than the original, and
track generations so a failed job never leaves half-written archives behind.
"""

from __future__ import annotations

import copy
import os
import threading
from dataclasses import asdict, dataclass, fields, replace

ROTATIONS = ("create", "copytruncate")
COUNTER_KEYS = ("rotated", "compressed", "refused", "failed", "planned",
                "restores")
FINDING_CODES = ("ROT_FILE_MISSING", "ROT_SYMLINK", "ROT_OWNER_MISMATCH",
                 "ROT_MODE_MISMATCH", "ROT_PERM_LOOSER")
POLICY_KEYS = ("owner", "group", "mode", "rotation", "su_user", "su_group",
               "world_writable_dir", "immutable", "compress")


class RotateError(ValueError):
    """Refusal raised while planning, rotating or restoring log files."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FileState:
    """One file known to the guard."""

    path: str
    owner: str
    group: str
    mode: int
    size: int
    inode: int
    generation: int = 0
    rotation: str = ""
    compress: bool = False
    su_user: str | None = None
    su_group: str | None = None
    world_writable_dir: bool = False
    immutable: bool = False
    symlink_target: str | None = None


@dataclass(frozen=True)
class PlannedRotation:
    """One line of a rotation plan."""

    path: str
    archive: str
    rotation: str
    owner: str
    group: str
    mode: int
    size: int
    compress: bool


@dataclass(frozen=True)
class RotationResult:
    """The outcome of rotating one log file."""

    path: str
    archive: str
    generation: int
    owner: str
    group: str
    mode: int
    inode: int
    compress: bool


class LogrotatePermissionGuard:
    """Plan and perform log rotations while policing file permissions."""

    def __init__(self, *, umask: int = 0o022, max_files_per_run: int = 32,
                 max_bytes_per_run: int = 8 * 1024 * 1024,
                 compress_mask: int = 0o700) -> None:
        self.umask = umask
        self.max_files_per_run = max_files_per_run
        self.max_bytes_per_run = max_bytes_per_run
        self.compress_mask = compress_mask
        self._lock = threading.RLock()
        self._files: dict[str, FileState] = {}
        self._logs: dict[str, dict] = {}
        self._findings: dict[str, tuple] = {}
        self._counters = {key: 0 for key in COUNTER_KEYS}
        self._next_inode = 1000
        self._path_locks: dict[str, threading.RLock] = {}

    @staticmethod
    def _invalid(detail: object) -> None:
        raise RotateError("ROTATE_INVALID_REQUEST", detail)

    @staticmethod
    def _unknown(path: str) -> None:
        raise RotateError("ROTATE_UNKNOWN_FILE", {"path": path})

    @staticmethod
    def _absolute_path(path: object) -> str:
        if not isinstance(path, str) or not path or not os.path.isabs(path):
            raise RotateError("ROTATE_INVALID_REQUEST", {"path": path})
        return path

    @classmethod
    def _nonempty_name(cls, value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            cls._invalid({"field": field, "value": value})
        return value

    @classmethod
    def _optional_name(cls, value: object, field: str) -> str | None:
        if value is None:
            return None
        return cls._nonempty_name(value, field)

    @classmethod
    def _mode_value(cls, value: object, field: str = "mode") -> int:
        if (not isinstance(value, int) or isinstance(value, bool)
                or value < 0 or value > 0o7777):
            cls._invalid({"field": field, "value": value})
        return value

    @classmethod
    def _size_value(cls, value: object, field: str = "size") -> int:
        if (not isinstance(value, int) or isinstance(value, bool)
                or value < 0):
            cls._invalid({"field": field, "value": value})
        return value

    @classmethod
    def _rotation_value(cls, value: object) -> str:
        if value not in ROTATIONS:
            cls._invalid({"field": "rotation", "value": value})
        return value

    @staticmethod
    def _generation_value(value: object) -> int:
        if (not isinstance(value, int) or isinstance(value, bool)
                or value < 0):
            raise RotateError("ROTATE_INVALID_REQUEST",
                              {"field": "generation", "value": value})
        return value

    def _new_inode(self) -> int:
        self._next_inode += 1
        return self._next_inode

    def _path_lock(self, path: str) -> threading.RLock:
        with self._lock:
            return self._path_locks.setdefault(path, threading.RLock())

    def _require_log(self, path: object) -> tuple[str, FileState, dict]:
        checked = self._absolute_path(path)
        policy = self._logs.get(checked)
        state = self._files.get(checked)
        if policy is None or state is None:
            self._unknown(checked)
        return checked, state, policy

    @staticmethod
    def _effective_identity(policy: dict) -> tuple[str, str]:
        owner = (policy["su_user"] if policy["su_user"] is not None
                 else policy["owner"])
        group = (policy["su_group"] if policy["su_group"] is not None
                 else policy["group"])
        return owner, group

    def _effective_mode(self, policy: dict) -> int:
        mode = policy["mode"]
        if policy["world_writable_dir"]:
            mode &= ~self.umask
        return mode & 0o7777

    def _unique_paths(self, paths) -> tuple[str, ...]:
        if isinstance(paths, str):
            values = (paths,)
        else:
            try:
                values = tuple(paths)
            except TypeError:
                self._invalid({"field": "paths", "value": paths})
        result = []
        seen = set()
        for path in values:
            checked = self._absolute_path(path)
            if checked not in seen:
                seen.add(checked)
                result.append(checked)
        return tuple(result)

    def _check_capacity(self, states: list[FileState]) -> None:
        if len(states) > self.max_files_per_run:
            raise RotateError("ROTATE_CAPACITY",
                              {"limit": self.max_files_per_run})
        if sum(state.size for state in states) > self.max_bytes_per_run:
            raise RotateError("ROTATE_CAPACITY",
                              {"limit": self.max_bytes_per_run})

    @staticmethod
    def _symlink_refused(path: str, target: str) -> None:
        raise RotateError("ROTATE_SYMLINK_REFUSED",
                          {"path": path, "target": target})

    def _cleanup_partials(self, path: str, next_generation: int) -> None:
        target = f"{path}.{next_generation}"
        self._files.pop(target, None)
        for generation in range(1, next_generation + 1):
            plain = f"{path}.{generation}"
            packed = plain + ".gz"
            packed_state = self._files.get(packed)
            if packed_state is None:
                continue
            if (generation == next_generation
                    or plain in self._files
                    or packed_state.generation != generation):
                self._files.pop(packed, None)

    def register_logfile(self, path: str, *, owner: str, group: str, mode: int,
                         rotation: str = "create", su_user: str | None = None,
                         su_group: str | None = None,
                         world_writable_dir: bool = False,
                         immutable: bool = False,
                         symlink_target: str | None = None,
                         size: int = 1024,
                         compress: bool = True) -> FileState:
        """Register a log file and its rotation policy."""
        checked = self._absolute_path(path)
        owner = self._nonempty_name(owner, "owner")
        group = self._nonempty_name(group, "group")
        mode = self._mode_value(mode)
        rotation = self._rotation_value(rotation)
        su_user = self._optional_name(su_user, "su_user")
        su_group = self._optional_name(su_group, "su_group")
        size = self._size_value(size)
        if symlink_target is not None and not isinstance(symlink_target, str):
            self._invalid({"field": "symlink_target", "value": symlink_target})

        policy = {
            "owner": owner,
            "group": group,
            "mode": mode,
            "rotation": rotation,
            "su_user": su_user,
            "su_group": su_group,
            "world_writable_dir": bool(world_writable_dir),
            "immutable": bool(immutable),
            "compress": bool(compress),
        }
        with self._lock:
            state = FileState(
                path=checked,
                owner=owner,
                group=group,
                mode=mode,
                size=size,
                inode=self._new_inode(),
                generation=0,
                rotation=rotation,
                compress=policy["compress"],
                su_user=su_user,
                su_group=su_group,
                world_writable_dir=policy["world_writable_dir"],
                immutable=policy["immutable"],
                symlink_target=symlink_target,
            )
            self._files[checked] = state
            self._logs[checked] = policy
            self._findings.pop(checked, None)
            return state

    def place_file(self, path: str, *, owner: str, group: str, mode: int,
                   size: int = 0) -> FileState:
        """Record an arbitrary file such as a compressed archive."""
        checked = self._absolute_path(path)
        owner = self._nonempty_name(owner, "owner")
        group = self._nonempty_name(group, "group")
        mode = self._mode_value(mode)
        size = self._size_value(size)

        with self._lock:
            previous = self._files.get(checked)
            if previous is None:
                state = FileState(
                    path=checked,
                    owner=owner,
                    group=group,
                    mode=mode,
                    size=size,
                    inode=self._new_inode(),
                )
            else:
                state = replace(
                    previous,
                    owner=owner,
                    group=group,
                    mode=mode,
                    size=size,
                    symlink_target=None,
                )
            self._files[checked] = state
            return state

    def stat(self, path: str):
        """Return the recorded state of ``path`` or None."""
        with self._lock:
            return self._files.get(path)

    def stat_log(self, path: str) -> FileState:
        """Return the state of a registered log file."""
        with self._lock:
            _, state, _ = self._require_log(path)
            return state

    def generation(self, path: str) -> int:
        """Return the rotation generation of a registered log file."""
        with self._lock:
            _, state, _ = self._require_log(path)
            return state.generation

    def archive_path(self, path: str, generation: int | None = None) -> str:
        """Return the archive path of ``path`` for a generation."""
        with self._lock:
            checked, state, _ = self._require_log(path)
            number = (state.generation + 1 if generation is None
                      else self._generation_value(generation))
            return f"{checked}.{number}"

    def plan(self, paths) -> tuple:
        """Build rotation plans without touching any file."""
        requested = self._unique_paths(paths)
        with self._lock:
            states = []
            for path in requested:
                state = self._files.get(path)
                if path not in self._logs or state is None:
                    self._unknown(path)
                states.append(state)

            self._check_capacity(states)

            for state in states:
                if state.symlink_target is not None:
                    self._counters["refused"] += 1
                    self._symlink_refused(state.path, state.symlink_target)

            entries = []
            for state in states:
                policy = self._logs[state.path]
                owner, group = self._effective_identity(policy)
                entries.append(PlannedRotation(
                    path=state.path,
                    archive=f"{state.path}.{state.generation + 1}",
                    rotation=policy["rotation"],
                    owner=owner,
                    group=group,
                    mode=self._effective_mode(policy),
                    size=state.size,
                    compress=policy["compress"],
                ))
            self._counters["planned"] += len(entries)
            return tuple(entries)

    def rotate(self, path: str) -> RotationResult:
        """Rotate one log file and return the result."""
        checked = self._absolute_path(path)
        with self._path_lock(checked), self._lock:
            _, state, policy = self._require_log(checked)
            if state.symlink_target is not None:
                self._counters["refused"] += 1
                self._symlink_refused(checked, state.symlink_target)
            if policy["immutable"]:
                self._counters["failed"] += 1
                raise RotateError("ROTATE_FAILED",
                                  {"reason": "immutable", "path": checked})

            generation = state.generation + 1
            archive = f"{checked}.{generation}"
            self._cleanup_partials(checked, generation)

            archived = FileState(
                path=archive,
                owner=state.owner,
                group=state.group,
                mode=state.mode,
                size=state.size,
                inode=self._new_inode(),
                generation=generation,
            )
            owner, group = self._effective_identity(policy)
            mode = self._effective_mode(policy)
            new_inode = (state.inode if policy["rotation"] == "copytruncate"
                         else self._new_inode())
            current = replace(
                state,
                owner=owner,
                group=group,
                mode=mode,
                size=0,
                inode=new_inode,
                generation=generation,
                rotation=policy["rotation"],
                compress=policy["compress"],
                su_user=policy["su_user"],
                su_group=policy["su_group"],
                world_writable_dir=policy["world_writable_dir"],
                immutable=policy["immutable"],
                symlink_target=None,
            )
            self._files[archive] = archived
            self._files[checked] = current
            self._counters["rotated"] += 1
            return RotationResult(
                path=checked,
                archive=archive,
                generation=generation,
                owner=owner,
                group=group,
                mode=mode,
                inode=new_inode,
                compress=policy["compress"],
            )

    def rotate_batch(self, paths) -> tuple:
        """Rotate several log files after checking the per-run limits."""
        entries = self.plan(paths)
        return tuple(self.rotate(entry.path) for entry in entries)

    def compress(self, path: str, *, generation: int | None = None) -> dict:
        """Compress one archive and return its new state."""
        checked = self._absolute_path(path)
        with self._path_lock(checked), self._lock:
            _, state, _ = self._require_log(checked)
            number = (state.generation if generation is None
                      else self._generation_value(generation))
            if number < 1 or number > state.generation:
                self._invalid({"field": "generation", "value": generation})

            archive = f"{checked}.{number}"
            packed = archive + ".gz"
            plain = self._files.get(archive)
            existing = self._files.get(packed)
            if plain is None:
                if existing is not None:
                    return {
                        "archive": packed,
                        "mode": existing.mode,
                        "owner": existing.owner,
                        "size": existing.size,
                    }
                raise RotateError("ROTATE_FAILED",
                                  {"reason": "archive_missing",
                                   "path": archive})

            mode = plain.mode & self.compress_mask & 0o7777
            packed_state = FileState(
                path=packed,
                owner=plain.owner,
                group=plain.group,
                mode=mode,
                size=plain.size,
                inode=(existing.inode if existing is not None
                       else self._new_inode()),
                generation=number,
            )
            self._files.pop(archive, None)
            self._files[packed] = packed_state
            self._counters["compressed"] += 1
            return {
                "archive": packed,
                "mode": mode,
                "owner": plain.owner,
                "size": plain.size,
            }

    @staticmethod
    def _finding(code: str, detail: dict) -> dict:
        return {"code": code, "detail": detail}

    def verify(self, path: str) -> tuple:
        """Return permission findings for one registered log file."""
        checked = self._absolute_path(path)
        with self._lock:
            if checked not in self._logs:
                self._unknown(checked)
            state = self._files.get(checked)
            policy = self._logs[checked]
            found = []

            if state is None:
                found.append(self._finding(
                    "ROT_FILE_MISSING", {"path": checked}))
                current_generation = 0
            elif state.symlink_target is not None:
                found.append(self._finding(
                    "ROT_SYMLINK",
                    {"path": checked, "target": state.symlink_target}))
                current_generation = state.generation
            else:
                current_generation = state.generation
                owner, group = self._effective_identity(policy)
                expected_mode = self._effective_mode(policy)
                if state.owner != owner or state.group != group:
                    found.append(self._finding(
                        "ROT_OWNER_MISMATCH",
                        {"path": checked, "owner": state.owner,
                         "group": state.group, "expected_owner": owner,
                         "expected_group": group}))
                if state.mode != expected_mode:
                    found.append(self._finding(
                        "ROT_MODE_MISMATCH",
                        {"path": checked, "mode": state.mode,
                         "expected_mode": expected_mode}))

                for number in range(1, current_generation + 1):
                    packed = f"{checked}.{number}.gz"
                    packed_state = self._files.get(packed)
                    if packed_state is None:
                        continue
                    if packed_state.symlink_target is not None:
                        found.append(self._finding(
                            "ROT_SYMLINK",
                            {"path": packed,
                             "target": packed_state.symlink_target}))
                    elif packed_state.mode & ~expected_mode:
                        found.append(self._finding(
                            "ROT_PERM_LOOSER",
                            {"path": packed, "mode": packed_state.mode,
                             "original_mode": expected_mode}))

            if found:
                self._findings[checked] = tuple(found)
            else:
                self._findings.pop(checked, None)
            return tuple(copy.deepcopy(found))

    def report(self) -> dict:
        """Return operation counters and the accumulated findings."""
        with self._lock:
            result = {key: self._counters[key] for key in COUNTER_KEYS}
            result["findings"] = copy.deepcopy(self._findings)
            return result

    def snapshot(self) -> dict:
        """Return a detached snapshot of files, findings and counters."""
        with self._lock:
            return {
                "version": 1,
                "files": {path: asdict(state)
                          for path, state in self._files.items()},
                "logs": copy.deepcopy(self._logs),
                "findings": copy.deepcopy(self._findings),
                "counters": copy.deepcopy(self._counters),
            }

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> None:
        raise RotateError("ROTATE_SNAPSHOT_INVALID", detail)

    @classmethod
    def _restore_file(cls, path: str, value: object) -> FileState:
        if isinstance(value, FileState):
            value = asdict(value)
        if not isinstance(value, dict):
            cls._snapshot_invalid({"path": path})
        required = {field.name for field in fields(FileState)}
        if set(value) != required:
            cls._snapshot_invalid({"path": path})
        try:
            checked = cls._absolute_path(value["path"])
            owner = cls._nonempty_name(value["owner"], "owner")
            group = cls._nonempty_name(value["group"], "group")
            mode = cls._mode_value(value["mode"])
            size = cls._size_value(value["size"])
            inode = value["inode"]
            generation = value["generation"]
            rotation = value["rotation"]
            if (not isinstance(inode, int) or isinstance(inode, bool)
                    or inode <= 0):
                raise ValueError("inode")
            if (not isinstance(generation, int) or isinstance(generation, bool)
                    or generation < 0):
                raise ValueError("generation")
            if rotation not in ("",) + ROTATIONS:
                raise ValueError("rotation")
            for key in ("compress", "world_writable_dir", "immutable"):
                if not isinstance(value[key], bool):
                    raise ValueError(key)
            for key in ("su_user", "su_group"):
                if value[key] is not None:
                    cls._nonempty_name(value[key], key)
            if (value["symlink_target"] is not None
                    and not isinstance(value["symlink_target"], str)):
                raise ValueError("symlink_target")
        except (RotateError, KeyError, TypeError, ValueError):
            cls._snapshot_invalid({"path": path})
        if checked != path:
            cls._snapshot_invalid({"path": path})
        return FileState(
            path=checked,
            owner=owner,
            group=group,
            mode=mode,
            size=size,
            inode=inode,
            generation=generation,
            rotation=rotation,
            compress=value["compress"],
            su_user=value["su_user"],
            su_group=value["su_group"],
            world_writable_dir=value["world_writable_dir"],
            immutable=value["immutable"],
            symlink_target=value["symlink_target"],
        )

    @classmethod
    def _restore_policy(cls, path: str, value: object) -> dict:
        if not isinstance(value, dict) or set(value) != set(POLICY_KEYS):
            cls._snapshot_invalid({"path": path})
        try:
            owner = cls._nonempty_name(value["owner"], "owner")
            group = cls._nonempty_name(value["group"], "group")
            mode = cls._mode_value(value["mode"])
            rotation = cls._rotation_value(value["rotation"])
            su_user = cls._optional_name(value["su_user"], "su_user")
            su_group = cls._optional_name(value["su_group"], "su_group")
            for key in ("world_writable_dir", "immutable", "compress"):
                if not isinstance(value[key], bool):
                    raise ValueError(key)
        except (RotateError, KeyError, TypeError, ValueError):
            cls._snapshot_invalid({"path": path})
        return {
            "owner": owner,
            "group": group,
            "mode": mode,
            "rotation": rotation,
            "su_user": su_user,
            "su_group": su_group,
            "world_writable_dir": value["world_writable_dir"],
            "immutable": value["immutable"],
            "compress": value["compress"],
        }

    @classmethod
    def _restore_findings(cls, value: object) -> dict:
        if not isinstance(value, dict):
            cls._snapshot_invalid({"field": "findings"})
        restored = {}
        for path, items in value.items():
            if not isinstance(path, str) or not isinstance(items, (list, tuple)):
                cls._snapshot_invalid({"field": "findings", "path": path})
            findings = []
            for item in items:
                if (not isinstance(item, dict)
                        or item.get("code") not in FINDING_CODES
                        or not isinstance(item.get("detail"), dict)):
                    cls._snapshot_invalid({"field": "findings",
                                           "path": path})
                findings.append(copy.deepcopy(item))
            restored[path] = tuple(findings)
        return restored

    @classmethod
    def _restore_counters(cls, value: object) -> dict:
        if not isinstance(value, dict) or set(value) != set(COUNTER_KEYS):
            cls._snapshot_invalid({"field": "counters"})
        restored = {}
        for key in COUNTER_KEYS:
            number = value[key]
            if (not isinstance(number, int) or isinstance(number, bool)
                    or number < 0):
                cls._snapshot_invalid({"field": "counters", "key": key})
            restored[key] = number
        return restored

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        required = {"version", "files", "logs", "findings", "counters"}
        if not isinstance(state, dict) or set(state) != required:
            self._snapshot_invalid({"field": "snapshot"})
        if (not isinstance(state["version"], int)
                or isinstance(state["version"], bool)
                or state["version"] != 1):
            self._snapshot_invalid({"field": "version"})
        if not isinstance(state["files"], dict):
            self._snapshot_invalid({"field": "files"})
        if not isinstance(state["logs"], dict):
            self._snapshot_invalid({"field": "logs"})

        restored_files = {}
        for path, value in state["files"].items():
            if not isinstance(path, str):
                self._snapshot_invalid({"field": "files", "path": path})
            restored_files[path] = self._restore_file(path, value)

        restored_logs = {}
        for path, value in state["logs"].items():
            if not isinstance(path, str) or path not in restored_files:
                self._snapshot_invalid({"field": "logs", "path": path})
            restored_logs[path] = self._restore_policy(path, value)
            file_state = restored_files[path]
            policy = restored_logs[path]
            for key in ("rotation", "compress", "su_user", "su_group",
                        "world_writable_dir", "immutable"):
                if getattr(file_state, key) != policy[key]:
                    self._snapshot_invalid({"field": "logs", "path": path})

        restored_findings = self._restore_findings(state["findings"])
        restored_counters = self._restore_counters(state["counters"])
        next_inode = max((item.inode for item in restored_files.values()),
                         default=1000) + 1

        with self._lock:
            self._files = restored_files
            self._logs = restored_logs
            self._findings = restored_findings
            self._counters = restored_counters
            self._next_inode = next_inode
