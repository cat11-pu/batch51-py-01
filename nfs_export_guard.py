"""NFS export table governance.

The guard parses an exports table, resolves the export that governs a mount
request, derives the effective option set for one client and refuses mounts
that would escape the granted options.  Reloads are versioned so a mount
decision always sees one complete table.
"""

from __future__ import annotations

import copy
import ipaddress
import posixpath
import threading
from dataclasses import dataclass

KNOWN_OPTIONS = ("rw", "ro", "sync", "async", "root_squash", "no_root_squash",
                 "all_squash", "no_all_squash", "subtree_check",
                 "no_subtree_check", "secure", "insecure", "nosuid", "noexec")
PSEUDO_ROOTS = ("/proc", "/sys", "/dev")
DEFAULT_OPTIONS = ("ro", "sync", "root_squash", "subtree_check")

_STAT_KEYS = ("loads", "failed_loads", "authorizations", "denials",
              "mounts", "restores")
_OPTION_GROUPS = {
    "rw": "direction",
    "ro": "direction",
    "sync": "sync",
    "async": "sync",
    "root_squash": "root_squash",
    "no_root_squash": "root_squash",
    "all_squash": "all_squash",
    "no_all_squash": "all_squash",
    "subtree_check": "subtree",
    "no_subtree_check": "subtree",
    "secure": "secure",
    "insecure": "secure",
}


class NfsExportError(ValueError):
    """Refusal raised while loading a table or restoring a snapshot."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClientSpec:
    pattern: str
    options: tuple


@dataclass(frozen=True)
class ExportEntry:
    path: str
    clients: tuple
    line: int


@dataclass(frozen=True)
class MountDecision:
    allowed: bool
    reason: str
    path: str
    client_ip: str
    options: tuple
    export_path: str | None
    version: int


@dataclass(frozen=True)
class _MountRecord:
    client_ip: str
    path: str
    export_path: str | None
    version: int
    options: tuple
    valid: bool


class _SnapshotMount(tuple):
    """Public (client_ip, path) pair with detached verification metadata."""

    def __new__(cls, record: _MountRecord):
        instance = super().__new__(
            cls, (record.client_ip, record.path)
        )
        instance.record = record
        return instance

    def __deepcopy__(self, memo):
        return _SnapshotMount(copy.deepcopy(self.record, memo))

    def __reduce__(self):
        return (_SnapshotMount, (self.record,))


def _error(line: int, message: str) -> NfsExportError:
    return NfsExportError(
        "NFS_PARSE_FAILED", {"line": line, "message": message}
    )


def _canonical_path(path: str, *, line: int | None = None) -> str:
    """Return a canonical absolute POSIX path or raise a parse error."""
    if not isinstance(path, str) or not path or "\x00" in path:
        message = "path must be a non-empty absolute path"
        if line is None:
            raise ValueError(message)
        raise _error(line, message)
    if not path.startswith("/"):
        message = "path must be absolute"
        if line is None:
            raise ValueError(message)
        raise _error(line, message)
    normalised = posixpath.normpath(path)
    if normalised.startswith("//"):
        normalised = "/" + normalised.lstrip("/")
    return normalised


def _is_pseudo_path(path: str) -> bool:
    return any(path == root or path.startswith(root + "/")
               for root in PSEUDO_ROOTS)


def _client_kind(pattern: str) -> tuple[str, object] | None:
    """Validate one client selector and return its kind and parsed value."""
    if pattern == "*":
        return ("wildcard", None)
    try:
        if "/" in pattern:
            network = ipaddress.ip_network(pattern, strict=False)
            if network.version != 4:
                return None
            return ("network", network)
        address = ipaddress.ip_address(pattern)
        if address.version != 4:
            return None
        return ("host", address)
    except ValueError:
        return None


def _client_specificity(pattern: str, client_ip: str) -> int:
    kind = _client_kind(pattern)
    if kind is None:
        return 0
    label, value = kind
    if label == "wildcard":
        return 1
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return 0
    if address.version != 4:
        return 0
    if label == "host":
        return 3 if address == value else 0
    return 2 if address in value else 0


def _check_option_conflicts(options: tuple, line: int) -> None:
    explicit = set(options)
    if "all_squash" in explicit and "root_squash" in explicit:
        raise _error(
            line,
            "all_squash and root_squash cannot be used together",
        )


def _parse_client(token: str, line: int) -> ClientSpec:
    if token.count("(") > 1 or token.count(")") > 1:
        raise _error(line, f"malformed client specification: {token!r}")
    if "(" in token:
        opening = token.find("(")
        closing = token.rfind(")")
        if closing != len(token) - 1 or opening > closing:
            raise _error(line, f"malformed client specification: {token!r}")
        pattern = token[:opening]
        option_text = token[opening + 1:closing]
    else:
        if ")" in token:
            raise _error(line, f"malformed client specification: {token!r}")
        pattern = token
        option_text = None

    if not pattern:
        raise _error(line, "client selector is missing")
    if _client_kind(pattern) is None:
        raise _error(line, f"invalid client selector: {pattern!r}")

    if option_text is None or option_text == "":
        options = ()
    else:
        options = tuple(part.strip() for part in option_text.split(","))
        if any(not option for option in options):
            raise _error(line, "option list contains an empty option")
        unknown = [option for option in options if option not in KNOWN_OPTIONS]
        if unknown:
            raise _error(
                line, f"unknown option: {unknown[0]!r}"
            )
    _check_option_conflicts(options, line)
    return ClientSpec(pattern=pattern, options=options)


def _line_tokens(text: str, line: int) -> list[str]:
    tokens = []
    current = []
    depth = 0
    for char in text:
        if char == "#" and depth == 0:
            break
        if char.isspace() and depth == 0:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        if char == "(":
            if depth:
                raise _error(line, "nested parentheses are not allowed")
            depth = 1
        elif char == ")":
            if not depth:
                raise _error(line, "unmatched closing parenthesis")
            depth = 0
        current.append(char)
    if depth:
        raise _error(line, "unclosed parenthesis")
    if current:
        tokens.append("".join(current))
    return tokens


def _parse_exports(text: str) -> tuple:
    if not isinstance(text, str):
        raise _error(0, "export table must be text")

    parsed = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        tokens = _line_tokens(raw_line, line_number)
        if not tokens:
            continue
        if len(tokens) < 2:
            raise _error(line_number, "export has no client selectors")
        if "(" in tokens[0] or ")" in tokens[0]:
            raise _error(line_number, "path must not contain parentheses")

        path = _canonical_path(tokens[0], line=line_number)
        if _is_pseudo_path(path):
            raise NfsExportError(
                "NFS_PSEUDO_PATH",
                {
                    "line": line_number,
                    "message": f"pseudo filesystem path cannot be exported: {path}",
                },
            )

        clients = tuple(
            _parse_client(token, line_number) for token in tokens[1:]
        )
        parsed.append(ExportEntry(
            path=path, clients=clients, line=line_number
        ))
    return tuple(parsed)


def _select_client(entry: ExportEntry,
                   client_ip: str) -> tuple[ClientSpec | None, int]:
    best = None
    best_score = 0
    for spec in entry.clients:
        score = _client_specificity(spec.pattern, client_ip)
        if score > best_score:
            best = spec
            best_score = score
    return best, best_score


def _path_depth(path: str) -> int:
    return len(tuple(part for part in path.split("/") if part))


def _path_contains(export_path: str, request_path: str) -> bool:
    if export_path == "/":
        return request_path.startswith("/")
    return (request_path == export_path
            or request_path.startswith(export_path + "/"))


def _resolve_options(raw_options: tuple) -> tuple:
    selected: dict[str, str] = {}
    standalone = set()
    for option in raw_options:
        group = _OPTION_GROUPS.get(option)
        if group is None:
            standalone.add(option)
        else:
            selected[group] = option

    if "direction" not in selected:
        selected["direction"] = "ro"
    if "sync" not in selected:
        selected["sync"] = "sync"
    if ("root_squash" not in selected
            and selected.get("all_squash") != "all_squash"):
        selected["root_squash"] = "root_squash"
    if "subtree" not in selected:
        selected["subtree"] = "subtree_check"

    return tuple(sorted(standalone.union(selected.values())))


def _parent_path(path: str) -> str | None:
    if path == "/":
        return None
    parent = posixpath.dirname(path)
    return parent or "/"


class NfsExportGuard:
    """Resolve exports, options and mount authorisations for NFS clients."""

    def __init__(self, source: str = "/etc/exports") -> None:
        self.source = source
        self._lock = threading.RLock()
        self._version = 0
        self._entries = ()
        self._mounts: list[_MountRecord] = []
        self._stats = {"loads": 0, "failed_loads": 0, "authorizations": 0,
                       "denials": 0, "mounts": 0, "restores": 0}

    def load_exports(self, text: str, *, source: str | None = None) -> int:
        """Parse ``text``, install the table and return the new version."""
        try:
            parsed = _parse_exports(text)
        except NfsExportError:
            with self._lock:
                self._stats["failed_loads"] += 1
            raise

        with self._lock:
            self._entries = parsed
            self._version += 1
            self._stats["loads"] += 1
            if source is not None:
                self.source = source
            return self._version

    def entries(self) -> tuple:
        """Return the installed export entries in file order."""
        with self._lock:
            return self._entries

    def current_version(self) -> int:
        """Return the installed table version (0 before the first load)."""
        with self._lock:
            return self._version

    def match_export(self, path: str, client_ip: str) -> ExportEntry | None:
        """Return the most specific export governing ``path`` for the client."""
        try:
            request_path = _canonical_path(path)
        except ValueError:
            return None
        with self._lock:
            return self._match_export_locked(request_path, client_ip)

    def _match_export_locked(self, path: str,
                             client_ip: str) -> ExportEntry | None:
        best = None
        best_key = None
        for index, entry in enumerate(self._entries):
            if not _path_contains(entry.path, path):
                continue
            _, score = _select_client(entry, client_ip)
            if not score:
                continue
            key = (_path_depth(entry.path), score, -index)
            if best_key is None or key > best_key:
                best = entry
                best_key = key
        return best

    def specificity(self, entry: ExportEntry, client_ip: str) -> int:
        """Rank how specifically ``entry`` names ``client_ip``."""
        _, score = _select_client(entry, client_ip)
        return score

    def effective_options(self, path: str, client_ip: str) -> tuple:
        """Return the effective options of ``path`` for the client, sorted."""
        try:
            request_path = _canonical_path(path)
        except ValueError:
            return ()
        with self._lock:
            entry = self._match_export_locked(request_path, client_ip)
            if entry is None:
                return ()
            spec, _ = _select_client(entry, client_ip)
            if spec is None:
                return ()
            return _resolve_options(spec.options)

    def _subtree_available(self, request_path: str, export_path: str,
                           client_ip: str) -> bool:
        if request_path == export_path:
            return True
        parent = _parent_path(request_path)
        if parent is None:
            return False
        return self._match_export_locked(parent, client_ip) is not None

    def authorize(self, *, path: str, client_ip: str,
                  request: str = "ro") -> MountDecision:
        """Decide whether the client may mount ``path`` with ``request``."""
        try:
            request_path = _canonical_path(path)
        except ValueError:
            request_path = None

        with self._lock:
            version = self._version
            entry = None
            if request_path is not None:
                entry = self._match_export_locked(request_path, client_ip)

            if entry is None or request_path is None:
                self._stats["denials"] += 1
                return MountDecision(
                    allowed=False,
                    reason="NO_EXPORT",
                    path=path,
                    client_ip=client_ip,
                    options=(),
                    export_path=None,
                    version=version,
                )

            spec, _ = _select_client(entry, client_ip)
            if spec is None:
                self._stats["denials"] += 1
                return MountDecision(
                    allowed=False,
                    reason="NO_EXPORT",
                    path=path,
                    client_ip=client_ip,
                    options=(),
                    export_path=None,
                    version=version,
                )

            options = _resolve_options(spec.options)
            if request == "rw" and "rw" not in options:
                self._stats["denials"] += 1
                return MountDecision(
                    allowed=False,
                    reason="READ_ONLY",
                    path=path,
                    client_ip=client_ip,
                    options=options,
                    export_path=entry.path,
                    version=version,
                )

            if ("subtree_check" in options
                    and not self._subtree_available(
                        request_path, entry.path, client_ip
                    )):
                self._stats["denials"] += 1
                return MountDecision(
                    allowed=False,
                    reason="SUBTREE_UNREACHABLE",
                    path=path,
                    client_ip=client_ip,
                    options=options,
                    export_path=entry.path,
                    version=version,
                )

            self._stats["authorizations"] += 1
            return MountDecision(
                allowed=True,
                reason="OK",
                path=path,
                client_ip=client_ip,
                options=options,
                export_path=entry.path,
                version=version,
            )

    def register_mount(self, *, client_ip: str, path: str) -> None:
        """Record that the client currently has ``path`` mounted."""
        try:
            request_path = _canonical_path(path)
        except ValueError:
            request_path = None

        with self._lock:
            entry = None
            options = ()
            valid = False
            if request_path is not None:
                entry = self._match_export_locked(request_path, client_ip)
                if entry is not None:
                    spec, _ = _select_client(entry, client_ip)
                    if spec is not None:
                        options = _resolve_options(spec.options)
                        valid = True
                        if ("subtree_check" in options
                                and not self._subtree_available(
                                    request_path, entry.path, client_ip
                                )):
                            valid = False
            self._mounts.append(_MountRecord(
                client_ip=client_ip,
                path=path,
                export_path=None if entry is None else entry.path,
                version=self._version,
                options=options,
                valid=valid,
            ))
            self._stats["mounts"] += 1

    def verify_mount(self, *, client_ip: str, path: str) -> bool:
        """Re-check a recorded mount against the installed table."""
        try:
            request_path = _canonical_path(path)
        except ValueError:
            return False

        with self._lock:
            candidates = []
            for record in self._mounts:
                if record.client_ip != client_ip:
                    continue
                try:
                    recorded_path = _canonical_path(record.path)
                except ValueError:
                    continue
                if recorded_path == request_path:
                    candidates.append(record)
            if not candidates:
                return False

            for record in candidates:
                if not record.valid or record.version != self._version:
                    continue
                entry = self._match_export_locked(request_path, client_ip)
                if entry is None or entry.path != record.export_path:
                    continue
                options = _resolve_options(
                    _select_client(entry, client_ip)[0].options
                )
                if options != record.options:
                    continue
                if ("subtree_check" in options
                        and not self._subtree_available(
                            request_path, entry.path, client_ip
                        )):
                    continue
                return True
            return False

    def mounts(self) -> tuple:
        """Return the recorded mounts in registration order."""
        with self._lock:
            return tuple((record.client_ip, record.path)
                         for record in self._mounts)

    def audit(self) -> dict:
        """Summarise the installed table: pseudo paths, duplicates, conflicts."""
        with self._lock:
            by_path: dict[str, list[int]] = {}
            for entry in self._entries:
                by_path.setdefault(entry.path, []).append(entry.line)
            duplicate_details = [
                {"path": path, "lines": tuple(lines)}
                for path, lines in by_path.items() if len(lines) > 1
            ]
            duplicates = [item["path"] for item in duplicate_details]
            pseudo_paths = [
                entry.path for entry in self._entries
                if _is_pseudo_path(entry.path)
            ]
            conflicts = []
            for entry in self._entries:
                for spec in entry.clients:
                    try:
                        _check_option_conflicts(spec.options, entry.line)
                    except NfsExportError as exc:
                        conflicts.append({
                            "path": entry.path,
                            "line": entry.line,
                            "client": spec.pattern,
                            "message": exc.detail["message"],
                        })
            return {
                "source": self.source,
                "version": self._version,
                "entry_count": len(self._entries),
                "client_count": sum(
                    len(entry.clients) for entry in self._entries
                ),
                "pseudo_paths": pseudo_paths,
                "duplicates": list(duplicates),
                "duplicate_paths": list(duplicates),
                "duplicate_details": duplicate_details,
                "conflicts": conflicts,
            }

    def snapshot(self) -> dict:
        """Return a detached snapshot of the table, mounts and counters."""
        with self._lock:
            return {
                "version": self._version,
                "entries": copy.deepcopy(self._entries),
                "mounts": tuple(
                    copy.deepcopy(_SnapshotMount(record))
                    for record in self._mounts
                ),
                "stats": copy.deepcopy(self._stats),
            }

    def _restore_entries(self, raw_entries: object) -> tuple:
        if not isinstance(raw_entries, (tuple, list)):
            raise ValueError("entries must be a sequence")

        restored = []
        for raw_entry in raw_entries:
            if isinstance(raw_entry, ExportEntry):
                raw_path = raw_entry.path
                raw_clients = raw_entry.clients
                raw_line = raw_entry.line
            elif isinstance(raw_entry, dict):
                if not {"path", "clients", "line"} <= set(raw_entry):
                    raise ValueError("invalid entry structure")
                raw_path = raw_entry["path"]
                raw_clients = raw_entry["clients"]
                raw_line = raw_entry["line"]
            elif isinstance(raw_entry, (tuple, list)) and len(raw_entry) == 3:
                raw_path, raw_clients, raw_line = raw_entry
            else:
                raise ValueError("invalid entry structure")

            if (not isinstance(raw_path, str)
                    or isinstance(raw_line, bool)
                    or not isinstance(raw_line, int)
                    or raw_line < 1):
                raise ValueError("invalid entry metadata")
            path = _canonical_path(raw_path)
            if _is_pseudo_path(path):
                raise ValueError("pseudo path in snapshot")
            if not isinstance(raw_clients, (tuple, list)) or not raw_clients:
                raise ValueError("entry must contain clients")

            clients = []
            for raw_client in raw_clients:
                if isinstance(raw_client, ClientSpec):
                    pattern = raw_client.pattern
                    raw_options = raw_client.options
                elif isinstance(raw_client, dict):
                    if not {"pattern", "options"} <= set(raw_client):
                        raise ValueError("invalid client structure")
                    pattern = raw_client["pattern"]
                    raw_options = raw_client["options"]
                elif (isinstance(raw_client, (tuple, list))
                      and len(raw_client) == 2):
                    pattern, raw_options = raw_client
                else:
                    raise ValueError("invalid client structure")

                if (not isinstance(pattern, str)
                        or _client_kind(pattern) is None):
                    raise ValueError("invalid client selector")
                if not isinstance(raw_options, (tuple, list)):
                    raise ValueError("client options must be a sequence")
                options = tuple(raw_options)
                if any(not isinstance(option, str)
                       or option not in KNOWN_OPTIONS for option in options):
                    raise ValueError("invalid client option")
                _check_option_conflicts(options, raw_line)
                clients.append(ClientSpec(
                    pattern=pattern,
                    options=options,
                ))
            restored.append(ExportEntry(
                path=path,
                clients=tuple(clients),
                line=raw_line,
            ))
        return tuple(restored)

    @staticmethod
    def _restore_mounts(raw_mounts: object) -> tuple:
        if not isinstance(raw_mounts, (tuple, list)):
            raise ValueError("mounts must be a sequence")
        restored = []
        for raw_mount in raw_mounts:
            if isinstance(raw_mount, _SnapshotMount):
                source = raw_mount.record
                if not isinstance(source, _MountRecord):
                    raise ValueError("invalid mount metadata")
                client_ip = source.client_ip
                path = source.path
                export_path = source.export_path
                version = source.version
                options = source.options
                valid = source.valid
            elif isinstance(raw_mount, _MountRecord):
                source = raw_mount
                client_ip = source.client_ip
                path = source.path
                export_path = source.export_path
                version = source.version
                options = source.options
                valid = source.valid
            elif (isinstance(raw_mount, (tuple, list))
                    and len(raw_mount) == 2):
                client_ip, path = raw_mount
                export_path = None
                version = None
                options = ()
                valid = None
            elif isinstance(raw_mount, dict):
                if not {"client_ip", "path"} <= set(raw_mount):
                    raise ValueError("invalid mount structure")
                client_ip = raw_mount["client_ip"]
                path = raw_mount["path"]
                export_path = raw_mount.get("export_path")
                version = raw_mount.get("version")
                options = raw_mount.get("options", ())
                valid = raw_mount.get("valid")
            else:
                raise ValueError("invalid mount structure")
            if not isinstance(client_ip, str) or not isinstance(path, str):
                raise ValueError("invalid mount data")
            if export_path is not None and not isinstance(export_path, str):
                raise ValueError("invalid mount export path")
            if (version is not None
                    and (isinstance(version, bool)
                         or not isinstance(version, int)
                         or version < 0)):
                raise ValueError("invalid mount version")
            if not isinstance(options, (tuple, list)):
                raise ValueError("invalid mount options")
            options = tuple(options)
            if any(not isinstance(option, str)
                   or option not in KNOWN_OPTIONS for option in options):
                raise ValueError("invalid mount option")
            if valid is not None and not isinstance(valid, bool):
                raise ValueError("invalid mount validity")
            restored.append((
                client_ip, path, export_path, version, options, valid,
            ))
        return tuple(restored)

    @staticmethod
    def _restore_stats(raw_stats: object) -> dict:
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(_STAT_KEYS):
            raise ValueError("invalid stats structure")
        restored = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if (isinstance(value, bool) or not isinstance(value, int)
                    or value < 0):
                raise ValueError(f"invalid stat: {key}")
            restored[key] = value
        return restored

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        try:
            if not isinstance(state, dict):
                raise ValueError("snapshot must be a mapping")
            if set(state) != {"version", "entries", "mounts", "stats"}:
                raise ValueError("snapshot has an invalid structure")
            version = state["version"]
            if (isinstance(version, bool) or not isinstance(version, int)
                    or version < 0):
                raise ValueError("invalid version")
            entries = self._restore_entries(state["entries"])
            restored_mounts = self._restore_mounts(state["mounts"])
            stats = self._restore_stats(state["stats"])
        except (KeyError, TypeError, ValueError, NfsExportError) as exc:
            detail = {"message": str(exc)}
            raise NfsExportError("NFS_SNAPSHOT_INVALID", detail) from exc

        rebuilt_mounts = []
        for (client_ip, path, export_path, mount_version,
             mount_options, mount_valid) in restored_mounts:
            if mount_version is not None:
                rebuilt_mounts.append(_MountRecord(
                    client_ip=client_ip,
                    path=path,
                    export_path=export_path,
                    version=mount_version,
                    options=mount_options,
                    valid=bool(mount_valid),
                ))
                continue
            try:
                request_path = _canonical_path(path)
            except ValueError:
                request_path = None
            entry = None
            if request_path is not None:
                entry = self._match_export_in(entries, request_path, client_ip)
            options = ()
            valid = False
            if entry is not None:
                spec, _ = _select_client(entry, client_ip)
                if spec is not None:
                    options = _resolve_options(spec.options)
                    valid = True
                    if ("subtree_check" in options
                            and not self._subtree_available_in(
                                entries, request_path, entry.path, client_ip
                            )):
                        valid = False
            rebuilt_mounts.append(_MountRecord(
                client_ip=client_ip,
                path=path,
                export_path=None if entry is None else entry.path,
                version=version,
                options=options,
                valid=valid,
            ))

        with self._lock:
            self._version = version
            self._entries = entries
            self._mounts = rebuilt_mounts
            self._stats = stats

    @staticmethod
    def _match_export_in(entries: tuple, path: str,
                         client_ip: str) -> ExportEntry | None:
        best = None
        best_key = None
        for index, entry in enumerate(entries):
            if not _path_contains(entry.path, path):
                continue
            _, score = _select_client(entry, client_ip)
            if not score:
                continue
            key = (_path_depth(entry.path), score, -index)
            if best_key is None or key > best_key:
                best = entry
                best_key = key
        return best

    @staticmethod
    def _subtree_available_in(entries: tuple, request_path: str,
                              export_path: str, client_ip: str) -> bool:
        if request_path == export_path:
            return True
        parent = _parent_path(request_path)
        if parent is None:
            return False
        return NfsExportGuard._match_export_in(
            entries, parent, client_ip
        ) is not None

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return dict(self._stats)
