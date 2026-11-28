"""sshd configuration effective-value auditor.

The auditor parses an sshd-style configuration text into directives and
``Match`` blocks, derives the values that are effective for a connection
context, adjudicates algorithm lists against a whitelist and produces an
audit report.  Reloads are versioned so that concurrent audits always observe
one complete configuration.
"""

from __future__ import annotations

import copy
import fnmatch
import glob
import ipaddress
import os
import shlex
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

ALGORITHM_KEYWORDS = ("ciphers", "macs", "kexalgorithms")
MATCH_KEYS = ("user", "group", "address", "localport")
CHECK_ORDER = ("permitrootlogin", "passwordauthentication", "maxauthtries", "ciphers")


class SshdAuditError(ValueError):
    """Refusal raised by the auditor.

    ``code`` distinguishes a syntax problem (``SSHD_PARSE_FAILED``) from a
    policy refusal (``SSHD_POLICY_REFUSED``) or a bad snapshot
    (``SSHD_SNAPSHOT_INVALID``).
    """

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Directive:
    keyword: str
    value: str
    line: int
    block: int


@dataclass(frozen=True)
class MatchBlock:
    index: int
    criteria: tuple
    line: int


@dataclass(frozen=True)
class ParsedConfig:
    source: str
    directives: tuple
    matches: tuple


@dataclass(frozen=True)
class ConfigChange:
    keyword: str
    before: str | None
    after: str | None


@dataclass(frozen=True)
class AuditFinding:
    keyword: str
    effective: str | None
    verdict: str
    reason: str


@dataclass(frozen=True)
class AuditReport:
    version: int
    context: dict
    findings: tuple
    verdict: str
    counts: dict


class SshdConfigAuditor:
    """Audit effective sshd settings for a connection context."""

    def __init__(self, *, config_dir: str = "/etc/ssh", defaults=None,
                 strict_ciphers=None, max_auth_tries: int = 3,
                 max_include_depth: int = 8, include_reader=None) -> None:
        self.config_dir = os.fspath(config_dir)
        self.defaults = {
            str(keyword).lower(): tuple(values)
            for keyword, values in dict(defaults or {}).items()
        }
        if strict_ciphers is None:
            self.strict_ciphers = ()
        elif isinstance(strict_ciphers, str):
            self.strict_ciphers = (strict_ciphers,)
        else:
            self.strict_ciphers = tuple(strict_ciphers)
        self.max_auth_tries = max_auth_tries
        self.max_include_depth = max_include_depth
        self._include_reader = include_reader
        self._lock = threading.RLock()
        self._version = 0
        self._config = None
        self._stats = {"parses": 0, "reloads": 0, "failed_reloads": 0,
                       "audits": 0, "restores": 0}

    def parse_config(self, text: str, *, source: str = "<inline>") -> ParsedConfig:
        """Parse ``text`` into a :class:`ParsedConfig` without installing it."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        source = os.fspath(source)
        with self._lock:
            self._stats["parses"] += 1
        parser = _ConfigParser(self, source)
        return parser.parse(text)

    def effective_value(self, keyword: str, *, context=None) -> str | None:
        """Return the winning raw value for ``keyword`` in ``context``."""
        keyword = str(keyword).lower()
        with self._lock:
            config = self._config
            if config is None:
                return None
            return self._effective_value(config, keyword, context)

    def effective_list(self, keyword: str, *, context=None) -> tuple:
        """Return the comma separated value of ``keyword`` as a token tuple."""
        value = self.effective_value(keyword, context=context)
        if value is None:
            return ()
        return _split_list(value)

    def effective_config(self, *, context=None) -> dict:
        """Return every keyword with its winning raw value."""
        with self._lock:
            config = self._config
            if config is None:
                return {}
            keywords = {
                directive.keyword
                for directive in config.directives
                if directive.block == -1
                or self._block_applies(config, directive.block, context)
            }
            return {
                keyword: self._effective_value(config, keyword, context)
                for keyword in sorted(keywords)
            }

    def match_applies(self, block_index: int, *, context) -> bool:
        """Report whether the match block at ``block_index`` applies."""
        with self._lock:
            config = self._config
            if config is None:
                return False
            for block in config.matches:
                if block.index == block_index:
                    return self._match_applies(block, context)
            return False

    def audit(self, *, context=None) -> AuditReport:
        """Produce an audit report for the installed configuration."""
        context_copy = copy.deepcopy(dict(context or {}))
        with self._lock:
            version = self._version
            findings = tuple(
                self._audit_finding(keyword, context)
                for keyword in CHECK_ORDER
            )
            counts = {
                "ok": sum(finding.verdict == "ok" for finding in findings),
                "deny": sum(finding.verdict == "deny" for finding in findings),
            }
            report = AuditReport(
                version=version,
                context=context_copy,
                findings=findings,
                verdict="allow" if counts["deny"] == 0 else "deny",
                counts=counts,
            )
            self._stats["audits"] += 1
            return report

    def require_compliant(self, *, context=None) -> AuditReport:
        """Return the report or raise a policy refusal."""
        report = self.audit(context=context)
        if report.verdict == "deny":
            failed = tuple(
                finding.keyword
                for finding in report.findings
                if finding.verdict == "deny"
            )
            raise SshdAuditError(
                "SSHD_POLICY_REFUSED",
                {"failed": failed},
            )
        return report

    def diff(self, other: ParsedConfig) -> tuple:
        """Compare the installed global values against ``other``."""
        if not isinstance(other, ParsedConfig):
            raise TypeError("other must be a ParsedConfig")
        with self._lock:
            current = self._global_values(self._config)
        incoming = self._global_values(other)
        changes = []
        for keyword in sorted(set(current) | set(incoming)):
            before = current.get(keyword)
            after = incoming.get(keyword)
            if before != after:
                changes.append(ConfigChange(keyword, before, after))
        return tuple(changes)

    def reload(self, text: str, *, source: str = "<inline>") -> int:
        """Parse and atomically install ``text``; return the new version."""
        try:
            parsed = self.parse_config(text, source=source)
        except SshdAuditError:
            with self._lock:
                self._stats["failed_reloads"] += 1
            raise
        with self._lock:
            self._config = parsed
            self._version += 1
            self._stats["reloads"] += 1
            return self._version

    def current_version(self) -> int:
        """Return the installed configuration version (0 before first load)."""
        with self._lock:
            return self._version

    def snapshot(self) -> dict:
        """Return a detached snapshot of version, configuration and counters."""
        with self._lock:
            state = {
                "version": self._version,
                "config": self._serialize_config(self._config),
                "stats": copy.deepcopy(self._stats),
            }
        return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        restored = self._validated_snapshot(state)
        with self._lock:
            self._version = restored["version"]
            self._config = restored["config"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return copy.deepcopy(self._stats)

    def _effective_value(self, config: ParsedConfig, keyword: str,
                         context) -> str | None:
        value = None
        for directive in config.directives:
            if directive.block == -1 and directive.keyword == keyword:
                value = directive.value

        for block in config.matches:
            if not self._match_applies(block, context):
                continue
            block_value = None
            for directive in config.directives:
                if directive.block == block.index and directive.keyword == keyword:
                    block_value = directive.value
            if block_value is not None:
                value = block_value

        if keyword in ALGORITHM_KEYWORDS and value is not None:
            return self._validate_algorithm_value(keyword, value)
        return value

    def _validate_algorithm_value(self, keyword: str, value: str) -> str:
        allowed = self.defaults.get(keyword, ())
        pieces = value.split(",")
        tokens = [piece.strip() for piece in pieces]
        if tokens and all(token and token in allowed for token in tokens):
            return value
        return ",".join(str(item) for item in allowed)

    def _block_applies(self, config: ParsedConfig, block_index: int,
                       context) -> bool:
        for block in config.matches:
            if block.index == block_index:
                return self._match_applies(block, context)
        return False

    def _match_applies(self, block: MatchBlock, context) -> bool:
        values = _lower_context(context)
        for key, criterion in block.criteria:
            if key == "user":
                if not _value_matches(values.get("user"), criterion, wildcard=True):
                    return False
            elif key == "group":
                group_value = values.get("group", values.get("groups"))
                if not _value_matches(group_value, criterion, wildcard=True):
                    return False
            elif key == "address":
                if not _address_matches(values.get("address"), criterion):
                    return False
            elif key == "localport":
                localport = values.get("localport")
                if localport is None or str(localport) != criterion:
                    return False
            else:
                return False
        return True

    def _audit_finding(self, keyword: str, context) -> AuditFinding:
        effective = self.effective_value(keyword, context=context)
        if keyword == "permitrootlogin":
            ok = effective is not None and effective.lower() == "no"
            reason = "root login is disabled" if ok else "permitrootlogin must be no"
        elif keyword == "passwordauthentication":
            ok = effective is not None and effective.lower() == "no"
            reason = (
                "password authentication is disabled"
                if ok else "passwordauthentication must be no"
            )
        elif keyword == "maxauthtries":
            try:
                attempts = int(effective) if effective is not None else None
            except (TypeError, ValueError):
                attempts = None
            ok = (
                attempts is not None
                and attempts >= 0
                and attempts <= int(self.max_auth_tries)
            )
            reason = (
                f"maxauthtries is at most {self.max_auth_tries}"
                if ok else f"maxauthtries must be at most {self.max_auth_tries}"
            )
        else:
            ciphers = self.effective_list(keyword, context=context)
            ok = bool(ciphers) and all(
                cipher in self.strict_ciphers for cipher in ciphers
            )
            reason = (
                "ciphers are restricted"
                if ok else "ciphers must only contain strict allowed values"
            )
        return AuditFinding(
            keyword=keyword,
            effective=effective,
            verdict="ok" if ok else "deny",
            reason=reason,
        )

    def _global_values(self, config: ParsedConfig | None) -> dict:
        if config is None:
            return {}
        values = {}
        for directive in config.directives:
            if directive.block == -1:
                values[directive.keyword] = directive.value
        for keyword in ALGORITHM_KEYWORDS:
            if keyword in values:
                values[keyword] = self._validate_algorithm_value(
                    keyword, values[keyword]
                )
        return values

    def _serialize_config(self, config: ParsedConfig | None) -> dict:
        if config is None:
            return {}
        return {
            "source": config.source,
            "directives": [
                {
                    "keyword": directive.keyword,
                    "value": directive.value,
                    "line": directive.line,
                    "block": directive.block,
                }
                for directive in config.directives
            ],
            "matches": [
                {
                    "index": block.index,
                    "criteria": [list(pair) for pair in block.criteria],
                    "line": block.line,
                }
                for block in config.matches
            ],
        }

    def _validated_snapshot(self, state) -> dict:
        invalid = "snapshot must contain version, config and stats"
        if not isinstance(state, Mapping):
            raise SshdAuditError("SSHD_SNAPSHOT_INVALID", {"message": invalid})

        try:
            copied = copy.deepcopy(dict(state))
        except Exception as exc:
            raise SshdAuditError(
                "SSHD_SNAPSHOT_INVALID",
                {"message": f"snapshot cannot be copied: {exc}"},
            ) from exc

        if set(copied) != {"version", "config", "stats"}:
            raise SshdAuditError("SSHD_SNAPSHOT_INVALID", {"message": invalid})

        version = copied["version"]
        config_data = copied["config"]
        stats_data = copied["stats"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 0
        ):
            raise SshdAuditError(
                "SSHD_SNAPSHOT_INVALID",
                {"message": "version must be a non-negative integer"},
            )
        if not isinstance(config_data, Mapping):
            raise SshdAuditError(
                "SSHD_SNAPSHOT_INVALID",
                {"message": "config must be a mapping"},
            )
        if not isinstance(stats_data, Mapping):
            raise SshdAuditError(
                "SSHD_SNAPSHOT_INVALID",
                {"message": "stats must be a mapping"},
            )

        expected_stats = {
            "parses", "reloads", "failed_reloads", "audits", "restores"
        }
        if set(stats_data) != expected_stats:
            raise SshdAuditError(
                "SSHD_SNAPSHOT_INVALID",
                {"message": "stats has invalid counters"},
            )
        stats = {}
        for name in expected_stats:
            count = stats_data[name]
            if (
                not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
            ):
                raise SshdAuditError(
                    "SSHD_SNAPSHOT_INVALID",
                    {"message": f"stats.{name} must be a non-negative integer"},
                )
            stats[name] = count

        if not config_data:
            if version != 0:
                raise SshdAuditError(
                    "SSHD_SNAPSHOT_INVALID",
                    {"message": "an installed version requires a config"},
                )
            config = None
        else:
            config = self._deserialize_config(config_data)
            if version == 0:
                raise SshdAuditError(
                    "SSHD_SNAPSHOT_INVALID",
                    {"message": "a config requires a non-zero version"},
                )

        return {"version": version, "config": config, "stats": stats}

    def _deserialize_config(self, data: Mapping) -> ParsedConfig:
        def fail(message: str):
            raise SshdAuditError(
                "SSHD_SNAPSHOT_INVALID",
                {"message": message},
            )

        if set(data) != {"source", "directives", "matches"}:
            fail("config has invalid keys")
        source = data["source"]
        directives_data = data["directives"]
        matches_data = data["matches"]
        if not isinstance(source, str):
            fail("config.source must be a string")
        if not _is_sequence(directives_data):
            fail("config.directives must be a sequence")
        if not _is_sequence(matches_data):
            fail("config.matches must be a sequence")

        directives = []
        for item in directives_data:
            if not isinstance(item, Mapping):
                fail("config directive must be a mapping")
            if set(item) != {"keyword", "value", "line", "block"}:
                fail("config directive has invalid keys")
            keyword = item["keyword"]
            value = item["value"]
            line = item["line"]
            block = item["block"]
            if not isinstance(keyword, str) or keyword != keyword.lower() or not keyword:
                fail("directive keyword is invalid")
            if not isinstance(value, str):
                fail("directive value is invalid")
            if not _is_positive_int(line):
                fail("directive line is invalid")
            if not isinstance(block, int) or isinstance(block, bool) or block < -1:
                fail("directive block is invalid")
            directives.append(Directive(keyword, value, line, block))

        matches = []
        for item in matches_data:
            if not isinstance(item, Mapping):
                fail("config match must be a mapping")
            if set(item) != {"index", "criteria", "line"}:
                fail("config match has invalid keys")
            index = item["index"]
            criteria_data = item["criteria"]
            line = item["line"]
            if not isinstance(index, int) or isinstance(index, bool) or index < 0:
                fail("match index is invalid")
            if not _is_positive_int(line):
                fail("match line is invalid")
            if not _is_sequence(criteria_data):
                fail("match criteria must be a sequence")
            criteria = []
            for pair in criteria_data:
                if not _is_sequence(pair) or len(pair) != 2:
                    fail("match criterion is invalid")
                key, value = pair
                if key not in MATCH_KEYS or not isinstance(value, str):
                    fail("match criterion is invalid")
                criteria.append((key, value))
            matches.append(MatchBlock(index, tuple(criteria), line))

        match_indexes = [block.index for block in matches]
        if match_indexes != list(range(len(matches))):
            fail("match indexes must be contiguous")
        for directive in directives:
            if directive.block >= len(matches):
                fail("directive refers to an unknown match block")
        return ParsedConfig(source, tuple(directives), tuple(matches))


class _ConfigParser:
    def __init__(self, auditor: SshdConfigAuditor, source: str) -> None:
        self.auditor = auditor
        self.source = source
        self.directives = []
        self.matches = []
        self._next_match_index = 0

    def parse(self, text: str) -> ParsedConfig:
        stack = []
        source_path = self._canonical_source(self.source)
        if source_path is not None:
            stack.append(source_path)
        self._parse_text(text, self.source, -1, 0, stack)
        return ParsedConfig(
            source=self.source,
            directives=tuple(self.directives),
            matches=tuple(self.matches),
        )

    def _parse_text(self, text: str, source: str, current_block: int,
                    depth: int, stack: list[str]) -> None:
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            line = _strip_comment(raw_line).strip()
            if not line:
                continue

            parts = line.split(None, 1)
            head = parts[0]
            rest = parts[1].strip() if len(parts) > 1 else ""
            if "=" in head:
                keyword, attached = head.split("=", 1)
                value = attached
                if rest:
                    value = f"{value} {rest}" if value else rest
                keyword = keyword.strip()
            elif rest.startswith("="):
                keyword = head
                value = rest[1:].strip()
            else:
                keyword = head
                value = rest
            keyword = keyword.lower()

            if keyword == "match":
                self._parse_match(value, line_number, source)
                current_block = self._next_match_index - 1
                continue

            if not value:
                self._parse_error(
                    line_number,
                    f"{keyword} requires a value",
                    source,
                )

            if keyword == "include":
                self._parse_include(
                    value, line_number, source, current_block, depth, stack
                )
                continue

            self.directives.append(
                Directive(keyword, value, line_number, current_block)
            )

    def _parse_match(self, value: str, line_number: int, source: str) -> None:
        if not value:
            self._parse_error(
                line_number,
                "Match requires at least one criterion",
                source,
            )
        try:
            tokens = shlex.split(value)
        except ValueError as exc:
            self._parse_error(line_number, f"invalid Match criteria: {exc}", source)

        criteria = []
        position = 0
        while position < len(tokens):
            token = tokens[position]
            if "=" in token:
                key, criterion_value = token.split("=", 1)
                position += 1
            else:
                key = token
                if position + 1 >= len(tokens):
                    self._parse_error(
                        line_number,
                        f"Match criterion {key.lower()} requires a value",
                        source,
                    )
                criterion_value = tokens[position + 1]
                position += 2
            key = key.lower()
            if key not in MATCH_KEYS:
                self._parse_error(
                    line_number,
                    f"unsupported Match criterion: {key}",
                    source,
                )
            if not criterion_value:
                self._parse_error(
                    line_number,
                    f"Match criterion {key} requires a value",
                    source,
                )
            criteria.append((key, criterion_value))

        if not criteria:
            self._parse_error(
                line_number,
                "Match requires at least one criterion",
                source,
            )
        self.matches.append(
            MatchBlock(self._next_match_index, tuple(criteria), line_number)
        )
        self._next_match_index += 1

    def _parse_include(self, value: str, line_number: int, source: str,
                       current_block: int, depth: int, stack: list[str]) -> None:
        try:
            patterns = shlex.split(value)
        except ValueError as exc:
            self._parse_error(
                line_number, f"invalid Include path: {exc}", source
            )
        if not patterns:
            self._parse_error(
                line_number, "Include requires a path", source
            )

        for pattern in patterns:
            resolved_pattern = pattern
            if not os.path.isabs(resolved_pattern):
                resolved_pattern = os.path.join(
                    self.auditor.config_dir, resolved_pattern
                )

            paths = sorted(glob.glob(resolved_pattern)) if glob.has_magic(
                resolved_pattern
            ) else [resolved_pattern]
            if not paths and self.auditor._include_reader is not None:
                paths = [resolved_pattern]
            if not paths:
                self._parse_error(
                    line_number,
                    f"included path not found: {pattern}",
                    source,
                )

            for path in paths:
                canonical = _canonical_path(path)
                if canonical in stack:
                    self._parse_error(
                        line_number,
                        f"include cycle detected: {pattern}",
                        source,
                    )
                if depth + 1 > self.auditor.max_include_depth:
                    self._parse_error(
                        line_number,
                        f"maximum include depth exceeded: {pattern}",
                        source,
                    )
                try:
                    included_text = self._read_include(path)
                except Exception as exc:
                    self._parse_error(
                        line_number,
                        f"failed to read include {pattern}: {exc}",
                        source,
                    )
                if isinstance(included_text, bytes):
                    try:
                        included_text = included_text.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        self._parse_error(
                            line_number,
                            f"failed to decode include {pattern}: {exc}",
                            source,
                        )
                if not isinstance(included_text, str):
                    self._parse_error(
                        line_number,
                        f"include reader returned non-text for {pattern}",
                        source,
                    )
                stack.append(canonical)
                try:
                    self._parse_text(
                        included_text,
                        path,
                        current_block,
                        depth + 1,
                        stack,
                    )
                finally:
                    stack.pop()

    def _read_include(self, path: str):
        reader = self.auditor._include_reader
        if reader is None:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        if callable(reader):
            try:
                included = reader(path)
            except (FileNotFoundError, KeyError):
                relative = os.path.relpath(path, self.auditor.config_dir)
                return reader(relative)
            if included is not None:
                return included
            relative = os.path.relpath(path, self.auditor.config_dir)
            return reader(relative)
        if isinstance(reader, Mapping):
            if path in reader:
                return reader[path]
            relative = os.path.relpath(path, self.auditor.config_dir)
            return reader[relative]
        raise TypeError("include_reader must be callable or a mapping")

    def _canonical_source(self, source: str) -> str | None:
        if source.startswith("<") and source.endswith(">"):
            return None
        if os.path.isabs(source):
            return _canonical_path(source)
        if os.path.exists(source):
            return _canonical_path(source)
        return _canonical_path(os.path.join(self.auditor.config_dir, source))

    def _parse_error(self, line: int, message: str, source: str):
        raise SshdAuditError(
            "SSHD_PARSE_FAILED",
            {"line": line, "message": f"{source}: {message}"},
        )


def _strip_comment(line: str) -> str:
    quote = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in ("'", '"'):
            quote = character
            continue
        if character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _split_list(value: str) -> tuple:
    result = []
    seen = set()
    for item in value.split(","):
        token = item.strip()
        if token and token not in seen:
            result.append(token)
            seen.add(token)
    return tuple(result)


def _lower_context(context) -> dict:
    if context is None:
        return {}
    if not isinstance(context, Mapping):
        raise TypeError("context must be a mapping")
    return {
        str(key).lower(): value
        for key, value in context.items()
    }


def _value_matches(value, criterion: str, *, wildcard: bool) -> bool:
    if value is None:
        return False
    candidates = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
    patterns = [item.strip() for item in criterion.split(",") if item.strip()]
    for candidate in candidates:
        candidate = str(candidate)
        for pattern in patterns:
            if wildcard:
                if fnmatch.fnmatchcase(candidate, pattern):
                    return True
            elif candidate == pattern:
                return True
    return False


def _address_matches(value, criterion: str) -> bool:
    if value is None:
        return False
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False

    networks = [item.strip() for item in criterion.split(",") if item.strip()]
    for network_text in networks:
        try:
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            return False
        if address.version == network.version and address in network:
            return True
    return False


def _canonical_path(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _is_sequence(value) -> bool:
    return isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    )


def _is_positive_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1
