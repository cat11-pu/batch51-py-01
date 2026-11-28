"""CSP 策略求值：指令回退链、nonce 与 hash 覆盖以及多份策略的交集判定。"""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

MAX_POLICY_CHARS = 4096
MAX_DIRECTIVES = 32
MAX_POLICIES = 8

MODES = ("enforce", "report-only")
COUNTER_KEYS = ("evaluated", "allowed", "blocked", "violations")

KIND_CHAINS = {
    "script": ("script-src-elem", "script-src", "default-src"),
    "style": ("style-src-elem", "style-src", "default-src"),
    "img": ("img-src", "default-src"),
    "connect": ("connect-src", "default-src"),
    "font": ("font-src", "default-src"),
    "media": ("media-src", "default-src"),
}

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

_DIRECTIVE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
_SCHEME_SOURCE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):$")
_NONCE_SOURCE = re.compile(r"^'nonce-(.*)'$", re.IGNORECASE)
_HASH_SOURCE = re.compile(r"^'(sha256|sha384|sha512)-(.*)'$", re.IGNORECASE)


class CspError(ValueError):
    """策略解析、求值或快照操作被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Policy:
    name: str
    mode: str
    directives: dict


@dataclass(frozen=True)
class PolicySet:
    enforce: tuple
    report_only: tuple
    digest: str


@dataclass(frozen=True)
class Violation:
    policy: str
    directive: str
    blocked_uri: str
    reason: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    directive: object
    matched: object
    violations: tuple
    blocked_by: tuple


def _chain_for(kind):
    if not isinstance(kind, str) or kind.lower() not in KIND_CHAINS:
        raise CspError("CSP_KIND_INVALID", "unknown resource kind: %r" % (kind,))
    return KIND_CHAINS[kind.lower()]


def effective_directive(directives, kind):
    """按 kind 的回退链返回第一个存在的指令名，全部缺失返回 None。"""
    chain = _chain_for(kind)
    if not isinstance(directives, dict):
        return None

    normalized = {}
    for key in directives:
        if isinstance(key, str):
            normalized.setdefault(key.lower(), key)

    for name in chain:
        if name in directives:
            return name
        if name in normalized:
            return name
    return None


def _parse_url(value, origin=""):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        if not parsed.scheme and origin:
            parsed = urlsplit(urljoin(origin, value))
        return parsed
    except (TypeError, ValueError):
        return None


def _effective_port(parsed):
    try:
        explicit = parsed.port
    except ValueError:
        return None, False
    if explicit is not None:
        return explicit, True
    return DEFAULT_PORTS.get(parsed.scheme.lower()), True


def _same_origin(url, origin):
    if not origin:
        return False
    left = _parse_url(url, origin)
    right = _parse_url(origin)
    if left is None or right is None:
        return False
    if not left.hostname or not right.hostname:
        return False
    if left.scheme.lower() != right.scheme.lower():
        return False
    if left.hostname.lower().rstrip(".") != right.hostname.lower().rstrip("."):
        return False
    left_port, left_ok = _effective_port(left)
    right_port, right_ok = _effective_port(right)
    return left_ok and right_ok and left_port == right_port


def _parse_host_source(expression):
    """Return (scheme, host, port, path), or None for a malformed host source."""
    if "://" in expression:
        parsed = _parse_url(expression)
        if parsed is None:
            return None
        scheme = parsed.scheme.lower()
        if not scheme:
            return None
        netloc = parsed.netloc
        path = parsed.path
    else:
        parsed = _parse_url("//" + expression)
        if parsed is None:
            return None
        scheme = None
        netloc = parsed.netloc
        path = parsed.path

    if not netloc:
        return None

    host_port = netloc.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        end = host_port.find("]")
        if end < 0:
            return None
        host = host_port[1:end]
        remainder = host_port[end + 1:]
        if remainder.startswith(":"):
            port_token = remainder[1:]
        elif remainder:
            return None
        else:
            port_token = None
    else:
        if host_port.count(":") > 1:
            return None
        if ":" in host_port:
            host, port_token = host_port.rsplit(":", 1)
        else:
            host, port_token = host_port, None

    host = host.lower().rstrip(".")
    if not host:
        return None

    if port_token is None or port_token == "":
        port = None
    elif port_token == "*":
        port = "*"
    elif port_token.isdigit():
        port = int(port_token)
    else:
        return None

    return scheme, host, port, path


def _host_matches(source_host, url_host):
    if not url_host:
        return False
    if source_host == "*":
        return True
    if source_host.startswith("*."):
        suffix = source_host[1:]
        return len(url_host) > len(suffix) and url_host.endswith(suffix)
    if "*" in source_host:
        return False
    return source_host == url_host


def source_matches(expression, url, *, origin=""):
    """判定单条来源表达式是否匹配目标 URL。"""
    if not isinstance(expression, str) or not isinstance(url, str):
        return False

    expression = expression.strip()
    if not expression:
        return False
    lowered = expression.lower()

    parsed = _parse_url(url, origin)
    if parsed is None:
        return False

    if lowered == "'self'":
        return _same_origin(url, origin)

    if lowered == "*":
        return parsed.scheme.lower() in ("http", "https")

    scheme_match = _SCHEME_SOURCE.match(expression)
    if scheme_match is not None:
        return parsed.scheme.lower() == scheme_match.group(1).lower()

    if lowered.startswith("'") or lowered.endswith("'"):
        return False

    source = _parse_host_source(expression)
    if source is None:
        return False
    source_scheme, source_host, source_port, source_path = source

    url_scheme = parsed.scheme.lower()
    if source_scheme is not None:
        if url_scheme != source_scheme:
            return False
    elif url_scheme not in ("http", "https", "ws", "wss"):
        return False

    if not parsed.hostname:
        return False
    url_host = parsed.hostname.lower().rstrip(".")
    if not _host_matches(source_host, url_host):
        return False

    url_port, port_ok = _effective_port(parsed)
    if not port_ok:
        return False
    if source_port == "*":
        pass
    elif source_port is not None:
        if url_port != source_port:
            return False
    elif url_port != DEFAULT_PORTS.get(url_scheme):
        return False

    if source_path and source_path != "/":
        if not parsed.path.startswith(source_path):
            return False

    return True


def _nonce_value(source):
    if not isinstance(source, str):
        return None
    match = _NONCE_SOURCE.match(source.strip())
    return match.group(1) if match is not None else None


def _hash_parts(source):
    if not isinstance(source, str):
        return None
    token = source.strip()
    match = _HASH_SOURCE.match(token)
    if match is not None:
        return match.group(1).lower(), match.group(2)
    if token.startswith("'") and token.endswith("'"):
        return None
    algorithm, separator, digest = token.partition("-")
    if separator and algorithm.lower() in ("sha256", "sha384", "sha512") and digest:
        return algorithm.lower(), digest
    return None


def _hash_matches(source, hashes):
    source_parts = _hash_parts(source)
    if source_parts is None:
        return False
    if isinstance(hashes, str):
        hashes = (hashes,)
    for supplied in hashes or ():
        supplied_parts = _hash_parts(supplied)
        if supplied_parts == source_parts:
            return True
    return False


def _has_nonce_or_hash(sources):
    for source in sources:
        if _nonce_value(source) is not None or _hash_parts(source) is not None:
            return True
    return False


def _none_sources(sources):
    return any(
        isinstance(source, str) and source.strip().lower() == "'none'"
        for source in sources
    )


def _validate_sources(sources):
    if isinstance(sources, str):
        sources = (sources,)
    try:
        values = tuple(sources)
    except TypeError as exc:
        raise CspError("CSP_DIRECTIVE_INVALID", "sources must be iterable") from exc
    if not all(isinstance(source, str) for source in values):
        raise CspError("CSP_DIRECTIVE_INVALID", "sources must be strings")
    if _none_sources(values):
        if any(source.strip().lower() != "'none'" for source in values):
            raise CspError(
                "CSP_DIRECTIVE_INVALID", "'none' cannot be combined with other sources"
            )
    return values


def _canonical_directives(directives):
    if not isinstance(directives, dict):
        raise CspError("CSP_POLICY_INVALID", "directives must be a mapping")

    normalized = {}
    for raw_name, raw_sources in directives.items():
        if not isinstance(raw_name, str) or not _DIRECTIVE_NAME.match(raw_name):
            raise CspError("CSP_DIRECTIVE_INVALID", "invalid directive name")
        name = raw_name.lower()
        if name in normalized:
            continue
        normalized[name] = _validate_sources(raw_sources)

    if len(normalized) > MAX_DIRECTIVES:
        raise CspError("CSP_TOO_MANY_DIRECTIVES", "too many directives")
    return dict(sorted(normalized.items()))


def _get_sources(directives, directive):
    if directive in directives:
        sources = directives[directive]
        return (sources,) if isinstance(sources, str) else tuple(sources)
    for name, sources in directives.items():
        if isinstance(name, str) and name.lower() == directive:
            return (sources,) if isinstance(sources, str) else tuple(sources)
    return ()


class CspPolicyEvaluator:
    """解析并求值 enforce 与 report-only 策略。"""

    def __init__(self, *, origin="", max_policies=MAX_POLICIES):
        self.origin = origin
        self.max_policies = max_policies
        self.revision = 0
        self._policies = {}
        self._counters = {key: 0 for key in COUNTER_KEYS}
        self._lock = threading.RLock()

    def parse_policy(self, text, *, mode="enforce", name="policy"):
        if not isinstance(text, str):
            raise CspError("CSP_POLICY_INVALID", "policy text must be a string")
        if len(text) > MAX_POLICY_CHARS:
            raise CspError("CSP_POLICY_TOO_LARGE", "policy exceeds 4096 characters")
        if mode not in MODES:
            raise CspError("CSP_MODE_INVALID", "invalid policy mode")
        if not isinstance(name, str):
            raise CspError("CSP_POLICY_INVALID", "policy name must be a string")

        directives = {}
        for segment in text.split(";"):
            tokens = segment.split()
            if not tokens:
                continue
            raw_name = tokens[0]
            if not _DIRECTIVE_NAME.match(raw_name):
                raise CspError("CSP_DIRECTIVE_INVALID", "invalid directive name")
            directive = raw_name.lower()
            if directive in directives:
                continue
            directives[directive] = _validate_sources(tuple(tokens[1:]))

        if not directives:
            raise CspError("CSP_POLICY_EMPTY", "policy contains no directives")
        if len(directives) > MAX_DIRECTIVES:
            raise CspError("CSP_TOO_MANY_DIRECTIVES", "too many directives")

        return Policy(
            name=name,
            mode=mode,
            directives=dict(sorted(directives.items())),
        )

    def register_policy(self, policy):
        if not isinstance(policy, Policy):
            raise CspError("CSP_POLICY_INVALID", "expected a Policy")
        if policy.mode not in MODES:
            raise CspError("CSP_MODE_INVALID", "invalid policy mode")
        if not isinstance(policy.name, str):
            raise CspError("CSP_POLICY_INVALID", "policy name must be a string")

        registered = Policy(
            name=policy.name,
            mode=policy.mode,
            directives=_canonical_directives(policy.directives),
        )
        with self._lock:
            self._policies[policy.name] = registered
            self.revision += 1
            return self.revision

    def _evaluate_policy(self, policy, url, kind, nonce, hashes):
        if not isinstance(policy, Policy):
            raise CspError("CSP_POLICY_INVALID", "expected a Policy")
        if policy.mode not in MODES:
            raise CspError("CSP_MODE_INVALID", "invalid policy mode")
        if not isinstance(policy.directives, dict):
            raise CspError("CSP_POLICY_INVALID", "directives must be a mapping")

        directive = effective_directive(policy.directives, kind)
        if directive is None:
            return True, None, None, None

        sources = _get_sources(policy.directives, directive)
        if _none_sources(sources):
            violation = Violation(
                policy=policy.name,
                directive=directive,
                blocked_uri=url,
                reason="none",
            )
            return False, directive, None, violation

        inline_kind = kind in ("script", "style")
        is_inline = inline_kind and isinstance(url, str) and url.lower().startswith("inline:")
        strict_dynamic = kind == "script" and any(
            isinstance(source, str) and source.strip().lower() == "'strict-dynamic'"
            for source in sources
        )
        nonce_or_hash = inline_kind and _has_nonce_or_hash(sources)
        matched = None

        for source in sources:
            if not isinstance(source, str):
                continue
            token = source.strip()
            lowered = token.lower()

            nonce_value = _nonce_value(token)
            if nonce_value is not None:
                if (
                    inline_kind
                    and isinstance(nonce, str)
                    and nonce
                    and nonce_value == nonce
                ):
                    matched = token
                    break
                continue

            hash_parts = _hash_parts(token)
            if hash_parts is not None:
                if inline_kind and _hash_matches(token, hashes):
                    matched = token
                    break
                continue

            if lowered == "'unsafe-inline'":
                if is_inline and not nonce_or_hash:
                    matched = token
                    break
                continue

            if lowered == "'strict-dynamic'":
                continue

            if lowered == "'none'":
                continue

            if token.startswith("'") and token.endswith("'"):
                if lowered == "'self'" and not strict_dynamic:
                    if source_matches(token, url, origin=self.origin):
                        matched = token
                        break
                continue

            if strict_dynamic:
                continue

            if source_matches(token, url, origin=self.origin):
                matched = token
                break

        if matched is not None:
            return True, directive, matched, None

        violation = Violation(
            policy=policy.name,
            directive=directive,
            blocked_uri=url,
            reason="inline" if is_inline else "source",
        )
        return False, directive, None, violation

    def evaluate(self, policy, *, url, kind="script", nonce=None, hashes=()):
        _chain_for(kind)
        if isinstance(hashes, str):
            hashes = (hashes,)
        else:
            hashes = tuple(hashes or ())

        if isinstance(policy, PolicySet):
            policies = tuple(policy.enforce) + tuple(policy.report_only)
            for item in policies:
                if not isinstance(item, Policy):
                    raise CspError("CSP_POLICY_INVALID", "PolicySet contains non-Policy")

            enforce_results = [
                self._evaluate_policy(item, url, kind, nonce, hashes)
                for item in policy.enforce
            ]
            report_results = [
                self._evaluate_policy(item, url, kind, nonce, hashes)
                for item in policy.report_only
            ]

            enforce_blocked = [result for result in enforce_results if not result[0]]
            allowed = not enforce_blocked
            violations = [result[3] for result in enforce_blocked]
            blocked_by = tuple(
                item.name
                for item, result in zip(policy.enforce, enforce_results)
                if not result[0]
            )

            report_violations = [result[3] for result in report_results if not result[0]]
            if not policy.enforce or not allowed:
                violations.extend(report_violations)

            if enforce_blocked:
                representative = enforce_blocked[0]
            elif enforce_results:
                representative = enforce_results[0]
            elif report_results:
                representative = report_results[0]
            else:
                representative = (True, None, None, None)

            decision = Decision(
                allowed=allowed,
                directive=representative[1],
                matched=representative[2],
                violations=tuple(violations),
                blocked_by=blocked_by,
            )
        elif isinstance(policy, Policy):
            result = self._evaluate_policy(policy, url, kind, nonce, hashes)
            if result[0]:
                decision = Decision(True, result[1], result[2], (), ())
            elif policy.mode == "report-only":
                decision = Decision(True, result[1], result[2], (result[3],), ())
            else:
                decision = Decision(
                    False, result[1], result[2], (result[3],), (policy.name,)
                )
        else:
            raise CspError("CSP_POLICY_INVALID", "expected Policy or PolicySet")

        with self._lock:
            self._counters["evaluated"] += 1
            if decision.allowed:
                self._counters["allowed"] += 1
            else:
                self._counters["blocked"] += 1
            self._counters["violations"] += len(decision.violations)

        return decision

    def merge_policies(self, policies):
        try:
            items = tuple(policies)
        except TypeError as exc:
            raise CspError("CSP_POLICY_INVALID", "policies must be iterable") from exc

        enforce = []
        report_only = []
        for policy in items:
            if not isinstance(policy, Policy):
                raise CspError("CSP_POLICY_INVALID", "expected a Policy")
            if policy.mode not in MODES:
                raise CspError("CSP_MODE_INVALID", "invalid policy mode")
            if policy.mode == "enforce":
                enforce.append(policy)
            else:
                report_only.append(policy)

        enforce_names = ",".join("%s:%s" % (policy.name, policy.mode) for policy in enforce)
        report_names = ",".join(
            "%s:%s" % (policy.name, policy.mode) for policy in report_only
        )
        return PolicySet(
            enforce=tuple(enforce),
            report_only=tuple(report_only),
            digest=enforce_names + ";" + report_names,
        )

    def check_nonce(self, policy, *, directive, nonce):
        if not isinstance(policy, Policy):
            raise CspError("CSP_POLICY_INVALID", "expected a Policy")
        if not isinstance(directive, str) or not isinstance(nonce, str) or not nonce:
            return False

        directive_name = directive.lower()
        if not (
            directive_name.startswith("script-src")
            or directive_name.startswith("style-src")
            or directive_name == "default-src"
        ):
            return False

        for source in _get_sources(policy.directives, directive_name):
            value = _nonce_value(source)
            if value is not None and value == nonce:
                return True
        return False

    def report(self, decisions):
        decisions = tuple(decisions)
        by_directive = {}
        by_policy = {}
        allowed = 0
        violations = 0

        for decision in decisions:
            if decision.allowed:
                allowed += 1
            for violation in decision.violations:
                violations += 1
                by_directive[violation.directive] = (
                    by_directive.get(violation.directive, 0) + 1
                )
                by_policy[violation.policy] = by_policy.get(violation.policy, 0) + 1

        total = len(decisions)
        return {
            "total": total,
            "allowed": allowed,
            "blocked": total - allowed,
            "violations": violations,
            "by_directive": dict(sorted(by_directive.items())),
            "by_policy": dict(sorted(by_policy.items())),
        }

    def snapshot(self):
        with self._lock:
            policies = {}
            for name in sorted(self._policies):
                policy = self._policies[name]
                policies[name] = {
                    "mode": policy.mode,
                    "directives": copy.deepcopy(policy.directives),
                }
            return {
                "revision": self.revision,
                "policies": policies,
                "counters": copy.deepcopy(self._counters),
            }

    def restore(self, state):
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise ValueError("state must be a mapping")
                if set(state) != {"revision", "policies", "counters"}:
                    raise ValueError("state must contain revision, policies and counters")

                revision = state["revision"]
                if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
                    raise ValueError("revision must be a non-negative integer")

                raw_policies = state["policies"]
                if not isinstance(raw_policies, dict):
                    raise ValueError("policies must be a mapping")
                policies = {}
                for name, entry in raw_policies.items():
                    if not isinstance(name, str) or not isinstance(entry, dict):
                        raise ValueError("invalid policy entry")
                    if "mode" not in entry or "directives" not in entry:
                        raise ValueError("policy entry must contain mode and directives")
                    mode = entry["mode"]
                    if mode not in MODES:
                        raise ValueError("invalid policy mode")
                    directives = _canonical_directives(entry["directives"])
                    policies[name] = Policy(name=name, mode=mode, directives=directives)

                raw_counters = state["counters"]
                if not isinstance(raw_counters, dict):
                    raise ValueError("counters must be a mapping")
                if set(raw_counters) != set(COUNTER_KEYS):
                    raise ValueError("invalid counter keys")
                counters = {}
                for key in COUNTER_KEYS:
                    value = raw_counters[key]
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        raise ValueError("counter values must be non-negative integers")
                    counters[key] = value
            except Exception as exc:
                if isinstance(exc, CspError) and exc.code == "CSP_SNAPSHOT_INVALID":
                    raise
                raise CspError("CSP_SNAPSHOT_INVALID", str(exc)) from None

            self.revision = revision
            self._policies = dict(sorted(policies.items()))
            self._counters = counters

    def stats(self):
        with self._lock:
            return copy.deepcopy(self._counters)
