"""Clickjacking header prober: XFO / CSP frame-ancestors evaluation with ancestor chains."""

from __future__ import annotations

import copy
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlsplit


class FrameError(ValueError):
    """Raised when a framing probe is refused or malformed."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class HeaderSet:
    url: str
    status: int
    pairs: tuple[tuple[str, str], ...]
    hops: tuple[str, ...]


@dataclass(frozen=True)
class XfoPolicy:
    mode: str
    raw: str
    supported: bool


@dataclass(frozen=True)
class FrameAncestors:
    present: bool
    sources: tuple[str, ...]
    raw: str


@dataclass(frozen=True)
class AncestorChain:
    origins: tuple[str, ...]


@dataclass(frozen=True)
class FrameVerdict:
    status: str
    reason: str
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class Probe:
    url: str
    target: str
    ancestors: AncestorChain
    verdict: FrameVerdict


@dataclass(frozen=True)
class _Origin:
    scheme: str
    host: str
    port: Optional[int]


_DEFAULT_PORTS = {
    "ftp": 21,
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
}
_SCHEME_ONLY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:$")
_PROBE_STATUSES = frozenset({"embeddable", "blocked"})


class ClickjackingHeaderProber:
    """Decide whether a target page can be framed by a chain of ancestor origins."""

    SNAPSHOT_KEYS = frozenset({"version", "probes", "verdicts", "stats"})
    SNAPSHOT_VERSION = 1

    def __init__(
        self,
        *,
        fetcher: Callable[[str], Any],
        max_probes_per_target: int = 4,
        max_redirects: int = 3,
    ) -> None:
        if not callable(fetcher):
            raise TypeError("fetcher must be callable")
        if not isinstance(max_probes_per_target, int) or isinstance(
            max_probes_per_target, bool
        ):
            raise TypeError("max_probes_per_target must be an integer")
        if not isinstance(max_redirects, int) or isinstance(max_redirects, bool):
            raise TypeError("max_redirects must be an integer")
        if max_probes_per_target < 0:
            raise ValueError("max_probes_per_target must not be negative")
        if max_redirects < 0:
            raise ValueError("max_redirects must not be negative")
        self._fetcher = fetcher
        self.max_probes_per_target = max_probes_per_target
        self.max_redirects = max_redirects
        self._lock = threading.RLock()
        self._target_locks: dict[str, threading.RLock] = {}
        self._probes: list[Probe] = []
        self._verdicts: dict[str, FrameVerdict] = {}
        self._target_counts: dict[str, int] = {}
        self._stats: dict[str, int] = {"probes": 0}

    def fetch_headers(self, url: str) -> HeaderSet:
        if not isinstance(url, str) or not url:
            raise FrameError("FRAME_HEADER_INVALID", {"url": url})

        current = url
        hops = [current]
        redirects = 0

        while True:
            response = self._fetcher(current)
            if isinstance(response, HeaderSet):
                return response

            status = self._response_status(response)
            pairs = self._response_pairs(response)
            location = self._first_header(pairs, "location")
            if 300 <= status < 400 and location:
                if redirects >= self.max_redirects:
                    raise FrameError(
                        "FRAME_REDIRECT_LIMIT",
                        {"url": current, "hops": tuple(hops), "redirects": redirects},
                    )
                redirects += 1
                current = urljoin(current, location)
                hops.append(current)
                continue
            return HeaderSet(
                url=current,
                status=status,
                pairs=pairs,
                hops=tuple(hops),
            )

    def parse_xfo(self, headers: HeaderSet) -> XfoPolicy:
        values = self._header_values(headers, "x-frame-options")
        if not values:
            return XfoPolicy(mode="none", raw="", supported=True)

        modes: set[str] = set()
        for value in values:
            for token in value.split(","):
                token = token.strip()
                if not token:
                    raise FrameError(
                        "FRAME_HEADER_INVALID",
                        {"header": "x-frame-options", "value": value},
                    )
                parts = token.split(None, 1)
                directive = parts[0].upper()
                if directive == "DENY":
                    modes.add("deny")
                elif directive == "SAMEORIGIN":
                    modes.add("sameorigin")
                elif directive == "ALLOW-FROM":
                    modes.add("unsupported")
                else:
                    raise FrameError(
                        "FRAME_HEADER_INVALID",
                        {"header": "x-frame-options", "value": token},
                    )

        raw = ", ".join(values)
        if "deny" in modes:
            return XfoPolicy(mode="deny", raw=raw, supported=True)
        if "unsupported" in modes:
            return XfoPolicy(mode="unsupported", raw=raw, supported=False)
        return XfoPolicy(mode="sameorigin", raw=raw, supported=True)

    def parse_frame_ancestors(self, headers: HeaderSet) -> FrameAncestors:
        policies = self._frame_ancestor_policies(headers)
        if policies is None:
            return FrameAncestors(present=False, sources=(), raw="")

        sources = tuple(source for policy in policies for source in policy)
        return FrameAncestors(
            present=True,
            sources=sources,
            raw=" ".join(sources),
        )

    def evaluate(self, url: str, *, ancestors: tuple[str, ...]) -> FrameVerdict:
        target = self._origin_key(url)
        chain = self._normalise_ancestor_chain(ancestors)
        target_lock = self._target_lock(target)

        with target_lock:
            with self._lock:
                count = self._target_counts.get(target, 0)
            if count >= self.max_probes_per_target:
                raise FrameError(
                    "FRAME_PROBE_LIMIT_EXCEEDED",
                    {"target": target, "count": count},
                )

            headers = self.fetch_headers(url)
            policies = self._frame_ancestor_policies(headers)
            if policies is not None:
                parsed_csp = self.parse_frame_ancestors(headers)
                verdict = self._evaluate_csp(headers, parsed_csp, policies, chain, target)
            else:
                xfo = self.parse_xfo(headers)
                verdict = self._evaluate_xfo(headers, xfo, chain, target)

            probe = Probe(
                url=url,
                target=target,
                ancestors=AncestorChain(chain),
                verdict=verdict,
            )
            with self._lock:
                self._probes.append(probe)
                self._verdicts[target] = verdict
                self._target_counts[target] = (
                    self._target_counts.get(target, 0) + 1
                )
                self._stats["probes"] += 1
            return verdict

    def report(self) -> dict:
        with self._lock:
            verdicts = dict(self._verdicts)
            total_probes = self._stats["probes"]

        targets = tuple(sorted(verdicts))
        embeddable = tuple(
            target
            for target in targets
            if verdicts[target].status == "embeddable"
        )
        blocked = tuple(
            target for target in targets if verdicts[target].status == "blocked"
        )
        return {
            "targets": targets,
            "embeddable": embeddable,
            "blocked": blocked,
            "counts": {
                "embeddable": len(embeddable),
                "blocked": len(blocked),
            },
            "probes": total_probes,
        }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "probes": copy.deepcopy(self._probes),
                "verdicts": copy.deepcopy(self._verdicts),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            candidate = copy.deepcopy(state)
            validated = self._validate_snapshot(candidate)
        except FrameError:
            raise
        except Exception as exc:
            raise FrameError("FRAME_SNAPSHOT_INVALID", str(exc)) from exc

        probes, verdicts, target_counts, stats = validated
        with self._lock:
            self._probes = probes
            self._verdicts = verdicts
            self._target_counts = target_counts
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return {"probes": self._stats["probes"]}

    def probe_count(self, target: str) -> int:
        if not isinstance(target, str):
            return 0
        with self._lock:
            if target in self._target_counts:
                return self._target_counts[target]
        try:
            key = self._origin_key(target)
        except FrameError:
            return 0
        with self._lock:
            return self._target_counts.get(key, 0)

    def reset(self) -> None:
        with self._lock:
            self._probes.clear()
            self._verdicts.clear()
            self._target_counts.clear()
            self._stats["probes"] = 0

    def _evaluate_csp(
        self,
        headers: HeaderSet,
        parsed: FrameAncestors,
        policies: tuple[tuple[str, ...], ...],
        ancestors: tuple[str, ...],
        target: str,
    ) -> FrameVerdict:
        target_origin = self._parse_origin(headers.url)
        ancestor_origins = tuple(
            self._parse_origin(ancestor) for ancestor in ancestors
        )

        allowed = True
        for policy in policies:
            for ancestor_origin in ancestor_origins:
                if not any(
                    self._source_matches(source, ancestor_origin, target_origin)
                    for source in policy
                ):
                    allowed = False
                    break
            if not allowed:
                break

        evidence = {
            "url": headers.url,
            "target": target,
            "ancestors": ancestors,
            "hops": headers.hops,
            "sources": parsed.sources,
        }
        if allowed:
            return FrameVerdict("embeddable", "csp_allows", evidence)
        return FrameVerdict("blocked", "csp_blocks", evidence)

    def _evaluate_xfo(
        self,
        headers: HeaderSet,
        policy: XfoPolicy,
        ancestors: tuple[str, ...],
        target: str,
    ) -> FrameVerdict:
        evidence = {
            "url": headers.url,
            "target": target,
            "ancestors": ancestors,
            "hops": headers.hops,
            "xfo": policy.mode,
        }

        if policy.mode == "none":
            return FrameVerdict("embeddable", "no_protection", evidence)
        if policy.mode == "deny":
            return FrameVerdict("blocked", "xfo_deny", evidence)
        if policy.mode == "unsupported":
            return FrameVerdict("blocked", "xfo_unsupported", evidence)

        target_origin = self._parse_origin(headers.url)
        same_origin = all(
            self._parse_origin(ancestor) == target_origin
            for ancestor in ancestors
        )
        if same_origin:
            return FrameVerdict("embeddable", "xfo_sameorigin", evidence)
        return FrameVerdict("blocked", "xfo_sameorigin", evidence)

    def _frame_ancestor_policies(
        self, headers: HeaderSet
    ) -> Optional[tuple[tuple[str, ...], ...]]:
        values = self._header_values(headers, "content-security-policy")
        policies: list[tuple[str, ...]] = []

        for value in values:
            for policy_text in value.split(","):
                for directive in policy_text.split(";"):
                    parts = directive.strip().split()
                    if not parts or parts[0].lower() != "frame-ancestors":
                        continue
                    sources = tuple(parts[1:])
                    if not sources:
                        raise FrameError(
                            "FRAME_HEADER_INVALID",
                            {"header": "content-security-policy", "directive": directive},
                        )
                    policies.append(sources)
                    break

        if not policies:
            return None
        return tuple(policies)

    def _source_matches(
        self,
        source: str,
        ancestor: _Origin,
        target: _Origin,
    ) -> bool:
        token = source.strip()
        lowered = token.lower()
        if not token:
            return False
        if token == "*":
            return True
        if lowered == "'self'":
            return ancestor == target
        if lowered == "'none'":
            return False
        if lowered.startswith("'") and lowered.endswith("'"):
            return False
        if _SCHEME_ONLY_RE.fullmatch(token):
            return ancestor.scheme == token[:-1].lower()

        parsed_source = self._parse_source(source, target.scheme)
        if parsed_source is None:
            return False
        source_scheme, source_host, source_port = parsed_source
        if ancestor.scheme != source_scheme or not self._host_matches(
            source_host, ancestor.host
        ):
            return False

        if source_port == "*":
            return True
        if source_port is None:
            expected_port = _DEFAULT_PORTS.get(source_scheme)
        else:
            expected_port = source_port
        return ancestor.port == expected_port

    def _parse_source(
        self, source: str, default_scheme: str
    ) -> Optional[tuple[str, str, Any]]:
        token = source.strip()
        scheme = default_scheme
        rest = token

        if "://" in token:
            scheme, rest = token.split("://", 1)
        elif token.startswith("//"):
            rest = token[2:]

        scheme = scheme.lower()
        authority = rest.split("/", 1)[0]
        if "@" in authority:
            authority = authority.rsplit("@", 1)[1]
        if not authority:
            return None

        port: Any = None
        if authority.startswith("["):
            closing = authority.find("]")
            if closing < 0:
                return None
            host = authority[1:closing].lower()
            remainder = authority[closing + 1 :]
            if remainder:
                if not remainder.startswith(":") or len(remainder) == 1:
                    return None
                port = remainder[1:]
        else:
            if ":" in authority:
                host, port = authority.rsplit(":", 1)
                if not port:
                    return None
            else:
                host = authority

        host = host.lower().rstrip(".")
        if not host:
            return None
        if port not in (None, "*"):
            try:
                port = int(port)
            except (TypeError, ValueError):
                return None
            if not 0 <= port <= 65535:
                return None
        return scheme, host, port

    def _host_matches(self, source_host: str, ancestor_host: str) -> bool:
        source_host = source_host.lower().rstrip(".")
        ancestor_host = ancestor_host.lower().rstrip(".")
        if source_host == "*":
            return True
        if source_host.startswith("*."):
            suffix = source_host[2:]
            return bool(suffix) and ancestor_host.endswith("." + suffix)
        return source_host == ancestor_host

    def _origin_key(self, url: str) -> str:
        return self._format_origin(self._parse_origin(url))

    def _parse_origin(self, url: str) -> _Origin:
        if not isinstance(url, str) or not url:
            raise FrameError("FRAME_HEADER_INVALID", {"url": url})
        try:
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise FrameError("FRAME_HEADER_INVALID", {"url": url}) from exc
        if not scheme or not host:
            raise FrameError("FRAME_HEADER_INVALID", {"url": url})
        if port is None:
            port = _DEFAULT_PORTS.get(scheme)
        return _Origin(
            scheme=scheme,
            host=host.lower().rstrip("."),
            port=port,
        )

    def _format_origin(self, origin: _Origin) -> str:
        host = origin.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = _DEFAULT_PORTS.get(origin.scheme)
        if origin.port is None or origin.port == default_port:
            return f"{origin.scheme}://{host}"
        return f"{origin.scheme}://{host}:{origin.port}"

    def _normalise_ancestor_chain(
        self, ancestors: tuple[str, ...]
    ) -> tuple[str, ...]:
        if isinstance(ancestors, str) or not isinstance(ancestors, Iterable):
            raise FrameError("FRAME_HEADER_INVALID", {"ancestors": ancestors})
        chain = tuple(ancestors)
        if any(not isinstance(ancestor, str) for ancestor in chain):
            raise FrameError("FRAME_HEADER_INVALID", {"ancestors": ancestors})
        return chain

    def _target_lock(self, target: str) -> threading.RLock:
        with self._lock:
            lock = self._target_locks.get(target)
            if lock is None:
                lock = threading.RLock()
                self._target_locks[target] = lock
            return lock

    def _response_status(self, response: Any) -> int:
        if isinstance(response, Mapping):
            status = response.get("status", response.get("status_code"))
        else:
            status = getattr(response, "status", None)
            if status is None:
                status = getattr(response, "status_code", None)
        if isinstance(status, Mapping):
            return 200
        if isinstance(status, bool):
            raise FrameError("FRAME_HEADER_INVALID", {"status": status})
        try:
            status = int(status)
        except (TypeError, ValueError) as exc:
            raise FrameError("FRAME_HEADER_INVALID", {"status": status}) from exc
        return status

    def _response_pairs(self, response: Any) -> tuple[tuple[str, str], ...]:
        raw_headers = self._response_headers(response)

        if raw_headers is None:
            return ()
        if hasattr(raw_headers, "items"):
            items = raw_headers.items()
        else:
            items = raw_headers

        pairs: list[tuple[str, str]] = []
        try:
            for name, value in items:
                values: Iterable[Any]
                if isinstance(value, (list, tuple)):
                    values = value
                else:
                    values = (value,)
                for item in values:
                    if isinstance(item, bytes):
                        item = item.decode("latin-1")
                    pairs.append((str(name).strip().lower(), str(item)))
        except (TypeError, ValueError) as exc:
            raise FrameError(
                "FRAME_HEADER_INVALID", {"headers": raw_headers}
            ) from exc
        return tuple(pairs)

    def _response_headers(self, response: Any) -> Any:
        if isinstance(response, Mapping):
            raw_headers = response.get("headers")
            status = response.get("status", response.get("status_code"))
        else:
            raw_headers = getattr(response, "headers", None)
            status = getattr(response, "status", None)
            if status is None:
                status = getattr(response, "status_code", None)
        if not raw_headers and isinstance(status, Mapping):
            return status
        return raw_headers

    def _header_values(self, headers: HeaderSet, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(
            value
            for header_name, value in headers.pairs
            if header_name.lower() == lowered
        )

    def _first_header(
        self, pairs: tuple[tuple[str, str], ...], name: str
    ) -> Optional[str]:
        lowered = name.lower()
        for header_name, value in pairs:
            if header_name.lower() == lowered:
                return value.strip()
        return None

    def _validate_snapshot(
        self, state: Any
    ) -> tuple[
        list[Probe],
        dict[str, FrameVerdict],
        dict[str, int],
        dict[str, int],
    ]:
        if not isinstance(state, Mapping) or set(state) != self.SNAPSHOT_KEYS:
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"state": state})
        version = state["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != self.SNAPSHOT_VERSION
        ):
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"version": version})

        raw_probes = state["probes"]
        raw_verdicts = state["verdicts"]
        raw_stats = state["stats"]
        if not isinstance(raw_probes, (list, tuple)):
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"probes": raw_probes})
        if not isinstance(raw_verdicts, dict):
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"verdicts": raw_verdicts})
        if not isinstance(raw_stats, dict) or set(raw_stats) != {"probes"}:
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"stats": raw_stats})
        probe_count = raw_stats.get("probes")
        if (
            not isinstance(probe_count, int)
            or isinstance(probe_count, bool)
            or probe_count < 0
            or probe_count != len(raw_probes)
        ):
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"stats": raw_stats})

        probes: list[Probe] = []
        target_counts: dict[str, int] = {}
        latest: dict[str, FrameVerdict] = {}
        for probe in raw_probes:
            if not isinstance(probe, Probe):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"probe": probe})
            if not isinstance(probe.url, str) or not isinstance(probe.target, str):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"probe": probe})
            if not isinstance(probe.ancestors, AncestorChain):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"probe": probe})
            if not isinstance(probe.ancestors.origins, tuple) or any(
                not isinstance(origin, str) for origin in probe.ancestors.origins
            ):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"probe": probe})
            verdict = probe.verdict
            if not isinstance(verdict, FrameVerdict):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"probe": probe})
            if verdict.status not in _PROBE_STATUSES or not isinstance(
                verdict.reason, str
            ):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"verdict": verdict})
            if not isinstance(verdict.evidence, Mapping):
                raise FrameError("FRAME_SNAPSHOT_INVALID", {"verdict": verdict})
            probes.append(probe)
            target_counts[probe.target] = target_counts.get(probe.target, 0) + 1
            latest[probe.target] = verdict

        if set(raw_verdicts) != set(latest):
            raise FrameError("FRAME_SNAPSHOT_INVALID", {"verdicts": raw_verdicts})
        for target, verdict in raw_verdicts.items():
            if not isinstance(target, str) or not isinstance(verdict, FrameVerdict):
                raise FrameError(
                    "FRAME_SNAPSHOT_INVALID", {"verdicts": raw_verdicts}
                )
            if verdict != latest[target]:
                raise FrameError(
                    "FRAME_SNAPSHOT_INVALID", {"target": target}
                )

        return (
            probes,
            dict(raw_verdicts),
            target_counts,
            {"probes": probe_count},
        )
