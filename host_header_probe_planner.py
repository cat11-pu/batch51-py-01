"""Host header probe planning with reflection and cache key classification."""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping
from dataclasses import dataclass


VARIANTS = (
    "plain",
    "case",
    "trailing-dot",
    "port",
    "absolute",
    "duplicate",
    "prefixed",
)

CACHE_MARKER_HEADERS = ("vary", "x-cache-key")

_SNAPSHOT_VERSION = 1
_STAT_KEYS = ("targets", "planned", "suppressed", "classifications", "restores")
_COUNTER_KEYS = ("planned", "suppressed", "classifications", "restores")


class HostError(ValueError):
    """Raised when a target definition or a probe list is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Probe:
    target_id: str
    variant: str
    host_header: str
    port: int


@dataclass(frozen=True)
class _Target:
    target_id: str
    host: str
    scheme: str
    ports: tuple[int, ...]
    probes: tuple[Probe, ...]


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _normalise_header(value: object) -> str:
    return " ".join(str(value).strip().split()).lower()


def _normalise_host(host: object) -> str:
    if not isinstance(host, str) or not host or host != host.strip():
        raise HostError("HOST_INVALID_HOST", {"host": host})
    if len(host) > 253:
        raise HostError("HOST_INVALID_HOST", {"host": host})
    if any(
        character.isspace()
        or ord(character) < 0x20
        or ord(character) == 0x7F
        or character in "/\\:@?#[]"
        for character in host
    ):
        raise HostError("HOST_INVALID_HOST", {"host": host})

    labels = host.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise HostError("HOST_INVALID_HOST", {"host": host})
    for label in labels:
        if label[0] == "-" or label[-1] == "-":
            raise HostError("HOST_INVALID_HOST", {"host": host})
        if any(
            not (character.isascii() and (character.isalnum() or character == "-"))
            for character in label
        ):
            raise HostError("HOST_INVALID_HOST", {"host": host})
    return host.lower()


def _normalise_scheme(scheme: object) -> str:
    if not isinstance(scheme, str):
        raise HostError("HOST_INVALID_PORT", {"scheme": scheme})
    normalised = scheme.lower()
    if normalised not in {"http", "https"}:
        raise HostError("HOST_INVALID_PORT", {"scheme": scheme})
    return normalised


def _normalise_ports(ports: object) -> tuple[int, ...]:
    if isinstance(ports, (str, bytes)):
        raise HostError("HOST_INVALID_PORT", {"ports": ports})
    try:
        raw_ports = tuple(ports)
    except TypeError as exc:
        raise HostError("HOST_INVALID_PORT", {"ports": ports}) from exc
    if not raw_ports:
        raise HostError("HOST_INVALID_PORT", {"ports": ports})

    result: list[int] = []
    seen: set[int] = set()
    for port in raw_ports:
        if not _is_int(port) or not 1 <= port <= 65535:
            raise HostError("HOST_INVALID_PORT", {"port": port})
        if port not in seen:
            seen.add(port)
            result.append(port)
    return tuple(result)


def _probe_key(probe: Probe) -> tuple[object, str]:
    return probe.port, _normalise_header(probe.host_header)


def _is_error_page(page_kind: object) -> bool:
    if _is_int(page_kind):
        return 400 <= page_kind <= 599
    if not isinstance(page_kind, str):
        return False
    kind = page_kind.strip().lower()
    if kind in {"error", "error_page", "not_found", "notfound", "not-found"}:
        return True
    return (
        (kind.isdigit() and 400 <= int(kind) <= 599)
        or kind.startswith("error")
        or kind.endswith("error")
    )


class HostHeaderProbePlanner:
    """Generate host header variants per target and grade observed reflections."""

    def __init__(self, *, per_target_limit: int = 10) -> None:
        if not _is_int(per_target_limit) or per_target_limit < 0:
            raise HostError(
                "HOST_INVALID_LIMIT",
                {"per_target_limit": per_target_limit},
            )
        self.per_target_limit = per_target_limit
        self._lock = threading.RLock()
        self._targets: dict[str, _Target] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    def add_target(self, target_id: str, *, host: str, scheme: str = "https",
                   ports=(443,)) -> int:
        with self._lock:
            if not isinstance(target_id, str):
                raise HostError("HOST_INVALID_TARGET", {"target_id": target_id})
            if target_id in self._targets:
                raise HostError("HOST_DUPLICATE_TARGET", {"target_id": target_id})

            normalised_host = _normalise_host(host)
            normalised_scheme = _normalise_scheme(scheme)
            normalised_ports = _normalise_ports(ports)
            probes, unique_count = self._build_probes(
                target_id,
                normalised_host,
                normalised_scheme,
                normalised_ports,
            )

            target = _Target(
                target_id=target_id,
                host=normalised_host,
                scheme=normalised_scheme,
                ports=normalised_ports,
                probes=probes,
            )
            self._targets[target_id] = target
            self._counters["planned"] += len(probes)
            self._counters["suppressed"] += unique_count - len(probes)
            return len(probes)

    def remove_target(self, target_id: str) -> bool:
        with self._lock:
            return self._targets.pop(target_id, None) is not None

    def plan_probes(self, target_id: str) -> tuple[Probe, ...]:
        with self._lock:
            return self._require_target(target_id).probes

    def variants_for(self, target_id: str) -> tuple[str, ...]:
        with self._lock:
            target = self._require_target(target_id)
            return tuple(probe.variant for probe in target.probes)

    def dedupe(self, target_id: str, probes) -> tuple[Probe, ...]:
        with self._lock:
            self._require_target(target_id)
            limit = self.per_target_limit
            if limit == 0:
                return ()

            result: list[Probe] = []
            seen: set[tuple[object, str]] = set()
            try:
                iterator = iter(probes)
            except TypeError as exc:
                raise HostError(
                    "HOST_PROBES_INVALID",
                    {"probes": probes},
                ) from exc

            for probe in iterator:
                try:
                    key = (probe.port, _normalise_header(probe.host_header))
                except AttributeError as exc:
                    raise HostError(
                        "HOST_PROBES_INVALID",
                        {"probe": probe},
                    ) from exc
                if key in seen:
                    continue
                seen.add(key)
                result.append(probe)
                if len(result) >= limit:
                    break
            return tuple(result)

    def classify_reflection(self, observation: dict) -> dict:
        if not isinstance(observation, Mapping):
            raise HostError("HOST_OBSERVATION_INVALID", {"observation": observation})

        headers = observation.get("response_headers")
        if headers is None:
            headers = observation.get("headers", {})
        cache_key = self.detect_cache_key(headers)
        body_echo = bool(observation.get("body_contains_host"))
        redirect_echo = bool(observation.get("redirect_contains_host"))

        if redirect_echo:
            channel = "redirect"
            risk = "medium"
        elif body_echo:
            channel = "body"
            if _is_error_page(observation.get("page_kind")):
                risk = "low"
            elif cache_key:
                risk = "high"
            else:
                risk = "medium"
        else:
            channel = "none"
            risk = "none"

        with self._lock:
            self._counters["classifications"] += 1
        return {"risk": risk, "channel": channel, "cache_key": cache_key}

    def detect_cache_key(self, headers: dict) -> bool:
        if not isinstance(headers, Mapping):
            return False
        for name, value in headers.items():
            header_name = str(name).strip().lower()
            if header_name == "vary":
                values = value if isinstance(value, (list, tuple)) else (value,)
                tokens = {
                    token.strip().lower()
                    for item in values
                    for token in str(item).split(",")
                }
                if "host" in tokens:
                    return True
            elif header_name == "x-cache-key":
                values = value if isinstance(value, (list, tuple)) else (value,)
                if any("host" in str(item).lower() for item in values):
                    return True
        return False

    def describe_target(self, target_id: str) -> dict:
        with self._lock:
            target = self._require_target(target_id)
            return {
                "target_id": target.target_id,
                "host": target.host,
                "scheme": target.scheme,
                "ports": target.ports,
                "planned": len(target.probes),
            }

    def list_targets(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._targets)

    def snapshot(self) -> dict:
        with self._lock:
            targets = [
                {
                    "target_id": target.target_id,
                    "host": target.host,
                    "scheme": target.scheme,
                    "ports": list(target.ports),
                    "probes": [
                        {
                            "target_id": probe.target_id,
                            "variant": probe.variant,
                            "host_header": probe.host_header,
                            "port": probe.port,
                        }
                        for probe in target.probes
                    ],
                }
                for target in self._targets.values()
            ]
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "per_target_limit": self.per_target_limit,
                "targets": targets,
                "stats": self._stats_locked(),
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = self._parse_snapshot(state)
            except HostError as exc:
                if exc.code == "HOST_SNAPSHOT_INVALID":
                    raise
                raise HostError(
                    "HOST_SNAPSHOT_INVALID",
                    {"reason": str(exc), "detail": exc.detail},
                ) from exc
            except Exception as exc:
                raise HostError(
                    "HOST_SNAPSHOT_INVALID",
                    {"reason": "UNREADABLE_STATE"},
                ) from exc

            self.per_target_limit = candidate["per_target_limit"]
            self._targets = candidate["targets"]
            self._counters = candidate["counters"]
            self._counters["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()

    def reset(self) -> None:
        with self._lock:
            self._counters = {key: 0 for key in _COUNTER_KEYS}

    def _build_probes(
        self,
        target_id: str,
        host: str,
        scheme: str,
        ports: tuple[int, ...],
    ) -> tuple[tuple[Probe, ...], int]:
        selected: list[Probe] = []
        seen: set[tuple[object, str]] = set()
        unique_count = 0
        for port in ports:
            candidates = (
                Probe(target_id, "plain", host, port),
                Probe(target_id, "case", host.upper(), port),
                Probe(target_id, "trailing-dot", f"{host}.", port),
                Probe(target_id, "port", f"{host}:{port}", port),
                Probe(target_id, "absolute", f"{scheme}://{host}:{port}", port),
                Probe(target_id, "duplicate", f"{host}, {host}", port),
                Probe(target_id, "prefixed", f"prefix.{host}", port),
            )
            for probe in candidates:
                key = _probe_key(probe)
                if key in seen:
                    continue
                seen.add(key)
                unique_count += 1
                if len(selected) < self.per_target_limit:
                    selected.append(probe)

        return tuple(selected), unique_count

    def _require_target(self, target_id: str) -> _Target:
        try:
            target = self._targets.get(target_id)
        except TypeError:
            target = None
        if target is None:
            raise HostError("HOST_UNKNOWN_TARGET", {"target_id": target_id})
        return target

    def _stats_locked(self) -> dict:
        return {
            "targets": len(self._targets),
            "planned": self._counters["planned"],
            "suppressed": self._counters["suppressed"],
            "classifications": self._counters["classifications"],
            "restores": self._counters["restores"],
        }

    def _parse_snapshot(self, state: object) -> dict:
        candidate = copy.deepcopy(state)
        if not isinstance(candidate, dict):
            self._snapshot_invalid("STATE_NOT_OBJECT")
        if set(candidate) != {
            "version", "per_target_limit", "targets", "stats",
        }:
            self._snapshot_invalid("INVALID_KEYS")
        if candidate["version"] != _SNAPSHOT_VERSION \
                or not _is_int(candidate["version"]):
            self._snapshot_invalid("UNSUPPORTED_VERSION")

        limit = candidate["per_target_limit"]
        if not _is_int(limit) or limit < 0:
            self._snapshot_invalid("INVALID_LIMIT")

        raw_targets = candidate["targets"]
        if not isinstance(raw_targets, (list, tuple)):
            self._snapshot_invalid("TARGETS_NOT_LIST")

        targets: dict[str, _Target] = {}
        for raw_target in raw_targets:
            if not isinstance(raw_target, dict) or set(raw_target) != {
                "target_id", "host", "scheme", "ports", "probes",
            }:
                self._snapshot_invalid("INVALID_TARGET")
            target_id = raw_target["target_id"]
            if not isinstance(target_id, str):
                self._snapshot_invalid("INVALID_TARGET_ID")
            if target_id in targets:
                self._snapshot_invalid("DUPLICATE_TARGET_ID")

            try:
                host = _normalise_host(raw_target["host"])
                scheme = _normalise_scheme(raw_target["scheme"])
                ports = _normalise_ports(raw_target["ports"])
            except HostError as exc:
                self._snapshot_invalid("INVALID_TARGET", code=exc.code)

            raw_probes = raw_target["probes"]
            if not isinstance(raw_probes, (list, tuple)):
                self._snapshot_invalid("PROBES_NOT_LIST")
            if len(raw_probes) > limit:
                self._snapshot_invalid("PROBE_LIMIT_EXCEEDED")

            probes: list[Probe] = []
            seen: set[tuple[object, str]] = set()
            for raw_probe in raw_probes:
                if not isinstance(raw_probe, dict) or set(raw_probe) != {
                    "target_id", "variant", "host_header", "port",
                }:
                    self._snapshot_invalid("INVALID_PROBE")
                if raw_probe["target_id"] != target_id:
                    self._snapshot_invalid("PROBE_TARGET_MISMATCH")
                variant = raw_probe["variant"]
                if variant not in VARIANTS:
                    self._snapshot_invalid("INVALID_VARIANT")
                host_header = raw_probe["host_header"]
                if not isinstance(host_header, str):
                    self._snapshot_invalid("INVALID_HOST_HEADER")
                port = raw_probe["port"]
                if not _is_int(port) or port not in ports:
                    self._snapshot_invalid("INVALID_PROBE_PORT")
                probe = Probe(target_id, variant, host_header, port)
                key = _probe_key(probe)
                if key in seen:
                    self._snapshot_invalid("DUPLICATE_PROBE")
                seen.add(key)
                probes.append(probe)

            targets[target_id] = _Target(
                target_id=target_id,
                host=host,
                scheme=scheme,
                ports=ports,
                probes=tuple(probes),
            )

        raw_stats = candidate["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(_STAT_KEYS):
            self._snapshot_invalid("INVALID_STATS")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                self._snapshot_invalid("INVALID_STAT", stat=key)
            stats[key] = value
        if stats["targets"] != len(targets):
            self._snapshot_invalid("TARGET_STAT_MISMATCH")

        return {
            "per_target_limit": limit,
            "targets": targets,
            "counters": {
                key: stats[key]
                for key in _COUNTER_KEYS
            },
        }

    @staticmethod
    def _snapshot_invalid(reason: str, **detail: object) -> None:
        payload = {"reason": reason}
        payload.update(detail)
        raise HostError("HOST_SNAPSHOT_INVALID", payload)
