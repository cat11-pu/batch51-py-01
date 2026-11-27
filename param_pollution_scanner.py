"""Parameter pollution scanner: probe matrix, parser dialects, result merge."""

from __future__ import annotations

import copy
import threading
from collections.abc import Mapping
from dataclasses import dataclass


class ParamError(ValueError):
    """Raised when a scanner operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Probe:
    probe_id: str
    endpoint_id: str
    param: str
    kind: str
    query: tuple


@dataclass(frozen=True)
class Result:
    probe_id: str
    param: str
    kind: str
    source: str
    frontend: object
    backend: object
    verdict: str


@dataclass(frozen=True)
class MergeRow:
    probe_id: str
    param: str
    kind: str
    source: str
    verdict: str
    observations: int


@dataclass(frozen=True)
class MergeReport:
    rows: tuple
    merged: int


class ParamPollutionScanner:
    """Build duplicate-parameter probes and compare front-end and back-end parsing."""

    _VERSION = 1
    _KINDS = (
        "duplicate_first",
        "duplicate_last",
        "bracket_dup",
        "scalar_then_array",
        "encoded_sep",
        "semicolon_sep",
    )
    _SOURCES = ("query", "body")
    _VERDICT_RANK = {
        "consistent": 0,
        "divergent_missing": 1,
        "polluted": 2,
    }
    _SNAPSHOT_KEYS = {"version", "endpoints", "probes", "results", "stats"}
    _STAT_KEYS = {
        "endpoints", "probes", "suppressed", "results", "merged", "restores",
    }

    def __init__(self, *, max_combos: int = 24, max_params: int = 6) -> None:
        self.max_combos = max_combos
        self.max_params = max_params
        self._lock = threading.RLock()
        self._clear()

    def add_endpoint(self, endpoint_id: str, *, path: str,
                     params: tuple = ()) -> None:
        with self._lock:
            if not isinstance(endpoint_id, str):
                raise ParamError("PARAM_INVALID_ENDPOINT", {
                    "endpoint_id": endpoint_id,
                })
            if endpoint_id in self._endpoints:
                raise ParamError("PARAM_DUPLICATE_ENDPOINT", endpoint_id)

            if (not isinstance(path, str) or not path.startswith("/")
                    or "?" in path):
                raise ParamError("PARAM_INVALID_ENDPOINT", {"path": path})

            normalized = self._normalize_params(params)
            if len(normalized) > self.max_params:
                raise ParamError("PARAM_TOO_MANY_PARAMS", {
                    "limit": self.max_params,
                    "count": len(normalized),
                })

            self._endpoints[endpoint_id] = {
                "endpoint_id": endpoint_id,
                "path": path,
                "params": normalized,
                "probe_ids": (),
            }

    def remove_endpoint(self, endpoint_id: str) -> bool:
        with self._lock:
            if endpoint_id not in self._endpoints:
                return False
            self._endpoints.pop(endpoint_id)

            stale = [
                probe_id for probe_id, probe in self._probes.items()
                if probe.endpoint_id == endpoint_id
            ]
            for probe_id in stale:
                self._probes.pop(probe_id, None)
                self._results.pop(probe_id, None)
            return True

    def build_matrix(self, endpoint_id: str) -> tuple[Probe, ...]:
        with self._lock:
            endpoint = self._endpoints.get(endpoint_id)
            if endpoint is None:
                raise ParamError("PARAM_UNKNOWN_ENDPOINT", endpoint_id)

            params = sorted(endpoint["params"], key=lambda item: item[0])
            potential = len(params) * len(self._KINDS)
            limit = max(0, self.max_combos)
            emitted_count = min(potential, limit)

            emitted: list[Probe] = []
            for name, base in params:
                variants = self._variants(name, base)
                for kind, query in variants:
                    if len(emitted) >= emitted_count:
                        break
                    probe_id = f"{endpoint_id}:{name}:{kind}"
                    emitted.append(Probe(
                        probe_id=probe_id,
                        endpoint_id=endpoint_id,
                        param=name,
                        kind=kind,
                        query=query,
                    ))
                if len(emitted) >= emitted_count:
                    break

            self._probe_total += len(emitted)
            self._suppressed_total += potential - len(emitted)
            for probe in emitted:
                self._probes[probe.probe_id] = probe
            endpoint["probe_ids"] = tuple(probe.probe_id for probe in emitted)
            return tuple(emitted)

    def classify_parser(self, values, resolved) -> str:
        if isinstance(values, (str, bytes)) or values is None:
            raise ParamError("PARAM_INVALID_VALUES", values)
        try:
            parsed = tuple(values)
        except TypeError:
            raise ParamError("PARAM_INVALID_VALUES", values) from None
        if not parsed or any(not isinstance(value, str) for value in parsed):
            raise ParamError("PARAM_INVALID_VALUES", values)

        if resolved is None:
            return "none"
        if resolved == parsed[0]:
            return "first"
        if resolved == parsed[-1]:
            return "last"
        if isinstance(resolved, (tuple, list)) and tuple(resolved) == parsed:
            return "array"
        if resolved == ",".join(parsed):
            return "joined"
        return "other"

    def param_state(self, *, present: bool, value) -> str:
        if not present:
            return "missing"
        if value == "":
            return "empty"
        return "present"

    def compare_backends(self, frontend, backend) -> str:
        front_missing = frontend is None
        back_missing = backend is None
        if front_missing and back_missing:
            return "consistent"
        if front_missing or back_missing:
            return "divergent_missing"
        if frontend == backend:
            return "consistent"
        return "polluted"

    def record(self, probe_id: str, *, source: str, frontend,
               backend) -> Result:
        with self._lock:
            probe = self._probes.get(probe_id)
            if probe is None:
                raise ParamError("PARAM_UNKNOWN_PROBE", probe_id)
            if source not in self._SOURCES:
                raise ParamError("PARAM_INVALID_SOURCE", source)

            result = Result(
                probe_id=probe_id,
                param=probe.param,
                kind=probe.kind,
                source=source,
                frontend=frontend,
                backend=backend,
                verdict=self.compare_backends(frontend, backend),
            )
            self._results.setdefault(probe_id, []).append(result)
            return result

    def merge(self, results=None) -> MergeReport:
        with self._lock:
            records = self._collect_results(results)

            grouped: dict[tuple[str, str, str], dict] = {}
            for result in records:
                key = (result.param, result.kind, result.source)
                entry = grouped.get(key)
                if entry is None:
                    entry = {
                        "probe_id": result.probe_id,
                        "verdict": result.verdict,
                        "observations": 0,
                    }
                    grouped[key] = entry
                entry["observations"] += 1
                current = self._VERDICT_RANK.get(entry["verdict"], -1)
                candidate = self._VERDICT_RANK.get(result.verdict, -1)
                if candidate > current:
                    entry["verdict"] = result.verdict

            rows = tuple(
                MergeRow(
                    probe_id=entry["probe_id"],
                    param=key[0],
                    kind=key[1],
                    source=key[2],
                    verdict=entry["verdict"],
                    observations=entry["observations"],
                )
                for key, entry in sorted(grouped.items())
            )
            merged = len(records) - len(rows)
            self._merged_total += merged
            return MergeReport(rows=rows, merged=merged)

    def describe_endpoint(self, endpoint_id: str) -> dict:
        with self._lock:
            endpoint = self._endpoints.get(endpoint_id)
            if endpoint is None:
                raise ParamError("PARAM_UNKNOWN_ENDPOINT", endpoint_id)
            return {
                "endpoint_id": endpoint_id,
                "path": endpoint["path"],
                "params": tuple(sorted(
                    endpoint["params"], key=lambda item: item[0],
                )),
                "probes": len(endpoint["probe_ids"]),
            }

    def results_for(self, probe_id: str) -> tuple[Result, ...]:
        with self._lock:
            return tuple(self._results.get(probe_id, ()))

    def snapshot(self) -> dict:
        with self._lock:
            endpoints = {
                endpoint_id: {
                    "endpoint_id": endpoint_id,
                    "path": endpoint["path"],
                    "params": tuple(endpoint["params"]),
                    "probe_ids": tuple(endpoint["probe_ids"]),
                }
                for endpoint_id, endpoint in self._endpoints.items()
            }
            probes = {
                probe_id: Probe(
                    probe_id=probe.probe_id,
                    endpoint_id=probe.endpoint_id,
                    param=probe.param,
                    kind=probe.kind,
                    query=tuple(probe.query),
                )
                for probe_id, probe in self._probes.items()
            }
            results = {
                probe_id: [
                    Result(
                        probe_id=result.probe_id,
                        param=result.param,
                        kind=result.kind,
                        source=result.source,
                        frontend=result.frontend,
                        backend=result.backend,
                        verdict=result.verdict,
                    )
                    for result in probe_results
                ]
                for probe_id, probe_results in self._results.items()
            }
            state = {
                "version": self._VERSION,
                "endpoints": endpoints,
                "probes": probes,
                "results": results,
                "stats": self._stats_locked(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        loaded = self._load_snapshot(state)
        with self._lock:
            endpoints, probes, results, counters = loaded
            self._endpoints = endpoints
            self._probes = probes
            self._results = results
            self._probe_total = counters["probes"]
            self._suppressed_total = counters["suppressed"]
            self._merged_total = counters["merged"]
            self._restore_total = counters["restores"] + 1

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()

    def reset(self) -> None:
        with self._lock:
            self._clear()

    def _clear(self) -> None:
        self._endpoints: dict[str, dict] = {}
        self._probes: dict[str, Probe] = {}
        self._results: dict[str, list[Result]] = {}
        self._probe_total = 0
        self._suppressed_total = 0
        self._merged_total = 0
        self._restore_total = 0

    def _stats_locked(self) -> dict:
        return {
            "endpoints": len(self._endpoints),
            "probes": self._probe_total,
            "suppressed": self._suppressed_total,
            "results": sum(len(items) for items in self._results.values()),
            "merged": self._merged_total,
            "restores": self._restore_total,
        }

    @staticmethod
    def _normalize_params(params) -> tuple:
        if isinstance(params, (str, bytes)) or params is None:
            raise ParamError("PARAM_INVALID_ENDPOINT", {"params": params})
        try:
            items = tuple(params)
        except TypeError:
            raise ParamError("PARAM_INVALID_ENDPOINT", {
                "params": params,
            }) from None

        normalized = []
        for item in items:
            if (isinstance(item, (str, bytes))
                    or not isinstance(item, (tuple, list))
                    or len(item) != 2):
                raise ParamError("PARAM_INVALID_ENDPOINT", {"params": params})
            name, value = item
            if not isinstance(name, str):
                raise ParamError("PARAM_INVALID_ENDPOINT", {"params": params})
            normalized.append((name, value))
        return tuple(normalized)

    def _variants(self, name: str, base) -> tuple[tuple[str, tuple], ...]:
        return (
            ("duplicate_first", ((name, base), (name, "probe"))),
            ("duplicate_last", ((name, "probe"), (name, base))),
            ("bracket_dup", ((f"{name}[]", base), (f"{name}[]", "probe"))),
            ("scalar_then_array", ((name, base), (f"{name}[]", "probe"))),
            ("encoded_sep", ((name, f"{base}%26{name}=probe"),)),
            ("semicolon_sep", ((name, f"{base};{name}=probe"),)),
        )

    def _collect_results(self, results) -> list[Result]:
        if results is None:
            return [
                result
                for probe_results in self._results.values()
                for result in probe_results
            ]
        if isinstance(results, Result):
            return [results]
        if isinstance(results, Mapping):
            collected = []
            for value in results.values():
                if isinstance(value, Result):
                    collected.append(value)
                else:
                    collected.extend(value)
            return collected
        return list(results)

    def _load_snapshot(self, state):
        def invalid(detail=None):
            return ParamError("PARAM_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != self._SNAPSHOT_KEYS:
            raise invalid(state)
        if (type(state.get("version")) is not int
                or state["version"] != self._VERSION):
            raise invalid(state.get("version"))

        raw_endpoints = state["endpoints"]
        if not isinstance(raw_endpoints, dict):
            raise invalid("endpoints")
        endpoints = {}
        for endpoint_id, record in raw_endpoints.items():
            if not isinstance(endpoint_id, str) or not isinstance(record, dict):
                raise invalid("endpoints")
            if set(record) != {
                "endpoint_id", "path", "params", "probe_ids",
            }:
                raise invalid("endpoints")
            path = record["path"]
            if (record["endpoint_id"] != endpoint_id
                    or not isinstance(path, str)
                    or not path.startswith("/") or "?" in path):
                raise invalid("endpoints")
            try:
                params = self._normalize_params(record["params"])
            except ParamError:
                raise invalid("endpoints") from None
            raw_probe_ids = record["probe_ids"]
            if (not isinstance(raw_probe_ids, (tuple, list))
                    or any(not isinstance(item, str) for item in raw_probe_ids)):
                raise invalid("endpoints")
            endpoints[endpoint_id] = {
                "endpoint_id": endpoint_id,
                "path": path,
                "params": params,
                "probe_ids": tuple(raw_probe_ids),
            }

        raw_probes = state["probes"]
        if not isinstance(raw_probes, dict):
            raise invalid("probes")
        probes = {}
        for probe_id, record in raw_probes.items():
            if not isinstance(probe_id, str):
                raise invalid("probes")
            if isinstance(record, Probe):
                probe = record
            elif isinstance(record, dict) and set(record) == {
                "probe_id", "endpoint_id", "param", "kind", "query",
            }:
                try:
                    query = self._normalize_params(record["query"])
                except ParamError:
                    raise invalid("probes") from None
                probe = Probe(
                    probe_id=record["probe_id"],
                    endpoint_id=record["endpoint_id"],
                    param=record["param"],
                    kind=record["kind"],
                    query=query,
                )
            else:
                raise invalid("probes")
            if (probe.probe_id != probe_id
                    or not isinstance(probe.endpoint_id, str)
                    or probe.endpoint_id not in endpoints
                    or not isinstance(probe.param, str)
                    or not isinstance(probe.kind, str)
                    or not isinstance(probe.query, tuple)
                    or any(
                        not isinstance(pair, (tuple, list)) or len(pair) != 2
                        or not isinstance(pair[0], str)
                        for pair in probe.query
                    )):
                raise invalid("probes")
            probes[probe_id] = Probe(
                probe_id=probe.probe_id,
                endpoint_id=probe.endpoint_id,
                param=probe.param,
                kind=probe.kind,
                query=tuple((name, value) for name, value in probe.query),
            )

        raw_results = state["results"]
        if not isinstance(raw_results, dict):
            raise invalid("results")
        results = {}
        for probe_id, rows in raw_results.items():
            if (not isinstance(probe_id, str)
                    or not isinstance(rows, (tuple, list))):
                raise invalid("results")
            loaded_rows = []
            for row in rows:
                if isinstance(row, Result):
                    result = row
                elif isinstance(row, dict) and set(row) == {
                    "probe_id", "param", "kind", "source",
                    "frontend", "backend", "verdict",
                }:
                    result = Result(**row)
                else:
                    raise invalid("results")
                if (not isinstance(result.probe_id, str)
                        or result.probe_id != probe_id
                        or not isinstance(result.param, str)
                        or not isinstance(result.kind, str)
                        or result.source not in self._SOURCES
                        or result.verdict not in self._VERDICT_RANK):
                    raise invalid("results")
                loaded_rows.append(result)
            results[probe_id] = loaded_rows

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != self._STAT_KEYS:
            raise invalid("stats")
        counters = {}
        for key in self._STAT_KEYS:
            value = raw_stats[key]
            if type(value) is not int or value < 0:
                raise invalid("stats")
            counters[key] = value

        return endpoints, probes, results, counters
