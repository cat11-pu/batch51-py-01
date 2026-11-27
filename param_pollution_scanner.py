"""Parameter pollution scanner: probe matrix, parser dialects, result merge."""

from __future__ import annotations

import threading
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

    def __init__(self, *, max_combos: int = 24, max_params: int = 6) -> None:
        self.max_combos = max_combos
        self.max_params = max_params
        self._lock = threading.RLock()

    def add_endpoint(self, endpoint_id: str, *, path: str,
                     params: tuple = ()) -> None:
        raise NotImplementedError

    def remove_endpoint(self, endpoint_id: str) -> bool:
        raise NotImplementedError

    def build_matrix(self, endpoint_id: str) -> tuple[Probe, ...]:
        raise NotImplementedError

    def classify_parser(self, values, resolved) -> str:
        raise NotImplementedError

    def param_state(self, *, present: bool, value) -> str:
        raise NotImplementedError

    def compare_backends(self, frontend, backend) -> str:
        raise NotImplementedError

    def record(self, probe_id: str, *, source: str, frontend,
               backend) -> Result:
        raise NotImplementedError

    def merge(self, results=None) -> MergeReport:
        raise NotImplementedError

    def describe_endpoint(self, endpoint_id: str) -> dict:
        raise NotImplementedError

    def results_for(self, probe_id: str) -> tuple[Result, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
