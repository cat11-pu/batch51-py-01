"""Container image configuration audit: user normalisation, env leaks, entrypoint form."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping


class ImageAuditError(ValueError):
    """Raised when an image configuration cannot be audited."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class EnvEntry:
    key: str
    value: str
    layer: int | None
    source: str


@dataclass(frozen=True)
class Layer:
    index: int
    stage: str
    created_by: str
    env: tuple[tuple[str, str], ...]
    deleted_files: tuple[str, ...]


@dataclass(frozen=True)
class ImageConfig:
    image: str
    digest: str | None
    user: str | None
    entrypoint: tuple[str, ...] | str | None
    env: tuple[EnvEntry, ...]
    exposed_ports: tuple[int, ...]
    volumes: tuple[str, ...]
    healthcheck: Mapping[str, Any] | None
    stage: str
    layers: tuple[Layer, ...]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    subject: str
    layer: int | None
    detail: Mapping[str, Any]


class ImageConfigAuditor:
    """Parse an image config snapshot and emit graded configuration findings."""

    SEVERITY_ORDER = ("high", "medium", "low")
    SECRET_KEY_PATTERN = re.compile(
        r"(PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)",
        re.IGNORECASE,
    )
    CONNECTION_PATTERN = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
    SNAPSHOT_KEYS = frozenset({"version", "config", "findings", "stats"})

    def __init__(self, *, max_layers: int = 40, max_config_bytes: int = 65536) -> None:
        self.max_layers = max_layers
        self.max_config_bytes = max_config_bytes
        self._lock = threading.RLock()

    def load_config(self, payload: dict) -> ImageConfig:
        raise NotImplementedError

    def audit_user(self, user: str | None = None) -> tuple[Finding, ...]:
        raise NotImplementedError

    def scan_env(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def check_entrypoint(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def check_base_image(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def check_ports(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def check_healthcheck(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def check_layers(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def audit(self) -> tuple[Finding, ...]:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
