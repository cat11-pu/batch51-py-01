"""Container image configuration audit.

The auditor deliberately works from the build-system export instead of only
looking at the final config: environment values and deleted files in earlier
layers remain recoverable and therefore remain part of the audit surface.
"""

from __future__ import annotations

import copy
import json
import re
import threading
from dataclasses import dataclass, replace
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
        r"("
        r"PASS[_-]?WORD|PASSWD|PASSCODE|SECRET|TOKEN|CREDENTIALS?|"
        r"API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
        r"(?<![A-Z0-9])(?:KEY|PASS|PWD)(?![A-Z0-9])|"
        r"口令|令牌|密钥|凭据"
        r")",
        re.IGNORECASE,
    )
    CONNECTION_PATTERN = re.compile(
        r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE
    )
    DIGEST_PATTERN = re.compile(r"sha256:[0-9a-fA-F]{64}\Z")
    SNAPSHOT_KEYS = frozenset({"version", "config", "findings", "stats"})
    SNAPSHOT_VERSION = 1
    _CONFIG_KEYS = frozenset(
        {
            "image",
            "digest",
            "user",
            "entrypoint",
            "env",
            "exposed_ports",
            "volumes",
            "healthcheck",
            "stage",
            "layers",
        }
    )
    _LAYER_KEYS = frozenset(
        {"index", "stage", "created_by", "env", "deleted_files"}
    )
    _LAYER_REQUIRED_KEYS = frozenset({"index", "stage", "created_by"})
    _ENV_ENTRY_KEYS = frozenset({"key", "value", "layer", "source"})
    _FINDING_KEYS = frozenset(
        {"code", "severity", "subject", "layer", "detail"}
    )
    _PROTOCOLS = frozenset({"tcp", "udp", "sctp"})

    def __init__(
        self, *, max_layers: int = 40, max_config_bytes: int = 65536
    ) -> None:
        if (
            not isinstance(max_layers, int)
            or isinstance(max_layers, bool)
            or max_layers < 0
        ):
            raise ImageAuditError(
                "IMAGE_CONFIG_INVALID", {"field": "max_layers"}
            )
        if (
            not isinstance(max_config_bytes, int)
            or isinstance(max_config_bytes, bool)
            or max_config_bytes < 0
        ):
            raise ImageAuditError(
                "IMAGE_CONFIG_INVALID", {"field": "max_config_bytes"}
            )

        self.max_layers = max_layers
        self.max_config_bytes = max_config_bytes
        self._lock = threading.RLock()
        self._config: ImageConfig | None = None
        self._findings: tuple[Finding, ...] = ()
        self._stats = {"loads": 0, "audits": 0}

    # ------------------------------------------------------------------
    # Loading and validation
    # ------------------------------------------------------------------

    def load_config(self, payload: dict) -> ImageConfig:
        """Validate and load one build-system payload."""
        try:
            if not isinstance(payload, Mapping):
                self._config_error("payload")

            layers = payload.get("layers", ())
            if not isinstance(layers, (list, tuple)):
                self._config_error("layers")
            if len(layers) > self.max_layers:
                self._limit_error("layers", len(layers), self.max_layers)

            serialized = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(serialized) > self.max_config_bytes:
                self._limit_error(
                    "config_bytes", len(serialized), self.max_config_bytes
                )

            config = self._parse_payload(payload)
        except ImageAuditError:
            raise
        except Exception as exc:  # keep malformed input from leaking internals
            raise ImageAuditError(
                "IMAGE_CONFIG_INVALID", {"reason": type(exc).__name__}
            ) from exc

        with self._lock:
            self._config = config
            self._findings = ()
            self._stats["loads"] += 1
        return config

    def _parse_payload(self, payload: Mapping[str, Any]) -> ImageConfig:
        data = self._select_final_stage(payload)

        if "layers" in payload:
            layers_raw = payload["layers"]
        elif "stages" in payload:
            layers_raw = self._collect_stage_layers(payload)
        elif "layers" in data:
            layers_raw = data["layers"]
        else:
            layers_raw = ()

        if not isinstance(layers_raw, (list, tuple)):
            self._config_error("layers")
        if len(layers_raw) > self.max_layers:
            self._limit_error("layers", len(layers_raw), self.max_layers)

        return self._build_config(data, layers_raw)

    def _select_final_stage(
        self, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Accept the exported flat form and common nested stage forms."""
        if "image" in payload or "digest" in payload:
            return dict(payload)

        stages = payload.get("stages")
        selected: Mapping[str, Any] | None = None
        stage_name: str | None = None

        if isinstance(stages, Mapping):
            selector = payload.get("final_stage")
            if isinstance(selector, str) and selector in stages:
                selected = stages[selector]
                stage_name = selector
            elif "final" in stages:
                selected = stages["final"]
                stage_name = "final"
            elif stages:
                stage_name = str(next(reversed(stages)))
                selected = stages[stage_name]
        elif isinstance(stages, (list, tuple)) and stages:
            selector = payload.get("final_stage", -1)
            selected_index: int | None = None
            if (
                isinstance(selector, int)
                and not isinstance(selector, bool)
                and -len(stages) <= selector < len(stages)
            ):
                selected_index = (
                    selector if selector >= 0 else len(stages) + selector
                )
            elif isinstance(selector, str):
                for index, stage in enumerate(stages):
                    if isinstance(stage, Mapping) and (
                        stage.get("name") == selector
                        or stage.get("stage") == selector
                    ):
                        selected_index = index
                        break
            if selected_index is None:
                selected_index = len(stages) - 1
            candidate = stages[selected_index]
            if not isinstance(candidate, Mapping):
                self._config_error("stages")
            selected = candidate
            stage_name = str(
                selected.get("name") or selected.get("stage") or selected_index
            )

        if selected is None:
            for key in ("final_config", "config", "final"):
                candidate = payload.get(key)
                if isinstance(candidate, Mapping):
                    selected = candidate
                    stage_name = str(candidate.get("stage") or "final")
                    break

        if selected is None:
            self._config_error("image")

        data = {
            key: value
            for key, value in payload.items()
            if key not in {"stages", "final_stage"}
        }
        data.update(selected)
        if "stage" not in data and stage_name is not None:
            data["stage"] = stage_name
        return data

    def _collect_stage_layers(
        self, payload: Mapping[str, Any]
    ) -> list[Any]:
        stages = payload.get("stages")
        collected: list[Any] = []

        if isinstance(stages, Mapping):
            iterable = [
                (str(name), stage) for name, stage in stages.items()
            ]
        elif isinstance(stages, (list, tuple)):
            iterable = [
                (
                    str(
                        stage.get("name") or stage.get("stage") or index
                    )
                    if isinstance(stage, Mapping)
                    else str(index),
                    stage,
                )
                for index, stage in enumerate(stages)
            ]
        else:
            return collected

        for name, stage in iterable:
            if not isinstance(stage, Mapping):
                self._config_error("stages")
            stage_layers = stage.get("layers", ())
            if not isinstance(stage_layers, (list, tuple)):
                self._config_error("layers")
            for layer in stage_layers:
                if isinstance(layer, Mapping):
                    item = dict(layer)
                    item.setdefault("stage", name)
                    collected.append(item)
                else:
                    collected.append(layer)
        return collected

    def _build_config(
        self, data: Mapping[str, Any], layers_raw: list[Any] | tuple[Any, ...]
    ) -> ImageConfig:
        image = data.get("image")
        if not isinstance(image, str) or not image.strip():
            self._config_error("image")

        digest = data.get("digest")
        if digest is not None:
            if (
                not isinstance(digest, str)
                or not self.DIGEST_PATTERN.fullmatch(digest)
            ):
                self._config_error("digest")

        user_raw = data.get("user")
        if user_raw is not None:
            if isinstance(user_raw, bool) or not isinstance(
                user_raw, (str, int)
            ):
                self._config_error("user")
            user: str | None = str(user_raw)
        else:
            user = None

        entrypoint = self._parse_entrypoint(data.get("entrypoint"))

        env_pairs = self._normalise_env(data.get("env", {}), "env")
        env = tuple(
            EnvEntry(key=key, value=value, layer=None, source="config")
            for key, value in env_pairs
        )

        exposed_ports = self._parse_ports(data.get("exposed_ports", ()))
        volumes = self._parse_volumes(data.get("volumes", ()))

        healthcheck_raw = data.get("healthcheck")
        if healthcheck_raw is not None and not isinstance(
            healthcheck_raw, Mapping
        ):
            self._config_error("healthcheck")
        healthcheck = (
            copy.deepcopy(dict(healthcheck_raw))
            if isinstance(healthcheck_raw, Mapping)
            else None
        )

        stage = data.get("stage", "final")
        if not isinstance(stage, str) or not stage.strip():
            self._config_error("stage")

        layers = tuple(
            self._parse_layer(layer, position)
            for position, layer in enumerate(layers_raw)
        )

        return ImageConfig(
            image=image,
            digest=digest,
            user=user,
            entrypoint=entrypoint,
            env=env,
            exposed_ports=exposed_ports,
            volumes=volumes,
            healthcheck=healthcheck,
            stage=stage,
            layers=layers,
        )

    def _parse_entrypoint(
        self, raw: Any
    ) -> tuple[str, ...] | str | None:
        if raw is None or isinstance(raw, str):
            return raw
        if not isinstance(raw, (list, tuple)):
            self._config_error("entrypoint")
        if any(not isinstance(item, str) for item in raw):
            self._config_error("entrypoint")
        return tuple(raw)

    def _normalise_env(
        self, raw: Any, field: str
    ) -> list[tuple[str, str]]:
        if isinstance(raw, Mapping):
            items = list(raw.items())
        elif isinstance(raw, (list, tuple)):
            items = []
            for item in raw:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    self._config_error(field)
                items.append((item[0], item[1]))
        else:
            self._config_error(field)

        result: list[tuple[str, str]] = []
        for key, value in items:
            if not isinstance(key, str) or not key.strip():
                self._config_error(field)
            if isinstance(value, str):
                text = value
            elif isinstance(value, (int, float, bool)) and not isinstance(
                value, complex
            ):
                text = str(value)
            else:
                self._config_error(field)
            result.append((key, text))
        return result

    def _parse_ports(self, raw: Any) -> tuple[int, ...]:
        if not isinstance(raw, (list, tuple)):
            self._config_error("exposed_ports")

        ports: list[int] = []
        seen: set[int] = set()
        for item in raw:
            port = self._parse_port(item)
            if port not in seen:
                seen.add(port)
                ports.append(port)
        return tuple(ports)

    def _parse_port(self, raw: Any) -> int:
        if isinstance(raw, bool):
            self._config_error("exposed_ports")

        if isinstance(raw, int):
            port = raw
        elif isinstance(raw, str):
            text = raw.strip()
            if not text:
                self._config_error("exposed_ports")
            if "/" in text:
                parts = text.split("/")
                if len(parts) != 2:
                    self._config_error("exposed_ports")
                port_text, protocol = parts
                if (
                    not port_text.isdigit()
                    or protocol.lower() not in self._PROTOCOLS
                ):
                    self._config_error("exposed_ports")
                port = int(port_text)
            elif text.isdigit():
                port = int(text)
            else:
                self._config_error("exposed_ports")
        else:
            self._config_error("exposed_ports")

        if port < 1 or port > 65535:
            self._config_error("exposed_ports")
        return port

    def _parse_volumes(self, raw: Any) -> tuple[str, ...]:
        if not isinstance(raw, (list, tuple)):
            self._config_error("volumes")
        if any(not isinstance(item, str) for item in raw):
            self._config_error("volumes")
        return tuple(raw)

    def _parse_layer(self, raw: Any, position: int) -> Layer:
        if not isinstance(raw, Mapping):
            self._config_error("layers")
        if not self._LAYER_REQUIRED_KEYS.issubset(raw):
            missing = sorted(self._LAYER_REQUIRED_KEYS.difference(raw))
            raise ImageAuditError(
                "IMAGE_CONFIG_INVALID",
                {"field": "layers", "position": position, "missing": missing},
            )

        index = raw["index"]
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
        ):
            self._config_error("layers")

        stage = raw["stage"]
        if not isinstance(stage, str) or not stage.strip():
            self._config_error("layers")

        created_by = raw["created_by"]
        if not isinstance(created_by, str):
            self._config_error("layers")

        env = tuple(self._normalise_env(raw.get("env", {}), "layers"))

        deleted_raw = raw.get("deleted_files", ())
        if not isinstance(deleted_raw, (list, tuple)):
            self._config_error("layers")
        if any(
            not isinstance(path, str) or not path.strip()
            for path in deleted_raw
        ):
            self._config_error("layers")

        return Layer(
            index=index,
            stage=stage,
            created_by=created_by,
            env=env,
            deleted_files=tuple(deleted_raw),
        )

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def audit_user(self, user: str | None = None) -> tuple[Finding, ...]:
        with self._lock:
            identity = (
                self._config.user if user is None and self._config else user
            )
        return self._audit_user(identity)

    def _audit_user(self, user: Any) -> tuple[Finding, ...]:
        if user is None:
            is_root = True
        else:
            if isinstance(user, bool) or not isinstance(user, (str, int)):
                self._config_error("user")
            text = str(user).strip()
            if not text:
                is_root = True
            else:
                user_part = text.split(":", 1)[0].strip()
                if not user_part or user_part.casefold() == "root":
                    is_root = True
                elif re.fullmatch(r"[+-]?\d+", user_part):
                    is_root = int(user_part, 10) == 0
                else:
                    is_root = False

        if not is_root:
            return ()
        return (
            Finding(
                code="IMAGE_ROOT_USER",
                severity="high",
                subject="user",
                layer=None,
                detail={},
            ),
        )

    def scan_env(self) -> tuple[Finding, ...]:
        with self._lock:
            config = self._require_config()
            findings = self._scan_env_for(config)
        return self._normalise_findings(findings)

    def _scan_env_for(self, config: ImageConfig) -> list[Finding]:
        entries: list[EnvEntry] = list(config.env)
        for layer in config.layers:
            for key, value in layer.env:
                entries.append(
                    EnvEntry(
                        key=key,
                        value=value,
                        layer=layer.index,
                        source="layer",
                    )
                )

        findings: list[Finding] = []
        for entry in entries:
            detail = {
                "key": entry.key,
                "length": len(entry.value),
                "layer": entry.layer,
            }
            if self.SECRET_KEY_PATTERN.search(entry.key):
                findings.append(
                    Finding(
                        code="IMAGE_ENV_SECRET",
                        severity="high",
                        subject=entry.key,
                        layer=entry.layer,
                        detail=detail,
                    )
                )
            if self.CONNECTION_PATTERN.search(entry.value):
                findings.append(
                    Finding(
                        code="IMAGE_ENV_CONNSTR",
                        severity="high",
                        subject=entry.key,
                        layer=entry.layer,
                        detail=dict(detail),
                    )
                )
        return findings

    def check_entrypoint(self) -> tuple[Finding, ...]:
        with self._lock:
            entrypoint = self._require_config().entrypoint

        if isinstance(entrypoint, str):
            return (
                Finding(
                    code="IMAGE_SHELL_ENTRYPOINT",
                    severity="medium",
                    subject="entrypoint",
                    layer=None,
                    detail={"form": "shell"},
                ),
            )
        if entrypoint is None or not entrypoint:
            return (
                Finding(
                    code="IMAGE_NO_ENTRYPOINT",
                    severity="low",
                    subject="entrypoint",
                    layer=None,
                    detail={},
                ),
            )
        return ()

    def check_base_image(self) -> tuple[Finding, ...]:
        with self._lock:
            config = self._require_config()
            if config.digest is not None:
                return ()
            image = config.image
        return (
            Finding(
                code="IMAGE_UNPINNED_BASE",
                severity="medium",
                subject=image,
                layer=None,
                detail={},
            ),
        )

    def check_ports(self) -> tuple[Finding, ...]:
        with self._lock:
            ports = self._require_config().exposed_ports

        findings = [
            Finding(
                code="IMAGE_PRIVILEGED_PORT",
                severity="high",
                subject=str(port),
                layer=None,
                detail={"port": port},
            )
            for port in ports
            if port < 1024
        ]
        return self._normalise_findings(findings)

    def check_healthcheck(self) -> tuple[Finding, ...]:
        with self._lock:
            healthcheck = self._require_config().healthcheck
        if healthcheck:
            return ()
        return (
            Finding(
                code="IMAGE_NO_HEALTHCHECK",
                severity="low",
                subject="healthcheck",
                layer=None,
                detail={},
            ),
        )

    def check_layers(self) -> tuple[Finding, ...]:
        with self._lock:
            layers = self._require_config().layers

        findings: list[Finding] = []
        for layer in layers:
            for path in layer.deleted_files:
                findings.append(
                    Finding(
                        code="IMAGE_DELETED_FILE_LEAK",
                        severity="high",
                        subject=path,
                        layer=layer.index,
                        detail={"path": path, "layer": layer.index},
                    )
                )
        return self._normalise_findings(findings)

    # ------------------------------------------------------------------
    # Aggregate audit and report
    # ------------------------------------------------------------------

    def audit(self) -> tuple[Finding, ...]:
        with self._lock:
            config = self._require_config()
            findings: list[Finding] = []
            findings.extend(self._audit_user(config.user))
            findings.extend(self._scan_env_for(config))
            findings.extend(self._check_entrypoint_for(config))
            findings.extend(self._check_base_image_for(config))
            findings.extend(self._check_ports_for(config))
            findings.extend(self._check_healthcheck_for(config))
            findings.extend(self._check_layers_for(config))

            ordered = self._normalise_findings(findings)
            self._findings = ordered
            self._stats["audits"] += 1
            return ordered

    def _check_entrypoint_for(
        self, config: ImageConfig
    ) -> list[Finding]:
        entrypoint = config.entrypoint
        if isinstance(entrypoint, str):
            return [
                Finding(
                    code="IMAGE_SHELL_ENTRYPOINT",
                    severity="medium",
                    subject="entrypoint",
                    layer=None,
                    detail={"form": "shell"},
                )
            ]
        if entrypoint is None or not entrypoint:
            return [
                Finding(
                    code="IMAGE_NO_ENTRYPOINT",
                    severity="low",
                    subject="entrypoint",
                    layer=None,
                    detail={},
                )
            ]
        return []

    def _check_base_image_for(
        self, config: ImageConfig
    ) -> list[Finding]:
        if config.digest is not None:
            return []
        return [
            Finding(
                code="IMAGE_UNPINNED_BASE",
                severity="medium",
                subject=config.image,
                layer=None,
                detail={},
            )
        ]

    def _check_ports_for(self, config: ImageConfig) -> list[Finding]:
        return [
            Finding(
                code="IMAGE_PRIVILEGED_PORT",
                severity="high",
                subject=str(port),
                layer=None,
                detail={"port": port},
            )
            for port in config.exposed_ports
            if port < 1024
        ]

    def _check_healthcheck_for(
        self, config: ImageConfig
    ) -> list[Finding]:
        if config.healthcheck:
            return []
        return [
            Finding(
                code="IMAGE_NO_HEALTHCHECK",
                severity="low",
                subject="healthcheck",
                layer=None,
                detail={},
            )
        ]

    def _check_layers_for(
        self, config: ImageConfig
    ) -> list[Finding]:
        return [
            Finding(
                code="IMAGE_DELETED_FILE_LEAK",
                severity="high",
                subject=path,
                layer=layer.index,
                detail={"path": path, "layer": layer.index},
            )
            for layer in config.layers
            for path in layer.deleted_files
        ]

    def report(self) -> dict:
        with self._lock:
            config = self._require_config()
            findings = tuple(self._findings)
            audits = self._stats["audits"]

            counts = {"high": 0, "medium": 0, "low": 0}
            for finding in findings:
                counts[finding.severity] += 1

            return {
                "image": config.image,
                "digest_pinned": config.digest is not None,
                "verdict": "fail" if findings else "pass",
                "counts": counts,
                "findings": [
                    self._finding_to_dict(finding) for finding in findings
                ],
                "audits": audits,
            }

    # ------------------------------------------------------------------
    # Snapshot, restore and counters
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "config": (
                    self._config_to_dict(self._config)
                    if self._config is not None
                    else None
                ),
                "findings": [
                    self._finding_to_dict(finding)
                    for finding in self._findings
                ],
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            candidate = copy.deepcopy(state)
            config, findings, stats = self._validate_snapshot(candidate)
        except ImageAuditError as exc:
            if exc.code == "IMAGE_SNAPSHOT_INVALID":
                raise
            raise ImageAuditError(
                "IMAGE_SNAPSHOT_INVALID", exc.detail
            ) from exc
        except Exception as exc:
            raise ImageAuditError(
                "IMAGE_SNAPSHOT_INVALID", {"reason": type(exc).__name__}
            ) from exc

        with self._lock:
            self._config = config
            self._findings = findings
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _config_to_dict(self, config: ImageConfig) -> dict[str, Any]:
        return {
            "image": config.image,
            "digest": config.digest,
            "user": config.user,
            "entrypoint": (
                list(config.entrypoint)
                if isinstance(config.entrypoint, tuple)
                else config.entrypoint
            ),
            "env": [
                {
                    "key": entry.key,
                    "value": entry.value,
                    "layer": entry.layer,
                    "source": entry.source,
                }
                for entry in config.env
            ],
            "exposed_ports": list(config.exposed_ports),
            "volumes": list(config.volumes),
            "healthcheck": copy.deepcopy(config.healthcheck),
            "stage": config.stage,
            "layers": [
                {
                    "index": layer.index,
                    "stage": layer.stage,
                    "created_by": layer.created_by,
                    "env": [list(item) for item in layer.env],
                    "deleted_files": list(layer.deleted_files),
                }
                for layer in config.layers
            ],
        }

    def _validate_snapshot(
        self, state: Any
    ) -> tuple[ImageConfig | None, tuple[Finding, ...], dict[str, int]]:
        if not isinstance(state, Mapping):
            self._snapshot_error("state")
        if set(state) != self.SNAPSHOT_KEYS:
            self._snapshot_error("keys")
        version = state["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != self.SNAPSHOT_VERSION
        ):
            self._snapshot_error("version")

        config_raw = state["config"]
        config = (
            None
            if config_raw is None
            else self._snapshot_config(config_raw)
        )

        findings_raw = state["findings"]
        if not isinstance(findings_raw, (list, tuple)):
            self._snapshot_error("findings")
        findings: list[Finding] = []
        for item in findings_raw:
            if (
                not isinstance(item, Mapping)
                or set(item) != self._FINDING_KEYS
            ):
                self._snapshot_error("findings")
            code = item["code"]
            severity = item["severity"]
            subject = item["subject"]
            layer = item["layer"]
            detail = item["detail"]
            if not isinstance(code, str) or not code:
                self._snapshot_error("findings")
            if severity not in self.SEVERITY_ORDER:
                self._snapshot_error("findings")
            if not isinstance(subject, str):
                self._snapshot_error("findings")
            if layer is not None and (
                not isinstance(layer, int)
                or isinstance(layer, bool)
                or layer < 0
            ):
                self._snapshot_error("findings")
            if not isinstance(detail, Mapping):
                self._snapshot_error("findings")
            findings.append(
                Finding(
                    code=code,
                    severity=severity,
                    subject=subject,
                    layer=layer,
                    detail=copy.deepcopy(dict(detail)),
                )
            )
        if config is None and findings:
            self._snapshot_error("findings")

        stats_raw = state["stats"]
        if not isinstance(stats_raw, Mapping):
            self._snapshot_error("stats")
        if set(stats_raw) != {"loads", "audits"}:
            self._snapshot_error("stats")
        loads = stats_raw["loads"]
        audits = stats_raw["audits"]
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            for value in (loads, audits)
        ):
            self._snapshot_error("stats")

        return config, tuple(findings), {"loads": loads, "audits": audits}

    def _snapshot_config(self, raw: Any) -> ImageConfig:
        if not isinstance(raw, Mapping) or set(raw) != self._CONFIG_KEYS:
            self._snapshot_error("config")

        env_raw = raw["env"]
        if not isinstance(env_raw, (list, tuple)):
            self._snapshot_error("config")

        env_entries: list[EnvEntry] = []
        env_pairs: list[list[str]] = []
        for entry in env_raw:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != self._ENV_ENTRY_KEYS
            ):
                self._snapshot_error("config")
            key = entry["key"]
            value = entry["value"]
            layer = entry["layer"]
            source = entry["source"]
            if not isinstance(key, str) or not key.strip():
                self._snapshot_error("config")
            if not isinstance(value, str):
                self._snapshot_error("config")
            if layer is not None and (
                not isinstance(layer, int)
                or isinstance(layer, bool)
                or layer < 0
            ):
                self._snapshot_error("config")
            if not isinstance(source, str) or not source:
                self._snapshot_error("config")
            env_entries.append(EnvEntry(key, value, layer, source))
            env_pairs.append([key, value])

        layers_raw = raw["layers"]
        if not isinstance(layers_raw, (list, tuple)):
            self._snapshot_error("config")
        for layer in layers_raw:
            if (
                not isinstance(layer, Mapping)
                or set(layer) != self._LAYER_KEYS
            ):
                self._snapshot_error("config")

        payload = {
            "image": raw["image"],
            "digest": raw["digest"],
            "user": raw["user"],
            "entrypoint": raw["entrypoint"],
            "env": env_pairs,
            "exposed_ports": raw["exposed_ports"],
            "volumes": raw["volumes"],
            "healthcheck": raw["healthcheck"],
            "stage": raw["stage"],
            "layers": layers_raw,
        }
        try:
            config = self._build_config(payload, layers_raw)
        except ImageAuditError as exc:
            if exc.code == "IMAGE_CONFIG_INVALID":
                self._snapshot_error("config")
            raise
        return replace(config, env=tuple(env_entries))

    # ------------------------------------------------------------------
    # Internal utilities
    # ------------------------------------------------------------------

    def _require_config(self) -> ImageConfig:
        if self._config is None:
            self._config_error("config")
        return self._config

    def _normalise_findings(
        self, findings: list[Finding] | tuple[Finding, ...]
    ) -> tuple[Finding, ...]:
        unique: dict[tuple[Any, ...], Finding] = {}
        for finding in findings:
            detail_key = json.dumps(
                finding.detail, sort_keys=True, ensure_ascii=False, default=str
            )
            key = (
                finding.code,
                finding.severity,
                finding.subject,
                finding.layer,
                detail_key,
            )
            unique.setdefault(key, finding)

        severity_rank = {
            severity: rank
            for rank, severity in enumerate(self.SEVERITY_ORDER)
        }

        def sort_key(finding: Finding) -> tuple[Any, ...]:
            detail_key = json.dumps(
                finding.detail, sort_keys=True, ensure_ascii=False, default=str
            )
            return (
                severity_rank.get(finding.severity, len(severity_rank)),
                finding.code,
                finding.subject,
                -1 if finding.layer is None else finding.layer,
                detail_key,
            )

        return tuple(sorted(unique.values(), key=sort_key))

    @staticmethod
    def _finding_to_dict(finding: Finding) -> dict[str, Any]:
        return {
            "code": finding.code,
            "severity": finding.severity,
            "subject": finding.subject,
            "layer": finding.layer,
            "detail": copy.deepcopy(dict(finding.detail)),
        }

    @staticmethod
    def _config_error(field: str) -> None:
        raise ImageAuditError("IMAGE_CONFIG_INVALID", {"field": field})

    @staticmethod
    def _limit_error(kind: str, actual: int, limit: int) -> None:
        raise ImageAuditError(
            "IMAGE_LIMIT_EXCEEDED",
            {"kind": kind, "actual": actual, "limit": limit},
        )

    @staticmethod
    def _snapshot_error(field: str) -> None:
        raise ImageAuditError("IMAGE_SNAPSHOT_INVALID", {"field": field})
