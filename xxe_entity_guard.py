"""Entity expansion budget guard for untrusted XML documents."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass


class XxeError(ValueError):
    """Raised when the guard refuses a document or a policy change."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DtdInspection:
    """Result of scanning the declaration section of a document."""

    declarations: int
    internal: tuple
    external: tuple
    parameter: tuple
    external_subset: str | None


_NAME_PATTERN = r"[A-Za-z_:][A-Za-z0-9_.:-]*"
_NAME_RE = re.compile(_NAME_PATTERN)
_REFERENCE_RE = re.compile(r"&(" + _NAME_PATTERN + r");")
_SYSTEM_RE = re.compile(r"\bSYSTEM\s*([\"'])(.*?)\1", re.IGNORECASE | re.DOTALL)
_PUBLIC_RE = re.compile(
    r"\bPUBLIC\s*([\"'])(.*?)\1\s*([\"'])(.*?)\3",
    re.IGNORECASE | re.DOTALL,
)

_STAT_KEYS = (
    "parses",
    "accepted",
    "rejected",
    "blocked_external",
    "restores",
)
_REPORT_KEYS = {
    "accepted",
    "code",
    "trigger",
    "references",
    "expanded_bytes",
    "external",
}


@dataclass(frozen=True)
class _Entity:
    name: str
    parameter: bool
    value: str | None
    system_id: str | None
    position: int

    @property
    def external(self) -> bool:
        return self.system_id is not None

    @property
    def kind(self) -> str:
        if self.parameter:
            return "parameter"
        if self.external:
            return "external"
        return "internal"


@dataclass(frozen=True)
class _Scan:
    entities: tuple
    internal: tuple
    external: tuple
    parameter: tuple
    external_subset: str | None
    external_ids: tuple
    references: tuple

    @property
    def entity_map(self) -> dict:
        return {entity.name: entity for entity in self.entities}


class _ScanBuilder:
    def __init__(self) -> None:
        self.entities: list[_Entity] = []
        self.names: set[str] = set()
        self.external_subset: str | None = None
        self._external_entries: list[tuple[int, str]] = []
        self.masked: list[tuple[int, int]] = []

    def add_entity(self, entity: _Entity) -> None:
        if entity.name in self.names:
            raise XxeError("XXE_DTD_INVALID", {"entity": entity.name})
        self.names.add(entity.name)
        self.entities.append(entity)
        if entity.external:
            self._external_entries.append((entity.position, entity.system_id or ""))

    def set_external_subset(self, identifier: str, position: int) -> None:
        if self.external_subset is None:
            self.external_subset = identifier
            self._external_entries.append((position, identifier))

    def external_ids(self) -> list[str]:
        return [identifier for _, identifier in sorted(self._external_entries)]


class XxeEntityGuard:
    """Inspect declared entities before parsing and enforce expansion budgets."""

    def __init__(self, *, max_depth: int = 6, max_bytes: int = 2048) -> None:
        if (
            not isinstance(max_depth, int)
            or isinstance(max_depth, bool)
            or max_depth < 0
        ):
            raise ValueError("max_depth must be a non-negative integer")
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 0
        ):
            raise ValueError("max_bytes must be a non-negative integer")
        self.max_depth = max_depth
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._namespaces: dict[str, dict] = {}
        self._entities: dict[str, _Entity] = {}
        self._external_subset: str | None = None
        self._reference_counts: dict[str, int] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}
        self._last_report: dict | None = None

    def declare_namespace(self, namespace: str, *, prefix: str) -> None:
        with self._lock:
            previous = self._namespaces.get(namespace)
            self._namespaces[namespace] = {
                "prefix": prefix,
                "allow": bool(previous and previous["allow"]),
            }

    def revoke_namespace(self, namespace: str) -> bool:
        with self._lock:
            if namespace not in self._namespaces:
                return False
            del self._namespaces[namespace]
            return True

    def block_external(self, namespace: str, *, allow: bool = False) -> bool:
        with self._lock:
            policy = self._namespaces.get(namespace)
            if policy is None:
                raise XxeError("XXE_UNKNOWN_NAMESPACE", {"namespace": namespace})
            previous = bool(policy["allow"])
            policy["allow"] = bool(allow)
            return previous

    def inspect_dtd(self, document: str) -> DtdInspection:
        with self._lock:
            scan = self._scan_document(document)
            self._install_scan(scan)
            return DtdInspection(
                declarations=len(scan.entities),
                internal=scan.internal,
                external=scan.external,
                parameter=scan.parameter,
                external_subset=scan.external_subset,
            )

    def expand_budget(self, document: str) -> dict:
        with self._lock:
            scan = self._scan_document(document)
            self._install_scan(scan)
            self._check_external_policy(scan)
            sizes, depths = self._entity_metrics(scan)
            references, expanded_bytes = self._measure_document(scan, sizes)
            return {
                "declared": len(scan.entities),
                "per_entity": {
                    entity.name: sizes[entity.name] for entity in scan.entities
                },
                "max_depth": max(depths.values(), default=0),
                "references": references,
                "expanded_bytes": expanded_bytes,
            }

    def parse_report(self, document: str) -> dict:
        with self._lock:
            builder = _ScanBuilder()
            report = {
                "accepted": False,
                "code": None,
                "trigger": None,
                "references": 0,
                "expanded_bytes": 0,
                "external": [],
            }
            try:
                scan = self._scan_document(document, builder)
                self._install_scan(scan)
                report["external"] = list(scan.external_ids)

                self._check_external_policy(scan)
                sizes, _depths = self._entity_metrics(scan)

                references = 0
                expanded_bytes = 0
                entity_map = scan.entity_map
                for name in scan.references:
                    entity = entity_map.get(name)
                    if entity is None:
                        raise XxeError("XXE_UNKNOWN_ENTITY", {"entity": name})
                    references += 1
                    if not entity.external:
                        expanded_bytes += sizes[name]
                    report["references"] = references
                    report["expanded_bytes"] = expanded_bytes
                    if expanded_bytes > self.max_bytes:
                        raise XxeError(
                            "XXE_BUDGET_EXCEEDED",
                            {"entity": name, "bytes": expanded_bytes},
                        )

                report.update(
                    {
                        "accepted": True,
                        "code": None,
                        "trigger": None,
                        "references": references,
                        "expanded_bytes": expanded_bytes,
                    }
                )
            except XxeError as error:
                report["accepted"] = False
                report["code"] = error.code
                report["trigger"] = self._error_trigger(error)
                if not report["external"]:
                    report["external"] = builder.external_ids()

            self._stats["parses"] += 1
            if report["accepted"]:
                self._stats["accepted"] += 1
            else:
                self._stats["rejected"] += 1
                if report["code"] == "XXE_EXTERNAL_BLOCKED":
                    self._stats["blocked_external"] += 1
            self._last_report = copy.deepcopy(report)
            return copy.deepcopy(report)

    def describe_entity(self, name: str) -> dict:
        with self._lock:
            entity = self._entities.get(name)
            if entity is None:
                raise XxeError("XXE_UNKNOWN_ENTITY", {"entity": name})
            return {
                "name": entity.name,
                "kind": entity.kind,
                "parameter": entity.parameter,
                "external": entity.external,
                "value": entity.value,
                "system_id": entity.system_id,
                "references": self._reference_counts.get(name, 0),
            }

    def entity_names(self) -> tuple:
        with self._lock:
            return tuple(self._entities)

    def reference_count(self, name: str) -> int:
        with self._lock:
            return self._reference_counts.get(name, 0)

    def reset(self) -> None:
        with self._lock:
            self._stats = {key: 0 for key in _STAT_KEYS}
            self._last_report = None

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "limits": {
                        "max_depth": self.max_depth,
                        "max_bytes": self.max_bytes,
                    },
                    "namespaces": self._namespaces,
                    "entities": [
                        {
                            "name": entity.name,
                            "parameter": entity.parameter,
                            "value": entity.value,
                            "system_id": entity.system_id,
                            "position": entity.position,
                        }
                        for entity in self._entities.values()
                    ],
                    "external_subset": self._external_subset,
                    "references": self._reference_counts,
                    "stats": self._stats,
                    "last_report": self._last_report,
                }
            )

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._validate_snapshot(state)
            except (KeyError, TypeError, ValueError, AttributeError) as error:
                raise XxeError("XXE_SNAPSHOT_INVALID", str(error)) from None

            self.max_depth = restored["max_depth"]
            self.max_bytes = restored["max_bytes"]
            self._namespaces = restored["namespaces"]
            self._entities = restored["entities"]
            self._external_subset = restored["external_subset"]
            self._reference_counts = restored["references"]
            self._stats = restored["stats"]
            self._last_report = restored["last_report"]
            self._stats["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _scan_document(
        self, document: str, builder: _ScanBuilder | None = None
    ) -> _Scan:
        if not isinstance(document, str) or not document.strip():
            raise XxeError("XXE_DTD_INVALID")

        if builder is None:
            builder = _ScanBuilder()
        length = len(document)
        index = 0

        while index < length:
            if document.startswith("<!--", index):
                end = self._find_terminator(document, index + 4, "-->")
                builder.masked.append((index, end))
                index = end
                continue
            if document.startswith("<?", index):
                end = self._find_terminator(document, index + 2, "?>")
                builder.masked.append((index, end))
                index = end
                continue
            if document.startswith("<![CDATA[", index):
                end = self._find_terminator(document, index + 9, "]]>")
                builder.masked.append((index, end))
                index = end
                continue
            if self._starts_keyword(document, index, "<!DOCTYPE"):
                end, external, subset = self._parse_doctype(document, index)
                if external is not None:
                    builder.set_external_subset(external, index)
                if subset is not None:
                    subset_start, subset_end = subset
                    self._scan_entities_in_region(
                        document, subset_start, subset_end, builder
                    )
                builder.masked.append((index, end))
                index = end
                continue
            if self._starts_keyword(document, index, "<!ENTITY"):
                parsed = self._parse_entity(document, index)
                if parsed is not None:
                    entity, end = parsed
                    builder.add_entity(entity)
                    builder.masked.append((index, end))
                    index = end
                    continue
            if document.startswith("<!", index):
                end = self._find_tag_end(document, index + 2)
                builder.masked.append((index, end))
                index = end
                continue
            index += 1

        if not builder.entities and builder.external_subset is None:
            raise XxeError("XXE_DTD_INVALID")

        masked_document = list(document)
        for start, end in builder.masked:
            masked_document[start:end] = [" "] * (end - start)
        content = "".join(masked_document)
        references = tuple(match.group(1) for match in _REFERENCE_RE.finditer(content))

        internal = tuple(
            entity.name
            for entity in builder.entities
            if not entity.parameter and not entity.external
        )
        external = tuple(
            entity.name
            for entity in builder.entities
            if not entity.parameter and entity.external
        )
        parameter = tuple(
            entity.name for entity in builder.entities if entity.parameter
        )
        return _Scan(
            entities=tuple(builder.entities),
            internal=internal,
            external=external,
            parameter=parameter,
            external_subset=builder.external_subset,
            external_ids=tuple(builder.external_ids()),
            references=references,
        )

    def _scan_entities_in_region(
        self,
        document: str,
        start: int,
        end: int,
        builder: _ScanBuilder,
    ) -> None:
        index = start
        while index < end:
            if document.startswith("<!--", index):
                index = self._find_terminator(document, index + 4, "-->", end)
                continue
            if document.startswith("<?", index):
                index = self._find_terminator(document, index + 2, "?>", end)
                continue
            if document.startswith("<![CDATA[", index):
                index = self._find_terminator(document, index + 9, "]]>", end)
                continue
            if self._starts_keyword(document, index, "<!ENTITY"):
                parsed = self._parse_entity(document, index, end)
                if parsed is not None:
                    entity, index = parsed
                    builder.add_entity(entity)
                    continue
            index += 1

    @staticmethod
    def _find_terminator(
        document: str, start: int, terminator: str, limit: int | None = None
    ) -> int:
        end_limit = len(document) if limit is None else limit
        found = document.find(terminator, start, end_limit)
        if found < 0:
            return end_limit
        return found + len(terminator)

    @staticmethod
    def _starts_keyword(document: str, index: int, keyword: str) -> bool:
        if document[index : index + len(keyword)].upper() != keyword.upper():
            return False
        following = index + len(keyword)
        return following >= len(document) or document[following].isspace()

    def _parse_doctype(
        self, document: str, start: int
    ) -> tuple[int, str | None, tuple[int, int] | None]:
        index = start + len("<!DOCTYPE")
        quote: str | None = None
        bracket_depth = 0
        subset_start: int | None = None
        subset_end: int | None = None

        while index < len(document):
            character = document[index]
            if quote is not None:
                if character == quote:
                    quote = None
            elif character in "\"'":
                quote = character
            elif character == "[" and bracket_depth == 0:
                bracket_depth = 1
                subset_start = index
            elif character == "]" and bracket_depth:
                bracket_depth -= 1
                if bracket_depth == 0:
                    subset_end = index
            elif character == ">" and bracket_depth == 0:
                end = index + 1
                break
            index += 1
        else:
            end = len(document)

        preamble_end = subset_start if subset_start is not None else end
        preamble = document[start:preamble_end]
        external = None
        system_match = _SYSTEM_RE.search(preamble)
        if system_match is not None:
            external = system_match.group(2)
        else:
            public_match = _PUBLIC_RE.search(preamble)
            if public_match is not None:
                external = public_match.group(4)

        subset = None
        if subset_start is not None:
            subset = (
                subset_start + 1,
                subset_end if subset_end is not None else end,
            )
        return end, external, subset

    def _parse_entity(
        self, document: str, start: int, limit: int | None = None
    ) -> tuple[_Entity, int] | None:
        limit = len(document) if limit is None else limit
        index = start + len("<!ENTITY")
        if index < limit and not document[index].isspace():
            return None
        while index < limit and document[index].isspace():
            index += 1

        parameter = False
        if index < limit and document[index] == "%":
            parameter = True
            index += 1
            while index < limit and document[index].isspace():
                index += 1

        name_match = _NAME_RE.match(document, index, limit)
        if name_match is None:
            return None
        name = name_match.group(0)
        index = name_match.end()
        if index >= limit or not document[index].isspace():
            return None
        while index < limit and document[index].isspace():
            index += 1

        if self._starts_keyword_in_range(document, index, limit, "SYSTEM"):
            index += len("SYSTEM")
            while index < limit and document[index].isspace():
                index += 1
            quoted = self._parse_quoted(document, index, limit)
            if quoted is None:
                return None
            identifier, index = quoted
            while index < limit and document[index].isspace():
                index += 1
            if index >= limit or document[index] != ">":
                return None
            return _Entity(name, parameter, None, identifier, start), index + 1

        if self._starts_keyword_in_range(document, index, limit, "PUBLIC"):
            index += len("PUBLIC")
            while index < limit and document[index].isspace():
                index += 1
            public_id = self._parse_quoted(document, index, limit)
            if public_id is None:
                return None
            _public, index = public_id
            while index < limit and document[index].isspace():
                index += 1
            system_id = self._parse_quoted(document, index, limit)
            if system_id is None:
                return None
            identifier, index = system_id
            while index < limit and document[index].isspace():
                index += 1
            if index >= limit or document[index] != ">":
                return None
            return _Entity(name, parameter, None, identifier, start), index + 1

        literal = self._parse_quoted(document, index, limit)
        if literal is None:
            return None
        value, index = literal
        while index < limit and document[index].isspace():
            index += 1
        if index >= limit or document[index] != ">":
            return None
        return _Entity(name, parameter, value, None, start), index + 1

    @staticmethod
    def _starts_keyword_in_range(
        document: str, index: int, limit: int, keyword: str
    ) -> bool:
        if document[index : index + len(keyword)].upper() != keyword.upper():
            return False
        following = index + len(keyword)
        return following >= limit or document[following].isspace()

    @staticmethod
    def _parse_quoted(
        document: str, index: int, limit: int
    ) -> tuple[str, int] | None:
        if index >= limit or document[index] not in "\"'":
            return None
        quote = document[index]
        end = document.find(quote, index + 1, limit)
        if end < 0:
            return None
        return document[index + 1 : end], end + 1

    @staticmethod
    def _find_tag_end(document: str, start: int) -> int:
        index = start
        quote: str | None = None
        while index < len(document):
            character = document[index]
            if quote is not None:
                if character == quote:
                    quote = None
            elif character in "\"'":
                quote = character
            elif character == ">":
                return index + 1
            index += 1
        return len(document)

    def _install_scan(self, scan: _Scan) -> None:
        self._entities = {entity.name: entity for entity in scan.entities}
        self._external_subset = scan.external_subset
        counts: dict[str, int] = {}
        for name in scan.references:
            counts[name] = counts.get(name, 0) + 1
        self._reference_counts = counts

    def _check_external_policy(self, scan: _Scan) -> None:
        if scan.external_subset is not None and not self._identifier_allowed(
            scan.external_subset
        ):
            raise XxeError(
                "XXE_EXTERNAL_BLOCKED", {"external": scan.external_subset}
            )

        for entity in scan.entities:
            if entity.external and not self._identifier_allowed(entity.system_id or ""):
                raise XxeError(
                    "XXE_EXTERNAL_BLOCKED", {"entity": entity.name}
                )

    def _identifier_allowed(self, identifier: str) -> bool:
        best: tuple[int, dict] | None = None
        for policy in self._namespaces.values():
            prefix = policy["prefix"]
            if identifier.startswith(prefix):
                candidate = (len(prefix), policy)
                if best is None or candidate[0] > best[0]:
                    best = candidate
        return bool(best and best[1]["allow"])

    def _entity_metrics(self, scan: _Scan) -> tuple[dict, dict]:
        entity_map = scan.entity_map
        sizes: dict[str, int] = {}
        depths: dict[str, int] = {}

        def visit(name: str, trail: tuple, root: str, depth: int) -> tuple[int, int]:
            entity = entity_map.get(name)
            if entity is None:
                raise XxeError("XXE_UNKNOWN_ENTITY", {"entity": name})
            if name in trail:
                raise XxeError("XXE_CYCLE", {"entity": name})
            if depth > self.max_depth:
                raise XxeError(
                    "XXE_DEPTH_EXCEEDED", {"entity": root, "depth": depth}
                )
            if name in sizes:
                return sizes[name], depths[name]
            if entity.external:
                sizes[name] = 0
                depths[name] = 1
                return 0, 1

            total = 0
            child_depth = 0
            next_trail = trail + (name,)
            for piece, reference in self._literal_pieces(entity.value or ""):
                if reference is None:
                    total += len(piece.encode("utf-8"))
                else:
                    size, depth_below = visit(
                        reference, next_trail, root, depth + 1
                    )
                    total += size
                    child_depth = max(child_depth, depth_below)

            own_depth = child_depth + 1 if child_depth else 1
            if own_depth > self.max_depth:
                raise XxeError(
                    "XXE_DEPTH_EXCEEDED",
                    {"entity": root, "depth": own_depth},
                )
            sizes[name] = total
            depths[name] = own_depth
            return total, own_depth

        for entity in scan.entities:
            size, _depth = visit(entity.name, (), entity.name, 1)
            if size > self.max_bytes:
                raise XxeError(
                    "XXE_BUDGET_EXCEEDED",
                    {"entity": entity.name, "bytes": size},
                )
        return sizes, depths

    def _measure_document(self, scan: _Scan, sizes: dict) -> tuple[int, int]:
        entity_map = scan.entity_map
        references = 0
        expanded_bytes = 0
        for name in scan.references:
            entity = entity_map.get(name)
            if entity is None:
                raise XxeError("XXE_UNKNOWN_ENTITY", {"entity": name})
            references += 1
            if not entity.external:
                expanded_bytes += sizes[name]
                if expanded_bytes > self.max_bytes:
                    raise XxeError(
                        "XXE_BUDGET_EXCEEDED",
                        {"entity": name, "bytes": expanded_bytes},
                    )
        return references, expanded_bytes

    def _literal_pieces(self, value: str):
        special = self._special_spans(value)
        references: list[tuple[int, int, str]] = []
        for match in _REFERENCE_RE.finditer(value):
            if any(start <= match.start() < end for start, end in special):
                continue
            references.append((match.start(), match.end(), match.group(1)))

        cursor = 0
        for start, end, name in references:
            yield value[cursor:start], None
            yield "", name
            cursor = end
        yield value[cursor:], None

    @staticmethod
    def _special_spans(value: str) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        index = 0
        while index < len(value):
            if value.startswith("<!--", index):
                end = value.find("-->", index + 4)
                end = len(value) if end < 0 else end + 3
            elif value.startswith("<?", index):
                end = value.find("?>", index + 2)
                end = len(value) if end < 0 else end + 2
            elif value.startswith("<![CDATA[", index):
                end = value.find("]]>", index + 9)
                end = len(value) if end < 0 else end + 3
            else:
                index += 1
                continue
            spans.append((index, end))
            index = end
        return spans

    @staticmethod
    def _error_trigger(error: XxeError) -> str | None:
        if isinstance(error.detail, dict):
            trigger = error.detail.get("entity")
            if isinstance(trigger, str):
                return trigger
        return None

    def _validate_snapshot(self, state: dict) -> dict:
        if not isinstance(state, dict):
            raise TypeError("snapshot must be a dictionary")
        expected = {
            "limits",
            "namespaces",
            "entities",
            "external_subset",
            "references",
            "stats",
            "last_report",
        }
        if set(state) != expected:
            raise ValueError("snapshot keys do not match")

        limits = state["limits"]
        if not isinstance(limits, dict) or set(limits) != {"max_depth", "max_bytes"}:
            raise ValueError("invalid limits")
        max_depth = limits["max_depth"]
        max_bytes = limits["max_bytes"]
        if not self._valid_non_negative_int(max_depth) or not self._valid_non_negative_int(
            max_bytes
        ):
            raise ValueError("invalid limits")

        namespaces = state["namespaces"]
        if not isinstance(namespaces, dict):
            raise ValueError("invalid namespaces")
        loaded_namespaces: dict[str, dict] = {}
        for namespace, policy in namespaces.items():
            if not isinstance(namespace, str):
                raise ValueError("invalid namespace name")
            if not isinstance(policy, dict) or set(policy) != {"prefix", "allow"}:
                raise ValueError("invalid namespace policy")
            if not isinstance(policy["prefix"], str) or not isinstance(
                policy["allow"], bool
            ):
                raise ValueError("invalid namespace policy")
            loaded_namespaces[namespace] = {
                "prefix": policy["prefix"],
                "allow": policy["allow"],
            }

        entities = state["entities"]
        if not isinstance(entities, list):
            raise ValueError("invalid entities")
        loaded_entities: dict[str, _Entity] = {}
        for item in entities:
            if not isinstance(item, dict) or set(item) != {
                "name",
                "parameter",
                "value",
                "system_id",
                "position",
            }:
                raise ValueError("invalid entity")
            if not isinstance(item["name"], str) or not item["name"]:
                raise ValueError("invalid entity name")
            if not isinstance(item["parameter"], bool):
                raise ValueError("invalid entity parameter flag")
            if item["value"] is not None and not isinstance(item["value"], str):
                raise ValueError("invalid entity value")
            if item["system_id"] is not None and not isinstance(
                item["system_id"], str
            ):
                raise ValueError("invalid entity system id")
            if (item["value"] is None) == (item["system_id"] is None):
                raise ValueError("invalid entity declaration")
            if not self._valid_non_negative_int(item["position"]):
                raise ValueError("invalid entity position")
            if item["name"] in loaded_entities:
                raise ValueError("duplicate entity")
            loaded_entities[item["name"]] = _Entity(
                item["name"],
                item["parameter"],
                item["value"],
                item["system_id"],
                item["position"],
            )

        external_subset = state["external_subset"]
        if external_subset is not None and not isinstance(external_subset, str):
            raise ValueError("invalid external subset")

        references = state["references"]
        if not isinstance(references, dict):
            raise ValueError("invalid references")
        loaded_references: dict[str, int] = {}
        for name, count in references.items():
            if not isinstance(name, str) or not self._valid_non_negative_int(count):
                raise ValueError("invalid references")
            loaded_references[name] = count

        stats = state["stats"]
        if not isinstance(stats, dict) or set(stats) != set(_STAT_KEYS):
            raise ValueError("invalid stats")
        loaded_stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            if not self._valid_non_negative_int(stats[key]):
                raise ValueError("invalid stats")
            loaded_stats[key] = stats[key]

        last_report = state["last_report"]
        loaded_report = None
        if last_report is not None:
            if not isinstance(last_report, dict) or set(last_report) != _REPORT_KEYS:
                raise ValueError("invalid last report")
            if not isinstance(last_report["accepted"], bool):
                raise ValueError("invalid last report")
            for key in ("code", "trigger"):
                if last_report[key] is not None and not isinstance(
                    last_report[key], str
                ):
                    raise ValueError("invalid last report")
            for key in ("references", "expanded_bytes"):
                if not self._valid_non_negative_int(last_report[key]):
                    raise ValueError("invalid last report")
            if not isinstance(last_report["external"], list) or not all(
                isinstance(item, str) for item in last_report["external"]
            ):
                raise ValueError("invalid last report")
            loaded_report = {
                "accepted": last_report["accepted"],
                "code": last_report["code"],
                "trigger": last_report["trigger"],
                "references": last_report["references"],
                "expanded_bytes": last_report["expanded_bytes"],
                "external": list(last_report["external"]),
            }

        return {
            "max_depth": max_depth,
            "max_bytes": max_bytes,
            "namespaces": loaded_namespaces,
            "entities": loaded_entities,
            "external_subset": external_subset,
            "references": loaded_references,
            "stats": loaded_stats,
            "last_report": loaded_report,
        }

    @staticmethod
    def _valid_non_negative_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
