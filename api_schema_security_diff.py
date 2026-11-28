"""OpenAPI 安全语义差分：鉴权继承变更、参数放宽与新增未鉴权路径。"""

from __future__ import annotations

import copy
import json
import re
import threading
from dataclasses import dataclass
from urllib.parse import unquote

MAX_DOC_CHARS = 1_000_000
MAX_OPERATIONS = 500

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

SEVERITIES = ("high", "medium", "low", "info")

SEVERITY_BY_CHANGE = {
    "removed": "high",
    "unauthenticated": "high",
    "required_relaxed": "high",
    "required_added": "high",
    "weakened": "medium",
    "replaced": "medium",
    "enum_widened": "medium",
    "type_loosened": "medium",
    "type_changed": "medium",
    "parameter_removed": "medium",
    "added": "info",
    "strengthened": "info",
    "enum_narrowed": "low",
    "required_tightened": "low",
    "optional_added": "low",
    "renamed": "info",
}

_TEMPLATE_RE = re.compile(r"\{[^{}]*\}")
_TEMPLATE_NAME_RE = re.compile(r"\{([^{}]*)\}")
_SLASH_RE = re.compile(r"/+")

_PATH_ITEM_KEYS = {
    "$ref",
    "summary",
    "description",
    "servers",
    "parameters",
}


class SchemaError(ValueError):
    """文档加载或差分被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str
    required: bool
    schema_type: object
    enum: tuple


@dataclass(frozen=True)
class Operation:
    path: str
    method: str
    security: object
    parameters: tuple
    template: tuple


@dataclass(frozen=True)
class Spec:
    name: str
    global_security: tuple
    operations: dict


@dataclass(frozen=True)
class SecurityChange:
    change: str
    path: str
    method: str
    before: tuple
    after: tuple
    severity: str


@dataclass(frozen=True)
class ParameterChange:
    change: str
    path: str
    method: str
    parameter: str
    severity: str


def _fail(code, detail=None):
    raise SchemaError(code, detail)


def normalize_path(path):
    """折叠重复斜杠、去掉尾斜杠并把模板参数名归一为 {}。"""
    if not isinstance(path, str):
        _fail("SCHEMA_INVALID", "path must be a string")
    normalized = _SLASH_RE.sub("/", path)
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    normalized = _TEMPLATE_RE.sub("{}", normalized)
    return normalized


def normalize_security(requirements):
    """把 security 数组归一为备选元组，每个备选内的 scheme 名排序。"""
    if not isinstance(requirements, (list, tuple)):
        _fail("SCHEMA_INVALID", "security must be an array")

    alternatives = []
    for requirement in requirements:
        if not isinstance(requirement, dict):
            _fail("SCHEMA_INVALID", "each security requirement must be an object")
        if any(not isinstance(scheme, str) for scheme in requirement):
            _fail("SCHEMA_INVALID", "security scheme names must be strings")
        schemes = tuple(sorted(requirement))
        alternatives.append(schemes)
    return tuple(alternatives)


def _template_names(path):
    return tuple(_TEMPLATE_NAME_RE.findall(path))


def _decode_pointer_token(token):
    return unquote(token).replace("~1", "/").replace("~0", "~")


def _resolve_pointer(root, ref):
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        _fail("SCHEMA_INVALID", "invalid internal reference: %s" % ref)

    current = root
    for raw_token in ref[2:].split("/"):
        token = _decode_pointer_token(raw_token)
        if isinstance(current, dict):
            if token not in current:
                _fail("SCHEMA_INVALID", "unresolved reference: %s" % ref)
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
                current = current[index]
            except (ValueError, IndexError):
                _fail("SCHEMA_INVALID", "unresolved reference: %s" % ref)
        else:
            _fail("SCHEMA_INVALID", "unresolved reference: %s" % ref)
    return current


def _resolve_refs(value, root, stack=(), cache=None):
    """展开文档内的 $ref；外部引用与引用环会被拒绝。"""
    if cache is None:
        cache = {}

    if isinstance(value, dict):
        if "$ref" in value:
            ref = value.get("$ref")
            if not isinstance(ref, str):
                _fail("SCHEMA_INVALID", "$ref must be a string")
            if not ref.startswith("#"):
                _fail("SCHEMA_EXTERNAL_REF", "external reference: %s" % ref)
            if ref in stack:
                _fail("SCHEMA_REF_CYCLE", "cyclic reference: %s" % ref)
            if ref in cache:
                return copy.deepcopy(cache[ref])
            target = _resolve_pointer(root, ref)
            resolved = _resolve_refs(target, root, stack + (ref,), cache)
            cache[ref] = resolved
            return copy.deepcopy(resolved)
        return {
            key: _resolve_refs(item, root, stack, cache)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_resolve_refs(item, root, stack, cache) for item in value]
    return value


def _document_size(doc):
    if isinstance(doc, str):
        return len(doc)
    try:
        serialized = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        _fail("SCHEMA_INVALID", "document must be JSON serializable")
    return len(serialized)


def _parse_document(doc):
    if not isinstance(doc, (str, dict)):
        _fail("SCHEMA_INVALID", "document must be a JSON string or object")

    if _document_size(doc) > MAX_DOC_CHARS:
        _fail("SCHEMA_TOO_LARGE", "document exceeds %d characters" % MAX_DOC_CHARS)

    if isinstance(doc, str):
        try:
            parsed = json.loads(doc)
        except (TypeError, ValueError):
            _fail("SCHEMA_INVALID", "document is not valid JSON")
    else:
        try:
            parsed = copy.deepcopy(doc)
        except Exception:
            _fail("SCHEMA_INVALID", "document cannot be copied")

    if not isinstance(parsed, dict):
        _fail("SCHEMA_INVALID", "document root must be an object")
    if not isinstance(parsed.get("openapi"), str) or not parsed["openapi"].strip():
        _fail("SCHEMA_INVALID", "missing or invalid openapi version")
    if not isinstance(parsed.get("paths"), dict):
        _fail("SCHEMA_INVALID", "paths must be an object")
    if "security" in parsed:
        normalize_security(parsed["security"])
    if "components" in parsed and not isinstance(parsed["components"], dict):
        _fail("SCHEMA_INVALID", "components must be an object")
    return parsed


def _as_list(value, detail):
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        _fail("SCHEMA_INVALID", detail)
    return list(value)


def _merge_required(left, right):
    merged = []
    for name in left:
        if name not in merged:
            merged.append(name)
    for name in right:
        if name not in merged:
            merged.append(name)
    return merged


def _effective_schema(schema):
    """展开 allOf 并合并 required/properties，返回只读语义视图。"""
    if schema is None:
        return {}
    if not isinstance(schema, dict):
        _fail("SCHEMA_INVALID", "schema must be an object")

    merged = {key: value for key, value in schema.items() if key != "allOf"}
    required = _as_list(schema.get("required"), "schema required must be an array")
    properties = {}
    raw_properties = schema.get("properties")
    if raw_properties is not None:
        if not isinstance(raw_properties, dict):
            _fail("SCHEMA_INVALID", "schema properties must be an object")
        properties.update(raw_properties)

    for branch in _as_list(schema.get("allOf"), "allOf must be an array"):
        branch_schema = _effective_schema(branch)
        required = _merge_required(
            required,
            _as_list(branch_schema.get("required"), "schema required must be an array"),
        )
        branch_properties = branch_schema.get("properties")
        if isinstance(branch_properties, dict):
            properties.update(branch_properties)
        for key, value in branch_schema.items():
            if key not in ("required", "properties") and key not in merged:
                merged[key] = value

    if any(not isinstance(name, str) for name in required):
        _fail("SCHEMA_INVALID", "schema required names must be strings")
    if any(not isinstance(name, str) for name in properties):
        _fail("SCHEMA_INVALID", "schema property names must be strings")

    if required:
        merged["required"] = required
    if properties:
        merged["properties"] = properties
    return merged


def _schema_from_content(content):
    if content is None:
        return None
    if not isinstance(content, dict):
        _fail("SCHEMA_INVALID", "content must be an object")
    if not content:
        return None
    media_type = "application/json" if "application/json" in content else sorted(content)[0]
    media = content.get(media_type)
    if not isinstance(media, dict):
        _fail("SCHEMA_INVALID", "media type definition must be an object")
    schema = media.get("schema")
    if schema is not None and not isinstance(schema, dict):
        _fail("SCHEMA_INVALID", "media type schema must be an object")
    return schema


def _enum_tuple(schema):
    enum = schema.get("enum", ())
    if enum is None:
        return ()
    if not isinstance(enum, (list, tuple)):
        _fail("SCHEMA_INVALID", "enum must be an array")
    return tuple(enum)


def _parse_parameter(raw):
    if not isinstance(raw, dict):
        _fail("SCHEMA_INVALID", "parameter must be an object")

    name = raw.get("name")
    location = raw.get("in")
    if not isinstance(name, str) or not name:
        _fail("SCHEMA_INVALID", "parameter name must be a non-empty string")
    if not isinstance(location, str) or not location:
        _fail("SCHEMA_INVALID", "parameter location must be a non-empty string")

    required = raw.get("required", False)
    if not isinstance(required, bool):
        _fail("SCHEMA_INVALID", "parameter required must be a boolean")

    schema = raw.get("schema")
    if schema is None:
        schema = _schema_from_content(raw.get("content"))
    if schema is not None and not isinstance(schema, dict):
        _fail("SCHEMA_INVALID", "parameter schema must be an object")
    effective = _effective_schema(schema)

    return Parameter(
        name=name,
        location=location,
        required=required,
        schema_type=effective.get("type"),
        enum=_enum_tuple(effective),
    )


def _parse_parameter_list(value):
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        _fail("SCHEMA_INVALID", "parameters must be an array")
    return tuple(_parse_parameter(item) for item in value)


def _merge_parameter_lists(path_parameters, operation_parameters):
    merged = {}
    for parameter in path_parameters:
        merged[(parameter.location, parameter.name)] = parameter
    for parameter in operation_parameters:
        merged[(parameter.location, parameter.name)] = parameter
    return tuple(merged.values())


def _request_body_parameters(raw_operation):
    raw_body = raw_operation.get("requestBody")
    if raw_body is None:
        return ()
    if not isinstance(raw_body, dict):
        _fail("SCHEMA_INVALID", "requestBody must be an object")

    schema = _schema_from_content(raw_body.get("content"))
    if schema is None:
        return ()
    effective = _effective_schema(schema)

    properties = effective.get("properties")
    if properties is None:
        properties = {}
    elif not isinstance(properties, dict):
        _fail("SCHEMA_INVALID", "schema properties must be an object")

    required_names = set(
        _as_list(effective.get("required"), "schema required must be an array")
    )
    if not properties and not required_names:
        return ()
    parameters = []
    for name in sorted(properties):
        property_schema = _effective_schema(properties[name])
        parameters.append(
            Parameter(
                name=name,
                location="body",
                required=name in required_names,
                schema_type=property_schema.get("type"),
                enum=_enum_tuple(property_schema),
            )
        )
    for name in sorted(required_names - set(properties)):
        parameters.append(
            Parameter(
                name=name,
                location="body",
                required=True,
                schema_type=None,
                enum=(),
            )
        )
    return tuple(parameters)


def _build_spec(document, name, max_operations):
    paths = document["paths"]
    if "security" in document:
        global_security = normalize_security(document["security"])
    else:
        global_security = ()

    operations = {}
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            _fail("SCHEMA_INVALID", "path keys must start with '/'")
        if not isinstance(path_item, dict):
            _fail("SCHEMA_INVALID", "path item must be an object")

        normalized_path = normalize_path(raw_path)
        template = _template_names(raw_path)
        path_parameters = _parse_parameter_list(path_item.get("parameters"))

        for key, raw_operation in path_item.items():
            if not isinstance(key, str):
                _fail("SCHEMA_INVALID", "path item keys must be strings")
            method = key.lower()
            if method not in HTTP_METHODS:
                if key in _PATH_ITEM_KEYS or key.startswith("x-"):
                    continue
                _fail("SCHEMA_INVALID", "unknown path item field: %s" % key)
            if not isinstance(raw_operation, dict):
                _fail("SCHEMA_INVALID", "operation must be an object")

            operation_parameters = _parse_parameter_list(
                raw_operation.get("parameters")
            )
            parameters = _merge_parameter_lists(
                path_parameters, operation_parameters
            ) + _request_body_parameters(raw_operation)

            if "security" in raw_operation:
                security = normalize_security(raw_operation["security"])
            else:
                security = None

            operation_key = (normalized_path, method)
            if operation_key not in operations:
                operations[operation_key] = Operation(
                    path=normalized_path,
                    method=method,
                    security=security,
                    parameters=parameters,
                    template=template,
                )

    if len(operations) > max_operations:
        _fail(
            "SCHEMA_TOO_MANY_OPERATIONS",
            "operation count %d exceeds %d" % (len(operations), max_operations),
        )
    return Spec(name=name, global_security=global_security, operations=operations)


def _strength(security):
    if not security:
        return 0
    return min(len(alternative) for alternative in security)


def _same_alternatives(left, right):
    return frozenset(left) == frozenset(right)


def _security_change(change, path, method, before, after):
    return SecurityChange(
        change=change,
        path=path,
        method=method,
        before=before,
        after=after,
        severity=SEVERITY_BY_CHANGE[change],
    )


def _diff_operation_security(operation, before, after):
    before_strength = _strength(before)
    after_strength = _strength(after)

    if before_strength > 0 and after_strength == 0:
        return _security_change("removed", operation.path, operation.method, before, after)
    if after_strength < before_strength:
        return _security_change("weakened", operation.path, operation.method, before, after)
    if after_strength > before_strength:
        return _security_change(
            "strengthened", operation.path, operation.method, before, after
        )
    if not _same_alternatives(before, after):
        return _security_change("replaced", operation.path, operation.method, before, after)
    return None


def _parameter_change(change, path, method, parameter):
    return ParameterChange(
        change=change,
        path=path,
        method=method,
        parameter=parameter,
        severity=SEVERITY_BY_CHANGE[change],
    )


def _enum_added(before, after):
    return [value for value in after if value not in before]


def _enum_removed(before, after):
    return [value for value in before if value not in after]


def _type_loosened(before, after):
    if before == after:
        return False
    if before == "integer" and after in ("number", "string"):
        return True
    if before == "number" and after == "string":
        return True
    return False


def _compare_parameters(path, method, before, after, label, changes):
    added = _enum_added(before.enum, after.enum)
    removed = _enum_removed(before.enum, after.enum)
    if added:
        changes.append(_parameter_change("enum_widened", path, method, label))
    if removed:
        changes.append(_parameter_change("enum_narrowed", path, method, label))

    if before.required and not after.required:
        changes.append(_parameter_change("required_relaxed", path, method, label))
    elif not before.required and after.required:
        changes.append(_parameter_change("required_tightened", path, method, label))

    if before.schema_type != after.schema_type:
        change = (
            "type_loosened"
            if _type_loosened(before.schema_type, after.schema_type)
            else "type_changed"
        )
        changes.append(_parameter_change(change, path, method, label))


def _parameter_map(parameters):
    return {(parameter.location, parameter.name): parameter for parameter in parameters}


def _diff_operation_parameters(operation, before, after):
    changes = []
    before_parameters = _parameter_map(before.parameters)
    after_parameters = _parameter_map(after.parameters)
    consumed_before = set()
    consumed_after = set()

    for index, before_name in enumerate(before.template):
        if index >= len(after.template):
            break
        after_name = after.template[index]
        before_key = ("path", before_name)
        after_key = ("path", after_name)
        before_parameter = before_parameters.get(before_key)
        after_parameter = after_parameters.get(after_key)
        if before_parameter is None and after_parameter is None:
            continue
        if before_parameter is not None and after_parameter is not None:
            consumed_before.add(before_key)
            consumed_after.add(after_key)
            if before_name != after_name:
                label = "%s->%s" % (before_name, after_name)
                changes.append(
                    _parameter_change("renamed", operation.path, operation.method, label)
                )
            else:
                label = after_name
            _compare_parameters(
                operation.path,
                operation.method,
                before_parameter,
                after_parameter,
                label,
                changes,
            )
        elif before_parameter is not None:
            consumed_before.add(before_key)
            changes.append(
                _parameter_change(
                    "parameter_removed", operation.path, operation.method, before_name
                )
            )
        else:
            consumed_after.add(after_key)
            change = "required_added" if after_parameter.required else "optional_added"
            changes.append(
                _parameter_change(change, operation.path, operation.method, after_name)
            )

    for key in sorted(before_parameters):
        if key in consumed_before:
            continue
        before_parameter = before_parameters[key]
        after_parameter = after_parameters.get(key)
        if after_parameter is None:
            changes.append(
                _parameter_change(
                    "parameter_removed",
                    operation.path,
                    operation.method,
                    before_parameter.name,
                )
            )
            continue
        consumed_before.add(key)
        consumed_after.add(key)
        _compare_parameters(
            operation.path,
            operation.method,
            before_parameter,
            after_parameter,
            after_parameter.name,
            changes,
        )

    for key in sorted(after_parameters):
        if key in consumed_after or key in before_parameters:
            continue
        after_parameter = after_parameters[key]
        change = "required_added" if after_parameter.required else "optional_added"
        changes.append(
            _parameter_change(
                change, operation.path, operation.method, after_parameter.name
            )
        )
    return changes


def _validated_spec(spec):
    if not isinstance(spec, Spec) or not isinstance(spec.operations, dict):
        _fail("SCHEMA_INVALID", "expected a loaded Spec")
    return spec


class ApiSchemaSecurityDiff:
    """比较两份 OpenAPI 文档的安全语义。"""

    def __init__(self, *, max_operations=MAX_OPERATIONS):
        self.max_operations = max_operations
        self.revision = 0
        self.baseline = ""
        self._operation_count = 0
        self._specs = {}
        self._operations = {}
        self._counters = {"loads": 0, "security_changes": 0, "parameter_changes": 0}
        self._lock = threading.RLock()

    def load_spec(self, doc, *, name="spec"):
        if not isinstance(name, str):
            _fail("SCHEMA_INVALID", "spec name must be a string")
        document = _parse_document(doc)
        resolved = _resolve_refs(document, document)
        spec = _build_spec(resolved, name, self.max_operations)

        with self._lock:
            self._specs[name] = spec
            self._operations = spec.operations
            self._operation_count = len(spec.operations)
            self.baseline = name
            self.revision += 1
            self._counters["loads"] += 1
        return spec

    def effective_security(self, spec, path, method):
        spec = _validated_spec(spec)
        if not isinstance(path, str) or not isinstance(method, str):
            _fail("SCHEMA_OPERATION_UNKNOWN", "path and method must be strings")
        key = (normalize_path(path), method.lower())
        operation = spec.operations.get(key)
        if operation is None:
            _fail(
                "SCHEMA_OPERATION_UNKNOWN",
                "unknown operation: %s %s" % (key[0], key[1]),
            )
        if operation.security is None:
            return spec.global_security
        return operation.security

    def diff_security(self, base, head):
        base = _validated_spec(base)
        head = _validated_spec(head)
        changes = []

        for key, head_operation in head.operations.items():
            after = (
                head.global_security
                if head_operation.security is None
                else head_operation.security
            )
            base_operation = base.operations.get(key)
            if base_operation is None:
                if _strength(after) == 0:
                    changes.append(
                        _security_change(
                            "unauthenticated",
                            head_operation.path,
                            head_operation.method,
                            (),
                            after,
                        )
                    )
                continue

            before = (
                base.global_security
                if base_operation.security is None
                else base_operation.security
            )
            change = _diff_operation_security(head_operation, before, after)
            if change is not None:
                changes.append(change)

        changes.sort(key=lambda item: (item.path, item.method, item.change))
        result = tuple(changes)
        with self._lock:
            self._counters["security_changes"] += len(result)
        return result

    def diff_parameters(self, base, head):
        base = _validated_spec(base)
        head = _validated_spec(head)
        changes = []

        for key, head_operation in head.operations.items():
            base_operation = base.operations.get(key)
            if base_operation is None:
                base_operation = Operation(
                    path=head_operation.path,
                    method=head_operation.method,
                    security=None,
                    parameters=(),
                    template=head_operation.template,
                )
            changes.extend(
                _diff_operation_parameters(
                    head_operation, base_operation, head_operation
                )
            )

        changes.sort(
            key=lambda item: (
                item.path,
                item.method,
                item.parameter,
                item.change,
            )
        )
        result = tuple(changes)
        with self._lock:
            self._counters["parameter_changes"] += len(result)
        return result

    def classify(self, changes):
        counts = {severity: 0 for severity in SEVERITIES}
        for change in changes:
            severity = getattr(change, "severity", None)
            if severity in counts:
                counts[severity] += 1

        verdict = "none"
        for severity in SEVERITIES:
            if counts[severity]:
                verdict = severity
                break
        counts["verdict"] = verdict
        return counts

    def report(self, security_changes, parameter_changes):
        security_changes = tuple(security_changes)
        parameter_changes = tuple(parameter_changes)

        def section(changes):
            counts = {}
            for change in changes:
                counts[change.change] = counts.get(change.change, 0) + 1
            return {
                "total": len(changes),
                "by_change": {key: counts[key] for key in sorted(counts)},
            }

        return {
            "security": section(security_changes),
            "parameters": section(parameter_changes),
            "verdict": self.classify(security_changes + parameter_changes)["verdict"],
        }

    def snapshot(self):
        with self._lock:
            return {
                "baseline": self.baseline,
                "revision": self.revision,
                "operation_count": self._operation_count,
                "counters": dict(self._counters),
            }

    def restore(self, state):
        if not isinstance(state, dict):
            _fail("SCHEMA_SNAPSHOT_INVALID", "snapshot must be an object")
        expected_keys = {"baseline", "revision", "operation_count", "counters"}
        if set(state) != expected_keys:
            _fail("SCHEMA_SNAPSHOT_INVALID", "snapshot has invalid fields")

        baseline = state["baseline"]
        revision = state["revision"]
        operation_count = state["operation_count"]
        counters = state["counters"]

        if not isinstance(baseline, str):
            _fail("SCHEMA_SNAPSHOT_INVALID", "baseline must be a string")
        if type(revision) is not int or revision < 0:
            _fail("SCHEMA_SNAPSHOT_INVALID", "revision must be a non-negative integer")
        if type(operation_count) is not int or operation_count < 0:
            _fail(
                "SCHEMA_SNAPSHOT_INVALID",
                "operation_count must be a non-negative integer",
            )
        if not isinstance(counters, dict):
            _fail("SCHEMA_SNAPSHOT_INVALID", "counters must be an object")
        expected_counters = {"loads", "security_changes", "parameter_changes"}
        if set(counters) != expected_counters:
            _fail("SCHEMA_SNAPSHOT_INVALID", "counters has invalid fields")
        copied_counters = {}
        for key in expected_counters:
            value = counters[key]
            if type(value) is not int or value < 0:
                _fail(
                    "SCHEMA_SNAPSHOT_INVALID",
                    "counter %s must be a non-negative integer" % key,
                )
            copied_counters[key] = value

        with self._lock:
            self.baseline = baseline
            self.revision = revision
            self._operation_count = operation_count
            self._counters = copied_counters
            self._specs = {}
            self._operations = {}

    def stats(self):
        with self._lock:
            return dict(self._counters)
