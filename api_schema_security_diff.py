"""OpenAPI 安全语义差分：鉴权继承变更、参数放宽与新增未鉴权路径。"""

from __future__ import annotations

import threading
from dataclasses import dataclass

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


def normalize_path(path):
    """折叠重复斜杠、去掉尾斜杠并把模板参数名归一为 {}。"""
    raise NotImplementedError


def normalize_security(requirements):
    """把 security 数组归一为备选元组，每个备选内的 scheme 名排序。"""
    raise NotImplementedError


class ApiSchemaSecurityDiff:
    """比较两份 OpenAPI 文档的安全语义。"""

    def __init__(self, *, max_operations=MAX_OPERATIONS):
        self.max_operations = max_operations
        self.revision = 0
        self.baseline = ""
        self._specs = {}
        self._operations = {}
        self._counters = {"loads": 0, "security_changes": 0, "parameter_changes": 0}
        self._lock = threading.RLock()

    def load_spec(self, doc, *, name="spec"):
        raise NotImplementedError

    def effective_security(self, spec, path, method):
        raise NotImplementedError

    def diff_security(self, base, head):
        raise NotImplementedError

    def diff_parameters(self, base, head):
        raise NotImplementedError

    def classify(self, changes):
        raise NotImplementedError

    def report(self, security_changes, parameter_changes):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
