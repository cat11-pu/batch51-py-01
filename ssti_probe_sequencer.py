"""SSTI 探测序列：按注入点维护表达式阶梯、判定回显形态并记录命中。"""

from __future__ import annotations

import re
import threading

DEFAULT_LADDER = ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}")

ENGINE_LADDERS = {
    "generic": DEFAULT_LADDER,
    "jinja2": ("{{7*7}}", "{{'7'*7}}"),
    "thymeleaf": ("${7*7}", "[[${7*7}]]"),
    "erb": ("<%= 7*7 %>", "<%= '7'*7 %>"),
}

ECHO_EVALUATED = "evaluated"
ECHO_RAW = "raw"
ECHO_ESCAPED = "escaped"
ECHO_ABSENT = "absent"

CONTEXT_UNKNOWN = "unknown"
CONTEXT_TEXT = "text"
CONTEXT_ATTR = "attr"
CONTEXT_SCRIPT = "script"

TEMPLATE_DELIMITERS = ("{{", "}}", "${", "<%", "%>", "#{", "[[", "]]")

_ARITHMETIC = re.compile(r"(\d+)\s*\*\s*(\d+)")
_REPEATED = re.compile(r"(\d+)\s*\*\s*'(\d)'")


class SstiError(ValueError):
    """探测流程拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SstiProbeSequencer:
    """按注入点保存表达式阶梯与回显判定结果。"""

    def __init__(self, *, max_points=32, max_escalations=4, ladders=None):
        self.max_points = max_points
        self.max_escalations = max_escalations
        self._ladders = dict(ENGINE_LADDERS)
        if ladders:
            self._ladders.update({str(key): tuple(value) for key, value in ladders.items()})
        self._points = {}
        self._lock = threading.RLock()
        self._stats = {
            "points_registered": 0,
            "payloads_issued": 0,
            "hits": 0,
            "escalations": 0,
            "escaped": 0,
            "raw": 0,
            "exhausted": 0,
            "restores": 0,
        }

    def register_point(self, param, *, engine="generic", now=None):
        raise NotImplementedError

    def points(self):
        raise NotImplementedError

    def ladder_for(self, param):
        raise NotImplementedError

    def expected_marker(self, payload):
        raise NotImplementedError

    def next_payload(self, param):
        raise NotImplementedError

    def evaluate_echo(self, param, payload, response_text):
        raise NotImplementedError

    def detect_context(self, param, response_text):
        raise NotImplementedError

    def context_for(self, param):
        raise NotImplementedError

    def escalate(self, param):
        raise NotImplementedError

    def mark_hit(self, param):
        raise NotImplementedError

    def is_exhausted(self, param):
        raise NotImplementedError

    def reset_point(self, param):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
