"""SSTI 探测序列：按注入点维护表达式阶梯、判定回显形态并记录命中。"""

from __future__ import annotations

import copy
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

_DELIMITER_PAIRS = (
    ("{{", "}}"),
    ("${", "}"),
    ("<%", "%>"),
    ("#{", "}"),
    ("[[", "]]"),
    ("&lt;%", "%&gt;"),
)

_ARITHMETIC = re.compile(r"(\d+)\s*\*\s*(\d+)")
_REPEAT_QUOTE_FIRST = re.compile(r"'(\d)'\s*\*\s*(\d+)")
_REPEAT_NUM_FIRST = re.compile(r"(\d+)\s*\*\s*'(\d)'")

_REFLECTION = re.compile(
    r"\{\{.*?\}\}|\$\{.*?\}|<%.*?%>|#\{.*?\}|\[\[.*?\]\]", re.S
)
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_ATTR_VALUE = re.compile(
    r"[A-Za-z_:][-\w:.]*\s*=\s*(?:\"[^\"]*\"|'[^']*')"
)

SNAPSHOT_VERSION = 1
_CONTEXTS = (CONTEXT_UNKNOWN, CONTEXT_TEXT, CONTEXT_ATTR, CONTEXT_SCRIPT)
_STAT_KEYS = (
    "points_registered",
    "payloads_issued",
    "hits",
    "escalations",
    "escaped",
    "raw",
    "exhausted",
    "restores",
)


def _html_escape(text):
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


class _PointState:
    """单个注入点的独立阶梯进度与判定状态。"""

    def __init__(self, engine):
        self.engine = engine
        self.step = 0
        self.context = CONTEXT_UNKNOWN
        self.hit = False
        self.exhausted = False
        self.raw_count = 0
        self.escaped_count = 0

    def snapshot(self):
        return {
            "engine": self.engine,
            "step": self.step,
            "context": self.context,
            "hit": self.hit,
            "exhausted": self.exhausted,
        }


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

    # ------------------------------------------------------------------
    # 注入点注册与阶梯
    # ------------------------------------------------------------------

    def _normalize_param(self, param):
        if not isinstance(param, str):
            raise SstiError("SSTI_INVALID_POINT", "param must be a string")
        normalized = param.strip()
        if not normalized:
            raise SstiError("SSTI_INVALID_POINT", "param must not be blank")
        return normalized

    def _require_point(self, param):
        normalized = self._normalize_param(param)
        state = self._points.get(normalized)
        if state is None:
            raise SstiError("SSTI_POINT_UNKNOWN", "point is not registered")
        return normalized, state

    def register_point(self, param, *, engine="generic"):
        normalized = self._normalize_param(param)
        with self._lock:
            existing = self._points.get(normalized)
            if existing is not None:
                return normalized
            if engine not in self._ladders:
                raise SstiError(
                    "SSTI_ENGINE_UNKNOWN", "engine %r has no ladder" % engine
                )
            if len(self._points) >= self.max_points:
                raise SstiError(
                    "SSTI_POINT_LIMIT",
                    "point limit %d reached" % self.max_points,
                )
            self._points[normalized] = _PointState(engine)
            self._stats["points_registered"] += 1
            return normalized

    def points(self):
        with self._lock:
            return sorted(self._points.keys())

    def ladder_for(self, param):
        normalized, state = self._require_point(param)
        ladder = self._ladders[state.engine]
        return list(ladder[: self.max_escalations])

    # ------------------------------------------------------------------
    # 载荷与期望回显
    # ------------------------------------------------------------------

    def _derive_marker(self, payload):
        repeat = _REPEAT_QUOTE_FIRST.search(payload) or _REPEAT_NUM_FIRST.search(
            payload
        )
        if repeat is not None:
            digit, count = repeat.groups()
            return digit * int(count)
        arithmetic = _ARITHMETIC.search(payload)
        if arithmetic is not None:
            left, right = arithmetic.groups()
            return str(int(left) * int(right))
        raise SstiError(
            "SSTI_PAYLOAD_OPAQUE", "cannot derive expected marker from payload"
        )

    def expected_marker(self, payload):
        if not isinstance(payload, str):
            raise SstiError(
                "SSTI_PAYLOAD_OPAQUE", "payload must be a string expression"
            )
        return self._derive_marker(payload)

    def next_payload(self, param):
        normalized, state = self._require_point(param)
        with self._lock:
            if state.hit or state.exhausted:
                return None
            ladder = self._ladders[state.engine][: self.max_escalations]
            if state.step >= len(ladder):
                if not state.exhausted:
                    state.exhausted = True
                    self._stats["exhausted"] += 1
                return None
            state.step += 1
            self._stats["payloads_issued"] += 1
            if state.step >= len(ladder):
                state.exhausted = True
                self._stats["exhausted"] += 1
            return {
                "point": normalized,
                "step": state.step,
                "payload": ladder[state.step - 1],
            }

    def escalate(self, param):
        _, state = self._require_point(param)
        with self._lock:
            if state.hit:
                raise SstiError(
                    "SSTI_POINT_CLOSED", "point already recorded a hit"
                )
            ladder = self._ladders[state.engine][: self.max_escalations]
            if state.step >= len(ladder):
                if not state.exhausted:
                    state.exhausted = True
                    self._stats["exhausted"] += 1
                raise SstiError(
                    "SSTI_LADDER_EXHAUSTED", "no more payloads on ladder"
                )
            state.step += 1
            self._stats["escalations"] += 1
            return state.step

    # ------------------------------------------------------------------
    # 回显判定
    # ------------------------------------------------------------------

    def _escaped_variants(self, payload, marker):
        variants = [_html_escape(payload)]
        arithmetic = _ARITHMETIC.search(payload)
        if arithmetic is not None:
            evaluated = payload[: arithmetic.start()] + marker + payload[
                arithmetic.end():
            ]
            variants.append(_html_escape(evaluated))
        for regex in (_REPEAT_QUOTE_FIRST, _REPEAT_NUM_FIRST):
            match = regex.search(payload)
            if match is not None:
                evaluated = payload[: match.start()] + marker + payload[
                    match.end():
                ]
                variants.append(_html_escape(evaluated))
        return variants

    def _inside_delimiters(self, response_text, index):
        for opener, closer in _DELIMITER_PAIRS:
            open_pos = response_text.rfind(opener, 0, index)
            if open_pos == -1:
                continue
            close_pos = response_text.find(closer, index)
            if close_pos != -1:
                return True
        return False

    def evaluate_echo(self, param, payload, response_text):
        _, state = self._require_point(param)
        if not isinstance(payload, str):
            raise SstiError(
                "SSTI_PAYLOAD_OPAQUE", "payload must be a string expression"
            )
        if not isinstance(response_text, str):
            raise SstiError("SSTI_INVALID_RESPONSE", "response must be text")
        marker = self._derive_marker(payload)
        with self._lock:
            if payload in response_text:
                state.raw_count += 1
                self._stats["raw"] += 1
                return ECHO_RAW

            if any(
                variant and variant in response_text
                for variant in self._escaped_variants(payload, marker)
            ):
                state.escaped_count += 1
                self._stats["escaped"] += 1
                return ECHO_ESCAPED

            marker_pos = response_text.find(marker)
            if marker_pos != -1 and not self._inside_delimiters(
                response_text, marker_pos
            ):
                state.hit = True
                self._stats["hits"] += 1
                return ECHO_EVALUATED

            return ECHO_ABSENT

    # ------------------------------------------------------------------
    # 上下文识别
    # ------------------------------------------------------------------

    def detect_context(self, param, response_text):
        normalized, state = self._require_point(param)
        if not isinstance(response_text, str):
            raise SstiError("SSTI_INVALID_RESPONSE", "response must be text")
        with self._lock:
            context = CONTEXT_UNKNOWN
            match = _REFLECTION.search(response_text)
            if match is not None:
                index = match.start()
                script = _SCRIPT_BLOCK.search(response_text)
                if script is not None and script.start() <= index < script.end():
                    context = CONTEXT_SCRIPT
                elif any(
                    attr.start() <= index < attr.end()
                    for attr in _ATTR_VALUE.finditer(response_text)
                ):
                    context = CONTEXT_ATTR
                elif self._inside_markup_tag(response_text, index):
                    context = CONTEXT_UNKNOWN
                else:
                    context = CONTEXT_TEXT
            state.context = context
            return context

    @staticmethod
    def _inside_markup_tag(response_text, index):
        open_pos = response_text.rfind("<", 0, index)
        if open_pos == -1:
            return False
        close_pos = response_text.find(">", open_pos)
        return close_pos == -1 or close_pos > index

    def context_for(self, param):
        _, state = self._require_point(param)
        with self._lock:
            return state.context

    # ------------------------------------------------------------------
    # 命中、耗尽与重置
    # ------------------------------------------------------------------

    def mark_hit(self, param):
        _, state = self._require_point(param)
        with self._lock:
            if state.hit:
                return False
            state.hit = True
            self._stats["hits"] += 1
            return True

    def is_exhausted(self, param):
        _, state = self._require_point(param)
        with self._lock:
            return state.exhausted

    def reset_point(self, param):
        normalized, state = self._require_point(param)
        with self._lock:
            engine = state.engine
            self._points[normalized] = _PointState(engine)
            return normalized

    # ------------------------------------------------------------------
    # 快照与恢复
    # ------------------------------------------------------------------

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "points": {
                    name: state.snapshot()
                    for name, state in self._points.items()
                },
                "stats": copy.deepcopy(self._stats),
                "ladders": copy.deepcopy(self._ladders),
            }

    def _validate_snapshot(self, state):
        if not isinstance(state, dict):
            raise SstiError("SSTI_SNAPSHOT_INVALID", "state must be a mapping")
        if set(state.keys()) != {
            "version",
            "points",
            "stats",
            "ladders",
        }:
            raise SstiError("SSTI_SNAPSHOT_INVALID", "unexpected snapshot keys")
        if state.get("version") != SNAPSHOT_VERSION:
            raise SstiError("SSTI_SNAPSHOT_INVALID", "unsupported version")

        points = state["points"]
        stats = state["stats"]
        ladders = state["ladders"]
        if not isinstance(points, dict) or not isinstance(stats, dict):
            raise SstiError("SSTI_SNAPSHOT_INVALID", "points/stats must map")
        if not isinstance(ladders, dict):
            raise SstiError("SSTI_SNAPSHOT_INVALID", "ladders must map")

        for name, entry in points.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad point entry")
            if set(entry.keys()) != {
                "engine",
                "step",
                "context",
                "hit",
                "exhausted",
            }:
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad point fields")
            if entry["engine"] not in ladders:
                raise SstiError("SSTI_SNAPSHOT_INVALID", "point engine missing")
            if not isinstance(entry["step"], int) or isinstance(
                entry["step"], bool
            ) or entry["step"] < 0:
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad step")
            if entry["context"] not in _CONTEXTS:
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad context")
            if not isinstance(entry["hit"], bool) or not isinstance(
                entry["exhausted"], bool
            ):
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad hit flags")

        if set(stats.keys()) != set(_STAT_KEYS):
            raise SstiError("SSTI_SNAPSHOT_INVALID", "bad stats fields")
        for value in stats.values():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad stats value")

        for engine, ladder in ladders.items():
            if not isinstance(engine, str) or not isinstance(
                ladder, (list, tuple)
            ) or any(not isinstance(item, str) for item in ladder):
                raise SstiError("SSTI_SNAPSHOT_INVALID", "bad ladder entry")

    def restore(self, state):
        self._validate_snapshot(state)
        with self._lock:
            restored_points = {}
            for name, entry in state["points"].items():
                point_state = _PointState(entry["engine"])
                point_state.step = entry["step"]
                point_state.context = entry["context"]
                point_state.hit = entry["hit"]
                point_state.exhausted = entry["exhausted"]
                restored_points[name] = point_state

            self._points = restored_points
            self._ladders = {
                engine: tuple(ladder)
                for engine, ladder in state["ladders"].items()
            }
            self._stats = copy.deepcopy(state["stats"])
            self._stats["restores"] += 1

    def stats(self):
        with self._lock:
            return copy.deepcopy(self._stats)
