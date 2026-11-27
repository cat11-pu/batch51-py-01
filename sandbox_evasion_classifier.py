"""样本沙箱反分析判定：时序停顿、环境探针与交互缺失的加权分级。"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

MAX_EVENTS = 512
MAX_INDICATORS = 32
MAX_SCORE = 100
DEFAULT_WINDOW_MS = 5000

VERDICTS = ("clean", "suspicious", "evasive", "uncertain")

DEFAULT_INDICATORS = (
    ("sleep_long", "timing", 30, 0.5),
    ("timing_poll", "timing", 20, 0.5),
    ("env_vm", "environment", 25, 0.8),
    ("debugger_attach", "environment", 35, 0.9),
    ("no_input", "interaction", 20, 0.6),
    ("name_blocklist", "identity", 40, 0.9),
    ("module_blocklist", "identity", 30, 0.8),
)

RESERVED_INDICATOR_NAMES = frozenset({"noname"})


class SandboxError(ValueError):
    """事件摄入或结论求值被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Indicator:
    name: str
    category: str
    weight: int
    confidence: float


@dataclass(frozen=True)
class Hit:
    indicator: str
    category: str
    key: str
    ts_ms: int
    effective: int


@dataclass(frozen=True)
class Verdict:
    score: int
    verdict: str
    categories: tuple
    hits: int
    truncated: bool


def effective_score(weight, confidence):
    """单条指标的有效分，向下取整。"""
    return int(weight * confidence)


def classify_score(score, categories, *, truncated=False):
    """按总分与参与计分的类别给出结论。"""
    if truncated:
        return "uncertain"
    if score < 20:
        return "clean"
    if score < 70 or len(categories) < 2:
        return "suspicious"
    return "evasive"


def _is_int(value):
    """布尔值不算整数。"""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_non_empty_text(value):
    return isinstance(value, str) and bool(value.strip())


_SNAPSHOT_KEYS = {"indicators", "samples", "counters"}
_COUNTER_KEYS = ("samples", "hits", "duplicates", "truncated", "resets")


class SandboxEvasionClassifier:
    """按样本累计信号并给出规避分析结论。"""

    def __init__(self, *, window_ms=DEFAULT_WINDOW_MS, max_events=MAX_EVENTS,
                 max_indicators=MAX_INDICATORS, indicators=None):
        self.window_ms = window_ms
        self.max_events = max_events
        self.max_indicators = max_indicators
        self._indicators = {}
        self._samples = {}
        self._counters = {"samples": 0, "hits": 0, "duplicates": 0,
                          "truncated": 0, "resets": 0}
        self._lock = threading.RLock()

        rows = DEFAULT_INDICATORS if indicators is None else indicators
        for name, category, weight, confidence in rows:
            self._register_indicator(name, category, weight, confidence,
                                     enforce_limit=True)

    def add_indicator(self, name, category, weight, confidence):
        with self._lock:
            return self._register_indicator(name, category, weight,
                                            confidence, enforce_limit=True)

    def _register_indicator(self, name, category, weight, confidence,
                            *, enforce_limit):
        if not _is_non_empty_text(name) or not _is_non_empty_text(category) \
                or name in RESERVED_INDICATOR_NAMES \
                or not _is_int(weight) or not 1 <= weight <= 100 \
                or not isinstance(confidence, (int, float)) \
                or isinstance(confidence, bool) \
                or not 0 < confidence <= 1:
            raise SandboxError("SANDBOX_INDICATOR_INVALID",
                               {"name": name, "category": category,
                                "weight": weight, "confidence": confidence})
        if name in self._indicators:
            raise SandboxError("SANDBOX_INDICATOR_EXISTS", name)
        if enforce_limit and len(self._indicators) >= self.max_indicators:
            raise SandboxError("SANDBOX_INDICATOR_LIMIT", self.max_indicators)
        indicator = Indicator(name=name, category=category,
                              weight=weight, confidence=confidence)
        self._indicators[name] = indicator
        return indicator

    def ingest_event(self, sample_id, kind, *, key="", ts_ms=0):
        if not isinstance(sample_id, str) or not sample_id:
            raise SandboxError("SANDBOX_SAMPLE_INVALID", sample_id)
        if not isinstance(key, str) or not _is_int(ts_ms) or ts_ms < 0:
            raise SandboxError("SANDBOX_EVENT_INVALID",
                               {"key": key, "ts_ms": ts_ms})
        with self._lock:
            indicator = self._indicators.get(kind)
            if indicator is None:
                raise SandboxError("SANDBOX_UNKNOWN_INDICATOR", kind)

            sample = self._samples.get(sample_id)
            if sample is None:
                sample = self._new_sample()
                self._samples[sample_id] = sample
                self._counters["samples"] += 1

            last_ts = sample["last_seen"].get((kind, key))
            if last_ts is not None and ts_ms - last_ts < self.window_ms:
                self._counters["duplicates"] += 1
                for hit in reversed(sample["hits"]):
                    if hit.indicator == kind and hit.key == key:
                        return hit
                raise SandboxError("SANDBOX_EVENT_INVALID", kind)

            if sample["event_count"] >= self.max_events:
                raise SandboxError("SANDBOX_TRACE_LIMIT", self.max_events)

            hit = Hit(
                indicator=indicator.name,
                category=indicator.category,
                key=key,
                ts_ms=ts_ms,
                effective=effective_score(indicator.weight,
                                           indicator.confidence),
            )
            sample["hits"].append(hit)
            sample["last_seen"][(kind, key)] = ts_ms
            sample["event_count"] += 1
            self._counters["hits"] += 1
            return hit

    def evaluate(self, sample_id):
        with self._lock:
            sample = self._require_sample(sample_id)
            return self._verdict(sample)

    def _verdict(self, sample):
        category_scores = {}
        for hit in sample["hits"]:
            current = category_scores.get(hit.category, 0)
            if hit.effective > current:
                category_scores[hit.category] = hit.effective
        score = min(MAX_SCORE, sum(category_scores.values()))
        categories = tuple(sorted(category_scores))
        verdict = classify_score(score, categories,
                                 truncated=sample["truncated"])
        return Verdict(score=score, verdict=verdict,
                       categories=categories, hits=len(sample["hits"]),
                       truncated=sample["truncated"])

    def _require_sample(self, sample_id):
        sample = self._samples.get(sample_id)
        if sample is None:
            raise SandboxError("SANDBOX_SAMPLE_UNKNOWN", sample_id)
        return sample

    @staticmethod
    def _new_sample():
        return {"hits": [], "last_seen": {}, "event_count": 0,
                "truncated": False, "truncate_reason": ""}

    def explain(self, sample_id):
        with self._lock:
            sample = self._require_sample(sample_id)
            verdict = self._verdict(sample)

            grouped = {}
            for hit in sample["hits"]:
                bucket = grouped.setdefault(
                    hit.category,
                    {"hits": 0, "score": 0, "indicators": set()},
                )
                bucket["hits"] += 1
                bucket["indicators"].add(hit.indicator)
                if hit.effective > bucket["score"]:
                    bucket["score"] = hit.effective

            categories = {}
            for name in sorted(grouped):
                bucket = grouped[name]
                categories[name] = {
                    "hits": bucket["hits"],
                    "score": bucket["score"],
                    "indicators": sorted(bucket["indicators"]),
                }

            ranking = {}
            for hit in sample["hits"]:
                ranking.setdefault(hit.indicator, hit.effective)
            top = sorted(ranking, key=lambda name: (-ranking[name], name))

            return {"score": verdict.score, "verdict": verdict.verdict,
                    "hits": verdict.hits, "categories": categories,
                    "top": top}

    def mark_truncated(self, sample_id, reason=""):
        with self._lock:
            sample = self._require_sample(sample_id)
            first_mark = not sample["truncated"]
            sample["truncated"] = True
            sample["truncate_reason"] = reason
            if first_mark:
                self._counters["truncated"] += 1
            return True

    def reset(self, sample_id):
        with self._lock:
            sample = self._require_sample(sample_id)
            cleared = len(sample["hits"])
            self._samples[sample_id] = self._new_sample()
            self._counters["resets"] += 1
            return cleared

    def snapshot(self):
        with self._lock:
            return copy.deepcopy({
                "indicators": self._indicators,
                "samples": self._samples,
                "counters": self._counters,
            })

    def restore(self, state):
        indicators, samples, counters = self._decode_snapshot(state)
        with self._lock:
            self._indicators = indicators
            self._samples = samples
            self._counters = counters

    @classmethod
    def _decode_snapshot(cls, state):
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise SandboxError("SANDBOX_SNAPSHOT_INVALID", "bad snapshot")
        raw_indicators = state["indicators"]
        raw_samples = state["samples"]
        raw_counters = state["counters"]
        if not isinstance(raw_indicators, dict) \
                or not isinstance(raw_samples, dict) \
                or not isinstance(raw_counters, dict):
            raise SandboxError("SANDBOX_SNAPSHOT_INVALID", "bad container")

        indicators = {}
        for name, payload in raw_indicators.items():
            if not isinstance(name, str) or not isinstance(payload, Indicator):
                raise SandboxError("SANDBOX_SNAPSHOT_INVALID",
                                   "bad indicator entry")
            if not _is_non_empty_text(payload.name) \
                    or not _is_non_empty_text(payload.category) \
                    or not _is_int(payload.weight) \
                    or not 1 <= payload.weight <= 100 \
                    or not isinstance(payload.confidence, (int, float)) \
                    or isinstance(payload.confidence, bool) \
                    or not 0 < payload.confidence <= 1 \
                    or payload.name != name:
                raise SandboxError("SANDBOX_SNAPSHOT_INVALID",
                                   "bad indicator field")
            indicators[name] = Indicator(
                name=payload.name, category=payload.category,
                weight=payload.weight, confidence=payload.confidence)

        samples = {}
        for sample_id, payload in raw_samples.items():
            if not isinstance(sample_id, str) or not sample_id \
                    or not isinstance(payload, dict):
                raise SandboxError("SANDBOX_SNAPSHOT_INVALID",
                                   "bad sample entry")
            hits = payload.get("hits")
            last_seen = payload.get("last_seen")
            event_count = payload.get("event_count")
            truncated = payload.get("truncated")
            reason = payload.get("truncate_reason")
            if set(payload) != {"hits", "last_seen", "event_count",
                                "truncated", "truncate_reason"} \
                    or not isinstance(hits, list) \
                    or not isinstance(last_seen, dict) \
                    or not _is_int(event_count) or event_count < 0 \
                    or not isinstance(truncated, bool) \
                    or not isinstance(reason, str):
                raise SandboxError("SANDBOX_SNAPSHOT_INVALID",
                                   "bad sample field")
            decoded_hits = []
            for hit in hits:
                if not isinstance(hit, Hit) \
                        or not isinstance(hit.indicator, str) \
                        or not isinstance(hit.category, str) \
                        or not isinstance(hit.key, str) \
                        or not _is_int(hit.ts_ms) or hit.ts_ms < 0 \
                        or not _is_int(hit.effective) or hit.effective < 0 \
                        or hit.indicator not in indicators:
                    raise SandboxError("SANDBOX_SNAPSHOT_INVALID",
                                       "bad hit entry")
                decoded_hits.append(Hit(
                    indicator=hit.indicator, category=hit.category,
                    key=hit.key, ts_ms=hit.ts_ms,
                    effective=hit.effective))
            decoded_seen = {}
            for signal, ts_ms in last_seen.items():
                if not isinstance(signal, tuple) or len(signal) != 2 \
                        or not all(isinstance(part, str) for part in signal) \
                        or not _is_int(ts_ms) or ts_ms < 0:
                    raise SandboxError("SANDBOX_SNAPSHOT_INVALID",
                                       "bad dedupe entry")
                decoded_seen[signal] = ts_ms
            samples[sample_id] = {
                "hits": decoded_hits,
                "last_seen": decoded_seen,
                "event_count": event_count,
                "truncated": truncated,
                "truncate_reason": reason,
            }

        if set(raw_counters) != set(_COUNTER_KEYS) \
                or any(not _is_int(raw_counters[key]) or raw_counters[key] < 0
                       for key in _COUNTER_KEYS):
            raise SandboxError("SANDBOX_SNAPSHOT_INVALID", "bad counters")
        counters = {key: raw_counters[key] for key in _COUNTER_KEYS}

        return indicators, samples, counters

    def stats(self):
        with self._lock:
            return dict(self._counters)
