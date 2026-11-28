"""依赖名称相似度索引：同形字归并、阈值分级与增量维护。"""

from __future__ import annotations

import threading

HOMOGLYPHS = {
    "\u0430": "a",  # а cyrillic
    "\u0435": "e",  # е cyrillic
    "\u043e": "o",  # о cyrillic
    "\u0440": "p",  # р cyrillic
    "\u0441": "c",  # с cyrillic
    "\u0445": "x",  # х cyrillic
    "\u0456": "i",  # і cyrillic
    "\u03bf": "o",  # ο greek
    "\u03b1": "a",  # α greek
    "\u0261": "g",  # ɡ latin script g
}

KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

LEVEL_EXACT = "exact"
LEVEL_CRITICAL = "critical"
LEVEL_HIGH = "high"
LEVEL_NEAR = "near"
LEVEL_FAR = "far"

MAX_NAME_LENGTH = 64
SNAPSHOT_VERSION = 1


def _build_keyboard_neighbours():
    neighbours = set()
    for row in KEYBOARD_ROWS:
        for index in range(len(row) - 1):
            neighbours.add(frozenset((row[index], row[index + 1])))
    return neighbours


KEYBOARD_NEIGHBOURS = _build_keyboard_neighbours()


class TyposquatError(ValueError):
    """索引操作被拒绝时抛出，code 为大写串。"""

    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class PackageTyposquatIndex:
    """为受关注包名建立相似度索引，按阈值给候选分级。"""

    def __init__(self, *, max_watches=64, high=0.90, near=0.80):
        self.max_watches = max_watches
        self.high = high
        self.near = near
        self._lock = threading.RLock()
        self._watches = {}
        self._history = {}
        self._stats = {
            "watches": 0,
            "watch_adds": 0,
            "queries": 0,
            "observed": 0,
            "removed": 0,
            "restores": 0,
        }

    @staticmethod
    def _normalize(name):
        if not isinstance(name, str):
            raise TyposquatError("TYPO_INVALID_NAME", "name 必须是字符串")
        normalized = name.strip().lower().replace("_", "-").replace(".", "-")
        while "--" in normalized:
            normalized = normalized.replace("--", "-")
        normalized = normalized.strip("-")
        if not normalized:
            raise TyposquatError("TYPO_INVALID_NAME", "归一化后名称为空")
        if len(normalized) > MAX_NAME_LENGTH:
            raise TyposquatError("TYPO_INVALID_NAME", "名称超过 64 字符上限")
        return normalized

    @staticmethod
    def _fold(name):
        return "".join(HOMOGLYPHS.get(char, char) for char in name)

    def _substitution_cost(self, left, right):
        if left == right:
            return 0.0
        pair = frozenset((left, right))
        if pair in KEYBOARD_NEIGHBOURS:
            return 0.5
        return 1.0

    def add_watch(self, name, *, ecosystem="pypi", now=None):
        normalized = self._normalize(name)
        with self._lock:
            existing = self._watches.get(normalized)
            if existing is not None:
                return normalized
            if len(self._watches) >= self.max_watches:
                raise TyposquatError(
                    "TYPO_WATCH_LIMIT",
                    "关注名单已达上限 %s" % self.max_watches,
                )
            self._watches[normalized] = ecosystem
            self._history.setdefault(normalized, set())
            self._stats["watch_adds"] += 1
            return normalized

    def remove_watch(self, name):
        with self._lock:
            try:
                normalized = self._normalize(name)
            except TyposquatError:
                return False
            if normalized not in self._watches:
                return False
            del self._watches[normalized]
            self._stats["removed"] += 1
            return True

    def watches(self):
        with self._lock:
            return sorted(self._watches)

    def similarity(self, left, right):
        left_name = self._normalize(left)
        right_name = self._normalize(right)
        if left_name == right_name:
            return 1.0
        longest = max(len(left_name), len(right_name))
        previous = list(range(len(right_name) + 1))
        for row_index, left_char in enumerate(left_name, start=1):
            current = [row_index]
            for column_index, right_char in enumerate(right_name, start=1):
                insert_cost = current[column_index - 1] + 1
                delete_cost = previous[column_index] + 1
                replace_cost = (
                    previous[column_index - 1]
                    + self._substitution_cost(left_char, right_char)
                )
                current.append(min(insert_cost, delete_cost, replace_cost))
            previous = current
        cost = previous[-1]
        return round(1.0 - cost / longest, 4)

    def _score_all(self, incoming):
        normalized = self._normalize(incoming)
        folded = self._fold(normalized)
        rows = []
        for watched in sorted(self._watches):
            if normalized == watched:
                level = LEVEL_EXACT
                score = 1.0
            elif folded == self._fold(watched):
                level = LEVEL_CRITICAL
                score = self.similarity(normalized, watched)
            else:
                score = self.similarity(normalized, watched)
                if score >= self.high:
                    level = LEVEL_HIGH
                elif score >= self.near:
                    level = LEVEL_NEAR
                else:
                    level = LEVEL_FAR
            rows.append(
                {
                    "level": level,
                    "package": watched,
                    "similarity": score,
                }
            )
        return normalized, rows

    @staticmethod
    def _best_row(rows):
        return min(rows, key=lambda row: (-row["similarity"], row["package"]))

    def classify(self, incoming):
        with self._lock:
            self._stats["queries"] += 1
            _, rows = self._score_all(incoming)
            if not rows:
                return {"level": LEVEL_FAR, "package": None, "similarity": 0.0}
            for row in rows:
                if row["level"] == LEVEL_EXACT:
                    return dict(row)
            for row in rows:
                if row["level"] == LEVEL_CRITICAL:
                    best = self._best_row(
                        [entry for entry in rows if entry["level"] == LEVEL_CRITICAL]
                    )
                    return dict(best)
            best = self._best_row(rows)
            if best["level"] == LEVEL_FAR:
                return {"level": LEVEL_FAR, "package": None, "similarity": best["similarity"]}
            return dict(best)

    def candidate(self, incoming, *, limit=3):
        with self._lock:
            _, rows = self._score_all(incoming)
            eligible = [
                row
                for row in rows
                if row["level"] != LEVEL_EXACT
                and (row["level"] == LEVEL_CRITICAL or row["similarity"] >= self.near)
            ]
            eligible.sort(key=lambda row: (-row["similarity"], row["package"]))
            if limit <= 0:
                return []
            return [dict(row) for row in eligible[:limit]]

    def observe(self, incoming, *, now=None):
        with self._lock:
            normalized, rows = self._score_all(incoming)
            self._stats["observed"] += 1
            hits = []
            for row in rows:
                if row["level"] in (LEVEL_EXACT, LEVEL_CRITICAL) or (
                    row["level"] != LEVEL_FAR and row["similarity"] >= self.near
                ):
                    history = self._history.setdefault(row["package"], set())
                    history.add(normalized)
                    hits.append(row)
            hits.sort(key=lambda row: row["package"])
            if hits:
                best = self._best_row(hits)
                result = {
                    "recorded": [row["package"] for row in hits],
                    "package": best["package"],
                    "level": best["level"],
                    "similarity": best["similarity"],
                }
            else:
                result = {
                    "recorded": [],
                    "package": None,
                    "level": LEVEL_FAR,
                    "similarity": 0.0,
                }
            return result

    def history_for(self, watched):
        with self._lock:
            try:
                normalized = self._normalize(watched)
            except TyposquatError:
                return []
            return sorted(self._history.get(normalized, ()))

    def snapshot(self):
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "watches": sorted(self._watches),
                "history": {
                    name: sorted(entries)
                    for name, entries in sorted(self._history.items())
                },
                "thresholds": {
                    "high": self.high,
                    "near": self.near,
                },
                "stats": self._snapshot_stats(),
            }

    def _snapshot_stats(self):
        stats = dict(self._stats)
        stats["watches"] = len(self._watches)
        return stats

    @staticmethod
    def _validate_snapshot(state):
        if not isinstance(state, dict):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "快照必须是字典")
        required = ("version", "watches", "history", "thresholds", "stats")
        for key in required:
            if key not in state:
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "缺少字段 %s" % key)
        if state["version"] != SNAPSHOT_VERSION or isinstance(state["version"], bool):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "version 不被支持")
        if not isinstance(state["watches"], list):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "watches 必须是列表")
        if not isinstance(state["history"], dict):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "history 必须是字典")
        if not isinstance(state["thresholds"], dict):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "thresholds 必须是字典")
        if not isinstance(state["stats"], dict):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "stats 必须是字典")

        normalized_watches = []
        for watched in state["watches"]:
            if not isinstance(watched, str):
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "watch 名称必须是字符串")
            normalized = PackageTyposquatIndex._normalize(watched)
            normalized_watches.append(normalized)
        if len(set(normalized_watches)) != len(normalized_watches):
            raise TyposquatError("TYPO_SNAPSHOT_INVALID", "watch 名称存在重复")

        restored_history = {}
        for watched, entries in state["history"].items():
            if not isinstance(watched, str) or not isinstance(entries, list):
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "history 结构不合法")
            normalized_watch = PackageTyposquatIndex._normalize(watched)
            normalized_entries = []
            for entry in entries:
                if not isinstance(entry, str):
                    raise TyposquatError("TYPO_SNAPSHOT_INVALID", "历史来料必须是字符串")
                normalized_entries.append(PackageTyposquatIndex._normalize(entry))
            if len(set(normalized_entries)) != len(normalized_entries):
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "历史来料存在重复")
            restored_history[normalized_watch] = set(normalized_entries)

        thresholds = state["thresholds"]
        for key in ("high", "near"):
            value = thresholds.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "阈值 %s 类型不符" % key)
            if not 0.0 <= float(value) <= 1.0:
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "阈值 %s 越界" % key)

        stats = state["stats"]
        expected_stats = (
            "watches",
            "watch_adds",
            "queries",
            "observed",
            "removed",
            "restores",
        )
        for key in expected_stats:
            value = stats.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "计数 %s 不合法" % key)

        return normalized_watches, restored_history, dict(thresholds), dict(stats)

    def restore(self, state):
        with self._lock:
            normalized_watches, restored_history, thresholds, restored_stats = (
                self._validate_snapshot(state)
            )
            if len(normalized_watches) > self.max_watches:
                raise TyposquatError("TYPO_SNAPSHOT_INVALID", "watch 数量超过硬顶")

            watches = {name: "pypi" for name in normalized_watches}
            history = {name: set(entries) for name, entries in restored_history.items()}
            for name in normalized_watches:
                history.setdefault(name, set())

            self._watches = watches
            self._history = history
            self.high = thresholds["high"]
            self.near = thresholds["near"]
            self._stats = restored_stats
            self._stats["watches"] = len(watches)
            self._stats["restores"] += 1
            return None

    def stats(self):
        with self._lock:
            stats = dict(self._stats)
            stats["watches"] = len(self._watches)
            return stats
