"""Dynamic difficulty director: metric windows, tier hysteresis, in-fight freeze."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class DirectorError(ValueError):
    """Raised when a difficulty decision cannot be taken."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Adjustment:
    seq: int
    from_tier: int
    to_tier: int
    changed: bool
    reason: str
    stress_bps: int
    at_ms: int
    window: dict


class _WindowSnapshot(dict):
    """Public six-key window view with exact state kept out of the mapping."""

    def __init__(self, values: dict, kill_ms: int, active: bool) -> None:
        super().__init__(values)
        self.raw_kill_ms = kill_ms
        self.window_active = active


class DifficultyDirector:
    """Raise or lower encounter difficulty from failure metrics with hysteresis."""

    DEFAULT_SCALING = ((10000, 10000), (11500, 11000),
                       (13000, 12000), (15000, 13500))

    SNAPSHOT_VERSION = 1
    WINDOW_KEYS = ("deaths", "wipes", "kills", "kill_ms_avg",
                   "healing", "members")
    STAT_KEYS = ("observations", "evaluations", "adjustments", "freezes")
    HISTORY_KEYS = ("seq", "from_tier", "to_tier", "changed", "reason",
                    "stress_bps", "at_ms", "window")
    SNAPSHOT_KEYS = ("version", "tier", "window", "history", "reasons",
                     "frozen", "stats")

    def __init__(self, *, scaling=None, up_threshold_bps: int = 12000,
                 down_threshold_bps: int = 4000, hysteresis_bps: int = 1500,
                 min_interval_ms: int = 30000, max_tier: int = 3,
                 max_history: int = 8) -> None:
        self.scaling = tuple(scaling) if scaling else self.DEFAULT_SCALING
        self.up_threshold_bps = up_threshold_bps
        self.down_threshold_bps = down_threshold_bps
        self.hysteresis_bps = hysteresis_bps
        self.min_interval_ms = min_interval_ms
        self.max_tier = max_tier
        self.max_history = max_history

        self._lock = threading.RLock()
        self._tier = 0
        self._window = self._blank_window(4)
        self._window_active = False
        self._history: list[Adjustment] = []
        self._seq = 0
        self._last_adjust_ms: int | None = None
        self._reasons = self._initial_reasons()
        self._frozen = False
        self._freeze_reason: object = None
        self._stats = {key: 0 for key in self.STAT_KEYS}

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _is_non_negative_int(cls, value: object) -> bool:
        return cls._is_int(value) and value >= 0

    @staticmethod
    def _blank_window(members: int) -> dict:
        return {
            "deaths": 0,
            "wipes": 0,
            "kills": 0,
            "kill_ms": 0,
            "healing": 0,
            "members": members,
        }

    @staticmethod
    def _kill_ms_avg(window: dict) -> int:
        kills = window["kills"]
        return window["kill_ms"] // kills if kills else 0

    @classmethod
    def _public_window(cls, window: dict) -> dict:
        return {
            "deaths": window["deaths"],
            "wipes": window["wipes"],
            "kills": window["kills"],
            "kill_ms_avg": cls._kill_ms_avg(window),
            "healing": window["healing"],
            "members": window["members"],
        }

    @staticmethod
    def _stress_bps(window: dict) -> int:
        kills = window["kills"] or 1
        return (window["deaths"] * 10000
                + window["wipes"] * 20000) // kills

    def _initial_reasons(self) -> dict[int, str]:
        reasons = {}
        for tier in range(max(0, self.max_tier) + 1):
            reasons[tier] = "INITIAL" if tier == 0 else "UNSET"
        return reasons

    def _clear_window(self) -> None:
        self._window = self._blank_window(self._window["members"])
        self._window_active = False

    def _in_cooldown(self, at_ms: int) -> bool:
        return (self._last_adjust_ms is not None
                and at_ms - self._last_adjust_ms < self.min_interval_ms)

    def _copy_adjustment(self, adjustment: Adjustment) -> Adjustment:
        return Adjustment(
            seq=adjustment.seq,
            from_tier=adjustment.from_tier,
            to_tier=adjustment.to_tier,
            changed=adjustment.changed,
            reason=adjustment.reason,
            stress_bps=adjustment.stress_bps,
            at_ms=adjustment.at_ms,
            window=copy.deepcopy(adjustment.window),
        )

    @classmethod
    def _adjustment_to_dict(cls, adjustment: Adjustment) -> dict:
        return {
            "seq": adjustment.seq,
            "from_tier": adjustment.from_tier,
            "to_tier": adjustment.to_tier,
            "changed": adjustment.changed,
            "reason": adjustment.reason,
            "stress_bps": adjustment.stress_bps,
            "at_ms": adjustment.at_ms,
            "window": copy.deepcopy(adjustment.window),
        }

    def observe(self, *, deaths: int = 0, wipes: int = 0, kills: int = 0,
                kill_ms: int = 0, healing: int = 0, members: int = 4,
                at_ms: int = 0) -> dict:
        """Add one encounter observation to the statistic window."""
        values = {
            "deaths": deaths,
            "wipes": wipes,
            "kills": kills,
            "kill_ms": kill_ms,
            "healing": healing,
        }
        for name, value in values.items():
            if not self._is_non_negative_int(value):
                raise DirectorError("DIRECTOR_INVALID_METRIC",
                                    {name: value})
        if not self._is_int(members) or members < 1:
            raise DirectorError("DIRECTOR_INVALID_METRIC",
                                {"members": members})

        with self._lock:
            if members != self._window["members"]:
                self._window = self._blank_window(members)
                self._window_active = False

            self._window["deaths"] += deaths
            self._window["wipes"] += wipes
            self._window["kills"] += kills
            self._window["kill_ms"] += kill_ms
            self._window["healing"] += healing
            self._window_active = True
            self._stats["observations"] += 1
            return self._public_window(self._window)

    def metrics(self) -> dict:
        """Current window: deaths, wipes, kills, kill_ms_avg, healing, members."""
        with self._lock:
            return self._public_window(self._window)

    def tier_of(self) -> int:
        """Current difficulty tier."""
        with self._lock:
            return self._tier

    def coefficients_of(self, tier: int | None = None) -> tuple[int, int]:
        """Monster hp and damage coefficients of a tier."""
        with self._lock:
            target = self._tier if tier is None else tier
            if (not self._is_int(target) or target < 0
                    or target > self.max_tier
                    or target >= len(self.scaling)):
                raise DirectorError("DIRECTOR_INVALID_TIER", target)
            try:
                hp, damage = self.scaling[target]
            except (TypeError, ValueError):
                raise DirectorError("DIRECTOR_INVALID_TIER", target) from None
            return (hp, damage)

    def evaluate_adjust(self, at_ms: int = 0) -> Adjustment:
        """Judge the window and move the tier when the hysteresis gate allows it."""
        with self._lock:
            self._stats["evaluations"] += 1
            judged = copy.deepcopy(self._window)
            public = self._public_window(judged)
            stress = self._stress_bps(judged)
            seq = self._seq
            from_tier = self._tier

            if self._frozen:
                return Adjustment(seq, from_tier, from_tier, False, "FROZEN",
                                  stress, at_ms, public)

            if self._window_active and self._in_cooldown(at_ms):
                return Adjustment(seq, from_tier, from_tier, False, "COOLDOWN",
                                  stress, at_ms, public)

            to_tier = from_tier
            reason = "NO_CHANGE"
            changed = False

            if self._window_active:
                up_line = (self.up_threshold_bps
                           + from_tier * self.hysteresis_bps)
                down_line = (self.down_threshold_bps
                             - from_tier * self.hysteresis_bps)
                if stress >= up_line and from_tier < self.max_tier:
                    to_tier = from_tier + 1
                    reason = "ADJUST_UP"
                    changed = True
                elif stress <= down_line and from_tier > 0:
                    to_tier = from_tier - 1
                    reason = "ADJUST_DOWN"
                    changed = True

            self._clear_window()

            if not changed:
                return Adjustment(seq, from_tier, to_tier, False, reason,
                                  stress, at_ms, public)

            self._seq += 1
            self._tier = to_tier
            self._last_adjust_ms = at_ms
            self._reasons[to_tier] = reason
            adjustment = Adjustment(self._seq, from_tier, to_tier, True,
                                    reason, stress, at_ms, public)
            self._history.append(self._copy_adjustment(adjustment))
            if self.max_history is not None and self.max_history >= 0:
                if self.max_history == 0:
                    self._history.clear()
                elif len(self._history) > self.max_history:
                    self._history = self._history[-self.max_history:]
            self._stats["adjustments"] += 1
            return adjustment

    def freeze(self, reason: str, *, at_ms: int = 0) -> bool:
        """Freeze adjustments for boss fights or scripted events."""
        with self._lock:
            if self._frozen:
                return False
            self._frozen = True
            self._freeze_reason = reason
            self._stats["freezes"] += 1
            return True

    def unfreeze(self, *, at_ms: int = 0) -> bool:
        """Release the freeze so the next evaluation can move the tier again."""
        with self._lock:
            if not self._frozen:
                return False
            self._frozen = False
            self._freeze_reason = None
            if self._seq:
                self._last_adjust_ms = at_ms
            else:
                self._last_adjust_ms = at_ms - self.min_interval_ms
            return True

    def is_frozen(self) -> bool:
        """Whether adjustments are currently frozen."""
        with self._lock:
            return self._frozen

    def reason_of(self, tier: int | None = None) -> str:
        """Reason recorded for the current tier or for the given tier."""
        with self._lock:
            target = self._tier if tier is None else tier
            if (not self._is_int(target) or target < 0
                    or target > self.max_tier):
                raise DirectorError("DIRECTOR_INVALID_TIER", target)
            return self._reasons.get(
                target, "INITIAL" if target == 0 else "UNSET")

    def history_of(self, limit: int | None = None) -> list[Adjustment]:
        """Actual tier changes in ascending sequence order."""
        with self._lock:
            if limit is None:
                rows = self._history
            elif not self._is_int(limit) or limit <= 0:
                rows = []
            else:
                rows = self._history[-limit:]
            return [self._copy_adjustment(row) for row in rows]

    def snapshot(self) -> dict:
        """Deep copy of tier, window, history, reasons, freeze flag and counters."""
        with self._lock:
            window = _WindowSnapshot(self._public_window(self._window),
                                     self._window["kill_ms"],
                                     self._window_active)
            return {
                "version": self.SNAPSHOT_VERSION,
                "tier": self._tier,
                "window": window,
                "history": [self._adjustment_to_dict(row)
                            for row in self._history],
                "reasons": dict(self._reasons),
                "frozen": self._frozen,
                "stats": dict(self._stats),
            }

    def _invalid_snapshot(self, detail: object = None) -> DirectorError:
        return DirectorError("DIRECTOR_SNAPSHOT_INVALID", detail)

    def _parse_window(self, value: object) -> dict:
        if not isinstance(value, dict):
            raise self._invalid_snapshot("window")
        for key in ("deaths", "wipes", "kills", "kill_ms_avg",
                    "healing", "members"):
            if key not in value:
                raise self._invalid_snapshot(f"window.{key}")
        for key in ("deaths", "wipes", "kills", "kill_ms_avg", "healing"):
            if not self._is_non_negative_int(value[key]):
                raise self._invalid_snapshot(f"window.{key}")
        if not self._is_int(value["members"]) or value["members"] < 1:
            raise self._invalid_snapshot("window.members")

        if isinstance(value, _WindowSnapshot):
            kill_ms = value.raw_kill_ms
            active = value.window_active
            if not self._is_non_negative_int(kill_ms):
                raise self._invalid_snapshot("window.kill_ms")
            if not isinstance(active, bool):
                raise self._invalid_snapshot("window.active")
        elif "kill_ms" in value:
            if not self._is_non_negative_int(value["kill_ms"]):
                raise self._invalid_snapshot("window.kill_ms")
            kill_ms = value["kill_ms"]
            active = value.get("active")
        else:
            kill_ms = value["kill_ms_avg"] * value["kills"]
            active = value.get("active")

        if not isinstance(value, _WindowSnapshot):
            if active is not None and not isinstance(active, bool):
                raise self._invalid_snapshot("window.active")
            if active is None:
                active = any(value[key] for key in
                             ("deaths", "wipes", "kills", "healing")
                             if key in value)
                if "kill_ms" in value:
                    active = active or bool(value["kill_ms"])

        return {
            "deaths": value["deaths"],
            "wipes": value["wipes"],
            "kills": value["kills"],
            "kill_ms": kill_ms,
            "healing": value["healing"],
            "members": value["members"],
            "_active": active,
        }

    def _parse_history(self, value: object) -> list[Adjustment]:
        if not isinstance(value, list):
            raise self._invalid_snapshot("history")
        rows = []
        previous_seq = 0
        for item in value:
            if isinstance(item, Adjustment):
                raw = self._adjustment_to_dict(item)
            elif isinstance(item, dict):
                raw = item
            else:
                raise self._invalid_snapshot("history.item")
            for key in self.HISTORY_KEYS:
                if key not in raw:
                    raise self._invalid_snapshot(f"history.{key}")

            seq = raw["seq"]
            from_tier = raw["from_tier"]
            to_tier = raw["to_tier"]
            changed = raw["changed"]
            reason = raw["reason"]
            stress = raw["stress_bps"]
            at_ms = raw["at_ms"]

            if not self._is_int(seq) or seq < 1 or seq <= previous_seq:
                raise self._invalid_snapshot("history.seq")
            if (not self._is_int(from_tier) or from_tier < 0
                    or from_tier > self.max_tier):
                raise self._invalid_snapshot("history.from_tier")
            if (not self._is_int(to_tier) or to_tier < 0
                    or to_tier > self.max_tier):
                raise self._invalid_snapshot("history.to_tier")
            if changed is not True or reason not in ("ADJUST_UP",
                                                      "ADJUST_DOWN"):
                raise self._invalid_snapshot("history.change")
            if not self._is_non_negative_int(stress):
                raise self._invalid_snapshot("history.stress_bps")
            if not self._is_int(at_ms):
                raise self._invalid_snapshot("history.at_ms")

            window = self._parse_window(raw["window"])
            window = self._public_window(window)
            rows.append(Adjustment(seq, from_tier, to_tier, True, reason,
                                   stress, at_ms, window))
            previous_seq = seq
        return rows

    def _parse_reasons(self, value: object) -> dict[int, str]:
        if not isinstance(value, dict):
            raise self._invalid_snapshot("reasons")
        reasons = self._initial_reasons()
        for key, reason in value.items():
            target = key
            if isinstance(target, str):
                try:
                    target = int(target)
                except ValueError:
                    raise self._invalid_snapshot("reasons.key") from None
            if (not self._is_int(target) or target < 0
                    or target > self.max_tier):
                raise self._invalid_snapshot("reasons.key")
            if not isinstance(reason, str):
                raise self._invalid_snapshot("reasons.value")
            reasons[target] = reason
        return reasons

    def _parse_stats(self, value: object) -> dict:
        if not isinstance(value, dict):
            raise self._invalid_snapshot("stats")
        stats = {}
        for key in self.STAT_KEYS:
            if key not in value or not self._is_non_negative_int(value[key]):
                raise self._invalid_snapshot(f"stats.{key}")
            stats[key] = value[key]
        return stats

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise self._invalid_snapshot("state")
        for key in self.SNAPSHOT_KEYS:
            if key not in state:
                raise self._invalid_snapshot(key)
        if (not self._is_int(state["version"])
                or state["version"] != self.SNAPSHOT_VERSION):
            raise self._invalid_snapshot("version")

        tier = state["tier"]
        if (not self._is_int(tier) or tier < 0
                or tier > self.max_tier):
            raise self._invalid_snapshot("tier")

        window = self._parse_window(state["window"])
        history = self._parse_history(state["history"])
        reasons = self._parse_reasons(state["reasons"])
        frozen = state["frozen"]
        if not isinstance(frozen, bool):
            raise self._invalid_snapshot("frozen")
        stats = self._parse_stats(state["stats"])

        return {
            "tier": tier,
            "window": window,
            "history": history,
            "reasons": reasons,
            "frozen": frozen,
            "stats": stats,
        }

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        try:
            parsed = self._parse_snapshot(state)
        except DirectorError:
            raise
        except Exception as exc:
            raise self._invalid_snapshot(exc) from None

        with self._lock:
            self._tier = parsed["tier"]
            window = parsed["window"]
            self._window_active = window.pop("_active", False)
            self._window = window
            self._history = parsed["history"]
            self._reasons = parsed["reasons"]
            self._frozen = parsed["frozen"]
            self._freeze_reason = None
            self._stats = parsed["stats"]
            max_seq = self._history[-1].seq if self._history else 0
            self._seq = max(self._stats["adjustments"], max_seq)
            self._last_adjust_ms = (self._history[-1].at_ms
                                    if self._history else None)

    def stats(self) -> dict:
        """Return observations, evaluations, adjustments and freezes."""
        with self._lock:
            return dict(self._stats)
