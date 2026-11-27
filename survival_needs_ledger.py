"""Survival needs ledger: decay, offline catch-up, effect stack, dying state machine."""

from __future__ import annotations

import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction

NEED_NAMES = ("hunger", "thirst", "warmth")
NEED_CAP = 100
REVIVE_FLOOR = 25
DEFAULT_TICK_MS = 1000
DEFAULT_DECAY = {"hunger": 1, "thirst": 2, "warmth": 1}

MAX_EFFECTS_PER_CHARACTER = 64
MAX_CATCHUP_WINDOW_MS = 31 * 24 * 60 * 60 * 1000

_COUNTER_NAMES = ("ticks", "consumes", "catchups", "revivals", "dying")


class SurvivalError(ValueError):
    """Raised when a survival settlement request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Effect:
    """One timed modifier applied to a single need."""

    effect_id: str
    need: str
    multiplier: float
    priority: int
    expires_at_ms: int


class _Character:
    __slots__ = ("lock", "time_ms", "needs", "dying", "effects")

    def __init__(
        self,
        *,
        time_ms: int,
        needs: dict[str, Fraction],
        dying: bool,
        effects: dict[str, Effect],
    ) -> None:
        self.lock = threading.RLock()
        self.time_ms = time_ms
        self.needs = needs
        self.dying = dying
        self.effects = effects


def _number_to_fraction(value: object, *, code: str, detail: object = None) -> Fraction:
    if isinstance(value, bool):
        raise SurvivalError(code, detail)
    if isinstance(value, Fraction):
        return value
    if isinstance(value, int):
        return Fraction(value)
    if isinstance(value, (float, Decimal)):
        if isinstance(value, float) and not math.isfinite(value):
            raise SurvivalError(code, detail)
        if isinstance(value, Decimal) and not value.is_finite():
            raise SurvivalError(code, detail)
        return Fraction(str(value))
    if isinstance(value, str):
        try:
            parsed = Fraction(value)
        except (ValueError, ZeroDivisionError):
            raise SurvivalError(code, detail) from None
        return parsed
    raise SurvivalError(code, detail)


def _out_number(value: Fraction):
    if value.denominator == 1:
        return value.numerator
    return float(value)


def _fraction_text(value: Fraction) -> str:
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator}/{value.denominator}"


def _require_int(value: object, *, code: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SurvivalError(code, value)
    if minimum is not None and value < minimum:
        raise SurvivalError(code, value)
    return value


def _character_sort_key(character_id: object):
    character_type = type(character_id)
    return (
        character_type.__module__,
        character_type.__qualname__,
        repr(character_id),
    )


def _public_effect(effect: Effect) -> Effect:
    return Effect(
        effect_id=effect.effect_id,
        need=effect.need,
        multiplier=_out_number(effect.multiplier),
        priority=effect.priority,
        expires_at_ms=effect.expires_at_ms,
    )


class SurvivalNeedsLedger:
    """Track per-character survival needs and settle them from server time."""

    __slots__ = (
        "_cap",
        "_tick_ms",
        "_decay",
        "_registry_lock",
        "_stats_lock",
        "_characters",
        "_counters",
    )

    def __init__(
        self,
        *,
        decay=None,
        tick_ms: int = DEFAULT_TICK_MS,
        cap: int = NEED_CAP,
    ) -> None:
        self._cap = _require_int(cap, code="SN_INVALID_CAP", minimum=1)
        self._tick_ms = _require_int(tick_ms, code="SN_INVALID_TICK_MS", minimum=1)

        raw_decay = DEFAULT_DECAY if decay is None else decay
        if not isinstance(raw_decay, Mapping):
            raise SurvivalError("SN_INVALID_DECAY", raw_decay)
        unknown = set(raw_decay) - set(NEED_NAMES)
        if unknown:
            raise SurvivalError("SN_UNKNOWN_NEED", sorted(unknown, key=str))
        parsed_decay = {}
        for need in NEED_NAMES:
            rate = _number_to_fraction(
                raw_decay.get(need, DEFAULT_DECAY[need]),
                code="SN_INVALID_DECAY",
                detail=need,
            )
            if rate < 0:
                raise SurvivalError("SN_INVALID_DECAY", need)
            parsed_decay[need] = rate
        self._decay = parsed_decay

        self._registry_lock = threading.RLock()
        self._stats_lock = threading.Lock()
        self._characters: dict[object, _Character] = {}
        self._counters: dict[str, int] = {name: 0 for name in _COUNTER_NAMES}

    @property
    def cap(self) -> int:
        return self._cap

    @property
    def tick_ms(self) -> int:
        return self._tick_ms

    @property
    def decay(self) -> dict[str, object]:
        return {name: _out_number(rate) for name, rate in self._decay.items()}

    def _bump(self, counter: str, amount: int = 1) -> None:
        with self._stats_lock:
            self._counters[counter] += amount

    def _pin_character(self, character_id) -> _Character:
        with self._registry_lock:
            try:
                character = self._characters[character_id]
            except (KeyError, TypeError):
                raise SurvivalError("SN_UNKNOWN_CHARACTER", character_id) from None
            character.lock.acquire()
        return character

    @staticmethod
    def _unpin(character: _Character) -> None:
        character.lock.release()

    def _needs_view(self, character: _Character) -> dict[str, object]:
        return {
            name: _out_number(character.needs[name])
            for name in NEED_NAMES
        }

    def _normalise_initial_needs(self, needs) -> dict[str, Fraction]:
        if needs is None:
            return {name: Fraction(self._cap) for name in NEED_NAMES}
        if not isinstance(needs, Mapping):
            raise SurvivalError("SN_INVALID_NEEDS", needs)
        unknown = set(needs) - set(NEED_NAMES)
        if unknown:
            raise SurvivalError("SN_UNKNOWN_NEED", sorted(unknown, key=str))

        cap = Fraction(self._cap)
        result = {name: cap for name in NEED_NAMES}
        for name, raw_value in needs.items():
            value = _number_to_fraction(
                raw_value,
                code="SN_INVALID_NEEDS",
                detail=name,
            )
            result[name] = min(cap, max(Fraction(0), value))
        return result

    def _prune_effects(self, character: _Character, at_ms: int | None = None) -> None:
        reference_time = character.time_ms if at_ms is None else at_ms
        expired = [
            effect_id
            for effect_id, effect in character.effects.items()
            if effect.expires_at_ms <= reference_time
        ]
        for effect_id in expired:
            del character.effects[effect_id]

    def _selected_multipliers(
        self,
        character: _Character,
        at_ms: int,
    ) -> dict[str, Fraction]:
        selected = {}
        for name in NEED_NAMES:
            selected[name] = Fraction(1)

        winners = {}
        for effect in character.effects.values():
            if effect.expires_at_ms <= at_ms:
                continue
            key = (effect.multiplier, effect.priority, effect.effect_id)
            current = winners.get(effect.need)
            if current is None or key > current[0]:
                winners[effect.need] = (key, effect)
        for name, (_, effect) in winners.items():
            selected[name] = effect.multiplier
        return selected

    def _settle(self, character: _Character, at_ms: int) -> None:
        if at_ms < character.time_ms:
            raise SurvivalError(
                "SN_TIME_REWIND",
                {"from_ms": character.time_ms, "to_ms": at_ms},
            )
        if at_ms == character.time_ms:
            self._prune_effects(character)
            return

        if not character.dying:
            cursor = character.time_ms
            while cursor < at_ms:
                self._prune_effects(character, cursor)
                expiries = [
                    effect.expires_at_ms
                    for effect in character.effects.values()
                    if cursor < effect.expires_at_ms <= at_ms
                ]
                segment_end = min(expiries) if expiries else at_ms
                elapsed = Fraction(segment_end - cursor, 1000)
                multipliers = self._selected_multipliers(character, cursor)

                for name in NEED_NAMES:
                    rate = self._decay[name] * multipliers[name]
                    if rate:
                        character.needs[name] = max(
                            Fraction(0),
                            character.needs[name] - rate * elapsed,
                        )
                cursor = segment_end

            self._prune_effects(character)
            if any(character.needs[name] <= 0 for name in NEED_NAMES):
                character.dying = True
                self._bump("dying")

        character.time_ms = at_ms
        self._prune_effects(character)

    def register(self, character_id, *, needs=None, at_ms=0):
        """Create a character ledger and return its starting needs."""
        at_ms = _require_int(at_ms, code="SN_TIME_REWIND", minimum=0)
        try:
            hash(character_id)
        except TypeError:
            raise SurvivalError("SN_INVALID_CHARACTER", character_id) from None

        with self._registry_lock:
            if character_id in self._characters:
                raise SurvivalError("SN_DUPLICATE_CHARACTER", character_id)

            initial = self._normalise_initial_needs(needs)
            dying = any(value <= 0 for value in initial.values())
            character = _Character(
                time_ms=at_ms,
                needs=initial,
                dying=dying,
                effects={},
            )
            self._characters[character_id] = character
            if dying:
                self._bump("dying")
            return self._needs_view(character)

    def consume(self, character_id, need, amount):
        """Restore one need and return the value after clamping."""
        character = self._pin_character(character_id)
        try:
            if need not in NEED_NAMES:
                raise SurvivalError("SN_UNKNOWN_NEED", need)
            parsed_amount = _number_to_fraction(
                amount,
                code="SN_INVALID_AMOUNT",
                detail=amount,
            )
            if parsed_amount <= 0:
                raise SurvivalError("SN_INVALID_AMOUNT", amount)

            cap = Fraction(self._cap)
            restored = min(cap, character.needs[need] + parsed_amount)
            character.needs[need] = restored
            self._bump("consumes")
            return _out_number(restored)
        finally:
            self._unpin(character)

    def _normalise_effect(self, effect) -> Effect:
        if isinstance(effect, Effect):
            raw = {
                "effect_id": effect.effect_id,
                "need": effect.need,
                "multiplier": effect.multiplier,
                "priority": effect.priority,
                "expires_at_ms": effect.expires_at_ms,
            }
        elif isinstance(effect, Mapping):
            raw = effect
        else:
            raise SurvivalError("SN_INVALID_EFFECT", effect)

        required = (
            "effect_id",
            "need",
            "multiplier",
            "priority",
            "expires_at_ms",
        )
        if any(field not in raw for field in required):
            raise SurvivalError("SN_INVALID_EFFECT", effect)

        effect_id = raw["effect_id"]
        if not isinstance(effect_id, str) or not effect_id:
            raise SurvivalError("SN_INVALID_EFFECT", effect_id)
        need = raw["need"]
        if need not in NEED_NAMES:
            raise SurvivalError("SN_UNKNOWN_NEED", need)
        multiplier = _number_to_fraction(
            raw["multiplier"],
            code="SN_INVALID_EFFECT",
            detail="multiplier",
        )
        if multiplier < 0:
            raise SurvivalError("SN_INVALID_EFFECT", "multiplier")
        priority = _require_int(
            raw["priority"],
            code="SN_INVALID_EFFECT",
        )
        expires_at_ms = _require_int(
            raw["expires_at_ms"],
            code="SN_TIME_REWIND",
            minimum=0,
        )
        return Effect(
            effect_id=effect_id,
            need=need,
            multiplier=multiplier,
            priority=priority,
            expires_at_ms=expires_at_ms,
        )

    def apply_effect(self, character_id, effect):
        """Attach a timed modifier and return the normalised effect."""
        character = self._pin_character(character_id)
        try:
            normalised = self._normalise_effect(effect)
            self._prune_effects(character)
            existing = character.effects.get(normalised.effect_id)
            if (
                existing is None
                and normalised.expires_at_ms > character.time_ms
                and len(character.effects) >= MAX_EFFECTS_PER_CHARACTER
            ):
                raise SurvivalError(
                    "SN_EFFECT_LIMIT",
                    MAX_EFFECTS_PER_CHARACTER,
                )
            if normalised.expires_at_ms > character.time_ms:
                character.effects[normalised.effect_id] = normalised
            else:
                character.effects.pop(normalised.effect_id, None)
            return _public_effect(normalised)
        finally:
            self._unpin(character)

    def tick(self, character_id, at_ms):
        """Settle natural decay up to the given server time."""
        character = self._pin_character(character_id)
        try:
            at_ms = _require_int(at_ms, code="SN_TIME_REWIND")
            previous = character.time_ms
            if at_ms < previous:
                raise SurvivalError(
                    "SN_TIME_REWIND",
                    {"from_ms": previous, "to_ms": at_ms},
                )
            if at_ms > previous:
                self._settle(character, at_ms)
                self._bump("ticks")
            else:
                self._prune_effects(character)
            return self._needs_view(character)
        finally:
            self._unpin(character)

    def offline_catchup(self, character_id, *, from_ms, to_ms):
        """Settle a missed window that the character spent offline."""
        character = self._pin_character(character_id)
        try:
            from_ms = _require_int(from_ms, code="SN_TIME_REWIND")
            to_ms = _require_int(to_ms, code="SN_TIME_REWIND")
            if from_ms < 0 or to_ms < 0 or to_ms < from_ms:
                raise SurvivalError(
                    "SN_TIME_REWIND",
                    {"from_ms": from_ms, "to_ms": to_ms},
                )
            if from_ms < character.time_ms:
                raise SurvivalError(
                    "SN_TIME_REWIND",
                    {"from_ms": from_ms, "to_ms": character.time_ms},
                )
            if to_ms - from_ms > MAX_CATCHUP_WINDOW_MS:
                raise SurvivalError(
                    "SN_CATCHUP_TOO_LONG",
                    {
                        "window_ms": to_ms - from_ms,
                        "limit_ms": MAX_CATCHUP_WINDOW_MS,
                    },
                )

            self._settle(character, to_ms)
            self._bump("catchups")
            return self._needs_view(character)
        finally:
            self._unpin(character)

    def state_of(self, character_id):
        """Return ``normal`` or ``dying`` for one character."""
        character = self._pin_character(character_id)
        try:
            return "dying" if character.dying else "normal"
        finally:
            self._unpin(character)

    def needs_of(self, character_id):
        """Return a detached mapping of the three need values."""
        character = self._pin_character(character_id)
        try:
            return self._needs_view(character)
        finally:
            self._unpin(character)

    def effects_of(self, character_id):
        """Return the live effect stack ordered by need and effect id."""
        character = self._pin_character(character_id)
        try:
            self._prune_effects(character)
            effects = sorted(
                character.effects.values(),
                key=lambda effect: (effect.need, effect.effect_id),
            )
            return tuple(_public_effect(effect) for effect in effects)
        finally:
            self._unpin(character)

    def revive(self, character_id, *, at_ms):
        """Lift a dying character back to the revive floor."""
        character = self._pin_character(character_id)
        try:
            at_ms = _require_int(at_ms, code="SN_TIME_REWIND", minimum=0)
            if not character.dying:
                raise SurvivalError("SN_NOT_DYING", character_id)
            if at_ms < character.time_ms:
                raise SurvivalError(
                    "SN_TIME_REWIND",
                    {"from_ms": character.time_ms, "to_ms": at_ms},
                )

            character.time_ms = at_ms
            self._prune_effects(character)

            floor = Fraction(min(REVIVE_FLOOR, self._cap))
            for name in NEED_NAMES:
                character.needs[name] = max(character.needs[name], floor)

            character.effects = {
                effect_id: effect
                for effect_id, effect in character.effects.items()
                if effect.multiplier <= 1
            }
            character.dying = False
            self._bump("revivals")
            return self._needs_view(character)
        finally:
            self._unpin(character)

    def _snapshot_character(self, character: _Character) -> dict[str, object]:
        self._prune_effects(character)
        return {
            "time_ms": character.time_ms,
            "needs": {
                name: _fraction_text(character.needs[name])
                for name in NEED_NAMES
            },
            "dying": character.dying,
            "effects": [
                {
                    "effect_id": effect.effect_id,
                    "need": effect.need,
                    "multiplier": _fraction_text(effect.multiplier),
                    "priority": effect.priority,
                    "expires_at_ms": effect.expires_at_ms,
                }
                for effect in sorted(
                    character.effects.values(),
                    key=lambda effect: (effect.need, effect.effect_id),
                )
            ],
        }

    def snapshot(self):
        """Return a detached state dictionary for the whole ledger."""
        with self._registry_lock:
            characters = sorted(
                self._characters.items(),
                key=lambda item: _character_sort_key(item[0]),
            )
            locked = []
            try:
                for _, character in characters:
                    character.lock.acquire()
                    locked.append(character)
                with self._stats_lock:
                    counters = dict(self._counters)
                character_states = {
                    character_id: self._snapshot_character(character)
                    for character_id, character in characters
                }
            finally:
                for character in reversed(locked):
                    character.lock.release()

        return {
            "version": 1,
            "config": {
                "cap": self._cap,
                "tick_ms": self._tick_ms,
                "decay": {
                    name: _fraction_text(rate)
                    for name, rate in self._decay.items()
                },
            },
            "characters": character_states,
            "counters": counters,
            "stats": {
                "characters": len(character_states),
                **counters,
            },
        }

    @staticmethod
    def _snapshot_invalid(detail: object = None):
        raise SurvivalError("SN_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(self, state):
        if not isinstance(state, Mapping):
            self._snapshot_invalid("state")
        version = state.get("version")
        if isinstance(version, bool) or version != 1:
            self._snapshot_invalid("version")

        config = state.get("config")
        if not isinstance(config, Mapping):
            self._snapshot_invalid("config")
        snapshot_cap = config.get("cap")
        snapshot_tick_ms = config.get("tick_ms")
        if (
            isinstance(snapshot_cap, bool)
            or not isinstance(snapshot_cap, int)
            or snapshot_cap != self._cap
            or isinstance(snapshot_tick_ms, bool)
            or not isinstance(snapshot_tick_ms, int)
            or snapshot_tick_ms != self._tick_ms
        ):
            self._snapshot_invalid("config")
        raw_decay = config.get("decay")
        if not isinstance(raw_decay, Mapping):
            self._snapshot_invalid("config.decay")
        if set(raw_decay) != set(NEED_NAMES):
            self._snapshot_invalid("config.decay")
        parsed_decay = {}
        for name in NEED_NAMES:
            try:
                value = _number_to_fraction(
                    raw_decay[name],
                    code="SN_SNAPSHOT_INVALID",
                    detail=f"config.decay.{name}",
                )
            except SurvivalError:
                self._snapshot_invalid(f"config.decay.{name}")
            if value < 0:
                self._snapshot_invalid(f"config.decay.{name}")
            parsed_decay[name] = value
        if parsed_decay != self._decay:
            self._snapshot_invalid("config.decay")

        raw_counters = state.get("counters")
        if not isinstance(raw_counters, Mapping):
            self._snapshot_invalid("counters")
        counters = {}
        for name in _COUNTER_NAMES:
            value = raw_counters.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                self._snapshot_invalid(f"counters.{name}")
            counters[name] = value

        raw_stats = state.get("stats")
        if not isinstance(raw_stats, Mapping):
            self._snapshot_invalid("stats")
        for name in ("characters", *_COUNTER_NAMES):
            value = raw_stats.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                self._snapshot_invalid(f"stats.{name}")
        if raw_stats.get("characters") != len(state.get("characters", {})):
            self._snapshot_invalid("stats.characters")
        for name in _COUNTER_NAMES:
            if raw_stats.get(name) != counters[name]:
                self._snapshot_invalid(f"stats.{name}")

        raw_characters = state.get("characters")
        if not isinstance(raw_characters, Mapping):
            self._snapshot_invalid("characters")

        cap = Fraction(self._cap)
        characters = {}
        for character_id, raw_character in raw_characters.items():
            if not isinstance(raw_character, Mapping):
                self._snapshot_invalid(character_id)
            raw_time = raw_character.get("time_ms")
            if isinstance(raw_time, bool) or not isinstance(raw_time, int) or raw_time < 0:
                self._snapshot_invalid(f"{character_id}.time_ms")

            raw_needs = raw_character.get("needs")
            if not isinstance(raw_needs, Mapping) or set(raw_needs) != set(NEED_NAMES):
                self._snapshot_invalid(f"{character_id}.needs")
            needs = {}
            for name in NEED_NAMES:
                try:
                    value = _number_to_fraction(
                        raw_needs[name],
                        code="SN_SNAPSHOT_INVALID",
                        detail=f"{character_id}.needs.{name}",
                    )
                except SurvivalError:
                    self._snapshot_invalid(f"{character_id}.needs.{name}")
                if value < 0 or value > cap:
                    self._snapshot_invalid(f"{character_id}.needs.{name}")
                needs[name] = value

            dying = raw_character.get("dying")
            if not isinstance(dying, bool):
                self._snapshot_invalid(f"{character_id}.dying")
            if not dying and any(value <= 0 for value in needs.values()):
                self._snapshot_invalid(f"{character_id}.dying")

            raw_effects = raw_character.get("effects")
            if not isinstance(raw_effects, list):
                self._snapshot_invalid(f"{character_id}.effects")
            if len(raw_effects) > MAX_EFFECTS_PER_CHARACTER:
                self._snapshot_invalid(f"{character_id}.effects")
            effects = {}
            for raw_effect in raw_effects:
                try:
                    effect = self._normalise_effect(raw_effect)
                except SurvivalError:
                    self._snapshot_invalid(f"{character_id}.effects")
                if effect.expires_at_ms <= raw_time:
                    self._snapshot_invalid(f"{character_id}.effects")
                if effect.effect_id in effects:
                    self._snapshot_invalid(f"{character_id}.effects")
                effects[effect.effect_id] = effect

            try:
                hash(character_id)
            except TypeError:
                self._snapshot_invalid(character_id)
            characters[character_id] = _Character(
                time_ms=raw_time,
                needs=needs,
                dying=dying,
                effects=effects,
            )

        return characters, counters

    def restore(self, state):
        """Replace the ledger with a previously taken snapshot."""
        try:
            characters, counters = self._parse_snapshot(state)
        except SurvivalError:
            raise
        except Exception:
            raise SurvivalError("SN_SNAPSHOT_INVALID", state) from None

        with self._registry_lock:
            old_characters = sorted(
                self._characters.values(),
                key=id,
            )
            locked = []
            try:
                for character in old_characters:
                    character.lock.acquire()
                    locked.append(character)
                self._characters = characters
                with self._stats_lock:
                    self._counters = counters
            finally:
                for character in reversed(locked):
                    character.lock.release()

    def stats(self):
        """Return settlement counters for the ledger."""
        with self._registry_lock:
            character_count = len(self._characters)
            with self._stats_lock:
                counters = dict(self._counters)
        return {
            "characters": character_count,
            **counters,
        }
