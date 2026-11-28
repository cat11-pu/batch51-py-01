"""Battle royale safe-zone shrinker: phase timeline, circle interpolation, damage settlement."""

from __future__ import annotations

import bisect
import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Real

DEFAULT_TICK_MS = 1000
DEFAULT_DAMAGE_PER_TICK = 1
DEFAULT_RESPAWN_PROTECT_MS = 5000
MAX_PHASES = 8
FULL_HEALTH = 100

_PHASE_LIMIT = 8
_EPSILON = 1e-9
_MISSING = object()


class ZoneError(ValueError):
    """Raised when a zone timeline or a settlement request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Zone:
    """One circular safe zone at a point in the match timeline."""

    phase: int
    center_x: float
    center_y: float
    radius: float


@dataclass(frozen=True)
class ZonePhase:
    """One configured phase: a hold window followed by a shrink into this circle."""

    phase: int
    hold_ms: int
    shrink_ms: int
    center_x: float
    center_y: float
    radius: float


@dataclass
class _PlayerState:
    x: float
    y: float
    health: int
    entered_at_ms: int
    protect_until_ms: int


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("not an integer")
    number = int(value)
    if number != value:
        raise ValueError("not an integer")
    return number


def _as_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError("not a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("not finite")
    return number


def _sort_ids(player_ids):
    try:
        return sorted(player_ids)
    except TypeError:
        return sorted(player_ids, key=lambda item: (type(item).__name__, repr(item)))


class BrZoneShrinker:
    """Advance the safe zone by match clock and settle out-of-zone damage."""

    def __init__(self, *, tick_ms: int = DEFAULT_TICK_MS,
                 damage_per_tick: int = DEFAULT_DAMAGE_PER_TICK,
                 respawn_protect_ms: int = DEFAULT_RESPAWN_PROTECT_MS) -> None:
        try:
            parsed_tick_ms = _as_int(tick_ms)
            parsed_damage = _as_int(damage_per_tick)
            parsed_protect = _as_int(respawn_protect_ms)
        except ValueError as exc:
            raise ZoneError("ZS_INVALID_CONFIG", str(exc)) from None
        if parsed_tick_ms <= 0 or parsed_damage < 0 or parsed_protect < 0:
            raise ZoneError("ZS_INVALID_CONFIG", "invalid match configuration")

        self._tick_ms = parsed_tick_ms
        self._damage_per_tick = parsed_damage
        self._respawn_protect_ms = parsed_protect
        self._phases: tuple[ZonePhase, ...] | None = None
        self._phase_starts: tuple[int, ...] = ()
        self._clock_ms = 0
        self._last_settled_tick = 0
        self._players: dict[object, _PlayerState] = {}
        self._lock = threading.RLock()

    @property
    def tick_ms(self) -> int:
        return self._tick_ms

    @property
    def damage_per_tick(self) -> int:
        return self._damage_per_tick

    @property
    def respawn_protect_ms(self) -> int:
        return self._respawn_protect_ms

    @staticmethod
    def _phase_values(raw_phase, index: int):
        if isinstance(raw_phase, ZonePhase):
            phase = raw_phase.phase
            hold_ms = raw_phase.hold_ms
            shrink_ms = raw_phase.shrink_ms
            center_x = raw_phase.center_x
            center_y = raw_phase.center_y
            radius = raw_phase.radius
        elif isinstance(raw_phase, Mapping):
            phase = raw_phase.get("phase", _MISSING)
            hold_ms = raw_phase.get("hold_ms", _MISSING)
            shrink_ms = raw_phase.get("shrink_ms", _MISSING)
            radius = raw_phase.get("radius", _MISSING)
            center = raw_phase.get("center", _MISSING)
            if center is not _MISSING:
                try:
                    center_x, center_y = center
                except (TypeError, ValueError):
                    raise ZoneError("ZS_INVALID_PHASE", index) from None
            else:
                center_x = raw_phase.get("center_x", _MISSING)
                center_y = raw_phase.get("center_y", _MISSING)
        else:
            phase = getattr(raw_phase, "phase", _MISSING)
            hold_ms = getattr(raw_phase, "hold_ms", _MISSING)
            shrink_ms = getattr(raw_phase, "shrink_ms", _MISSING)
            radius = getattr(raw_phase, "radius", _MISSING)
            center_x = getattr(raw_phase, "center_x", _MISSING)
            center_y = getattr(raw_phase, "center_y", _MISSING)
            if center_x is _MISSING or center_y is _MISSING:
                center = getattr(raw_phase, "center", _MISSING)
                if center is not _MISSING:
                    try:
                        center_x, center_y = center
                    except (TypeError, ValueError):
                        raise ZoneError("ZS_INVALID_PHASE", index) from None

        if any(value is _MISSING for value in
               (phase, hold_ms, shrink_ms, center_x, center_y, radius)):
            raise ZoneError("ZS_INVALID_PHASE", index)

        try:
            parsed_phase = _as_int(phase)
            parsed_hold = _as_int(hold_ms)
            parsed_shrink = _as_int(shrink_ms)
            parsed_x = _as_float(center_x)
            parsed_y = _as_float(center_y)
            parsed_radius = _as_float(radius)
        except ValueError:
            raise ZoneError("ZS_INVALID_PHASE", index) from None

        if parsed_phase != index:
            raise ZoneError("ZS_INVALID_PHASE", index)
        if parsed_hold < 0 or parsed_shrink < 0 or parsed_radius < 0:
            raise ZoneError("ZS_INVALID_PHASE", index)
        if index == 0 and parsed_shrink != 0:
            raise ZoneError("ZS_INVALID_PHASE", index)

        return ZonePhase(
            phase=parsed_phase,
            hold_ms=parsed_hold,
            shrink_ms=parsed_shrink,
            center_x=parsed_x,
            center_y=parsed_y,
            radius=parsed_radius,
        )

    @classmethod
    def _normalise_phases(cls, phases) -> tuple[ZonePhase, ...]:
        try:
            raw_phases = list(phases)
        except TypeError:
            raise ZoneError("ZS_INVALID_PHASE", "phases") from None

        if len(raw_phases) > _PHASE_LIMIT:
            raise ZoneError("ZS_TOO_MANY_PHASES", len(raw_phases))
        if not raw_phases:
            raise ZoneError("ZS_INVALID_PHASE", "empty phase table")

        parsed = [cls._phase_values(raw, index)
                  for index, raw in enumerate(raw_phases)]

        last_index = len(parsed) - 1
        for index, phase in enumerate(parsed):
            if index == 0:
                if phase.radius == 0 and last_index != 0:
                    raise ZoneError("ZS_INVALID_PHASE", index)
                continue

            previous = parsed[index - 1]
            if phase.radius >= previous.radius:
                raise ZoneError("ZS_INVALID_PHASE", index)
            if phase.radius == 0 and index != last_index:
                raise ZoneError("ZS_INVALID_PHASE", index)

            distance = math.hypot(
                phase.center_x - previous.center_x,
                phase.center_y - previous.center_y,
            )
            if distance > previous.radius + _EPSILON:
                raise ZoneError("ZS_CENTER_OUTSIDE", index)

        return tuple(parsed)

    @staticmethod
    def _build_phase_starts(phases: tuple[ZonePhase, ...]) -> tuple[int, ...]:
        if not phases:
            return ()
        starts = [0]
        for phase in phases[:-1]:
            starts.append(starts[-1] + phase.hold_ms + phase.shrink_ms)
        return tuple(starts)

    def _require_phases(self) -> tuple[ZonePhase, ...]:
        if self._phases is None:
            raise ZoneError("ZS_PHASES_NOT_CONFIGURED")
        return self._phases

    def _phase_index_at(self, clock_ms: int) -> int:
        return bisect.bisect_right(self._phase_starts, clock_ms) - 1

    def _zone_at(self, clock_ms: int) -> Zone:
        phases = self._require_phases()
        index = self._phase_index_at(clock_ms)
        if index < 0:
            index = 0

        phase = phases[index]
        if index == 0 or phase.shrink_ms == 0:
            return Zone(phase.phase, phase.center_x, phase.center_y, phase.radius)

        progress = (clock_ms - self._phase_starts[index]) / phase.shrink_ms
        if progress <= 0:
            previous = phases[index - 1]
            return Zone(
                phase.phase,
                previous.center_x,
                previous.center_y,
                previous.radius,
            )
        if progress >= 1:
            return Zone(phase.phase, phase.center_x, phase.center_y, phase.radius)

        previous = phases[index - 1]
        return Zone(
            phase.phase,
            previous.center_x + (phase.center_x - previous.center_x) * progress,
            previous.center_y + (phase.center_y - previous.center_y) * progress,
            previous.radius + (phase.radius - previous.radius) * progress,
        )

    @staticmethod
    def _is_outside(player: _PlayerState, zone: Zone) -> bool:
        distance = math.hypot(player.x - zone.center_x, player.y - zone.center_y)
        return distance > zone.radius + _EPSILON

    def configure_phases(self, phases):
        """Install the phase table once and return the normalised phases."""
        with self._lock:
            if self._phases is not None:
                raise ZoneError("ZS_PHASES_LOCKED")
            parsed = self._normalise_phases(phases)
            self._phase_starts = self._build_phase_starts(parsed)
            self._phases = parsed
            return self._phases

    def advance(self, elapsed_ms):
        """Move the match clock forward and return the phase numbers crossed."""
        with self._lock:
            try:
                elapsed = _as_int(elapsed_ms)
            except ValueError:
                raise ZoneError("ZS_CLOCK_REWIND", elapsed_ms) from None
            if elapsed < 0:
                raise ZoneError("ZS_CLOCK_REWIND", elapsed_ms)

            phases = self._require_phases()
            previous_clock = self._clock_ms
            new_clock = previous_clock + elapsed
            crossed = tuple(
                phase.phase
                for phase in phases[1:]
                if previous_clock < self._phase_starts[phase.phase] <= new_clock
            )
            self._clock_ms = new_clock
            return crossed

    def current_zone(self):
        """Return the circle that is in force for the current match clock."""
        with self._lock:
            return self._zone_at(self._clock_ms)

    def next_zone(self):
        """Return the next configured circle, or None once the last shrink runs."""
        with self._lock:
            phases = self._require_phases()
            current = self._zone_at(self._clock_ms)
            if current.phase >= len(phases) - 1:
                return None
            target = phases[current.phase + 1]
            return Zone(
                target.phase,
                target.center_x,
                target.center_y,
                target.radius,
            )

    def player_entered(self, player_id, *, x, y, at_ms=0):
        """Register a player on the battlefield at the given position."""
        with self._lock:
            try:
                parsed_x = _as_float(x)
                parsed_y = _as_float(y)
                entered_at = _as_int(at_ms)
                hash(player_id)
            except (TypeError, ValueError):
                raise ZoneError("ZS_INVALID_PLAYER", player_id) from None
            if entered_at < 0:
                raise ZoneError("ZS_INVALID_PLAYER", player_id)

            protect_until = entered_at
            if entered_at > 0:
                protect_until += self._respawn_protect_ms
            self._players[player_id] = _PlayerState(
                x=parsed_x,
                y=parsed_y,
                health=FULL_HEALTH,
                entered_at_ms=entered_at,
                protect_until_ms=protect_until,
            )

    def player_respawn(self, player_id, *, x, y, at_ms):
        """Bring a player back after a revive or a late drop."""
        with self._lock:
            try:
                parsed_x = _as_float(x)
                parsed_y = _as_float(y)
                entered_at = _as_int(at_ms)
                hash(player_id)
            except (TypeError, ValueError):
                raise ZoneError("ZS_INVALID_PLAYER", player_id) from None
            if entered_at < 0:
                raise ZoneError("ZS_INVALID_PLAYER", player_id)

            self._players[player_id] = _PlayerState(
                x=parsed_x,
                y=parsed_y,
                health=FULL_HEALTH,
                entered_at_ms=entered_at,
                protect_until_ms=entered_at + self._respawn_protect_ms,
            )

    def move_player(self, player_id, *, x, y):
        """Update a player position without touching health or timers."""
        with self._lock:
            player = self._players.get(player_id)
            if player is None:
                raise ZoneError("ZS_UNKNOWN_PLAYER", player_id)
            try:
                player.x = _as_float(x)
                player.y = _as_float(y)
            except ValueError:
                raise ZoneError("ZS_INVALID_PLAYER", player_id) from None

    def _players_outside_locked(self) -> tuple[object, ...]:
        if self._phases is None:
            return ()
        zone = self._zone_at(self._clock_ms)
        outside = [
            player_id
            for player_id, player in self._players.items()
            if player.health > 0
            and self._clock_ms >= player.entered_at_ms
            and self._is_outside(player, zone)
        ]
        return tuple(_sort_ids(outside))

    def damage_tick(self):
        """Settle every whole tick that elapsed since the previous settlement."""
        with self._lock:
            self._require_phases()
            target_tick = self._clock_ms // self._tick_ms
            if target_tick <= self._last_settled_tick:
                return {}

            damage: dict[object, int] = {}
            ordered_ids = _sort_ids(self._players)

            for tick_index in range(self._last_settled_tick + 1, target_tick + 1):
                tick_time = tick_index * self._tick_ms
                zone = self._zone_at(tick_time)

                if zone.radius <= _EPSILON and self._winner_at(zone, tick_time):
                    break

                for player_id in ordered_ids:
                    player = self._players[player_id]
                    if player.health <= 0:
                        continue
                    if tick_time < player.entered_at_ms:
                        continue
                    if tick_time < player.protect_until_ms:
                        continue
                    if not self._is_outside(player, zone):
                        continue

                    loss = min(self._damage_per_tick, player.health)
                    if loss <= 0:
                        continue
                    player.health -= loss
                    damage[player_id] = damage.get(player_id, 0) + loss

            self._last_settled_tick = target_tick
            return {
                player_id: damage[player_id]
                for player_id in _sort_ids(damage)
            }

    def _winner_at(self, zone: Zone, tick_time: int) -> bool:
        if zone.radius > _EPSILON:
            return False
        for player in self._players.values():
            if player.health <= 0 or tick_time < player.entered_at_ms:
                continue
            if math.hypot(
                player.x - zone.center_x,
                player.y - zone.center_y,
            ) <= _EPSILON:
                return True
        return False

    def players_outside(self):
        """Return the living players currently outside the interpolated circle."""
        with self._lock:
            return self._players_outside_locked()

    def health_of(self, player_id):
        """Return the remaining health of one player."""
        with self._lock:
            player = self._players.get(player_id)
            if player is None:
                raise ZoneError("ZS_UNKNOWN_PLAYER", player_id)
            return player.health

    def snapshot(self):
        """Return a detached state dictionary for the running match."""
        with self._lock:
            if self._phases is None:
                phases = None
            else:
                phases = [
                    {
                        "phase": phase.phase,
                        "hold_ms": phase.hold_ms,
                        "shrink_ms": phase.shrink_ms,
                        "center": [phase.center_x, phase.center_y],
                        "radius": phase.radius,
                    }
                    for phase in self._phases
                ]

            players = {}
            for player_id in _sort_ids(self._players):
                player = self._players[player_id]
                players[player_id] = {
                    "x": player.x,
                    "y": player.y,
                    "health": player.health,
                    "entered_at_ms": player.entered_at_ms,
                    "protect_until_ms": player.protect_until_ms,
                }

            return {
                "version": 1,
                "clock_ms": self._clock_ms,
                "settled_ticks": self._last_settled_tick,
                "ticks": self._last_settled_tick,
                "phases": phases,
                "players": players,
                "tick_ms": self._tick_ms,
                "damage_per_tick": self._damage_per_tick,
                "respawn_protect_ms": self._respawn_protect_ms,
            }

    def restore(self, state):
        """Replace the running match with a previously taken snapshot."""
        with self._lock:
            try:
                if not isinstance(state, Mapping):
                    raise ValueError("snapshot must be a mapping")
                if "clock_ms" not in state or "phases" not in state:
                    raise ValueError("snapshot is incomplete")
                if "players" not in state:
                    raise ValueError("snapshot is incomplete")

                clock_ms = _as_int(state["clock_ms"])
                if clock_ms < 0:
                    raise ValueError("negative clock")

                for key, configured in (
                    ("tick_ms", self._tick_ms),
                    ("damage_per_tick", self._damage_per_tick),
                    ("respawn_protect_ms", self._respawn_protect_ms),
                ):
                    if key in state and _as_int(state[key]) != configured:
                        raise ValueError("configuration mismatch")

                raw_phases = state["phases"]
                if raw_phases is None:
                    phases = None
                    phase_starts = ()
                else:
                    phases = self._normalise_phases(raw_phases)
                    phase_starts = self._build_phase_starts(phases)

                if "settled_ticks" in state:
                    settled = _as_int(state["settled_ticks"])
                    if "ticks" in state and _as_int(state["ticks"]) != settled:
                        raise ValueError("inconsistent tick counters")
                elif "ticks" in state:
                    settled = _as_int(state["ticks"])
                else:
                    raise ValueError("missing settled tick counter")
                if settled < 0 or settled > clock_ms // self._tick_ms:
                    raise ValueError("invalid settled tick counter")

                raw_players = state["players"]
                if not isinstance(raw_players, Mapping):
                    raise ValueError("players must be a mapping")

                players = {}
                for player_id, raw_player in raw_players.items():
                    if not isinstance(raw_player, Mapping):
                        raise ValueError("invalid player state")
                    if "x" not in raw_player or "y" not in raw_player:
                        raise ValueError("missing player position")
                    if "health" not in raw_player:
                        raise ValueError("missing player health")

                    x = _as_float(raw_player["x"])
                    y = _as_float(raw_player["y"])
                    health = _as_int(raw_player["health"])
                    entered_at = _as_int(raw_player.get("entered_at_ms", 0))
                    protect_until = _as_int(
                        raw_player.get("protect_until_ms", entered_at)
                    )
                    if health < 0 or health > FULL_HEALTH:
                        raise ValueError("invalid health")
                    if entered_at < 0 or protect_until < entered_at:
                        raise ValueError("invalid player timer")

                    players[player_id] = _PlayerState(
                        x=x,
                        y=y,
                        health=health,
                        entered_at_ms=entered_at,
                        protect_until_ms=protect_until,
                    )
            except (KeyError, TypeError, ValueError, OverflowError, ZoneError):
                raise ZoneError("ZS_SNAPSHOT_INVALID", state) from None

            self._clock_ms = clock_ms
            self._last_settled_tick = settled
            self._phases = phases
            self._phase_starts = phase_starts
            self._players = players

    def stats(self):
        """Return clock, phase and settlement counters."""
        with self._lock:
            if self._phases is None:
                phase_number = -1
                phase_count = 0
                outside = 0
            else:
                phase_number = self._phase_index_at(self._clock_ms)
                phase_count = len(self._phases)
                outside = len(self._players_outside_locked())

            return {
                "clock_ms": self._clock_ms,
                "phase": phase_number,
                "phases": phase_count,
                "players": len(self._players),
                "outside": outside,
                "ticks": self._last_settled_tick,
            }
