"""Season soft reset: rating compression toward baseline, placement matches, idempotent batches."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass


class LadderError(ValueError):
    """Raised when a ladder reset or placement operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PlayerState:
    player: str
    season: str
    prev_rating: int
    rating: int
    uncertainty: int
    provisional: bool
    played: int
    needed: int
    matches_last_season: int


class SoftResetPlanner:
    """Plan and apply a season soft reset, then track placement progress."""

    _SNAPSHOT_VERSION = 1
    _PLAYER_FIELDS = (
        "player",
        "season",
        "prev_rating",
        "rating",
        "uncertainty",
        "provisional",
        "played",
        "needed",
        "matches_last_season",
    )
    _STATS_FIELDS = ("batches", "players", "applied", "placements")
    _COUNTER_FIELDS = (
        "batch_seq",
        "batches",
        "players",
        "applied",
        "placements",
    )

    def __init__(self, *, baseline: int = 1500, keep_bps: int = 5000,
                 placement_matches: int = 10, rating_floor: int = 800,
                 rating_ceiling: int = 2000, placement_delta: int = 25,
                 uncertainty_start: int = 100, uncertainty_step: int = 100,
                 uncertainty_cap: int = 300, uncertainty_decay: int = 40,
                 uncertainty_floor: int = 0) -> None:
        self.baseline = baseline
        self.keep_bps = keep_bps
        self.placement_matches = placement_matches
        self.rating_floor = rating_floor
        self.rating_ceiling = rating_ceiling
        self.placement_delta = placement_delta
        self.uncertainty_start = uncertainty_start
        self.uncertainty_step = uncertainty_step
        self.uncertainty_cap = uncertainty_cap
        self.uncertainty_decay = uncertainty_decay
        self.uncertainty_floor = uncertainty_floor
        self._lock = threading.RLock()
        self._season: str | None = None
        self._batches: dict[str, dict] = {}
        self._players: dict[str, PlayerState] = {}
        self._batch_seq = 0
        self._placements = 0

    def register_player(self, player: str, rating: int, *,
                        matches_last_season: int = 0) -> PlayerState:
        """Register a player with a rating inside the configured bounds."""
        if not self._valid_player_id(player):
            raise LadderError("LADDER_INVALID_PLAYER", player)

        with self._lock:
            if player in self._players:
                raise LadderError("LADDER_PLAYER_EXISTS", player)
            if not self._is_int(rating):
                raise LadderError("LADDER_RATING_OUT_OF_RANGE", rating)
            if rating < self.rating_floor or rating > self.rating_ceiling:
                raise LadderError("LADDER_RATING_OUT_OF_RANGE", rating)
            if not self._is_int(matches_last_season) or matches_last_season < 0:
                raise LadderError("LADDER_INVALID_PLAYER", player)
            state = PlayerState(
                player=player,
                season=self._season or "",
                prev_rating=rating,
                rating=rating,
                uncertainty=self.uncertainty_start,
                provisional=False,
                played=0,
                needed=self.placement_matches,
                matches_last_season=matches_last_season,
            )
            self._players[player] = state
            return state

    def plan_batch(self, season: str, players=None) -> str:
        """Build a reset batch for a new season and return its identifier."""
        if not isinstance(season, str) or not season.strip():
            raise LadderError("LADDER_INVALID_SEASON", season)

        with self._lock:
            recipients = self._prepare_recipients(
                list(self._players) if players is None else players
            )
            for player in recipients:
                if player not in self._players:
                    raise LadderError("LADDER_UNKNOWN_PLAYER", player)

            if self._season is not None:
                if season != self._season:
                    if self._season_key(season) <= self._season_key(self._season):
                        raise LadderError("LADDER_SEASON_ORDER", season)
                else:
                    batch_id = self._active_batch_id()
                    if batch_id is not None:
                        return batch_id

            self._batch_seq += 1
            batch_id = f"{season}#{self._batch_seq}"
            for existing in self._batches.values():
                existing["active"] = False
            self._batches[batch_id] = {
                "id": batch_id,
                "season": season,
                "players": list(recipients),
                "applied": [],
                "active": True,
            }
            self._season = season
            return batch_id

    def apply(self, batch_id: str, *, players=None) -> dict:
        """Apply the compression of one batch and report how many players moved."""
        with self._lock:
            if not isinstance(batch_id, str) or not batch_id.strip():
                raise LadderError("LADDER_UNKNOWN_BATCH", batch_id)
            batch = self._batches.get(batch_id)
            if batch is None or not batch["active"]:
                raise LadderError("LADDER_UNKNOWN_BATCH", batch_id)

            selected = self._prepare_recipients(
                list(batch["players"]) if players is None else players
            )
            for player in selected:
                if player not in self._players or player not in batch["players"]:
                    raise LadderError("LADDER_UNKNOWN_PLAYER", player)

            applied_players = set(batch["applied"])
            applied = 0
            skipped = 0
            for player in selected:
                if player in applied_players:
                    skipped += 1
                    continue

                state = self._players[player]
                previous_rating = state.rating
                if state.matches_last_season > 0:
                    rating = self.baseline + (
                        (previous_rating - self.baseline) * self.keep_bps
                    ) // 10000
                    rating = max(self.rating_floor, min(self.rating_ceiling, rating))
                else:
                    rating = previous_rating

                uncertainty = min(
                    self.uncertainty_cap,
                    state.uncertainty + self.uncertainty_step,
                )
                self._players[player] = PlayerState(
                    player=player,
                    season=batch["season"],
                    prev_rating=previous_rating,
                    rating=rating,
                    uncertainty=uncertainty,
                    provisional=True,
                    played=0,
                    needed=self.placement_matches,
                    matches_last_season=state.matches_last_season,
                )
                batch["applied"].append(player)
                applied_players.add(player)
                applied += 1

            return {"batch": batch_id, "applied": applied, "skipped": skipped}

    def record_placement(self, player: str, *, won: bool,
                         completed: bool = True, now: str | None = None) -> int:
        """Record one placement match result and return the resulting rating."""
        del now
        if not self._valid_player_id(player):
            raise LadderError("LADDER_INVALID_PLAYER", player)

        with self._lock:
            state = self._players.get(player)
            if state is None:
                raise LadderError("LADDER_UNKNOWN_PLAYER", player)
            if not state.provisional:
                raise LadderError("LADDER_NOT_PROVISIONAL", player)

            rating = state.rating
            uncertainty = state.uncertainty
            if completed:
                rating += self.placement_delta if won else -self.placement_delta
                uncertainty = max(self.uncertainty_floor,
                                  uncertainty - self.uncertainty_decay)

            played = state.played + 1
            self._players[player] = PlayerState(
                player=state.player,
                season=state.season,
                prev_rating=state.prev_rating,
                rating=rating,
                uncertainty=uncertainty,
                provisional=played < state.needed,
                played=played,
                needed=state.needed,
                matches_last_season=state.matches_last_season,
            )
            self._placements += 1
            return rating

    def rating_of(self, player: str) -> int:
        """Current rating of one player."""
        return self._state_for(player).rating

    def uncertainty_of(self, player: str) -> int:
        """Current rating uncertainty of one player."""
        return self._state_for(player).uncertainty

    def provisional_of(self, player: str) -> bool:
        """Whether the player is still in placement."""
        return self._state_for(player).provisional

    def progress(self, player: str) -> dict:
        """Return played, needed and remaining placement matches."""
        state = self._state_for(player)
        return {
            "played": state.played,
            "needed": state.needed,
            "remaining": max(0, state.needed - state.played),
        }

    def state_of(self, player: str) -> PlayerState:
        """Full ladder state of one player."""
        return self._state_for(player)

    def snapshot(self) -> dict:
        """Deep copy of season, batches, player states and counters."""
        with self._lock:
            stats = self.stats()
            counters = {
                "batch_seq": self._batch_seq,
                **stats,
            }
            return copy.deepcopy({
                "version": self._SNAPSHOT_VERSION,
                "season": self._season,
                "batches": self._batches,
                "players": {
                    player: {
                        field: getattr(state, field)
                        for field in self._PLAYER_FIELDS
                    }
                    for player, state in self._players.items()
                },
                "counters": counters,
                "stats": stats,
            })

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        try:
            candidate = self._parse_snapshot(copy.deepcopy(state))
        except LadderError:
            raise
        except Exception as exc:
            raise LadderError("LADDER_SNAPSHOT_INVALID", repr(exc)) from None

        with self._lock:
            season, batches, players, batch_seq, placements = candidate
            self._season = season
            self._batches = batches
            self._players = players
            self._batch_seq = batch_seq
            self._placements = placements

    def stats(self) -> dict:
        """Return the counters exposed to the season dashboard."""
        with self._lock:
            return {
                "batches": len(self._batches),
                "players": len(self._players),
                "applied": sum(
                    len(batch["applied"]) for batch in self._batches.values()
                ),
                "placements": self._placements,
            }

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _valid_player_id(player: object) -> bool:
        return isinstance(player, str) and bool(player.strip())

    @staticmethod
    def _season_key(season: str) -> tuple:
        return tuple(
            (0, int(part)) if part.isdigit() else (1, part.casefold())
            for part in re.split(r"(\d+)", season)
        )

    def _prepare_recipients(self, players) -> list[str]:
        if isinstance(players, (str, bytes)):
            raise LadderError("LADDER_INVALID_PLAYER", players)
        try:
            recipients = list(players)
        except TypeError:
            raise LadderError("LADDER_INVALID_PLAYER", players) from None
        if not recipients:
            raise LadderError("LADDER_INVALID_PLAYER", players)

        seen: set[str] = set()
        for player in recipients:
            if not self._valid_player_id(player):
                raise LadderError("LADDER_INVALID_PLAYER", player)
            if player in seen:
                raise LadderError("LADDER_INVALID_PLAYER", player)
            seen.add(player)
        return recipients

    def _active_batch_id(self) -> str | None:
        for batch_id, batch in self._batches.items():
            if batch["active"]:
                return batch_id
        return None

    def _state_for(self, player: str) -> PlayerState:
        if not self._valid_player_id(player):
            raise LadderError("LADDER_INVALID_PLAYER", player)
        with self._lock:
            state = self._players.get(player)
            if state is None:
                raise LadderError("LADDER_UNKNOWN_PLAYER", player)
            return state

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> LadderError:
        return LadderError("LADDER_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(self, state):
        if not isinstance(state, dict):
            raise self._snapshot_invalid("snapshot must be a mapping")
        required = {"version", "season", "batches", "players",
                    "counters", "stats"}
        if not required.issubset(state):
            raise self._snapshot_invalid("missing snapshot keys")
        if state["version"] != self._SNAPSHOT_VERSION:
            raise self._snapshot_invalid("unsupported snapshot version")

        season = state["season"]
        if season is not None and (
                not isinstance(season, str) or not season.strip()):
            raise self._snapshot_invalid("invalid season")
        raw_batches = state["batches"]
        raw_players = state["players"]
        raw_counters = state["counters"]
        raw_stats = state["stats"]
        if not all(isinstance(value, dict) for value in (
                raw_batches, raw_players, raw_counters, raw_stats)):
            raise self._snapshot_invalid("snapshot sections must be mappings")

        players: dict[str, PlayerState] = {}
        for player, raw in raw_players.items():
            if not self._valid_player_id(player) or not isinstance(raw, dict):
                raise self._snapshot_invalid("invalid player entry")
            if not set(self._PLAYER_FIELDS).issubset(raw):
                raise self._snapshot_invalid("incomplete player entry")
            if raw["player"] != player:
                raise self._snapshot_invalid("player key does not match entry")
            if not isinstance(raw["season"], str):
                raise self._snapshot_invalid("invalid player season")
            for field in ("prev_rating", "rating", "uncertainty", "played",
                          "needed", "matches_last_season"):
                if (not self._is_int(raw[field])
                        or (raw[field] < 0 and field != "rating")):
                    raise self._snapshot_invalid(f"invalid player {field}")
            if not isinstance(raw["provisional"], bool):
                raise self._snapshot_invalid("invalid player provisional flag")
            players[player] = PlayerState(
                player=player,
                season=raw["season"],
                prev_rating=raw["prev_rating"],
                rating=raw["rating"],
                uncertainty=raw["uncertainty"],
                provisional=raw["provisional"],
                played=raw["played"],
                needed=raw["needed"],
                matches_last_season=raw["matches_last_season"],
            )

        batches: dict[str, dict] = {}
        active_batches: list[str] = []
        for batch_id, raw in raw_batches.items():
            if not isinstance(batch_id, str) or not batch_id.strip():
                raise self._snapshot_invalid("invalid batch id")
            if not isinstance(raw, dict):
                raise self._snapshot_invalid("invalid batch entry")
            if not {"id", "season", "players", "applied",
                    "active"}.issubset(raw):
                raise self._snapshot_invalid("incomplete batch entry")
            if raw["id"] != batch_id:
                raise self._snapshot_invalid("batch key does not match entry")
            if not isinstance(raw["season"], str) or not raw["season"].strip():
                raise self._snapshot_invalid("invalid batch season")
            if not isinstance(raw["active"], bool):
                raise self._snapshot_invalid("invalid batch active flag")
            recipients = raw["players"]
            applied = raw["applied"]
            if not isinstance(recipients, list) or not recipients:
                raise self._snapshot_invalid("invalid batch recipients")
            if not isinstance(applied, list):
                raise self._snapshot_invalid("invalid batch applied list")
            if len(set(recipients)) != len(recipients):
                raise self._snapshot_invalid("duplicate batch recipients")
            if len(set(applied)) != len(applied):
                raise self._snapshot_invalid("duplicate applied players")
            if any(not self._valid_player_id(player) for player in recipients):
                raise self._snapshot_invalid("invalid batch recipient")
            if any(player not in players for player in recipients):
                raise self._snapshot_invalid("batch recipient is not a player")
            if any(player not in recipients for player in applied):
                raise self._snapshot_invalid("applied player is not a recipient")
            if raw["active"]:
                active_batches.append(batch_id)
            batches[batch_id] = {
                "id": batch_id,
                "season": raw["season"],
                "players": list(recipients),
                "applied": list(applied),
                "active": raw["active"],
            }

        if len(active_batches) > 1:
            raise self._snapshot_invalid("multiple active batches")
        if batches:
            if len(active_batches) != 1:
                raise self._snapshot_invalid("missing active batch")
            active = batches[active_batches[0]]
            if active["season"] != season:
                raise self._snapshot_invalid("active batch season mismatch")
        elif season is not None:
            raise self._snapshot_invalid("season without batches")

        for field in self._COUNTER_FIELDS:
            if field not in raw_counters or not self._is_int(raw_counters[field]):
                raise self._snapshot_invalid(f"invalid counter {field}")
            if raw_counters[field] < 0:
                raise self._snapshot_invalid(f"negative counter {field}")
        for field in self._STATS_FIELDS:
            if field not in raw_stats or not self._is_int(raw_stats[field]):
                raise self._snapshot_invalid(f"invalid stat {field}")
            if raw_stats[field] < 0:
                raise self._snapshot_invalid(f"negative stat {field}")

        expected_stats = {
            "batches": len(batches),
            "players": len(players),
            "applied": sum(len(batch["applied"]) for batch in batches.values()),
            "placements": raw_counters["placements"],
        }
        if raw_stats != expected_stats:
            raise self._snapshot_invalid("stats do not match snapshot data")
        if any(raw_counters[field] != expected_stats[field]
               for field in self._STATS_FIELDS):
            raise self._snapshot_invalid("counters do not match snapshot data")
        if batches:
            suffixes = []
            for batch_id in batches:
                _, separator, suffix = batch_id.rpartition("#")
                if not separator or not suffix.isdigit():
                    raise self._snapshot_invalid("invalid batch id")
                suffixes.append(int(suffix))
            if raw_counters["batch_seq"] < max(suffixes):
                raise self._snapshot_invalid("batch sequence is behind batches")

        return (
            season,
            batches,
            players,
            raw_counters["batch_seq"],
            raw_counters["placements"],
        )
