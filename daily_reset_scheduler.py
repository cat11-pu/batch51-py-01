"""Daily reset scheduler: per-server wall clock, catch-up windows, idempotent cycles."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAILY = "daily"
WEEKLY = "weekly"
MAX_SERVERS = 64
DEFAULT_HOUR = 5
DEFAULT_MINUTE = 0

MAX_PENDING = 10_000
MAX_DONE = 100_000
MAX_PENDING_CYCLES = MAX_PENDING
MAX_DONE_CYCLES = MAX_DONE
PENDING_LIMIT = MAX_PENDING
DONE_LIMIT = MAX_DONE

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_DAILY_KEY_RE = re.compile(r"^daily:\d{4}-\d{2}-\d{2}$")
_WEEKLY_KEY_RE = re.compile(r"^weekly:\d{4}-W\d{2}$")


class ResetError(ValueError):
    """Raised when a reset schedule or cycle request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ServerSchedule:
    """The reset configuration of one game server."""

    server_id: str
    timezone: str
    daily_hour: int
    daily_minute: int
    weekly_weekday: int


@dataclass
class _ServerState:
    schedule: ServerSchedule
    zone: ZoneInfo
    last_run_ms: int | None = None
    replay_floor_ms: int | None = None
    pending: dict[str, int] | None = None
    done: set[str] | None = None

    def __post_init__(self) -> None:
        if self.pending is None:
            self.pending = {}
        if self.done is None:
            self.done = set()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pending_limit() -> int:
    return min(MAX_PENDING, MAX_PENDING_CYCLES, PENDING_LIMIT)


def _done_limit() -> int:
    return min(MAX_DONE, MAX_DONE_CYCLES, DONE_LIMIT)


def _validate_schedule_values(hour: object, minute: object, weekday: object) -> None:
    if not (_is_int(hour) and 0 <= hour <= 23):
        raise ResetError("DR_INVALID_SCHEDULE", {"daily_hour": hour})
    if not (_is_int(minute) and 0 <= minute <= 59):
        raise ResetError("DR_INVALID_SCHEDULE", {"daily_minute": minute})
    if not (_is_int(weekday) and 0 <= weekday <= 6):
        raise ResetError("DR_INVALID_SCHEDULE", {"weekly_weekday": weekday})


def _parse_timezone(name: object) -> tuple[str, ZoneInfo]:
    if not isinstance(name, str) or not name:
        raise ResetError("DR_INVALID_TIMEZONE", name)
    try:
        zone = ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, TypeError, OSError):
        raise ResetError("DR_INVALID_TIMEZONE", name) from None
    return name, zone


def _validate_server_id(server_id: object) -> str:
    if not isinstance(server_id, str) or not server_id:
        raise ResetError("DR_INVALID_SERVER", server_id)
    return server_id


def _require_time_ms(value: object, field: str) -> int:
    if not _is_int(value):
        raise ResetError("DR_INVALID_TIME", {field: value})
    return value


def _validate_period(period: object) -> str:
    if period not in (DAILY, WEEKLY):
        raise ResetError("DR_INVALID_PERIOD", period)
    return period


def _ms_to_datetime(value_ms: int) -> datetime:
    seconds, millis = divmod(value_ms, 1000)
    try:
        result = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise ResetError("DR_INVALID_TIME", value_ms) from None
    return result.replace(microsecond=millis * 1000)


def _datetime_to_ms(value: datetime) -> int:
    return int((value.astimezone(timezone.utc) - _EPOCH).total_seconds() * 1000)


def _valid_local_datetime(naive: datetime, zone: ZoneInfo, fold: int) -> datetime | None:
    candidate = naive.replace(tzinfo=zone, fold=fold)
    roundtrip = candidate.astimezone(timezone.utc).astimezone(zone)
    if roundtrip.replace(tzinfo=None) != naive:
        return None
    return candidate


def _local_occurs_ms(naive: datetime, zone: ZoneInfo) -> int | None:
    first = _valid_local_datetime(naive, zone, 0)
    if first is not None:
        return _datetime_to_ms(first)

    second = _valid_local_datetime(naive, zone, 1)
    if second is not None:
        return _datetime_to_ms(second)

    candidate = naive
    for _ in range(24 * 60):
        candidate += timedelta(minutes=1)
        if candidate.date() != naive.date():
            return None
        resolved = _valid_local_datetime(candidate, zone, 0)
        if resolved is not None:
            return _datetime_to_ms(resolved)
    return None


def _scheduled_instant(day: date, hour: int, minute: int, zone: ZoneInfo) -> int | None:
    naive = datetime.combine(day, time(hour, minute))
    try:
        return _local_occurs_ms(naive, zone)
    except (OverflowError, OSError, ValueError):
        return None


def _daily_key(day: date) -> str:
    return f"daily:{day.isoformat()}"


def _weekly_key(day: date) -> str:
    iso = day.isocalendar()
    return f"weekly:{iso.year:04d}-W{iso.week:02d}"


def _next_daily_event(state: _ServerState, after_ms: int) -> tuple[int, str]:
    schedule = state.schedule
    local_day = _ms_to_datetime(after_ms).astimezone(state.zone).date()
    for offset in range(0, 3700):
        day = local_day + timedelta(days=offset)
        due_ms = _scheduled_instant(
            day, schedule.daily_hour, schedule.daily_minute, state.zone
        )
        if due_ms is not None and due_ms > after_ms:
            return due_ms, _daily_key(day)
    raise ResetError("DR_INVALID_TIME", after_ms)


def _next_weekly_event(state: _ServerState, after_ms: int) -> tuple[int, str]:
    schedule = state.schedule
    local_day = _ms_to_datetime(after_ms).astimezone(state.zone).date()
    days_ahead = (schedule.weekly_weekday - local_day.weekday()) % 7
    day = local_day + timedelta(days=days_ahead)
    for _ in range(0, 10):
        due_ms = _scheduled_instant(
            day, schedule.daily_hour, schedule.daily_minute, state.zone
        )
        if due_ms is not None and due_ms > after_ms:
            return due_ms, _weekly_key(day)
        day += timedelta(days=7)
    raise ResetError("DR_INVALID_TIME", after_ms)


def _next_event(state: _ServerState, after_ms: int, period: str) -> tuple[int, str]:
    if period == DAILY:
        return _next_daily_event(state, after_ms)
    return _next_weekly_event(state, after_ms)


def _events_in_window(
    state: _ServerState,
    from_ms: int,
    to_ms: int,
    *,
    inclusive_start: bool,
) -> list[tuple[int, int, str]]:
    events: list[tuple[int, int, str]] = []
    for period, rank in ((DAILY, 0), (WEEKLY, 1)):
        cursor = from_ms - 1 if inclusive_start else from_ms
        while True:
            due_ms, key = _next_event(state, cursor, period)
            if due_ms > to_ms:
                break
            events.append((due_ms, rank, key))
            cursor = due_ms
    events.sort()
    return events


class DailyResetScheduler:
    """Compute, materialise and settle daily and weekly reset cycles."""

    def __init__(self, *, max_servers: int = MAX_SERVERS,
                 default_hour: int = DEFAULT_HOUR,
                 default_minute: int = DEFAULT_MINUTE) -> None:
        if not _is_int(max_servers) or max_servers < 0:
            raise ResetError("DR_INVALID_SCHEDULE", {"max_servers": max_servers})
        _validate_schedule_values(default_hour, default_minute, 0)
        self._max_servers = max_servers
        self._default_hour = default_hour
        self._default_minute = default_minute
        self._lock = threading.RLock()
        self._servers: dict[str, _ServerState] = {}
        self._materialized = 0
        self._done = 0
        self._catchups = 0

    @property
    def max_servers(self) -> int:
        return self._max_servers

    @property
    def default_hour(self) -> int:
        return self._default_hour

    @property
    def default_minute(self) -> int:
        return self._default_minute

    def register_server(self, server_id, *, timezone, daily_hour=None,
                        daily_minute=None, weekly_weekday=0):
        """Register a server and return its normalised schedule."""
        server_id = _validate_server_id(server_id)
        timezone_name, zone = _parse_timezone(timezone)
        hour = self._default_hour if daily_hour is None else daily_hour
        minute = self._default_minute if daily_minute is None else daily_minute
        _validate_schedule_values(hour, minute, weekly_weekday)

        with self._lock:
            if server_id in self._servers:
                raise ResetError("DR_SERVER_EXISTS", server_id)
            if len(self._servers) >= self._max_servers:
                raise ResetError("DR_SERVER_LIMIT", server_id)
            schedule = ServerSchedule(
                server_id=server_id,
                timezone=timezone_name,
                daily_hour=hour,
                daily_minute=minute,
                weekly_weekday=weekly_weekday,
            )
            self._servers[server_id] = _ServerState(schedule=schedule, zone=zone)
            return schedule

    def set_timezone(self, server_id, timezone):
        """Change a server timezone and recompute its queued resets."""
        with self._lock:
            state = self._server_state(server_id)
            timezone_name, zone = _parse_timezone(timezone)
            old_next = self._next_queued_instants(state)
            schedule = ServerSchedule(
                server_id=state.schedule.server_id,
                timezone=timezone_name,
                daily_hour=state.schedule.daily_hour,
                daily_minute=state.schedule.daily_minute,
                weekly_weekday=state.schedule.weekly_weekday,
            )
            replacement = _ServerState(
                schedule=schedule,
                zone=zone,
                last_run_ms=state.last_run_ms,
                replay_floor_ms=state.replay_floor_ms,
                pending=dict(state.pending),
                done=set(state.done),
            )
            new_next = self._next_queued_instants(replacement)
            if state.last_run_ms is not None:
                moved_earlier = [
                    new for old, new in zip(old_next, new_next)
                    if old is not None and new is not None and new < old
                ]
                if moved_earlier:
                    floor = min(moved_earlier) - 1
                    if (replacement.replay_floor_ms is None
                            or floor < replacement.replay_floor_ms):
                        replacement.replay_floor_ms = floor
            self._servers[server_id] = replacement

    def server_of(self, server_id):
        """Return the schedule of one server."""
        with self._lock:
            return self._server_state(server_id).schedule

    def servers(self):
        """Return every registered server id in sorted order."""
        with self._lock:
            return tuple(sorted(self._servers))

    def next_reset(self, server_id, after_ms, period=DAILY):
        """Return the epoch millisecond of the next reset strictly after after_ms."""
        after_ms = _require_time_ms(after_ms, "after_ms")
        period = _validate_period(period)
        with self._lock:
            state = self._server_state(server_id)
            due_ms, _ = _next_event(state, after_ms, period)
            return due_ms

    def run_due(self, server_id, now_ms):
        """Materialise the cycles that became due at now_ms and return their keys."""
        now_ms = _require_time_ms(now_ms, "now_ms")
        with self._lock:
            state = self._server_state(server_id)
            if state.last_run_ms is None:
                state.last_run_ms = now_ms
                state.replay_floor_ms = None
                return ()
            if now_ms < state.last_run_ms:
                raise ResetError("DR_TIME_REWIND", {
                    "server_id": server_id,
                    "last_run_ms": state.last_run_ms,
                    "now_ms": now_ms,
                })

            window_start = state.last_run_ms
            if state.replay_floor_ms is not None:
                window_start = min(window_start, state.replay_floor_ms)
            events = _events_in_window(
                state, window_start, now_ms, inclusive_start=False
            )
            new_keys = self._materialize(state, events)
            state.last_run_ms = now_ms
            state.replay_floor_ms = None
            return new_keys

    def catch_up(self, server_id, *, from_ms, to_ms):
        """Materialise every cycle inside an explicit maintenance window."""
        from_ms = _require_time_ms(from_ms, "from_ms")
        to_ms = _require_time_ms(to_ms, "to_ms")
        if from_ms > to_ms:
            raise ResetError("DR_TIME_REWIND", {
                "from_ms": from_ms,
                "to_ms": to_ms,
            })
        with self._lock:
            state = self._server_state(server_id)
            events = _events_in_window(
                state, from_ms, to_ms, inclusive_start=True
            )
            new_keys = self._materialize(state, events)
            self._catchups += 1
            return new_keys

    def mark_done(self, server_id, cycle_key):
        """Mark one materialised cycle as settled; False when already settled."""
        with self._lock:
            state = self._server_state(server_id)
            if not isinstance(cycle_key, str):
                raise ResetError("DR_UNKNOWN_CYCLE", cycle_key)
            if cycle_key in state.done:
                return False
            if cycle_key not in state.pending:
                raise ResetError("DR_UNKNOWN_CYCLE", cycle_key)
            if len(state.done) >= _done_limit():
                raise ResetError("DR_DONE_LIMIT", {
                    "server_id": server_id,
                    "limit": _done_limit(),
                })
            del state.pending[cycle_key]
            state.done.add(cycle_key)
            self._done += 1
            return True

    def pending(self, server_id):
        """Return materialised but unsettled cycle keys in chronological order."""
        with self._lock:
            state = self._server_state(server_id)
            ordered = sorted(
                state.pending.items(),
                key=lambda item: (
                    item[1],
                    0 if item[0].startswith("daily:") else 1,
                    item[0],
                ),
            )
            return tuple(key for key, _ in ordered)

    def snapshot(self):
        """Return a detached state dictionary for every server."""
        with self._lock:
            servers = {}
            for server_id in sorted(self._servers):
                state = self._servers[server_id]
                schedule = state.schedule
                servers[server_id] = {
                    "schedule": {
                        "server_id": schedule.server_id,
                        "timezone": schedule.timezone,
                        "daily_hour": schedule.daily_hour,
                        "daily_minute": schedule.daily_minute,
                        "weekly_weekday": schedule.weekly_weekday,
                    },
                    "last_run_ms": state.last_run_ms,
                    "replay_floor_ms": state.replay_floor_ms,
                    "pending": [
                        [key, due_ms]
                        for key, due_ms in sorted(
                            state.pending.items(),
                            key=lambda item: (
                                item[1],
                                0 if item[0].startswith("daily:") else 1,
                                item[0],
                            ),
                        )
                    ],
                    "done": sorted(state.done),
                }
            counters = {
                "materialized": self._materialized,
                "done": self._done,
                "catchups": self._catchups,
            }
            return {
                "version": 1,
                "servers": servers,
                "counters": dict(counters),
                "stats": {
                    "servers": len(self._servers),
                    **counters,
                },
            }

    def restore(self, state):
        """Replace all schedules and progress with a previous snapshot."""
        with self._lock:
            try:
                servers, materialized, done_count, catchups = self._decode_snapshot(state)
            except Exception as exc:
                if isinstance(exc, ResetError) and exc.code == "DR_SNAPSHOT_INVALID":
                    raise
                raise ResetError("DR_SNAPSHOT_INVALID", str(exc)) from None
            self._servers = servers
            self._materialized = materialized
            self._done = done_count
            self._catchups = catchups

    def stats(self):
        """Return server and cycle counters."""
        with self._lock:
            return {
                "servers": len(self._servers),
                "materialized": self._materialized,
                "done": self._done,
                "catchups": self._catchups,
            }

    def _server_state(self, server_id: object) -> _ServerState:
        if not isinstance(server_id, str) or server_id not in self._servers:
            raise ResetError("DR_UNKNOWN_SERVER", server_id)
        return self._servers[server_id]

    def _next_queued_instants(self, state: _ServerState) -> tuple[int | None, int | None]:
        if state.last_run_ms is None:
            return None, None
        daily = _next_daily_event(state, state.last_run_ms)[0]
        weekly = _next_weekly_event(state, state.last_run_ms)[0]
        return daily, weekly

    def _materialize(
        self,
        state: _ServerState,
        events: list[tuple[int, int, str]],
    ) -> tuple[str, ...]:
        new_events: list[tuple[int, int, str]] = []
        for due_ms, rank, key in events:
            if key in state.pending or key in state.done:
                continue
            new_events.append((due_ms, rank, key))
        if len(state.pending) + len(new_events) > _pending_limit():
            raise ResetError("DR_PENDING_LIMIT", {
                "server_id": state.schedule.server_id,
                "limit": _pending_limit(),
            })
        for due_ms, _, key in new_events:
            state.pending[key] = due_ms
        self._materialized += len(new_events)
        return tuple(key for _, _, key in new_events)

    def _decode_snapshot(
        self,
        state: object,
    ) -> tuple[dict[str, _ServerState], int, int, int]:
        if not isinstance(state, dict):
            raise ResetError("DR_SNAPSHOT_INVALID", "state")
        if state.get("version") != 1:
            raise ResetError("DR_SNAPSHOT_INVALID", "version")
        raw_servers = state.get("servers")
        counters = state.get("counters")
        reported_stats = state.get("stats")
        if not isinstance(raw_servers, dict):
            raise ResetError("DR_SNAPSHOT_INVALID", "servers")
        if not isinstance(counters, dict) or not isinstance(reported_stats, dict):
            raise ResetError("DR_SNAPSHOT_INVALID", "counters")
        if len(raw_servers) > self._max_servers:
            raise ResetError("DR_SNAPSHOT_INVALID", "servers limit")

        servers: dict[str, _ServerState] = {}
        total_pending = 0
        total_done = 0

        for raw_id, raw_server in raw_servers.items():
            if not isinstance(raw_id, str) or not raw_id or not isinstance(raw_server, dict):
                raise ResetError("DR_SNAPSHOT_INVALID", "server")
            raw_schedule = raw_server.get("schedule")
            if not isinstance(raw_schedule, dict):
                raise ResetError("DR_SNAPSHOT_INVALID", "schedule")
            if raw_schedule.get("server_id") != raw_id:
                raise ResetError("DR_SNAPSHOT_INVALID", "schedule server")
            timezone_name, zone = _parse_timezone(raw_schedule.get("timezone"))
            hour = raw_schedule.get("daily_hour")
            minute = raw_schedule.get("daily_minute")
            weekday = raw_schedule.get("weekly_weekday")
            _validate_schedule_values(hour, minute, weekday)
            schedule = ServerSchedule(
                server_id=raw_id,
                timezone=timezone_name,
                daily_hour=hour,
                daily_minute=minute,
                weekly_weekday=weekday,
            )

            last_run_ms = raw_server.get("last_run_ms")
            replay_floor_ms = raw_server.get("replay_floor_ms")
            if last_run_ms is not None and not _is_int(last_run_ms):
                raise ResetError("DR_SNAPSHOT_INVALID", "last_run_ms")
            if replay_floor_ms is not None and not _is_int(replay_floor_ms):
                raise ResetError("DR_SNAPSHOT_INVALID", "replay_floor_ms")

            raw_pending = raw_server.get("pending")
            raw_done = raw_server.get("done")
            if not isinstance(raw_pending, list) or not isinstance(raw_done, list):
                raise ResetError("DR_SNAPSHOT_INVALID", "cycles")
            if len(raw_pending) > _pending_limit() or len(raw_done) > _done_limit():
                raise ResetError("DR_SNAPSHOT_INVALID", "cycle limit")

            server_keys: set[str] = set()
            pending: dict[str, int] = {}
            for item in raw_pending:
                if (not isinstance(item, (list, tuple)) or len(item) != 2
                        or not isinstance(item[0], str) or not _is_int(item[1])):
                    raise ResetError("DR_SNAPSHOT_INVALID", "pending")
                key, due_ms = item
                self._validate_cycle_key(key)
                if key in server_keys:
                    raise ResetError("DR_SNAPSHOT_INVALID", "duplicate cycle")
                pending[key] = due_ms
                server_keys.add(key)

            done: set[str] = set()
            for key in raw_done:
                if not isinstance(key, str):
                    raise ResetError("DR_SNAPSHOT_INVALID", "done")
                self._validate_cycle_key(key)
                if key in server_keys:
                    raise ResetError("DR_SNAPSHOT_INVALID", "duplicate cycle")
                done.add(key)
                server_keys.add(key)

            total_pending += len(pending)
            total_done += len(done)
            servers[raw_id] = _ServerState(
                schedule=schedule,
                zone=zone,
                last_run_ms=last_run_ms,
                replay_floor_ms=replay_floor_ms,
                pending=pending,
                done=done,
            )

        materialized = counters.get("materialized")
        done_count = counters.get("done")
        catchups = counters.get("catchups")
        if not all(_is_int(value) and value >= 0
                   for value in (materialized, done_count, catchups)):
            raise ResetError("DR_SNAPSHOT_INVALID", "counters")
        if materialized != total_pending + total_done:
            raise ResetError("DR_SNAPSHOT_INVALID", "materialized")
        if done_count != total_done:
            raise ResetError("DR_SNAPSHOT_INVALID", "done")
        expected_stats = {
            "servers": len(servers),
            "materialized": materialized,
            "done": done_count,
            "catchups": catchups,
        }
        if reported_stats != expected_stats:
            raise ResetError("DR_SNAPSHOT_INVALID", "stats")
        return servers, materialized, done_count, catchups

    @staticmethod
    def _validate_cycle_key(key: str) -> None:
        if _DAILY_KEY_RE.fullmatch(key):
            try:
                date.fromisoformat(key.split(":", 1)[1])
            except ValueError:
                raise ResetError("DR_SNAPSHOT_INVALID", key) from None
            return
        if _WEEKLY_KEY_RE.fullmatch(key):
            week = int(key.rsplit("W", 1)[1])
            if 1 <= week <= 53:
                return
        raise ResetError("DR_SNAPSHOT_INVALID", key)
