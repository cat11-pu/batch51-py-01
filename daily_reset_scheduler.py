"""Daily reset scheduler: per-server wall clock, catch-up windows, idempotent cycles."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

DAILY = "daily"
WEEKLY = "weekly"
MAX_SERVERS = 64
DEFAULT_HOUR = 5
DEFAULT_MINUTE = 0


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


class DailyResetScheduler:
    """Compute, materialise and settle daily and weekly reset cycles."""

    def __init__(self, *, max_servers: int = MAX_SERVERS,
                 default_hour: int = DEFAULT_HOUR,
                 default_minute: int = DEFAULT_MINUTE) -> None:
        self.max_servers = max_servers
        self.default_hour = default_hour
        self.default_minute = default_minute
        self._lock = threading.RLock()

    def register_server(self, server_id, *, timezone, daily_hour=None,
                        daily_minute=None, weekly_weekday=0):
        """Register a server and return its normalised schedule."""
        raise NotImplementedError

    def set_timezone(self, server_id, timezone):
        """Change a server timezone and recompute its queued resets."""
        raise NotImplementedError

    def server_of(self, server_id):
        """Return the schedule of one server."""
        raise NotImplementedError

    def servers(self):
        """Return every registered server id in sorted order."""
        raise NotImplementedError

    def next_reset(self, server_id, after_ms, period=DAILY):
        """Return the epoch millisecond of the next reset strictly after after_ms."""
        raise NotImplementedError

    def run_due(self, server_id, now_ms):
        """Materialise the cycles that became due at now_ms and return their keys."""
        raise NotImplementedError

    def catch_up(self, server_id, *, from_ms, to_ms):
        """Materialise every cycle inside an explicit maintenance window."""
        raise NotImplementedError

    def mark_done(self, server_id, cycle_key):
        """Mark one materialised cycle as settled; False when already settled."""
        raise NotImplementedError

    def pending(self, server_id):
        """Return materialised but unsettled cycle keys in chronological order."""
        raise NotImplementedError

    def snapshot(self):
        """Return a detached state dictionary for every server."""
        raise NotImplementedError

    def restore(self, state):
        """Replace all schedules and progress with a previous snapshot."""
        raise NotImplementedError

    def stats(self):
        """Return server and cycle counters."""
        raise NotImplementedError
