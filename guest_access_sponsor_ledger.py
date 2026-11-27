"""Guest access ledger: sponsor guarantees, access windows, renewals and expiry."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GuestError(ValueError):
    """Raised when a guest access operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SponsorView:
    sponsor_id: str
    grantable: tuple[str, ...]
    guest_count: int


@dataclass(frozen=True)
class GuestView:
    guest_id: str
    sponsor_id: str | None
    state: str
    scope: tuple[str, ...]
    invited_at: int
    granted_at: int | None
    expires_at: int | None
    disabled_reason: str | None
    renewal_pending: bool


@dataclass
class _SponsorRecord:
    sponsor_id: str
    grantable: tuple[str, ...]
    registered_at: int | None = None


@dataclass
class _GuestRecord:
    guest_id: str
    sponsor_id: str | None
    state: str
    scope: tuple[str, ...]
    invited_at: int
    granted_at: int | None
    expires_at: int | None
    disabled_reason: str | None
    renewal_pending: bool


_STAT_KEYS = (
    "sponsors",
    "guests_invited",
    "guests_bound",
    "renewals_requested",
    "renewals_approved",
    "expired",
    "revoked",
    "transferred",
)

_SNAPSHOT_KEYS = {"version", "sponsors", "guests", "stats"}
_GUEST_KEYS = {
    "guest_id",
    "sponsor_id",
    "state",
    "scope",
    "invited_at",
    "granted_at",
    "expires_at",
    "disabled_reason",
    "renewal_pending",
}


def _normalize_identifier(value: object, detail: str) -> str:
    if not isinstance(value, str):
        raise GuestError("GUEST_INVALID_REQUEST", detail)
    normalized = value.strip()
    if not normalized:
        raise GuestError("GUEST_INVALID_REQUEST", detail)
    return normalized


def _normalize_scope(value: object, detail: str) -> tuple[str, ...]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (bytes, bytearray)):
        raise GuestError("GUEST_INVALID_REQUEST", detail)
    else:
        try:
            values = list(value)
        except TypeError:
            raise GuestError("GUEST_INVALID_REQUEST", detail) from None

    normalized = set()
    for item in values:
        if not isinstance(item, str):
            raise GuestError("GUEST_INVALID_REQUEST", detail)
        token = item.strip().lower()
        if token:
            normalized.add(token)
    return tuple(sorted(normalized))


def _intersection(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(left).intersection(right)))


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class GuestAccessLedger:
    """Track sponsorship, scoped access windows and expiry settlement for guests."""

    def __init__(self, *, default_window_ticks: int = 1000,
                 renewal_window_ticks: int = 200,
                 max_guests_per_sponsor: int = 20) -> None:
        self.default_window_ticks = default_window_ticks
        self.renewal_window_ticks = renewal_window_ticks
        self.max_guests_per_sponsor = max_guests_per_sponsor
        self._lock = threading.RLock()
        self._sponsors: dict[str, _SponsorRecord] = {}
        self._guests: dict[str, _GuestRecord] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def register_sponsor(self, sponsor_id: str, grantable, *, now: int) -> SponsorView:
        with self._lock:
            sponsor_id = _normalize_identifier(sponsor_id, "sponsor_id")
            if sponsor_id in self._sponsors:
                existing = self._sponsors[sponsor_id]
                if existing.registered_at == now:
                    try:
                        scope = _normalize_scope(grantable, "grantable")
                    except GuestError:
                        raise GuestError("GUEST_SPONSOR_EXISTS", sponsor_id) from None
                    if existing.grantable == scope:
                        return self._sponsor_view(existing)
                raise GuestError("GUEST_SPONSOR_EXISTS", sponsor_id)
            scope = _normalize_scope(grantable, "grantable")
            self._sponsors[sponsor_id] = _SponsorRecord(sponsor_id, scope, now)
            self._stats["sponsors"] += 1
            return self._sponsor_view(self._sponsors[sponsor_id])

    def update_sponsor_scope(self, sponsor_id: str, grantable, *,
                             now: int) -> SponsorView:
        with self._lock:
            sponsor_id = _normalize_identifier(sponsor_id, "sponsor_id")
            sponsor = self._sponsors.get(sponsor_id)
            if sponsor is None:
                raise GuestError("GUEST_SPONSOR_UNKNOWN", sponsor_id)
            sponsor.grantable = _normalize_scope(grantable, "grantable")

            for guest in self._guests.values():
                if guest.state != "active" or guest.sponsor_id != sponsor_id:
                    continue
                narrowed = _intersection(guest.scope, sponsor.grantable)
                if narrowed:
                    guest.scope = narrowed
                    continue
                guest.scope = ()
                guest.state = "disabled"
                guest.disabled_reason = "scope_revoked"
                guest.renewal_pending = False
            return self._sponsor_view(sponsor)

    def invite_guest(self, guest_id: str, *, now: int) -> GuestView:
        with self._lock:
            guest_id = _normalize_identifier(guest_id, "guest_id")
            if guest_id in self._guests:
                raise GuestError("GUEST_ALREADY_EXISTS", guest_id)
            guest = _GuestRecord(
                guest_id=guest_id,
                sponsor_id=None,
                state="pending",
                scope=(),
                invited_at=now,
                granted_at=None,
                expires_at=None,
                disabled_reason=None,
                renewal_pending=False,
            )
            self._guests[guest_id] = guest
            self._stats["guests_invited"] += 1
            return self._guest_view(guest)

    def bind_sponsor(self, guest_id: str, sponsor_id: str, scope, *,
                     now: int) -> GuestView:
        with self._lock:
            guest_id = _normalize_identifier(guest_id, "guest_id")
            guest = self._guests.get(guest_id)
            if guest is None:
                raise GuestError("GUEST_UNKNOWN", guest_id)
            sponsor_id = _normalize_identifier(sponsor_id, "sponsor_id")
            sponsor = self._sponsors.get(sponsor_id)
            if sponsor is None:
                raise GuestError("GUEST_SPONSOR_UNKNOWN", sponsor_id)
            if guest.state != "pending":
                raise GuestError("GUEST_INVALID_REQUEST", "guest is not pending")

            requested = _normalize_scope(scope, "scope")
            if not set(requested).issubset(sponsor.grantable):
                raise GuestError("GUEST_SCOPE_EXCEEDED", requested)
            if not requested:
                raise GuestError("GUEST_INVALID_REQUEST", "scope is empty")
            if self._active_guest_count(sponsor_id) >= self.max_guests_per_sponsor:
                raise GuestError("GUEST_CAPACITY_EXCEEDED", sponsor_id)

            guest.sponsor_id = sponsor_id
            guest.state = "active"
            guest.scope = _intersection(requested, sponsor.grantable)
            guest.granted_at = now
            guest.expires_at = now + self.default_window_ticks
            guest.disabled_reason = None
            guest.renewal_pending = False
            self._stats["guests_bound"] += 1
            return self._guest_view(guest)

    def request_renewal(self, guest_id: str, *, now: int) -> GuestView:
        with self._lock:
            guest = self._guest_or_raise(guest_id)
            if guest.renewal_pending:
                raise GuestError("GUEST_RENEWAL_PENDING", guest.guest_id)
            if guest.state != "active" or guest.expires_at is None:
                raise GuestError("GUEST_INVALID_REQUEST", "guest is not active")
            if now >= guest.expires_at:
                raise GuestError("GUEST_INVALID_REQUEST", "guest has expired")
            if now < guest.expires_at - self.renewal_window_ticks:
                raise GuestError("GUEST_RENEWAL_TOO_EARLY", guest.guest_id)

            guest.renewal_pending = True
            self._stats["renewals_requested"] += 1
            return self._guest_view(guest)

    def approve_renewal(self, guest_id: str, *, now: int) -> GuestView:
        with self._lock:
            guest = self._guest_or_raise(guest_id)
            if not guest.renewal_pending:
                raise GuestError("GUEST_RENEWAL_MISSING", guest.guest_id)
            if guest.state not in {"active", "disabled"}:
                raise GuestError("GUEST_RENEWAL_MISSING", guest.guest_id)
            if guest.state == "disabled" and guest.disabled_reason != "expired":
                raise GuestError("GUEST_RENEWAL_MISSING", guest.guest_id)

            if (guest.state == "active" and guest.expires_at is not None
                    and now >= guest.expires_at):
                self._mark_expired(guest)

            if guest.sponsor_id is None:
                raise GuestError("GUEST_RENEWAL_MISSING", guest.guest_id)
            sponsor = self._sponsors.get(guest.sponsor_id)
            if sponsor is None:
                raise GuestError("GUEST_SPONSOR_UNKNOWN", guest.sponsor_id)

            renewed_scope = _intersection(guest.scope, sponsor.grantable)
            guest.expires_at = now + self.default_window_ticks
            guest.renewal_pending = False
            if renewed_scope:
                guest.scope = renewed_scope
                guest.state = "active"
                guest.disabled_reason = None
            else:
                guest.scope = ()
                guest.state = "disabled"
                guest.disabled_reason = "scope_revoked"
            self._stats["renewals_approved"] += 1
            return self._guest_view(guest)

    def settle_expiry(self, *, now: int) -> int:
        with self._lock:
            changed = 0
            for guest in self._guests.values():
                if (guest.state == "active" and guest.expires_at is not None
                        and guest.expires_at <= now):
                    self._mark_expired(guest)
                    changed += 1
            return changed

    def revoke_guest(self, guest_id: str, sponsor: str, *, now: int) -> GuestView:
        with self._lock:
            guest = self._guest_or_raise(guest_id)
            sponsor = _normalize_identifier(sponsor, "sponsor")
            if guest.sponsor_id != sponsor:
                raise GuestError("GUEST_NOT_SPONSOR", sponsor)
            if guest.state == "active":
                guest.state = "disabled"
                guest.disabled_reason = "revoked"
                guest.renewal_pending = False
                self._stats["revoked"] += 1
            return self._guest_view(guest)

    def transfer_guest(self, guest_id: str, new_sponsor: str, *,
                       now: int) -> GuestView:
        with self._lock:
            guest = self._guest_or_raise(guest_id)
            new_sponsor = _normalize_identifier(new_sponsor, "new_sponsor")
            sponsor = self._sponsors.get(new_sponsor)
            if sponsor is None:
                raise GuestError("GUEST_SPONSOR_UNKNOWN", new_sponsor)
            if guest.state != "active":
                raise GuestError("GUEST_INVALID_REQUEST", "guest is not active")

            same_sponsor = guest.sponsor_id == new_sponsor
            if (not same_sponsor
                    and self._active_guest_count(new_sponsor) >= self.max_guests_per_sponsor):
                raise GuestError("GUEST_CAPACITY_EXCEEDED", new_sponsor)

            transferred_scope = _intersection(guest.scope, sponsor.grantable)
            guest.sponsor_id = new_sponsor
            if transferred_scope:
                guest.scope = transferred_scope
                guest.state = "active"
                guest.disabled_reason = None
            else:
                guest.scope = ()
                guest.state = "disabled"
                guest.disabled_reason = "scope_exceeded"
                guest.renewal_pending = False
            if not same_sponsor:
                self._stats["transferred"] += 1
            return self._guest_view(guest)

    def reconcile(self, *, now: int) -> int:
        with self._lock:
            changed = 0
            for guest in self._guests.values():
                if guest.state != "active":
                    continue
                if guest.expires_at is not None and guest.expires_at <= now:
                    self._mark_expired(guest)
                    changed += 1
                    continue
                if guest.sponsor_id is None:
                    continue
                sponsor = self._sponsors.get(guest.sponsor_id)
                if sponsor is None:
                    continue
                narrowed = _intersection(guest.scope, sponsor.grantable)
                if narrowed == guest.scope:
                    continue
                changed += 1
                if narrowed:
                    guest.scope = narrowed
                else:
                    guest.scope = ()
                    guest.state = "disabled"
                    guest.disabled_reason = "scope_revoked"
                    guest.renewal_pending = False
            return changed

    def effective_scope(self, guest_id: str) -> tuple:
        with self._lock:
            guest = self._guest_or_raise(guest_id)
            if guest.state != "active" or guest.sponsor_id is None:
                return ()
            sponsor = self._sponsors.get(guest.sponsor_id)
            if sponsor is None:
                return ()
            return _intersection(guest.scope, sponsor.grantable)

    def guest(self, guest_id: str) -> GuestView:
        with self._lock:
            return self._guest_view(self._guest_or_raise(guest_id))

    def guests_for(self, sponsor_id: str) -> list:
        with self._lock:
            sponsor_id = _normalize_identifier(sponsor_id, "sponsor_id")
            if sponsor_id not in self._sponsors:
                raise GuestError("GUEST_SPONSOR_UNKNOWN", sponsor_id)
            guests = (
                guest for guest in self._guests.values()
                if guest.sponsor_id == sponsor_id
            )
            return [
                self._guest_view(guest)
                for guest in sorted(guests, key=lambda item: item.guest_id)
            ]

    def snapshot(self) -> dict:
        with self._lock:
            sponsors = {
                sponsor_id: {"grantable": list(sponsor.grantable)}
                for sponsor_id, sponsor in sorted(self._sponsors.items())
            }
            guests = {
                guest_id: {
                    "guest_id": guest.guest_id,
                    "sponsor_id": guest.sponsor_id,
                    "state": guest.state,
                    "scope": list(guest.scope),
                    "invited_at": guest.invited_at,
                    "granted_at": guest.granted_at,
                    "expires_at": guest.expires_at,
                    "disabled_reason": guest.disabled_reason,
                    "renewal_pending": guest.renewal_pending,
                }
                for guest_id, guest in sorted(self._guests.items())
            }
            return {
                "version": 1,
                "sponsors": sponsors,
                "guests": guests,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                sponsors, guests, stats = self._validate_snapshot(state)
            except GuestError as exc:
                if exc.code == "GUEST_SNAPSHOT_INVALID":
                    raise
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid snapshot") from None
            except Exception:
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid snapshot") from None
            self._sponsors = sponsors
            self._guests = guests
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _active_guest_count(self, sponsor_id: str) -> int:
        return sum(
            1 for guest in self._guests.values()
            if guest.state == "active" and guest.sponsor_id == sponsor_id
        )

    def _guest_or_raise(self, guest_id: str) -> _GuestRecord:
        guest_id = _normalize_identifier(guest_id, "guest_id")
        guest = self._guests.get(guest_id)
        if guest is None:
            raise GuestError("GUEST_UNKNOWN", guest_id)
        return guest

    def _mark_expired(self, guest: _GuestRecord) -> None:
        guest.state = "disabled"
        guest.disabled_reason = "expired"
        self._stats["expired"] += 1

    def _sponsor_view(self, sponsor: _SponsorRecord) -> SponsorView:
        return SponsorView(
            sponsor_id=sponsor.sponsor_id,
            grantable=tuple(sponsor.grantable),
            guest_count=self._active_guest_count(sponsor.sponsor_id),
        )

    def _guest_view(self, guest: _GuestRecord) -> GuestView:
        return GuestView(
            guest_id=guest.guest_id,
            sponsor_id=guest.sponsor_id,
            state=guest.state,
            scope=tuple(guest.scope),
            invited_at=guest.invited_at,
            granted_at=guest.granted_at,
            expires_at=guest.expires_at,
            disabled_reason=guest.disabled_reason,
            renewal_pending=guest.renewal_pending,
        )

    def _validate_snapshot(
        self, state: object
    ) -> tuple[dict[str, _SponsorRecord], dict[str, _GuestRecord], dict[str, int]]:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid fields")
        if not _is_int(state.get("version")) or state["version"] != 1:
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid version")
        if not isinstance(state.get("sponsors"), dict):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid sponsors")
        if not isinstance(state.get("guests"), dict):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid guests")
        if not isinstance(state.get("stats"), dict):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid stats")

        sponsors: dict[str, _SponsorRecord] = {}
        for raw_id, raw_sponsor in state["sponsors"].items():
            sponsor_id = self._snapshot_identifier(raw_id, "sponsor_id")
            if sponsor_id in sponsors:
                raise GuestError("GUEST_SNAPSHOT_INVALID", "duplicate sponsor")
            if isinstance(raw_sponsor, dict):
                if set(raw_sponsor) != {"grantable"}:
                    raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid sponsor")
                raw_grantable = raw_sponsor["grantable"]
            elif isinstance(raw_sponsor, (list, tuple)):
                raw_grantable = raw_sponsor
            else:
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid sponsor")
            grantable = _normalize_scope(raw_grantable, "grantable")
            sponsors[sponsor_id] = _SponsorRecord(sponsor_id, grantable)

        stats = self._validate_stats(state["stats"])
        guests: dict[str, _GuestRecord] = {}
        for raw_id, raw_guest in state["guests"].items():
            guest = self._validate_guest(raw_id, raw_guest, sponsors)
            if guest.guest_id in guests:
                raise GuestError("GUEST_SNAPSHOT_INVALID", "duplicate guest")
            guests[guest.guest_id] = guest
        if stats["sponsors"] != len(sponsors):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "sponsor count mismatch")
        return sponsors, guests, stats

    def _validate_stats(self, raw_stats: dict) -> dict[str, int]:
        if set(raw_stats) != set(_STAT_KEYS):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid stats fields")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid stat")
            stats[key] = value
        return stats

    def _validate_guest(
        self,
        raw_id: object,
        raw_guest: object,
        sponsors: dict[str, _SponsorRecord],
    ) -> _GuestRecord:
        if not isinstance(raw_guest, dict) or set(raw_guest) != _GUEST_KEYS:
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid guest")
        guest_id = self._snapshot_identifier(raw_id, "guest_id")
        if raw_guest["guest_id"] != guest_id:
            raise GuestError("GUEST_SNAPSHOT_INVALID", "guest id mismatch")

        state = raw_guest["state"]
        if state not in {"pending", "active", "disabled"}:
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid guest state")
        sponsor_id = raw_guest["sponsor_id"]
        if sponsor_id is not None:
            sponsor_id = self._snapshot_identifier(sponsor_id, "sponsor_id")
            if sponsor_id not in sponsors:
                raise GuestError("GUEST_SNAPSHOT_INVALID", "unknown sponsor")
        scope = _normalize_scope(raw_guest["scope"], "scope")
        invited_at = raw_guest["invited_at"]
        granted_at = raw_guest["granted_at"]
        expires_at = raw_guest["expires_at"]
        disabled_reason = raw_guest["disabled_reason"]
        renewal_pending = raw_guest["renewal_pending"]

        if not _is_int(invited_at):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid invited_at")
        if granted_at is not None and not _is_int(granted_at):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid granted_at")
        if expires_at is not None and not _is_int(expires_at):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid expires_at")
        if disabled_reason is not None and (
                not isinstance(disabled_reason, str) or not disabled_reason.strip()):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid disabled_reason")
        if not isinstance(renewal_pending, bool):
            raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid renewal_pending")

        if state == "pending":
            if (sponsor_id is not None or scope or granted_at is not None
                    or expires_at is not None or disabled_reason is not None
                    or renewal_pending):
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid pending guest")
        elif state == "active":
            if (sponsor_id is None or not scope or granted_at is None
                    or expires_at is None or disabled_reason is not None
                    or expires_at < granted_at):
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid active guest")
            if not set(scope).issubset(sponsors[sponsor_id].grantable):
                raise GuestError("GUEST_SNAPSHOT_INVALID", "scope exceeds sponsor")
        else:
            if (sponsor_id is None or disabled_reason is None
                    or granted_at is None or expires_at is None):
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid disabled guest")
            if renewal_pending and disabled_reason != "expired":
                raise GuestError("GUEST_SNAPSHOT_INVALID", "invalid renewal state")

        return _GuestRecord(
            guest_id=guest_id,
            sponsor_id=sponsor_id,
            state=state,
            scope=scope,
            invited_at=invited_at,
            granted_at=granted_at,
            expires_at=expires_at,
            disabled_reason=disabled_reason,
            renewal_pending=renewal_pending,
        )

    def _snapshot_identifier(self, value: object, detail: str) -> str:
        try:
            normalized = _normalize_identifier(value, detail)
        except GuestError:
            raise GuestError("GUEST_SNAPSHOT_INVALID", detail) from None
        if normalized != value:
            raise GuestError("GUEST_SNAPSHOT_INVALID", detail)
        return normalized
