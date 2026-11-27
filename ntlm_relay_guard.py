"""NTLM relay guard: challenge-to-target binding, EPA enforcement, replay detection."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


_STATS_KEYS = (
    "issued",
    "accepted",
    "replayed",
    "mismatch",
    "expired",
    "epa_rejected",
)
_TARGET_FIELDS = {"service_id", "channel_id", "epa_policy"}
_CHALLENGE_FIELDS = {
    "challenge_id",
    "account",
    "service_id",
    "channel_id",
    "nonce",
    "issued_at",
    "expires_at",
    "state",
}
_EPA_POLICIES = {"off", "optional", "required"}
_CHALLENGE_STATES = {"pending", "consumed", "expired"}


class NtlmRelayError(ValueError):
    """Raised when the guard refuses a negotiation step."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TargetInfo:
    service_id: str
    channel_id: str
    epa_policy: str


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    account: str
    service_id: str
    channel_id: str
    nonce: str
    issued_at: str
    expires_at: str
    state: str


@dataclass(frozen=True)
class ResponseVerdict:
    challenge_id: str
    account: str
    service_id: str
    channel_id: str
    status: str


@dataclass(frozen=True)
class EpaVerdict:
    service_id: str
    policy: str
    status: str
    bound: bool


def _request_invalid(detail: object) -> NtlmRelayError:
    return NtlmRelayError("NTLM_REQUEST_INVALID", detail)


def _snapshot_invalid(detail: object) -> NtlmRelayError:
    return NtlmRelayError("NTLM_SNAPSHOT_INVALID", detail)


class NtlmRelayGuard:
    """Bind every challenge to one target service and one source channel."""

    def __init__(self, *, challenge_ttl: int = 120,
                 max_pending_per_account: int = 8, clock=None) -> None:
        if type(challenge_ttl) is not int or challenge_ttl < 0:
            raise ValueError("challenge_ttl must be a non-negative integer")
        if (type(max_pending_per_account) is not int
                or max_pending_per_account < 0):
            raise ValueError(
                "max_pending_per_account must be a non-negative integer")
        self.challenge_ttl = challenge_ttl
        self.max_pending_per_account = max_pending_per_account
        self._clock = clock
        self._lock = threading.RLock()
        self._targets: dict[str, TargetInfo] = {}
        self._challenges: dict[str, Challenge] = {}
        self._stats = {key: 0 for key in _STATS_KEYS}
        self._next_id = 1

    @staticmethod
    def _require_text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise _request_invalid(f"{field} must be a non-empty string")
        return value

    @staticmethod
    def _decode_time(value: object, field: str) -> tuple[datetime, str]:
        if not isinstance(value, str) or not value.strip():
            raise _request_invalid(f"{field} must be an ISO 8601 timestamp")
        try:
            parsed = datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise _request_invalid(f"invalid {field}") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise _request_invalid(f"{field} must include a timezone offset")
        return parsed, value

    def _resolve_now(self, now: str | None) -> tuple[datetime, str]:
        if now is not None:
            return self._decode_time(now, "now")
        if self._clock is None:
            current = datetime.now(timezone.utc)
        else:
            current = self._clock()
            if isinstance(current, str):
                return self._decode_time(current, "clock")
            if not isinstance(current, datetime):
                raise _request_invalid("clock must return datetime or string")
            if current.tzinfo is None or current.utcoffset() is None:
                raise _request_invalid("clock result must include a timezone")
        return current, current.isoformat(timespec="seconds")

    @staticmethod
    def _target_dict(target: TargetInfo) -> dict:
        return {
            "service_id": target.service_id,
            "channel_id": target.channel_id,
            "epa_policy": target.epa_policy,
        }

    @staticmethod
    def _challenge_dict(challenge: Challenge) -> dict:
        return {
            "challenge_id": challenge.challenge_id,
            "account": challenge.account,
            "service_id": challenge.service_id,
            "channel_id": challenge.channel_id,
            "nonce": challenge.nonce,
            "issued_at": challenge.issued_at,
            "expires_at": challenge.expires_at,
            "state": challenge.state,
        }

    @staticmethod
    def _challenge_expired(challenge: Challenge, current: datetime) -> bool:
        expires_at = datetime.fromisoformat(challenge.expires_at)
        return current > expires_at

    def _mark_expired(self, challenge_id: str) -> Challenge:
        challenge = self._challenges[challenge_id]
        expired = Challenge(
            challenge_id=challenge.challenge_id,
            account=challenge.account,
            service_id=challenge.service_id,
            channel_id=challenge.channel_id,
            nonce=challenge.nonce,
            issued_at=challenge.issued_at,
            expires_at=challenge.expires_at,
            state="expired",
        )
        self._challenges[challenge_id] = expired
        self._stats["expired"] += 1
        return expired

    def register_target(self, *, service_id: str, channel_id: str,
                        epa_policy: str = "optional") -> None:
        service_id = self._require_text(service_id, "service_id")
        channel_id = self._require_text(channel_id, "channel_id")
        if not isinstance(epa_policy, str) or epa_policy not in _EPA_POLICIES:
            raise _request_invalid("invalid epa_policy")
        target = TargetInfo(
            service_id=service_id,
            channel_id=channel_id,
            epa_policy=epa_policy,
        )
        with self._lock:
            self._targets[service_id] = target

    def target_info(self, service_id: str) -> TargetInfo:
        service_id = self._require_text(service_id, "service_id")
        with self._lock:
            try:
                return self._targets[service_id]
            except KeyError as exc:
                raise NtlmRelayError(
                    "NTLM_TARGET_UNKNOWN", service_id) from exc

    def issue_challenge(self, *, account: str, service_id: str,
                        channel_id: str, nonce: str | None = None,
                        now: str | None = None) -> Challenge:
        account = self._require_text(account, "account")
        service_id = self._require_text(service_id, "service_id")
        channel_id = self._require_text(channel_id, "channel_id")
        if nonce is not None:
            nonce = self._require_text(nonce, "nonce")
        current, issued_at = self._resolve_now(now)

        with self._lock:
            target = self._targets.get(service_id)
            if target is None:
                raise NtlmRelayError("NTLM_TARGET_UNKNOWN", service_id)
            if target.channel_id != channel_id:
                raise NtlmRelayError("NTLM_CHANNEL_MISMATCH", {
                    "expected": target.channel_id,
                    "actual": channel_id,
                })

            pending = sum(
                1 for challenge in self._challenges.values()
                if challenge.account == account and challenge.state == "pending"
            )
            if pending >= self.max_pending_per_account:
                raise NtlmRelayError("NTLM_PENDING_LIMIT", {
                    "account": account,
                    "limit": self.max_pending_per_account,
                })

            challenge_id = str(self._next_id)
            generated_nonce = (
                secrets.token_hex(16) if nonce is None else nonce)
            expires_at = (
                current + timedelta(seconds=self.challenge_ttl)
            ).isoformat(timespec="seconds")
            challenge = Challenge(
                challenge_id=challenge_id,
                account=account,
                service_id=service_id,
                channel_id=channel_id,
                nonce=generated_nonce,
                issued_at=issued_at,
                expires_at=expires_at,
                state="pending",
            )
            self._challenges[challenge_id] = challenge
            self._next_id += 1
            self._stats["issued"] += 1
            return challenge

    def bind_target(self, *, challenge_id: str, service_id: str,
                    channel_id: str, now: str | None = None) -> Challenge:
        challenge_id = self._require_text(challenge_id, "challenge_id")
        service_id = self._require_text(service_id, "service_id")
        channel_id = self._require_text(channel_id, "channel_id")
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise _request_invalid("unknown challenge")
            if challenge.state == "consumed":
                raise NtlmRelayError(
                    "NTLM_CHALLENGE_CONSUMED", challenge_id)
            current, _ = self._resolve_now(now)
            if (challenge.state == "expired"
                    or self._challenge_expired(challenge, current)):
                if challenge.state == "pending":
                    self._mark_expired(challenge_id)
                raise NtlmRelayError(
                    "NTLM_CHALLENGE_EXPIRED", challenge_id)

            target = self._targets.get(service_id)
            if target is None:
                raise NtlmRelayError("NTLM_TARGET_UNKNOWN", service_id)
            if target.channel_id != channel_id:
                self._stats["mismatch"] += 1
                raise NtlmRelayError("NTLM_CHANNEL_MISMATCH", {
                    "expected": target.channel_id,
                    "actual": channel_id,
                })

            rebound = Challenge(
                challenge_id=challenge.challenge_id,
                account=challenge.account,
                service_id=service_id,
                channel_id=channel_id,
                nonce=challenge.nonce,
                issued_at=challenge.issued_at,
                expires_at=challenge.expires_at,
                state="pending",
            )
            self._challenges[challenge_id] = rebound
            return rebound

    def verify_response(self, *, challenge_id: str, account: str,
                        channel_id: str, response_digest: str,
                        now: str | None = None) -> ResponseVerdict:
        challenge_id = self._require_text(challenge_id, "challenge_id")
        account = self._require_text(account, "account")
        channel_id = self._require_text(channel_id, "channel_id")

        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                raise _request_invalid("unknown challenge")

            if challenge.account != account:
                self._stats["mismatch"] += 1
                raise NtlmRelayError("NTLM_ACCOUNT_MISMATCH", {
                    "expected": challenge.account,
                    "actual": account,
                })

            if challenge.state == "consumed":
                self._stats["replayed"] += 1
                raise NtlmRelayError("NTLM_REPLAY_DETECTED", challenge_id)

            current, _ = self._resolve_now(now)
            if (challenge.state == "expired"
                    or self._challenge_expired(challenge, current)):
                if challenge.state == "pending":
                    self._mark_expired(challenge_id)
                raise NtlmRelayError("NTLM_CHALLENGE_EXPIRED", challenge_id)

            if challenge.channel_id != channel_id:
                self._stats["mismatch"] += 1
                raise NtlmRelayError("NTLM_CHANNEL_MISMATCH", {
                    "expected": challenge.channel_id,
                    "actual": channel_id,
                })

            target = self._targets.get(challenge.service_id)
            if target is not None and target.epa_policy == "required":
                self._stats["epa_rejected"] += 1
                raise NtlmRelayError(
                    "NTLM_CHANNEL_MISMATCH",
                    "extended protection required but not supplied",
                )

            if not isinstance(response_digest, str):
                raise _request_invalid("response_digest must be a string")
            material = (
                f"{challenge.nonce}|{challenge.account}|{challenge.channel_id}"
            ).encode("utf-8")
            expected = hashlib.sha256(material).hexdigest()
            if not hmac.compare_digest(
                    response_digest.encode("utf-8"), expected.encode("ascii")):
                self._stats["mismatch"] += 1
                raise NtlmRelayError(
                    "NTLM_RESPONSE_MISMATCH", challenge_id)

            consumed = Challenge(
                challenge_id=challenge.challenge_id,
                account=challenge.account,
                service_id=challenge.service_id,
                channel_id=challenge.channel_id,
                nonce=challenge.nonce,
                issued_at=challenge.issued_at,
                expires_at=challenge.expires_at,
                state="consumed",
            )
            self._challenges[challenge_id] = consumed
            self._stats["accepted"] += 1
            return ResponseVerdict(
                challenge_id=consumed.challenge_id,
                account=consumed.account,
                service_id=consumed.service_id,
                channel_id=consumed.channel_id,
                status="accepted",
            )

    def check_epa(self, *, service_id: str,
                  client_digest: str | None = None) -> EpaVerdict:
        service_id = self._require_text(service_id, "service_id")
        if client_digest is not None and not isinstance(client_digest, str):
            raise _request_invalid("client_digest must be a string")

        with self._lock:
            target = self._targets.get(service_id)
            if target is None:
                raise NtlmRelayError("NTLM_TARGET_UNKNOWN", service_id)

            bound = bool(client_digest and client_digest.strip())
            if target.epa_policy == "off":
                return EpaVerdict(
                    service_id=service_id,
                    policy=target.epa_policy,
                    status="disabled",
                    bound=False,
                )
            if target.epa_policy == "required" and not bound:
                self._stats["epa_rejected"] += 1
                raise NtlmRelayError(
                    "NTLM_CHANNEL_MISMATCH",
                    "extended protection required but not supplied",
                )
            return EpaVerdict(
                service_id=service_id,
                policy=target.epa_policy,
                status="required" if target.epa_policy == "required" else "ok",
                bound=bound,
            )

    def pending_for(self, account: str, *,
                    now: str | None = None) -> list[Challenge]:
        account = self._require_text(account, "account")
        current, _ = self._resolve_now(now)
        with self._lock:
            pending = [
                challenge for challenge in self._challenges.values()
                if (challenge.account == account
                    and challenge.state == "pending"
                    and not self._challenge_expired(challenge, current))
            ]
            pending.sort(key=lambda challenge: (
                datetime.fromisoformat(challenge.issued_at),
                int(challenge.challenge_id),
            ))
            return pending

    def expire_pending(self, *, now: str | None = None) -> int:
        current, _ = self._resolve_now(now)
        with self._lock:
            expired = [
                challenge_id
                for challenge_id, challenge in self._challenges.items()
                if (challenge.state == "pending"
                    and self._challenge_expired(challenge, current))
            ]
            for challenge_id in expired:
                self._mark_expired(challenge_id)
            return len(expired)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "targets": {
                    service_id: self._target_dict(target)
                    for service_id, target in self._targets.items()
                },
                "challenges": {
                    challenge_id: self._challenge_dict(challenge)
                    for challenge_id, challenge
                    in self._challenges.items()
                },
                "stats": dict(self._stats),
            }

    @staticmethod
    def _decode_state(
            state: object) -> tuple[
                dict[str, TargetInfo],
                dict[str, Challenge],
                dict[str, int],
                int,
            ]:
        if not isinstance(state, dict):
            raise _snapshot_invalid("state must be an object")
        if set(state) != {"version", "targets", "challenges", "stats"}:
            raise _snapshot_invalid("unexpected snapshot fields")
        if state["version"] != 1 or type(state["version"]) is not int:
            raise _snapshot_invalid("unsupported snapshot version")
        if not isinstance(state["targets"], dict):
            raise _snapshot_invalid("targets must be an object")
        if not isinstance(state["challenges"], dict):
            raise _snapshot_invalid("challenges must be an object")
        if not isinstance(state["stats"], dict):
            raise _snapshot_invalid("stats must be an object")

        decoded_targets: dict[str, TargetInfo] = {}
        for service_key, raw_target in state["targets"].items():
            if not isinstance(service_key, str) or not service_key.strip():
                raise _snapshot_invalid("invalid target key")
            if (not isinstance(raw_target, dict)
                    or set(raw_target) != _TARGET_FIELDS):
                raise _snapshot_invalid("invalid target record")
            target = TargetInfo(
                service_id=raw_target["service_id"],
                channel_id=raw_target["channel_id"],
                epa_policy=raw_target["epa_policy"],
            )
            if (not isinstance(target.service_id, str)
                    or not isinstance(target.channel_id, str)
                    or not target.service_id.strip()
                    or not target.channel_id.strip()
                    or target.service_id != service_key
                    or target.epa_policy not in _EPA_POLICIES):
                raise _snapshot_invalid("invalid target values")
            decoded_targets[service_key] = target

        decoded_challenges: dict[str, Challenge] = {}
        for challenge_key, raw_challenge in state["challenges"].items():
            if not isinstance(challenge_key, str) or not challenge_key.strip():
                raise _snapshot_invalid("invalid challenge key")
            if (not isinstance(raw_challenge, dict)
                    or set(raw_challenge) != _CHALLENGE_FIELDS):
                raise _snapshot_invalid("invalid challenge record")
            challenge = Challenge(
                challenge_id=raw_challenge["challenge_id"],
                account=raw_challenge["account"],
                service_id=raw_challenge["service_id"],
                channel_id=raw_challenge["channel_id"],
                nonce=raw_challenge["nonce"],
                issued_at=raw_challenge["issued_at"],
                expires_at=raw_challenge["expires_at"],
                state=raw_challenge["state"],
            )
            text_values = (
                challenge.challenge_id,
                challenge.account,
                challenge.service_id,
                challenge.channel_id,
                challenge.nonce,
                challenge.issued_at,
                challenge.expires_at,
            )
            if (not all(isinstance(value, str) and value.strip()
                        for value in text_values)
                    or challenge.challenge_id != challenge_key
                    or challenge.state not in _CHALLENGE_STATES
                    or challenge.service_id not in decoded_targets):
                raise _snapshot_invalid("invalid challenge values")
            try:
                numeric_id = int(challenge.challenge_id)
            except ValueError as exc:
                raise _snapshot_invalid(
                    "challenge_id must be numeric") from exc
            if numeric_id < 1 or str(numeric_id) != challenge.challenge_id:
                raise _snapshot_invalid("invalid challenge_id")
            try:
                issued_at = datetime.fromisoformat(challenge.issued_at)
                expires_at = datetime.fromisoformat(challenge.expires_at)
            except ValueError as exc:
                raise _snapshot_invalid(
                    "invalid challenge timestamps") from exc
            if (issued_at.tzinfo is None or issued_at.utcoffset() is None
                    or expires_at.tzinfo is None
                    or expires_at.utcoffset() is None
                    or expires_at < issued_at):
                raise _snapshot_invalid("invalid challenge timestamps")
            decoded_challenges[challenge_key] = challenge

        raw_stats = state["stats"]
        if set(raw_stats) != set(_STATS_KEYS):
            raise _snapshot_invalid("invalid stats fields")
        decoded_stats: dict[str, int] = {}
        for key in _STATS_KEYS:
            value = raw_stats[key]
            if type(value) is not int or value < 0:
                raise _snapshot_invalid("invalid stats value")
            decoded_stats[key] = value

        consumed = sum(
            1 for challenge in decoded_challenges.values()
            if challenge.state == "consumed")
        expired = sum(
            1 for challenge in decoded_challenges.values()
            if challenge.state == "expired")
        if decoded_stats["issued"] != len(decoded_challenges):
            raise _snapshot_invalid("issued stat does not match challenges")
        if decoded_stats["accepted"] != consumed:
            raise _snapshot_invalid("accepted stat does not match challenges")
        if decoded_stats["expired"] != expired:
            raise _snapshot_invalid("expired stat does not match challenges")

        next_id = max(
            (int(challenge_id) for challenge_id in decoded_challenges),
            default=0,
        ) + 1
        return decoded_targets, decoded_challenges, decoded_stats, next_id

    def restore(self, state: dict) -> None:
        try:
            targets, challenges, stats, next_id = self._decode_state(state)
        except NtlmRelayError:
            raise
        except Exception as exc:
            raise _snapshot_invalid("malformed snapshot") from exc

        pending_by_account: dict[str, int] = {}
        for challenge in challenges.values():
            if challenge.state == "pending":
                pending_by_account[challenge.account] = (
                    pending_by_account.get(challenge.account, 0) + 1)
        if any(count > self.max_pending_per_account
               for count in pending_by_account.values()):
            raise _snapshot_invalid("pending limit exceeded")

        with self._lock:
            self._targets = targets
            self._challenges = challenges
            self._stats = stats
            self._next_id = next_id

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
