"""SCRAM channel binding guard: mechanism policy, downgrade refusal, binding check."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


_SCRAM_SHA_256_PLUS = "SCRAM-SHA-256-PLUS"
_SCRAM_SHA_256 = "SCRAM-SHA-256"
_DEFAULT_SUPPORTED = frozenset({_SCRAM_SHA_256_PLUS, _SCRAM_SHA_256})

_STATES = frozenset({"offered", "negotiated", "verified", "rejected"})
_CORE_STATS = ("offers", "negotiations", "verified", "downgrades", "mismatch")
_DEFAULT_STATS = {
    "offers": 0,
    "negotiations": 0,
    "verified": 0,
    "downgrades": 0,
    "mismatch": 0,
    "binding_missing": 0,
    "channel_unbound": 0,
}


class ScramError(ValueError):
    """Raised when a negotiation step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Offer:
    session_id: str
    mechanisms: tuple[str, ...]
    has_binding: bool
    state: str


@dataclass(frozen=True)
class BindingVerdict:
    session_id: str
    mechanism: str
    status: str
    digest: str


@dataclass
class _Session:
    session_id: str
    mechanisms: tuple[str, ...]
    state: str = "offered"
    mechanism: str | None = None
    channel_digest: str | None = None
    binding_at_offer: str | None = None
    reject_reason: str | None = None


class ScramChannelBindingGuard:
    """Decide whether a session may continue with its actual binding data."""

    def __init__(self, *, policy: str = "require", supported=None,
                 clock=None) -> None:
        if policy not in {"require", "optional"}:
            raise ScramError("SCRAM_REQUEST_INVALID",
                             {"reason": "unknown policy", "policy": policy})
        self.policy = policy
        self.supported = self._normalise_supported(supported)
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, _Session] = {}
        self._closed: set[str] = set()
        self._stats = dict(_DEFAULT_STATS)

    @staticmethod
    def _normalise_supported(supported) -> frozenset[str]:
        if supported is None:
            return _DEFAULT_SUPPORTED
        if isinstance(supported, (str, bytes, bytearray)):
            raise ScramError("SCRAM_REQUEST_INVALID",
                             {"reason": "supported must be a collection"})
        try:
            values = tuple(supported)
        except TypeError as exc:
            raise ScramError(
                "SCRAM_REQUEST_INVALID",
                {"reason": "supported must be a collection"},
            ) from exc
        for value in values:
            if not isinstance(value, str) or not value:
                raise ScramError(
                    "SCRAM_REQUEST_INVALID",
                    {"reason": "supported mechanisms must be non-empty strings"},
                )
        return frozenset(values)

    @staticmethod
    def _session_id(session_id) -> str:
        if not isinstance(session_id, str) or not session_id:
            raise ScramError(
                "SCRAM_REQUEST_INVALID",
                {"reason": "session_id must be a non-empty string"},
            )
        return session_id

    @staticmethod
    def _is_binding_mechanism(mechanism: str) -> bool:
        return mechanism.endswith("-PLUS")

    @staticmethod
    def _optional_data(value, field_name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ScramError(
                "SCRAM_REQUEST_INVALID",
                {"reason": f"{field_name} must be a string"},
            )
        return value or None

    def _clean_mechanisms(self, mechanisms) -> tuple[str, ...]:
        if mechanisms is None or isinstance(mechanisms, (str, bytes, bytearray)):
            raise ScramError(
                "SCRAM_REQUEST_INVALID",
                {"reason": "mechanisms must be a non-empty collection"},
            )
        try:
            raw = tuple(mechanisms)
        except TypeError as exc:
            raise ScramError(
                "SCRAM_REQUEST_INVALID",
                {"reason": "mechanisms must be a non-empty collection"},
            ) from exc
        if not raw:
            raise ScramError(
                "SCRAM_REQUEST_INVALID",
                {"reason": "mechanisms must not be empty"},
            )
        for mechanism in raw:
            if not isinstance(mechanism, str) or not mechanism:
                raise ScramError(
                    "SCRAM_REQUEST_INVALID",
                    {"reason": "mechanism names must be non-empty strings"},
                )
        unsupported = sorted({m for m in raw if m not in self.supported})
        if unsupported:
            raise ScramError(
                "SCRAM_MECHANISM_UNSUPPORTED",
                {"reason": "unsupported mechanism", "mechanisms": unsupported},
            )
        return tuple(sorted(set(raw)))

    def _get_session(self, session_id) -> _Session:
        sid = self._session_id(session_id)
        session = self._sessions.get(sid)
        if session is None:
            if sid in self._closed:
                raise ScramError(
                    "SCRAM_SESSION_CLOSED",
                    {"reason": "session is closed", "session_id": sid},
                )
            raise ScramError(
                "SCRAM_SESSION_UNKNOWN",
                {"reason": "session was never offered", "session_id": sid},
            )
        return session

    @staticmethod
    def _state_error(session: _Session, reason: str) -> ScramError:
        return ScramError(
            "SCRAM_STATE_INVALID",
            {
                "reason": reason,
                "session_id": session.session_id,
                "state": session.state,
            },
        )

    def offer(self, *, session_id: str, mechanisms,
              binding_data: str | None = None) -> Offer:
        with self._lock:
            sid = self._session_id(session_id)
            if sid in self._closed:
                raise ScramError(
                    "SCRAM_SESSION_CLOSED",
                    {"reason": "session is closed", "session_id": sid},
                )
            if sid in self._sessions:
                raise ScramError(
                    "SCRAM_STATE_INVALID",
                    {
                        "reason": "session was already offered",
                        "session_id": sid,
                        "state": self._sessions[sid].state,
                    },
                )
            mechs = self._clean_mechanisms(mechanisms)
            actual_binding = self._optional_data(binding_data, "binding_data")
            session = _Session(
                session_id=sid,
                mechanisms=mechs,
                binding_at_offer=actual_binding,
            )
            self._sessions[sid] = session
            self._stats["offers"] += 1
            return Offer(
                session_id=sid,
                mechanisms=mechs,
                has_binding=actual_binding is not None,
                state=session.state,
            )

    def select_mechanism(self, *, session_id: str,
                         mechanism: str | None = None) -> str:
        with self._lock:
            session = self._get_session(session_id)
            if session.state != "offered":
                raise self._state_error(
                    session, "mechanism can only be selected while offered")

            if mechanism is not None:
                if not isinstance(mechanism, str) or not mechanism:
                    raise ScramError(
                        "SCRAM_REQUEST_INVALID",
                        {"reason": "mechanism must be a non-empty string"},
                    )
                if mechanism not in self.supported:
                    raise ScramError(
                        "SCRAM_MECHANISM_UNSUPPORTED",
                        {"reason": "unsupported mechanism",
                         "mechanism": mechanism},
                    )
                if mechanism not in session.mechanisms:
                    raise ScramError(
                        "SCRAM_MECHANISM_NOT_OFFERED",
                        {"reason": "mechanism was not offered",
                         "mechanism": mechanism,
                         "session_id": session.session_id},
                    )
                if (self.policy == "require"
                        and not self._is_binding_mechanism(mechanism)):
                    session.state = "rejected"
                    session.reject_reason = f"downgrade:{mechanism}"
                    self._stats["downgrades"] += 1
                    raise ScramError(
                        "SCRAM_DOWNGRADE_REJECTED",
                        {
                            "reason": "non-binding mechanism rejected "
                                      "under require policy",
                            "mechanism": mechanism,
                            "session_id": session.session_id,
                        },
                    )
                chosen = mechanism
            else:
                binding_choices = [
                    m for m in session.mechanisms
                    if self._is_binding_mechanism(m)
                ]
                if self.policy == "require":
                    if not binding_choices:
                        raise ScramError(
                            "SCRAM_NO_ACCEPTABLE_MECHANISM",
                            {
                                "reason": "no binding-capable mechanism offered",
                                "session_id": session.session_id,
                            },
                        )
                    chosen = binding_choices[0]
                else:
                    chosen = (binding_choices[0] if binding_choices
                              else session.mechanisms[0])

            session.mechanism = chosen
            session.state = "negotiated"
            session.reject_reason = None
            self._stats["negotiations"] += 1
            return chosen

    def bind_channel(self, *, session_id: str, channel_digest: str) -> None:
        with self._lock:
            session = self._get_session(session_id)
            if not isinstance(channel_digest, str) or not channel_digest:
                raise ScramError(
                    "SCRAM_REQUEST_INVALID",
                    {"reason": "channel_digest must be a non-empty string"},
                )
            if session.state == "offered":
                raise self._state_error(
                    session, "mechanism must be selected before binding")
            if session.state == "rejected":
                raise self._state_error(
                    session, "rejected session cannot bind a channel")

            previous = session.channel_digest
            if session.state == "verified":
                if previous == channel_digest:
                    return
                session.channel_digest = channel_digest
                session.state = "negotiated"
                session.reject_reason = None
                return

            session.channel_digest = channel_digest
            session.reject_reason = None

    def verify_binding(self, *, session_id: str,
                       binding_data: str | None) -> BindingVerdict:
        with self._lock:
            session = self._get_session(session_id)
            if session.state != "negotiated":
                raise self._state_error(
                    session,
                    "binding can only be verified after negotiation",
                )
            if session.channel_digest is None:
                self._stats["channel_unbound"] += 1
                raise ScramError(
                    "SCRAM_CHANNEL_UNBOUND",
                    {
                        "reason": "channel digest was never registered",
                        "session_id": session.session_id,
                    },
                )
            if binding_data is None or binding_data == "":
                self._stats["binding_missing"] += 1
                session.reject_reason = "binding_data_missing"
                raise ScramError(
                    "SCRAM_CHANNEL_UNBOUND",
                    {
                        "reason": "binding data is missing",
                        "session_id": session.session_id,
                    },
                )
            if not isinstance(binding_data, str):
                raise ScramError(
                    "SCRAM_REQUEST_INVALID",
                    {"reason": "binding_data must be a string"},
                )
            if binding_data != session.channel_digest:
                self._stats["mismatch"] += 1
                session.reject_reason = "binding_mismatch"
                raise ScramError(
                    "SCRAM_BINDING_MISMATCH",
                    {
                        "reason": "binding data does not match channel digest",
                        "session_id": session.session_id,
                    },
                )

            session.state = "verified"
            session.reject_reason = None
            self._stats["verified"] += 1
            return BindingVerdict(
                session_id=session.session_id,
                mechanism=session.mechanism,
                status="verified",
                digest=session.channel_digest,
            )

    def reject_downgrade(self, *, session_id: str, mechanism: str) -> str:
        with self._lock:
            session = self._get_session(session_id)
            if session.state != "offered":
                raise self._state_error(
                    session, "downgrade rejection is only valid while offered")
            if not isinstance(mechanism, str) or not mechanism:
                raise ScramError(
                    "SCRAM_REQUEST_INVALID",
                    {"reason": "mechanism must be a non-empty string"},
                )
            if mechanism not in self.supported:
                raise ScramError(
                    "SCRAM_MECHANISM_UNSUPPORTED",
                    {"reason": "unsupported mechanism", "mechanism": mechanism},
                )
            if self._is_binding_mechanism(mechanism):
                raise ScramError(
                    "SCRAM_REQUEST_INVALID",
                    {"reason": "only non-binding mechanisms are downgrades",
                     "mechanism": mechanism},
                )
            if mechanism not in session.mechanisms:
                raise ScramError(
                    "SCRAM_MECHANISM_NOT_OFFERED",
                    {"reason": "mechanism was not offered",
                     "mechanism": mechanism,
                     "session_id": session.session_id},
                )
            session.state = "rejected"
            session.reject_reason = f"downgrade:{mechanism}"
            self._stats["downgrades"] += 1
            return "SCRAM_DOWNGRADE_REJECTED"

    def session_state(self, session_id: str) -> str:
        with self._lock:
            sid = self._session_id(session_id)
            session = self._sessions.get(sid)
            if session is None:
                raise ScramError(
                    "SCRAM_SESSION_UNKNOWN",
                    {"reason": "session was never offered", "session_id": sid},
                )
            return session.state

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            sid = self._session_id(session_id)
            if sid in self._sessions:
                del self._sessions[sid]
                self._closed.add(sid)
                return True
            return False

    def snapshot(self) -> dict:
        with self._lock:
            sessions = {}
            for sid, session in self._sessions.items():
                sessions[sid] = {
                    "session_id": session.session_id,
                    "mechanisms": tuple(session.mechanisms),
                    "state": session.state,
                    "mechanism": session.mechanism,
                    "channel_digest": session.channel_digest,
                    "binding_at_offer": session.binding_at_offer,
                    "reject_reason": session.reject_reason,
                }
            return copy.deepcopy({
                "version": 1,
                "sessions": sessions,
                "stats": dict(self._stats),
            })

    @staticmethod
    def _snapshot_error(reason: str) -> ScramError:
        return ScramError("SCRAM_SNAPSHOT_INVALID", {"reason": reason})

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise self._snapshot_error("snapshot must be a mapping")
                if set(state) != {"version", "sessions", "stats"}:
                    raise self._snapshot_error("invalid top-level fields")
                if (isinstance(state["version"], bool)
                        or state["version"] != 1):
                    raise self._snapshot_error("unsupported snapshot version")

                sessions_raw = state["sessions"]
                stats_raw = state["stats"]
                if not isinstance(sessions_raw, dict):
                    raise self._snapshot_error("sessions must be a mapping")
                if not isinstance(stats_raw, dict):
                    raise self._snapshot_error("stats must be a mapping")

                new_stats = dict(_DEFAULT_STATS)
                for key, value in stats_raw.items():
                    if (not isinstance(key, str)
                            or isinstance(value, bool)
                            or not isinstance(value, int)
                            or value < 0):
                        raise self._snapshot_error("invalid stats entry")
                    new_stats[key] = value
                for key in _CORE_STATS:
                    if key not in stats_raw:
                        raise self._snapshot_error(
                            f"missing stats entry: {key}")

                new_sessions: dict[str, _Session] = {}
                for sid, raw in sessions_raw.items():
                    if not isinstance(sid, str) or not sid:
                        raise self._snapshot_error("invalid session id")
                    if not isinstance(raw, dict):
                        raise self._snapshot_error("session record must be a mapping")

                    mechanisms_raw = raw.get("mechanisms")
                    if (mechanisms_raw is None
                            or isinstance(
                                mechanisms_raw, (str, bytes, bytearray))):
                        raise self._snapshot_error("invalid mechanisms")
                    try:
                        mechanisms = tuple(mechanisms_raw)
                    except TypeError as exc:
                        raise self._snapshot_error(
                            "invalid mechanisms") from exc
                    if not mechanisms:
                        raise self._snapshot_error("empty mechanisms")
                    for mechanism in mechanisms:
                        if (not isinstance(mechanism, str)
                                or not mechanism
                                or mechanism not in self.supported):
                            raise self._snapshot_error(
                                "invalid or unsupported mechanism")

                    session_state = raw.get("state")
                    if session_state not in _STATES:
                        raise self._snapshot_error("invalid session state")

                    mechanism = raw.get("mechanism")
                    if mechanism is not None:
                        if (not isinstance(mechanism, str)
                                or mechanism not in mechanisms):
                            raise self._snapshot_error(
                                "selected mechanism was not offered")

                    channel_digest = raw.get("channel_digest")
                    if channel_digest is not None and (
                            not isinstance(channel_digest, str)
                            or not channel_digest):
                        raise self._snapshot_error("invalid channel digest")

                    binding_at_offer = raw.get(
                        "binding_at_offer", raw.get("binding_data"))
                    if binding_at_offer is not None and (
                            not isinstance(binding_at_offer, str)
                            or not binding_at_offer):
                        raise self._snapshot_error(
                            "invalid offer binding data")

                    reject_reason = raw.get("reject_reason")
                    if (reject_reason is not None
                            and not isinstance(reject_reason, str)):
                        raise self._snapshot_error("invalid reject reason")

                    embedded_id = raw.get("session_id", sid)
                    if embedded_id != sid:
                        raise self._snapshot_error(
                            "session id does not match record key")

                    if session_state == "offered":
                        if mechanism is not None or channel_digest is not None:
                            raise self._snapshot_error(
                                "offered session has negotiated data")
                    elif session_state == "negotiated":
                        if mechanism is None:
                            raise self._snapshot_error(
                                "negotiated session has no mechanism")
                    elif session_state == "verified":
                        if mechanism is None or channel_digest is None:
                            raise self._snapshot_error(
                                "verified session has incomplete binding")

                    new_sessions[sid] = _Session(
                        session_id=sid,
                        mechanisms=tuple(sorted(set(mechanisms))),
                        state=session_state,
                        mechanism=mechanism,
                        channel_digest=channel_digest,
                        binding_at_offer=binding_at_offer,
                        reject_reason=reject_reason,
                    )
            except ScramError as exc:
                if exc.code == "SCRAM_SNAPSHOT_INVALID":
                    raise
                raise self._snapshot_error(str(exc)) from exc

            self._sessions = new_sessions
            self._stats = new_stats
            self._closed.clear()

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
