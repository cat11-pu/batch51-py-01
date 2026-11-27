"""授权码流程的回调准入：state 一次性、PKCE 仅 S256、redirect_uri 精确匹配。

模块只做本地状态机与判定，不涉及真实网络与密码学库；code_challenge 按
base64url(sha256(code_verifier)) 去填充的约定口径比对。
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import re
import secrets
import threading
from dataclasses import dataclass, replace
from typing import Any

DEFAULT_METHODS = ("S256",)
SNAPSHOT_VERSION = 1

STAT_KEYS = (
    "authorizations",
    "callbacks",
    "exchanges",
    "replays",
    "rejections",
    "revoked",
    "restores",
)

_STATE_RE = re.compile(r"[A-Za-z0-9._~-]{8,128}\Z")
_CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_VERIFIER_RE = re.compile(r"[A-Za-z0-9._~-]+\Z")
_SNAPSHOT_KEYS = {"version", "clients", "requests", "tokens", "audit", "stats"}
_CLIENT_FIELDS = {"tenant", "client_id", "redirect_uris", "methods", "revoked"}
_REQUEST_FIELDS = {
    "tenant", "client_id", "state", "redirect_uri", "code_challenge",
    "challenge_method", "scopes", "issued_at", "expires_at", "code",
    "code_issued_at", "consumed", "subject",
}
_TOKEN_FIELDS = {
    "tenant", "client_id", "subject", "scopes", "state", "redirect_uri",
    "issued_at",
}
_AUDIT_FIELDS = {"action", "tenant", "client_id", "state", "reason"}
_REPLAY_CODES = {"OAUTH_STATE_REUSED", "OAUTH_STATE_CONSUMED"}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_str_tuple(value: Any, *, nonempty: bool = False) -> bool:
    if not isinstance(value, (list, tuple)):
        return False
    return all(isinstance(item, str) and (item or not nonempty) for item in value)


class OauthError(ValueError):
    """拒绝请求时抛出，code 为大写原因码，detail 为可选说明。"""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClientRegistration:
    tenant: str
    client_id: str
    redirect_uris: tuple[str, ...]
    methods: tuple[str, ...]
    revoked: bool


@dataclass(frozen=True)
class AuthorizationRequest:
    tenant: str
    client_id: str
    state: str
    redirect_uri: str
    code_challenge: str
    challenge_method: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    code: str | None
    code_issued_at: int | None
    consumed: bool


@dataclass(frozen=True)
class ExchangeReceipt:
    tenant: str
    client_id: str
    subject: str
    scopes: tuple[str, ...]
    token_id: str
    state: str
    redirect_uri: str


class OauthStateReplayGuard:
    """按租户与客户端维护授权请求、回调与兑换的一次性状态。"""

    def __init__(self, *, state_ttl: int = 600, code_ttl: int = 120,
                 max_pending_per_client: int = 32, min_verifier_len: int = 43,
                 max_verifier_len: int = 128, max_clients: int = 64) -> None:
        values = {
            "state_ttl": state_ttl,
            "code_ttl": code_ttl,
            "max_pending_per_client": max_pending_per_client,
            "min_verifier_len": min_verifier_len,
            "max_verifier_len": max_verifier_len,
            "max_clients": max_clients,
        }
        if any(not _is_int(value) or value < 0 for value in values.values()):
            raise ValueError("guard limits must be non-negative integers")
        if min_verifier_len > max_verifier_len:
            raise ValueError("min_verifier_len exceeds max_verifier_len")

        self.state_ttl = state_ttl
        self.code_ttl = code_ttl
        self.max_pending_per_client = max_pending_per_client
        self.min_verifier_len = min_verifier_len
        self.max_verifier_len = max_verifier_len
        self.max_clients = max_clients
        self._lock = threading.RLock()
        self._clients: dict[tuple[str, str], ClientRegistration] = {}
        self._requests: dict[tuple[str, str, str], AuthorizationRequest] = {}
        self._subjects: dict[tuple[str, str, str], str] = {}
        self._tokens: dict[str, dict] = {}
        self._audit: list[dict] = []
        self._stats = {name: 0 for name in STAT_KEYS}

    def register_client(self, tenant: str, client_id: str, *, redirect_uris,
                        methods=DEFAULT_METHODS) -> ClientRegistration:
        if not isinstance(tenant, str) or not tenant or \
                not isinstance(client_id, str) or not client_id:
            raise OauthError("OAUTH_INVALID_REQUEST", "tenant and client_id are required")
        if isinstance(redirect_uris, str) or not isinstance(redirect_uris, (list, tuple)):
            raise OauthError("OAUTH_INVALID_REQUEST", "redirect_uris must be a sequence")
        if not _is_str_tuple(redirect_uris, nonempty=True):
            raise OauthError("OAUTH_INVALID_REQUEST", "invalid redirect_uri registration")
        if isinstance(methods, str) or not isinstance(methods, (list, tuple)):
            raise OauthError("OAUTH_INVALID_REQUEST", "methods must be a sequence")
        if not _is_str_tuple(methods, nonempty=True):
            raise OauthError("OAUTH_INVALID_REQUEST", "invalid method registration")

        key = (tenant, client_id)
        with self._lock:
            existing = self._clients.get(key)
            if existing is not None and existing.revoked:
                raise OauthError("OAUTH_CLIENT_UNKNOWN", client_id)
            if existing is None and len(self._clients) >= self.max_clients:
                raise OauthError("OAUTH_CAPACITY_EXCEEDED", client_id)
            registration = ClientRegistration(
                tenant=tenant,
                client_id=client_id,
                redirect_uris=tuple(redirect_uris),
                methods=tuple(methods),
                revoked=False,
            )
            self._clients[key] = registration
            return registration

    def begin_authorization(self, tenant: str, client_id: str, *, redirect_uri: str,
                            state: str, code_challenge: str,
                            challenge_method: str = "S256",
                            scopes=("openid",), now: int) -> AuthorizationRequest:
        with self._lock:
            try:
                self._require_now(now)
                client = self._require_client(tenant, client_id)
                if not isinstance(state, str) or not _STATE_RE.fullmatch(state):
                    raise OauthError("OAUTH_INVALID_REQUEST", "invalid state")
                if not isinstance(redirect_uri, str) or \
                        redirect_uri not in client.redirect_uris:
                    raise OauthError("OAUTH_REDIRECT_URI_MISMATCH", redirect_uri)
                if challenge_method != "S256" or challenge_method not in client.methods:
                    raise OauthError("OAUTH_PKCE_METHOD_REJECTED", challenge_method)
                if not isinstance(code_challenge, str) or \
                        not _CHALLENGE_RE.fullmatch(code_challenge):
                    raise OauthError("OAUTH_INVALID_REQUEST", "invalid code_challenge")
                if isinstance(scopes, str) or not isinstance(scopes, (list, tuple)):
                    raise OauthError("OAUTH_INVALID_REQUEST", "scopes must be a sequence")
                if not _is_str_tuple(scopes, nonempty=True):
                    raise OauthError("OAUTH_INVALID_REQUEST", "invalid scopes")

                key = (tenant, client_id, state)
                if key in self._requests:
                    raise OauthError("OAUTH_STATE_REUSED", state)

                pending = sum(
                    1 for request in self._requests.values()
                    if request.tenant == tenant
                    and request.client_id == client_id
                    and not request.consumed
                    and now < request.expires_at
                )
                if pending >= self.max_pending_per_client:
                    raise OauthError("OAUTH_CAPACITY_EXCEEDED", client_id)

                request = AuthorizationRequest(
                    tenant=tenant,
                    client_id=client_id,
                    state=state,
                    redirect_uri=redirect_uri,
                    code_challenge=code_challenge,
                    challenge_method=challenge_method,
                    scopes=tuple(scopes),
                    issued_at=now,
                    expires_at=now + self.state_ttl,
                    code=None,
                    code_issued_at=None,
                    consumed=False,
                )
                self._requests[key] = request
                self._stats["authorizations"] += 1
                self._append_audit("begin", tenant, client_id, state, "OAUTH_OK")
                return request
            except OauthError as exc:
                self._record_failure("begin", tenant, client_id, state, exc.code)
                raise

    def handle_callback(self, tenant: str, client_id: str, *, state: str, subject: str,
                        now: int) -> AuthorizationRequest:
        with self._lock:
            try:
                self._require_now(now)
                self._require_client(tenant, client_id)
                if not isinstance(state, str):
                    raise OauthError("OAUTH_STATE_UNKNOWN", state)
                key = (tenant, client_id, state)
                request = self._requests.get(key)
                if request is None:
                    raise OauthError("OAUTH_STATE_UNKNOWN", state)
                if request.consumed:
                    raise OauthError("OAUTH_STATE_CONSUMED", state)
                if now >= request.expires_at:
                    raise OauthError("OAUTH_STATE_EXPIRED", state)
                if request.code is not None:
                    raise OauthError("OAUTH_STATE_REUSED", state)
                if not isinstance(subject, str):
                    raise OauthError("OAUTH_INVALID_REQUEST", "subject must be a string")

                issued = replace(
                    request,
                    code=self._new_code(),
                    code_issued_at=now,
                )
                self._requests[key] = issued
                self._subjects[key] = subject
                self._stats["callbacks"] += 1
                self._append_audit("callback", tenant, client_id, state, "OAUTH_OK")
                return issued
            except OauthError as exc:
                self._record_failure("callback", tenant, client_id, state, exc.code)
                raise

    def exchange_code(self, tenant: str, client_id: str, *, state: str, code: str,
                      redirect_uri: str, code_verifier: str, now: int) -> ExchangeReceipt:
        with self._lock:
            try:
                self._require_now(now)
                client = self._require_client(tenant, client_id)
                if not isinstance(state, str):
                    raise OauthError("OAUTH_STATE_UNKNOWN", state)
                key = (tenant, client_id, state)
                request = self._requests.get(key)
                if request is None:
                    raise OauthError("OAUTH_STATE_UNKNOWN", state)
                if request.consumed:
                    raise OauthError("OAUTH_STATE_CONSUMED", state)
                if not isinstance(redirect_uri, str) or \
                        redirect_uri != request.redirect_uri or \
                        redirect_uri not in client.redirect_uris:
                    raise OauthError("OAUTH_REDIRECT_URI_MISMATCH", redirect_uri)
                if not isinstance(code, str) or request.code is None or \
                        not hmac.compare_digest(
                            code.encode("utf-8"), request.code.encode("ascii")
                        ):
                    raise OauthError("OAUTH_CODE_MISMATCH", "code")
                if request.code_issued_at is None:
                    raise OauthError("OAUTH_CODE_MISMATCH", "code")
                if now >= request.code_issued_at + self.code_ttl:
                    raise OauthError("OAUTH_CODE_EXPIRED", state)
                self._validate_verifier(code_verifier)

                expected = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode("ascii")).digest()
                ).decode("ascii").rstrip("=")
                if not hmac.compare_digest(expected, request.code_challenge):
                    raise OauthError("OAUTH_VERIFIER_MISMATCH", "code_verifier")

                subject = self._subjects.get(key)
                if subject is None:
                    raise OauthError("OAUTH_STATE_UNKNOWN", state)
                receipt = ExchangeReceipt(
                    tenant=request.tenant,
                    client_id=request.client_id,
                    subject=subject,
                    scopes=request.scopes,
                    token_id=self._new_token_id(),
                    state=request.state,
                    redirect_uri=request.redirect_uri,
                )
                consumed = replace(request, consumed=True)
                self._requests[key] = consumed
                self._tokens[receipt.token_id] = {
                    "tenant": request.tenant,
                    "client_id": request.client_id,
                    "subject": receipt.subject,
                    "scopes": request.scopes,
                    "state": request.state,
                    "redirect_uri": request.redirect_uri,
                    "issued_at": now,
                }
                self._stats["exchanges"] += 1
                self._append_audit("exchange", tenant, client_id, state, "OAUTH_OK")
                return receipt
            except OauthError as exc:
                self._record_failure("exchange", tenant, client_id, state, exc.code)
                raise

    def revoke_client(self, tenant: str, client_id: str, *, now: int) -> int:
        with self._lock:
            try:
                self._require_now(now)
                client = self._require_client(tenant, client_id)
                pending_keys = [
                    key for key, request in self._requests.items()
                    if request.tenant == tenant
                    and request.client_id == client_id
                    and not request.consumed
                ]
                cleared = len(pending_keys)
                for key in [
                    key for key, request in self._requests.items()
                    if request.tenant == tenant and request.client_id == client_id
                ]:
                    del self._requests[key]
                    self._subjects.pop(key, None)
                for token_id in [
                    token_id for token_id, token in self._tokens.items()
                    if token["tenant"] == tenant and token["client_id"] == client_id
                ]:
                    del self._tokens[token_id]
                self._clients[(tenant, client_id)] = replace(client, revoked=True)
                self._stats["revoked"] += 1
                self._append_audit("revoke", tenant, client_id, None, "OAUTH_OK")
                return cleared
            except OauthError as exc:
                self._record_failure("revoke", tenant, client_id, None, exc.code)
                raise

    def pending_for(self, tenant: str, client_id: str) -> tuple[AuthorizationRequest, ...]:
        with self._lock:
            return tuple(
                request for request in self._requests.values()
                if request.tenant == tenant
                and request.client_id == client_id
                and not request.consumed
            )

    def audit_log(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(copy.deepcopy(entry) for entry in self._audit)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "clients": {
                    key: self._client_dict(client)
                    for key, client in self._clients.items()
                },
                "requests": {
                    key: self._request_dict(request, self._subjects.get(key))
                    for key, request in self._requests.items()
                },
                "tokens": {
                    token_id: {
                        "tenant": token["tenant"],
                        "client_id": token["client_id"],
                        "subject": token["subject"],
                        "scopes": list(token["scopes"]),
                        "state": token["state"],
                        "redirect_uri": token["redirect_uri"],
                        "issued_at": token["issued_at"],
                    }
                    for token_id, token in self._tokens.items()
                },
                "audit": copy.deepcopy(self._audit),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = self._parse_snapshot(state)
            except OauthError:
                raise
            except Exception as exc:
                raise OauthError("OAUTH_SNAPSHOT_INVALID", None) from exc

            self._clients = candidate["clients"]
            self._requests = candidate["requests"]
            self._subjects = candidate["subjects"]
            self._tokens = candidate["tokens"]
            self._audit = candidate["audit"]
            self._stats = candidate["stats"]
            self._stats["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _require_now(self, now: Any) -> None:
        if not _is_int(now):
            raise OauthError("OAUTH_INVALID_REQUEST", "now must be an integer")

    def _require_client(self, tenant: Any, client_id: Any) -> ClientRegistration:
        if not isinstance(tenant, str) or not isinstance(client_id, str):
            raise OauthError("OAUTH_CLIENT_UNKNOWN", client_id)
        client = self._clients.get((tenant, client_id))
        if client is None or client.revoked:
            raise OauthError("OAUTH_CLIENT_UNKNOWN", client_id)
        return client

    def _validate_verifier(self, verifier: Any) -> None:
        if not isinstance(verifier, str) or \
                not self.min_verifier_len <= len(verifier) <= self.max_verifier_len or \
                not _VERIFIER_RE.fullmatch(verifier):
            raise OauthError("OAUTH_VERIFIER_INVALID", "code_verifier")

    def _new_code(self) -> str:
        existing = {request.code for request in self._requests.values()
                    if request.code is not None}
        while True:
            candidate = secrets.token_hex(24)
            if candidate not in existing:
                return candidate

    def _new_token_id(self) -> str:
        while True:
            candidate = secrets.token_hex(16)
            if candidate not in self._tokens:
                return candidate

    def _append_audit(self, action: str, tenant: Any, client_id: Any,
                      state: Any, reason: str | None) -> None:
        self._audit.append({
            "action": action,
            "tenant": tenant if isinstance(tenant, str) else str(tenant),
            "client_id": client_id if isinstance(client_id, str) else str(client_id),
            "state": state if isinstance(state, str) or state is None else str(state),
            "reason": reason,
        })

    def _record_failure(self, action: str, tenant: Any, client_id: Any,
                        state: Any, reason: str) -> None:
        self._stats["rejections"] += 1
        if reason in _REPLAY_CODES:
            self._stats["replays"] += 1
        self._append_audit(action, tenant, client_id, state, reason)

    @staticmethod
    def _client_dict(client: ClientRegistration) -> dict:
        return {
            "tenant": client.tenant,
            "client_id": client.client_id,
            "redirect_uris": list(client.redirect_uris),
            "methods": list(client.methods),
            "revoked": client.revoked,
        }

    @staticmethod
    def _request_dict(request: AuthorizationRequest, subject: str | None) -> dict:
        return {
            "tenant": request.tenant,
            "client_id": request.client_id,
            "state": request.state,
            "redirect_uri": request.redirect_uri,
            "code_challenge": request.code_challenge,
            "challenge_method": request.challenge_method,
            "scopes": list(request.scopes),
            "issued_at": request.issued_at,
            "expires_at": request.expires_at,
            "code": request.code,
            "code_issued_at": request.code_issued_at,
            "consumed": request.consumed,
            "subject": subject,
        }

    def _parse_snapshot(self, state: Any) -> dict:
        def invalid(detail: Any = None) -> None:
            raise OauthError("OAUTH_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            invalid("snapshot keys")
        if not _is_int(state["version"]) or state["version"] != SNAPSHOT_VERSION:
            invalid("version")

        raw_clients = state["clients"]
        if not isinstance(raw_clients, dict):
            invalid("clients")
        clients: dict[tuple[str, str], ClientRegistration] = {}
        for key, value in raw_clients.items():
            if not isinstance(key, tuple) or len(key) != 2 or \
                    not all(isinstance(item, str) and item for item in key):
                invalid("client key")
            if not isinstance(value, dict) or set(value) != _CLIENT_FIELDS:
                invalid("client record")
            tenant, client_id = key
            if value["tenant"] != tenant or value["client_id"] != client_id:
                invalid("client key")
            if not _is_str_tuple(value["redirect_uris"], nonempty=True) or \
                    not _is_str_tuple(value["methods"], nonempty=True) or \
                    not isinstance(value["revoked"], bool):
                invalid("client record")
            clients[key] = ClientRegistration(
                tenant=tenant,
                client_id=client_id,
                redirect_uris=tuple(value["redirect_uris"]),
                methods=tuple(value["methods"]),
                revoked=value["revoked"],
            )
        if len(clients) > self.max_clients:
            invalid("max_clients")

        raw_requests = state["requests"]
        if not isinstance(raw_requests, dict):
            invalid("requests")
        requests: dict[tuple[str, str, str], AuthorizationRequest] = {}
        subjects: dict[tuple[str, str, str], str] = {}
        for key, value in raw_requests.items():
            if not isinstance(key, tuple) or len(key) != 3 or \
                    not all(isinstance(item, str) and item for item in key):
                invalid("request key")
            if not isinstance(value, dict) or set(value) != _REQUEST_FIELDS:
                invalid("request record")
            tenant, client_id, request_state = key
            if (value["tenant"], value["client_id"], value["state"]) != key:
                invalid("request key")
            if not all(isinstance(value[field], str) and value[field]
                       for field in ("tenant", "client_id", "state", "redirect_uri",
                                     "code_challenge", "challenge_method")):
                invalid("request record")
            if not _STATE_RE.fullmatch(request_state) or \
                    not _CHALLENGE_RE.fullmatch(value["code_challenge"]):
                invalid("request shape")
            if value["challenge_method"] != "S256":
                invalid("request method")
            if not _is_str_tuple(value["scopes"], nonempty=True):
                invalid("request scopes")
            if not _is_int(value["issued_at"]) or not _is_int(value["expires_at"]):
                invalid("request times")
            if value["expires_at"] < value["issued_at"]:
                invalid("request expiry")
            if not isinstance(value["consumed"], bool):
                invalid("request consumed")
            code = value["code"]
            code_issued_at = value["code_issued_at"]
            if code is not None and (not isinstance(code, str) or not code):
                invalid("request code")
            if code_issued_at is not None and not _is_int(code_issued_at):
                invalid("request code time")
            if (code is None) != (code_issued_at is None):
                invalid("request code binding")
            if value["consumed"] and code is None:
                invalid("consumed request")
            subject = value["subject"]
            if subject is not None and not isinstance(subject, str):
                invalid("request subject")
            if (code is not None) != (subject is not None):
                invalid("request subject binding")
            if value["consumed"] and subject is None:
                invalid("consumed subject")
            client = clients.get((tenant, client_id))
            if client is None or client.revoked:
                invalid("request client")
            if value["redirect_uri"] not in client.redirect_uris:
                invalid("request redirect_uri")
            requests[key] = AuthorizationRequest(
                tenant=tenant,
                client_id=client_id,
                state=request_state,
                redirect_uri=value["redirect_uri"],
                code_challenge=value["code_challenge"],
                challenge_method=value["challenge_method"],
                scopes=tuple(value["scopes"]),
                issued_at=value["issued_at"],
                expires_at=value["expires_at"],
                code=code,
                code_issued_at=code_issued_at,
                consumed=value["consumed"],
            )
            if subject is not None:
                subjects[key] = subject

        raw_tokens = state["tokens"]
        if not isinstance(raw_tokens, dict):
            invalid("tokens")
        tokens: dict[str, dict] = {}
        for token_id, value in raw_tokens.items():
            if not isinstance(token_id, str) or len(token_id) != 32 or \
                    any(char not in "0123456789abcdef" for char in token_id):
                invalid("token id")
            if not isinstance(value, dict) or set(value) != _TOKEN_FIELDS:
                invalid("token record")
            if not all(isinstance(value[field], str) and value[field]
                       for field in ("tenant", "client_id", "state",
                                     "redirect_uri")) or \
                    not isinstance(value["subject"], str):
                invalid("token record")
            if not _is_str_tuple(value["scopes"], nonempty=True) or \
                    not _is_int(value["issued_at"]):
                invalid("token record")
            key = (value["tenant"], value["client_id"], value["state"])
            request = requests.get(key)
            if request is None or not request.consumed or \
                    request.redirect_uri != value["redirect_uri"] or \
                    request.scopes != tuple(value["scopes"]) or \
                    subjects.get(key) != value["subject"]:
                invalid("token request")
            client = clients.get((value["tenant"], value["client_id"]))
            if client is None or client.revoked:
                invalid("token client")
            tokens[token_id] = {
                "tenant": value["tenant"],
                "client_id": value["client_id"],
                "subject": value["subject"],
                "scopes": tuple(value["scopes"]),
                "state": value["state"],
                "redirect_uri": value["redirect_uri"],
                "issued_at": value["issued_at"],
            }

        consumed_requests = {key for key, request in requests.items()
                             if request.consumed}
        token_requests = {
            (token["tenant"], token["client_id"], token["state"])
            for token in tokens.values()
        }
        if consumed_requests != token_requests or \
                len(consumed_requests) != len(tokens):
            invalid("token ledger")

        raw_audit = state["audit"]
        if not isinstance(raw_audit, list):
            invalid("audit")
        audit: list[dict] = []
        for entry in raw_audit:
            if not isinstance(entry, dict) or set(entry) != _AUDIT_FIELDS:
                invalid("audit entry")
            if not all(isinstance(entry[field], str) and entry[field]
                       for field in ("action", "tenant", "client_id")):
                invalid("audit entry")
            if entry["state"] is not None and not isinstance(entry["state"], str):
                invalid("audit state")
            if entry["reason"] is not None and \
                    (not isinstance(entry["reason"], str) or not entry["reason"]):
                invalid("audit reason")
            audit.append(copy.deepcopy(entry))

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != set(STAT_KEYS):
            invalid("stats")
        stats: dict[str, int] = {}
        for name in STAT_KEYS:
            value = raw_stats[name]
            if not _is_int(value) or value < 0:
                invalid("stats")
            stats[name] = value
        if stats["authorizations"] < len(requests):
            invalid("authorization counter")
        if stats["callbacks"] < sum(1 for request in requests.values()
                                    if request.code is not None):
            invalid("callback counter")
        if stats["exchanges"] < len(tokens):
            invalid("exchange counter")
        if stats["revoked"] < sum(1 for client in clients.values()
                                  if client.revoked):
            invalid("revocation counter")

        return {
            "clients": clients,
            "requests": requests,
            "subjects": subjects,
            "tokens": tokens,
            "audit": audit,
            "stats": stats,
        }
