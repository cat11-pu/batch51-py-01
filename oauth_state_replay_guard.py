"""授权码流程的回调准入：state 一次性、PKCE 仅 S256、redirect_uri 精确匹配。

模块只做本地状态机与判定，不涉及真实网络与密码学库；code_challenge 按
base64url(sha256(code_verifier)) 去填充的约定口径比对。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

DEFAULT_METHODS = ("S256",)

STAT_KEYS = (
    "authorizations",
    "callbacks",
    "exchanges",
    "replays",
    "rejections",
    "revoked",
    "restores",
)


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
        self.state_ttl = state_ttl
        self.code_ttl = code_ttl
        self.max_pending_per_client = max_pending_per_client
        self.min_verifier_len = min_verifier_len
        self.max_verifier_len = max_verifier_len
        self.max_clients = max_clients
        self._lock = threading.RLock()
        self._clients: dict[tuple[str, str], ClientRegistration] = {}
        self._requests: dict[tuple[str, str, str], AuthorizationRequest] = {}
        self._tokens: dict[str, dict] = {}
        self._audit: list[dict] = []
        self._stats = {name: 0 for name in STAT_KEYS}

    def register_client(self, tenant: str, client_id: str, *, redirect_uris,
                        methods=DEFAULT_METHODS) -> ClientRegistration:
        raise NotImplementedError

    def begin_authorization(self, tenant: str, client_id: str, *, redirect_uri: str,
                            state: str, code_challenge: str,
                            challenge_method: str = "S256",
                            scopes=("openid",), now: int) -> AuthorizationRequest:
        raise NotImplementedError

    def handle_callback(self, tenant: str, client_id: str, *, state: str, subject: str,
                        now: int) -> AuthorizationRequest:
        raise NotImplementedError

    def exchange_code(self, tenant: str, client_id: str, *, state: str, code: str,
                      redirect_uri: str, code_verifier: str, now: int) -> ExchangeReceipt:
        raise NotImplementedError

    def revoke_client(self, tenant: str, client_id: str, *, now: int) -> int:
        raise NotImplementedError

    def pending_for(self, tenant: str, client_id: str) -> tuple[AuthorizationRequest, ...]:
        raise NotImplementedError

    def audit_log(self) -> tuple[dict, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
