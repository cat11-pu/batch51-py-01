"""多租户 JWT 校验：alg 族匹配、kid 形状校验、声明校验顺序与密钥轮换审计。

第三方密码学库不可用，签名核对通过注入的 backend(alg, material, signing_input, signature)
完成；本模块只负责编排：解析、选钥、算法与密钥类型绑定、声明顺序、审计与快照。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

ALG_FAMILIES = {
    "HS256": "hmac",
    "HS384": "hmac",
    "HS512": "hmac",
    "RS256": "rsa",
    "RS384": "rsa",
    "RS512": "rsa",
    "ES256": "ec",
    "ES384": "ec",
    "ES512": "ec",
}

ALG_NONE_MARKERS = frozenset({"none", "None", "NONE", ""})

DEFAULT_ALGS = ("RS256", "ES256")

STAT_KEYS = ("verdicts", "rejected", "rotations", "revocations", "lookups", "restores")


class JwtError(ValueError):
    """拒绝校验时抛出，code 为大写原因码，detail 为可选说明。"""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TenantProfile:
    tenant: str
    issuer: str
    audience: str


@dataclass(frozen=True)
class KeyRecord:
    tenant: str
    kid: str
    alg: str
    kind: str
    material: str
    not_before: int
    expires_at: int | None
    revoked: bool
    readonly: bool


@dataclass(frozen=True)
class Verdict:
    tenant: str
    subject: str
    kid: str
    alg: str
    claims: Mapping[str, Any]
    warnings: tuple[str, ...]
    key_lookups: int


class JwtAlgConfusionGuard:
    """按租户维护签发方资料与密钥库，校验顺序与选钥规则由实现决定。"""

    def __init__(self, *, allowed_algs=DEFAULT_ALGS, clock_skew: int = 0,
                 max_token_bytes: int = 8192, max_nesting_depth: int = 1,
                 max_keys_per_tenant: int = 64) -> None:
        self.allowed_algs = tuple(allowed_algs)
        self.clock_skew = clock_skew
        self.max_token_bytes = max_token_bytes
        self.max_nesting_depth = max_nesting_depth
        self.max_keys_per_tenant = max_keys_per_tenant
        self._lock = threading.RLock()
        self._tenants: dict[str, TenantProfile] = {}
        self._keys: dict[str, list[KeyRecord]] = {}
        self._audit: list[dict] = []
        self._stats = {name: 0 for name in STAT_KEYS}

    def register_tenant(self, tenant: str, *, issuer: str, audience: str) -> TenantProfile:
        raise NotImplementedError

    def install_key(self, tenant: str, kid: str, *, alg: str, material: str, kind: str,
                    not_before: int = 0, expires_at: int | None = None) -> KeyRecord:
        raise NotImplementedError

    def rotate_key(self, tenant: str, kid: str, *, new_kid: str, alg: str, material: str,
                   kind: str, expires_at: int | None, now: int) -> KeyRecord:
        raise NotImplementedError

    def revoke_key(self, tenant: str, kid: str, *, now: int) -> int:
        raise NotImplementedError

    def decode_header(self, token: str) -> dict:
        raise NotImplementedError

    def resolve_key(self, token: str, *, tenant: str, now: int) -> KeyRecord:
        raise NotImplementedError

    def verify(self, token: str, *, tenant: str, now: int, backend: Callable[..., bool],
               expected_aud: str | None = None) -> Verdict:
        raise NotImplementedError

    def key_inventory(self, tenant: str, *, now: int | None = None) -> tuple[KeyRecord, ...]:
        raise NotImplementedError

    def audit_log(self) -> tuple[dict, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
