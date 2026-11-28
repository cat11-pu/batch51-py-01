"""多租户 JWT 校验：alg 族匹配、kid 形状校验、声明校验顺序与密钥轮换审计。

第三方密码学库不可用，签名核对通过注入的 backend(alg, material, signing_input, signature)
完成；本模块只负责编排：解析、选钥、算法与密钥类型绑定、声明顺序、审计与快照。
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
import threading
from dataclasses import dataclass
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

DEFAULT_ALGS = ("RS256", "ES256")

ALG_NONE_MARKERS = frozenset({"none", "None", "NONE", ""})

STAT_KEYS = ("verdicts", "rejected", "rotations", "revocations", "lookups", "restores")

SNAPSHOT_VERSION = 1

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_MISSING = object()


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
        if not isinstance(tenant, str) or not tenant:
            raise JwtError("JWT_INVALID_ARGUMENT", {"tenant": tenant, "reason": "invalid tenant"})
        if not isinstance(issuer, str) or not isinstance(audience, str):
            raise JwtError(
                "JWT_INVALID_ARGUMENT",
                {"tenant": tenant, "reason": "issuer and audience must be strings"},
            )
        with self._lock:
            profile = TenantProfile(tenant=tenant, issuer=issuer, audience=audience)
            self._tenants[tenant] = profile
            self._keys.setdefault(tenant, [])
            return profile

    def install_key(self, tenant: str, kid: str, *, alg: str, material: str, kind: str,
                    not_before: int = 0, expires_at: int | None = None) -> KeyRecord:
        with self._lock:
            if tenant not in self._tenants:
                raise JwtError("JWT_TENANT_UNKNOWN", {"tenant": tenant})
            self._validate_kid(kid)
            if not isinstance(alg, str) or alg not in ALG_FAMILIES:
                raise JwtError("JWT_ALG_REJECTED", {"alg": alg, "reason": "unsupported algorithm"})
            if not isinstance(kind, str) or not kind:
                raise JwtError("JWT_INVALID_ARGUMENT", {"kid": kid, "reason": "invalid key kind"})
            if not isinstance(material, (str, bytes)):
                raise JwtError("JWT_INVALID_ARGUMENT", {"kid": kid, "reason": "invalid key material"})
            self._validate_time_value("not_before", not_before, allow_none=False)
            self._validate_time_value("expires_at", expires_at, allow_none=True)

            rows = self._keys.setdefault(tenant, [])
            if any(row.kid == kid and row.alg == alg for row in rows):
                raise JwtError("JWT_KEY_CONFLICT", {"tenant": tenant, "kid": kid, "alg": alg})
            if len(rows) >= self.max_keys_per_tenant:
                raise JwtError(
                    "JWT_KEY_CAPACITY",
                    {"tenant": tenant, "limit": self.max_keys_per_tenant, "count": len(rows)},
                )

            record = KeyRecord(
                tenant=tenant,
                kid=kid,
                alg=alg,
                kind=kind,
                material=material,
                not_before=not_before,
                expires_at=expires_at,
                revoked=False,
                readonly=False,
            )
            rows.append(record)
            return record

    def rotate_key(self, tenant: str, kid: str, *, new_kid: str, alg: str, material: str,
                   kind: str, expires_at: int | None, now: int) -> KeyRecord:
        with self._lock:
            if tenant not in self._tenants:
                raise JwtError("JWT_TENANT_UNKNOWN", {"tenant": tenant})
            self._validate_kid(kid)
            self._validate_kid(new_kid)
            if not isinstance(alg, str) or alg not in ALG_FAMILIES:
                raise JwtError("JWT_ALG_REJECTED", {"alg": alg, "reason": "unsupported algorithm"})
            if not isinstance(kind, str) or not kind:
                raise JwtError("JWT_INVALID_ARGUMENT", {"kid": new_kid, "reason": "invalid key kind"})
            if not isinstance(material, (str, bytes)):
                raise JwtError(
                    "JWT_INVALID_ARGUMENT", {"kid": new_kid, "reason": "invalid key material"}
                )
            self._validate_time_value("expires_at", expires_at, allow_none=True)
            self._validate_time_value("now", now, allow_none=False)

            rows = self._keys.setdefault(tenant, [])
            sources = [row for row in rows if row.kid == kid]
            if not sources:
                raise JwtError("JWT_KEY_UNKNOWN", {"tenant": tenant, "kid": kid})
            active_sources = [row for row in sources if not row.revoked]
            if not active_sources:
                raise JwtError("JWT_KEY_REVOKED", {"tenant": tenant, "kid": kid})
            source = active_sources[-1]

            if new_kid == kid:
                if any(row.kid == new_kid and row.alg == alg for row in rows):
                    raise JwtError(
                        "JWT_KEY_CONFLICT",
                        {"tenant": tenant, "kid": new_kid, "alg": alg},
                    )
            elif any(row.kid == new_kid for row in rows):
                raise JwtError("JWT_KEY_CONFLICT", {"tenant": tenant, "kid": new_kid})

            if len(rows) >= self.max_keys_per_tenant:
                raise JwtError(
                    "JWT_KEY_CAPACITY",
                    {"tenant": tenant, "limit": self.max_keys_per_tenant, "count": len(rows)},
                )

            if new_kid == kid:
                old_index = rows.index(source)
                rows[old_index] = self._replace_key(source, readonly=True)
            else:
                for index, row in enumerate(rows):
                    if row.kid == kid:
                        rows[index] = self._replace_key(row, readonly=True)

            record = KeyRecord(
                tenant=tenant,
                kid=new_kid,
                alg=alg,
                kind=kind,
                material=material,
                not_before=now,
                expires_at=expires_at,
                revoked=False,
                readonly=False,
            )
            rows.append(record)
            self._stats["rotations"] += 1
            self._audit.append({
                "code": "JWT_KEY_ROTATED",
                "tenant": tenant,
                "kid": new_kid,
                "alg": alg,
                "key_lookups": 0,
                "detail": {"old_kid": kid, "new_kid": new_kid},
            })
            return record

    def revoke_key(self, tenant: str, kid: str, *, now: int) -> int:
        del now
        with self._lock:
            rows = self._keys.get(tenant)
            if not rows:
                return 0

            changed = 0
            first_alg = None
            for index, row in enumerate(rows):
                if row.kid == kid and not row.revoked:
                    if first_alg is None:
                        first_alg = row.alg
                    rows[index] = self._replace_key(row, revoked=True)
                    changed += 1
            if changed:
                self._stats["revocations"] += 1
                self._audit.append({
                    "code": "JWT_KEY_REVOKED",
                    "tenant": tenant,
                    "kid": kid,
                    "alg": first_alg,
                    "key_lookups": 0,
                    "detail": {"changed": changed},
                })
            return changed

    def decode_header(self, token: str) -> dict:
        with self._lock:
            _, header, _, _ = self._parse_token(token)
            return copy.deepcopy(header)

    def resolve_key(self, token: str, *, tenant: str, now: int) -> KeyRecord:
        with self._lock:
            _, header, _, _ = self._parse_token(token)
            alg = header.get("alg")
            kid = header.get("kid")
            self._validate_alg(alg)
            self._validate_kid(kid)
            return self._lookup_key_locked(tenant, kid, alg, now)

    def verify(self, token: str, *, tenant: str, now: int, backend: Callable[..., bool],
               expected_aud: str | None = None) -> Verdict:
        with self._lock:
            key_lookups = 0
            kid = None
            alg = None
            try:
                parts, header, claims, _ = self._parse_token(token)
                alg = header.get("alg")
                kid = header.get("kid")

                self._validate_alg(alg)
                self._validate_kid(kid)

                key_lookups = 1
                key = self._lookup_key_locked(tenant, kid, alg, now)

                signing_input = f"{parts[0]}.{parts[1]}"
                try:
                    signature_ok = bool(backend(alg, key.material, signing_input, parts[2]))
                except Exception as exc:
                    raise JwtError(
                        "JWT_SIGNATURE_INVALID",
                        {"reason": "signature backend failed", "error": str(exc)},
                    ) from exc
                if not signature_ok:
                    raise JwtError(
                        "JWT_SIGNATURE_INVALID",
                        {"kid": kid, "alg": alg, "reason": "signature mismatch"},
                    )

                profile = self._tenants.get(tenant)
                if profile is None:
                    raise JwtError("JWT_TENANT_UNKNOWN", {"tenant": tenant})
                self._validate_claims(claims, profile, now=now, expected_aud=expected_aud)

                warnings = ("JWT_KEY_READ_ONLY",) if key.readonly else ()
                verdict = Verdict(
                    tenant=tenant,
                    subject=claims.get("sub", ""),
                    kid=kid,
                    alg=alg,
                    claims=copy.deepcopy(claims),
                    warnings=warnings,
                    key_lookups=key_lookups,
                )
                self._stats["verdicts"] += 1
                self._audit.append({
                    "code": "JWT_OK",
                    "tenant": tenant,
                    "kid": kid,
                    "alg": alg,
                    "key_lookups": key_lookups,
                    "detail": None,
                })
                return verdict
            except JwtError as exc:
                self._stats["rejected"] += 1
                self._audit.append({
                    "code": exc.code,
                    "tenant": tenant,
                    "kid": kid,
                    "alg": alg,
                    "key_lookups": key_lookups,
                    "detail": copy.deepcopy(exc.detail),
                })
                raise

    def key_inventory(self, tenant: str, *, now: int | None = None) -> tuple[KeyRecord, ...]:
        del now
        with self._lock:
            return tuple(self._keys.get(tenant, ()))

    def audit_log(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(copy.deepcopy(self._audit))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "tenants": {
                    tenant: {"issuer": profile.issuer, "audience": profile.audience}
                    for tenant, profile in self._tenants.items()
                },
                "keys": {
                    tenant: [self._key_to_state(row) for row in rows]
                    for tenant, rows in self._keys.items()
                },
                "audit": copy.deepcopy(self._audit),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                tenants, keys, audit, stats = self._validate_snapshot(state)
            except JwtError:
                raise
            except Exception as exc:
                raise JwtError(
                    "JWT_SNAPSHOT_INVALID", {"reason": str(exc)}
                ) from exc

            self._tenants = tenants
            self._keys = keys
            self._audit = audit
            self._stats = stats
            self._stats["restores"] += 1

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _validate_snapshot(self, state: Any):
        if not isinstance(state, Mapping):
            self._snapshot_error("snapshot must be a mapping")
        expected_fields = {"version", "tenants", "keys", "audit", "stats"}
        if set(state.keys()) != expected_fields:
            self._snapshot_error("snapshot must contain exactly version, tenants, keys, audit, stats")

        version = state["version"]
        if (not isinstance(version, int) or isinstance(version, bool)
                or version != SNAPSHOT_VERSION):
            self._snapshot_error("unsupported snapshot version")

        tenants_raw = state["tenants"]
        if not isinstance(tenants_raw, Mapping):
            self._snapshot_error("tenants must be a mapping")
        tenants: dict[str, TenantProfile] = {}
        for tenant, profile_raw in tenants_raw.items():
            if not isinstance(tenant, str) or not tenant:
                self._snapshot_error("invalid tenant name")
            if not isinstance(profile_raw, Mapping):
                self._snapshot_error("tenant profile must be a mapping")
            issuer = profile_raw.get("issuer", _MISSING)
            audience = profile_raw.get("audience", _MISSING)
            if not isinstance(issuer, str) or not isinstance(audience, str):
                self._snapshot_error("tenant issuer and audience must be strings")
            tenants[tenant] = TenantProfile(
                tenant=tenant, issuer=issuer, audience=audience
            )

        keys_raw = state["keys"]
        if not isinstance(keys_raw, Mapping):
            self._snapshot_error("keys must be a mapping")
        keys: dict[str, list[KeyRecord]] = {}
        for tenant, rows_raw in keys_raw.items():
            if not isinstance(tenant, str) or tenant not in tenants:
                self._snapshot_error("key tenant must be registered")
            if not isinstance(rows_raw, (list, tuple)):
                self._snapshot_error("tenant keys must be a sequence")
            if len(rows_raw) > self.max_keys_per_tenant:
                self._snapshot_error("tenant key capacity exceeded")
            rows: list[KeyRecord] = []
            for row_raw in rows_raw:
                rows.append(self._key_from_state(tenant, row_raw))
            keys[tenant] = rows
        for tenant in tenants:
            keys.setdefault(tenant, [])

        audit_raw = state["audit"]
        if not isinstance(audit_raw, (list, tuple)):
            self._snapshot_error("audit must be a sequence")
        audit: list[dict] = []
        for entry_raw in audit_raw:
            if not isinstance(entry_raw, Mapping):
                self._snapshot_error("audit entry must be a mapping")
            required = {"code", "tenant", "kid", "alg", "key_lookups", "detail"}
            if set(entry_raw.keys()) != required:
                self._snapshot_error("invalid audit entry fields")
            code = entry_raw["code"]
            audit_tenant = entry_raw["tenant"]
            key_lookups = entry_raw["key_lookups"]
            if not isinstance(code, str) or not isinstance(audit_tenant, str):
                self._snapshot_error("invalid audit entry types")
            if (not isinstance(key_lookups, int) or isinstance(key_lookups, bool)
                    or key_lookups < 0):
                self._snapshot_error("invalid audit lookup count")
            audit.append(copy.deepcopy(dict(entry_raw)))

        stats_raw = state["stats"]
        if not isinstance(stats_raw, Mapping):
            self._snapshot_error("stats must be a mapping")
        if set(stats_raw.keys()) != set(STAT_KEYS):
            self._snapshot_error("invalid stats fields")
        stats: dict[str, int] = {}
        for name in STAT_KEYS:
            value = stats_raw[name]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                self._snapshot_error("stats values must be non-negative integers")
            stats[name] = value

        return tenants, keys, audit, stats

    def _key_from_state(self, tenant: str, raw: Any) -> KeyRecord:
        if not isinstance(raw, Mapping):
            self._snapshot_error("key record must be a mapping")
        required = {
            "tenant", "kid", "alg", "kind", "material", "not_before",
            "expires_at", "revoked", "readonly",
        }
        if set(raw.keys()) != required:
            self._snapshot_error("invalid key record fields")
        if raw["tenant"] != tenant:
            self._snapshot_error("key record tenant mismatch")
        kid = raw["kid"]
        if not isinstance(kid, str) or self._kid_invalid(kid):
            self._snapshot_error("invalid key record kid")
        alg = raw["alg"]
        if not isinstance(alg, str) or alg not in ALG_FAMILIES:
            self._snapshot_error("invalid key record algorithm")
        kind = raw["kind"]
        if not isinstance(kind, str) or not kind:
            self._snapshot_error("invalid key record kind")
        material = raw["material"]
        if not isinstance(material, (str, bytes)):
            self._snapshot_error("invalid key record material")
        not_before = raw["not_before"]
        expires_at = raw["expires_at"]
        if not isinstance(not_before, int) or isinstance(not_before, bool):
            self._snapshot_error("invalid key not_before")
        if expires_at is not None and (
                not isinstance(expires_at, int) or isinstance(expires_at, bool)):
            self._snapshot_error("invalid key expires_at")
        revoked = raw["revoked"]
        readonly = raw["readonly"]
        if not isinstance(revoked, bool) or not isinstance(readonly, bool):
            self._snapshot_error("invalid key flags")
        return KeyRecord(
            tenant=tenant,
            kid=kid,
            alg=alg,
            kind=kind,
            material=material,
            not_before=not_before,
            expires_at=expires_at,
            revoked=revoked,
            readonly=readonly,
        )

    @staticmethod
    def _key_to_state(row: KeyRecord) -> dict:
        return {
            "tenant": row.tenant,
            "kid": row.kid,
            "alg": row.alg,
            "kind": row.kind,
            "material": row.material,
            "not_before": row.not_before,
            "expires_at": row.expires_at,
            "revoked": row.revoked,
            "readonly": row.readonly,
        }

    @staticmethod
    def _snapshot_error(reason: str) -> None:
        raise JwtError("JWT_SNAPSHOT_INVALID", {"reason": reason})

    @staticmethod
    def _replace_key(row: KeyRecord, **changes: Any) -> KeyRecord:
        values = {
            "tenant": row.tenant,
            "kid": row.kid,
            "alg": row.alg,
            "kind": row.kind,
            "material": row.material,
            "not_before": row.not_before,
            "expires_at": row.expires_at,
            "revoked": row.revoked,
            "readonly": row.readonly,
        }
        values.update(changes)
        return KeyRecord(**values)

    def _parse_token(self, token: Any):
        if not isinstance(token, str):
            raise JwtError("JWT_MALFORMED", {"reason": "token must be a string"})
        try:
            token_bytes = token.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise JwtError("JWT_MALFORMED", {"reason": "token is not valid UTF-8"}) from exc
        if len(token_bytes) > self.max_token_bytes:
            raise JwtError(
                "JWT_MALFORMED",
                {"reason": "token too large", "size": len(token_bytes),
                 "limit": self.max_token_bytes},
            )

        parts = token.split(".")
        if len(parts) != 3:
            raise JwtError(
                "JWT_MALFORMED",
                {"reason": "token must have exactly three segments", "segments": len(parts)},
            )

        header_raw = self._decode_segment(parts[0], "header")
        claims_raw = self._decode_segment(parts[1], "claims")
        self._decode_segment(parts[2], "signature")

        try:
            header_text = header_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JwtError("JWT_MALFORMED", {"reason": "header is not valid UTF-8"}) from exc
        try:
            header = json.loads(header_text)
        except (TypeError, ValueError) as exc:
            raise JwtError("JWT_MALFORMED", {"reason": "header is not valid JSON"}) from exc
        if not isinstance(header, dict):
            raise JwtError("JWT_MALFORMED", {"reason": "header must be a JSON object"})

        nesting_depth = self._payload_nesting_depth(claims_raw, 1)
        if nesting_depth > self.max_nesting_depth:
            raise JwtError(
                "JWT_NESTING_LIMIT",
                {"depth": nesting_depth, "limit": self.max_nesting_depth},
            )

        try:
            claims_text = claims_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JwtError("JWT_MALFORMED", {"reason": "claims are not valid UTF-8"}) from exc
        try:
            claims = json.loads(claims_text)
        except (TypeError, ValueError) as exc:
            raise JwtError("JWT_MALFORMED", {"reason": "claims are not valid JSON"}) from exc
        if not isinstance(claims, dict):
            raise JwtError("JWT_MALFORMED", {"reason": "claims must be a JSON object"})

        return parts, header, claims, nesting_depth

    def _decode_segment(self, segment: str, label: str) -> bytes:
        if not isinstance(segment, str) or _B64URL_RE.fullmatch(segment) is None:
            raise JwtError(
                "JWT_MALFORMED",
                {"reason": "segment is not base64url", "segment": label},
            )
        if len(segment) % 4 == 1:
            raise JwtError(
                "JWT_MALFORMED",
                {"reason": "invalid base64url length", "segment": label},
            )
        padded = segment + ("=" * (-len(segment) % 4))
        try:
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        except (binascii.Error, ValueError) as exc:
            raise JwtError(
                "JWT_MALFORMED",
                {"reason": "segment is not decodable base64url", "segment": label},
            ) from exc

    def _payload_nesting_depth(self, raw: bytes, depth: int) -> int:
        if depth > self.max_nesting_depth:
            return depth
        try:
            text = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            return depth

        candidate = None
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            candidate = text
        else:
            if isinstance(parsed, str):
                candidate = parsed.strip()

        if not candidate:
            return depth
        parts = candidate.split(".")
        if len(parts) != 3:
            return depth
        if not all(_B64URL_RE.fullmatch(part) and len(part) % 4 != 1 for part in parts):
            return depth
        try:
            inner_header_raw = self._decode_segment(parts[0], "nested header")
            inner_header = json.loads(inner_header_raw.decode("utf-8"))
            inner_claims_raw = self._decode_segment(parts[1], "nested claims")
            self._decode_segment(parts[2], "nested signature")
        except (JwtError, UnicodeDecodeError, TypeError, ValueError):
            return depth
        if not isinstance(inner_header, dict):
            return depth
        return self._payload_nesting_depth(inner_claims_raw, depth + 1)

    def _validate_alg(self, alg: Any) -> None:
        reason = None
        if not isinstance(alg, str):
            reason = "algorithm must be a string"
        else:
            stripped = alg.strip()
            if not stripped:
                reason = "algorithm is empty"
            elif stripped.lower() == "none":
                reason = "unsigned tokens are not allowed"
            elif alg not in self.allowed_algs:
                reason = "algorithm is not allowed"
            elif alg not in ALG_FAMILIES:
                reason = "algorithm is unsupported"
        if reason is not None:
            raise JwtError(
                "JWT_ALG_REJECTED",
                {"alg": alg, "allowed_algs": list(self.allowed_algs), "reason": reason},
            )

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str) or self._kid_invalid(kid):
            raise JwtError(
                "JWT_KID_REJECTED",
                {"kid": kid, "reason": "kid must be non-empty without path separators or '..'"},
            )

    @staticmethod
    def _kid_invalid(kid: str) -> bool:
        return kid == "" or "/" in kid or "\\" in kid or ".." in kid

    def _lookup_key_locked(self, tenant: str, kid: str, alg: str, now: int) -> KeyRecord:
        self._stats["lookups"] += 1
        rows = self._keys.get(tenant, ())
        candidates = [row for row in rows if row.kid == kid]
        family = ALG_FAMILIES.get(alg)

        exact = [row for row in candidates if row.alg == alg]
        if not exact:
            if any(row.kind == family for row in candidates):
                raise JwtError(
                    "JWT_KEY_UNKNOWN",
                    {"tenant": tenant, "kid": kid, "alg": alg},
                )
            if candidates:
                raise JwtError(
                    "JWT_ALG_CONFUSION",
                    {"kid": kid, "alg": alg, "kind": candidates[0].kind},
                )
            raise JwtError(
                "JWT_KEY_UNKNOWN",
                {"tenant": tenant, "kid": kid, "alg": alg},
            )

        active = [row for row in exact if not row.revoked]
        if not active:
            raise JwtError(
                "JWT_KEY_REVOKED",
                {"tenant": tenant, "kid": kid, "alg": alg},
            )

        usable = [
            row for row in active
            if now >= row.not_before and (row.expires_at is None or now < row.expires_at)
        ]
        row = usable[-1] if usable else active[-1]

        if family != row.kind:
            raise JwtError(
                "JWT_ALG_CONFUSION",
                {"kid": kid, "alg": alg, "kind": row.kind},
            )
        if row.expires_at is not None and now >= row.expires_at:
            raise JwtError(
                "JWT_KEY_EXPIRED",
                {"tenant": tenant, "kid": kid, "alg": alg,
                 "now": now, "expires_at": row.expires_at},
            )
        if now < row.not_before:
            raise JwtError(
                "JWT_KEY_NOT_YET_VALID",
                {"tenant": tenant, "kid": kid, "alg": alg,
                 "now": now, "not_before": row.not_before},
            )
        return row

    def _validate_claims(self, claims: Mapping[str, Any], profile: TenantProfile, *,
                         now: int, expected_aud: str | None) -> None:
        exp = self._claim_time(claims, "exp")
        if exp is not None and exp <= now - self.clock_skew:
            raise JwtError(
                "JWT_EXPIRED",
                {"exp": exp, "now": now, "clock_skew": self.clock_skew},
            )

        nbf = self._claim_time(claims, "nbf")
        if nbf is not None and nbf > now + self.clock_skew:
            raise JwtError(
                "JWT_NOT_YET_VALID",
                {"nbf": nbf, "now": now, "clock_skew": self.clock_skew},
            )

        iat = self._claim_time(claims, "iat")
        if iat is not None and iat > now:
            raise JwtError(
                "JWT_ISSUED_IN_FUTURE",
                {"iat": iat, "now": now, "clock_skew": self.clock_skew},
            )

        issuer = claims.get("iss", _MISSING)
        if issuer != profile.issuer:
            actual = None if issuer is _MISSING else issuer
            raise JwtError(
                "JWT_ISSUER_MISMATCH",
                {"expected": profile.issuer, "actual": actual},
            )

        audience = claims.get("aud", _MISSING)
        expected = profile.audience if expected_aud is None else expected_aud
        if isinstance(audience, str):
            audience_ok = audience == expected
        elif (isinstance(audience, (list, tuple))
              and bool(audience)
              and all(isinstance(item, str) for item in audience)):
            audience_ok = expected in audience
        else:
            audience_ok = False
        if not audience_ok:
            actual = None if audience is _MISSING else audience
            raise JwtError(
                "JWT_AUDIENCE_MISMATCH",
                {"expected": expected, "actual": actual},
            )

    @staticmethod
    def _claim_time(claims: Mapping[str, Any], name: str):
        value = claims.get(name, _MISSING)
        if value is _MISSING:
            return None
        if not isinstance(value, int) or isinstance(value, bool):
            raise JwtError(
                "JWT_CLAIM_INVALID",
                {"claim": name, "reason": "claim must be an integer epoch second"},
            )
        return value

    @staticmethod
    def _validate_time_value(name: str, value: Any, *, allow_none: bool) -> None:
        if value is None and allow_none:
            return
        if not isinstance(value, int) or isinstance(value, bool):
            raise JwtError(
                "JWT_INVALID_ARGUMENT",
                {"argument": name, "reason": "must be an integer epoch second"},
            )
