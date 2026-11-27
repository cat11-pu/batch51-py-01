"""Upload filter bypass prober: filename variants, multipart parts and retrievability."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping


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

    def __init__(
        self,
        *,
        transport: Callable[[str, UploadPart], Any],
        max_uploads_per_target: int = 8,
        max_bytes: int = 2_000_000,
        max_variants: int = 12,
    ) -> None:
        self._transport = transport
        self.max_uploads_per_target = max_uploads_per_target
        self.max_bytes = max_bytes
        self.max_variants = max_variants
        self._lock = threading.RLock()
        self._target_locks: dict[str, threading.RLock] = {}

    def plan(self, base_name: str = "shell", *, kinds: tuple[str, ...] | None = None) -> tuple[Variant, ...]:
        raise NotImplementedError

    def build_part(self, variant: Variant) -> UploadPart:
        raise NotImplementedError

    def submit(self, target: str, variant: Variant) -> SubmitResult:
        raise NotImplementedError

    def judge(self, submission: SubmitResult, *, fetch: Callable[[str], Any] | None = None) -> BypassVerdict:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def submissions_for(self, target: str) -> tuple[SubmitResult, ...]:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
