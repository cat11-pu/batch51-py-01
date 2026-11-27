"""Commit graph sweeper for secrets in blob objects with rename tracking."""

from __future__ import annotations

import threading


SECRET_KINDS = (
    "aws_access_key_id",
    "private_key_block",
    "hex_secret_assignment",
)


class SweepError(ValueError):
    """Raised when the sweeper refuses a commit, object or cursor."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class GitBlobSecretSweeper:
    """Walk commits, scan each blob once and keep results per path."""

    def __init__(self, *, max_objects: int = 500, rename_threshold: float = 0.6) -> None:
        self.max_objects = max_objects
        self.rename_threshold = rename_threshold
        self._lock = threading.RLock()

    def add_commit(self, commit_id: str, *, parents=(), objects=()) -> dict:
        raise NotImplementedError

    def register_blob(self, oid: str, *, content) -> int:
        raise NotImplementedError

    def walk_commits(self, *, from_commit: str | None = None) -> tuple:
        raise NotImplementedError

    def scan_object(self, oid: str, *, content=None) -> dict:
        raise NotImplementedError

    def sweep(self, from_commit: str | None = None) -> dict:
        raise NotImplementedError

    def resume(self, cursor: dict) -> int:
        raise NotImplementedError

    def checkpoint(self) -> dict:
        raise NotImplementedError

    def follow_renames(self, commit_id: str) -> dict:
        raise NotImplementedError

    def results_for_path(self, path: str) -> tuple:
        raise NotImplementedError

    def describe_commit(self, commit_id: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError
