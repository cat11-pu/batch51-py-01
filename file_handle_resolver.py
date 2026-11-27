"""File handle resolver: mount namespaces, capability checks, generation-safe cache."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class FhError(ValueError):
    """Raised when the resolver refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Resolution:
    handle_id: str
    mount_id: str
    namespace: str
    path: str
    inode: int
    generation: int
    kind: str


class FileHandleResolver:
    """Resolve mount id plus file handle back to a path under access control."""

    def __init__(self, *, cache_size: int = 16) -> None:
        self.cache_size = cache_size
        self._lock = threading.RLock()

    def add_mount(self, mount_id: str, namespace: str, *, root: str = "/") -> None:
        raise NotImplementedError

    def remove_mount(self, mount_id: str) -> bool:
        raise NotImplementedError

    def enter_namespace(self, caller: str, namespace: str) -> None:
        raise NotImplementedError

    def grant(self, caller: str, mount_id: str | None = None, *,
              path_prefix: str = "/") -> None:
        raise NotImplementedError

    def add_object(self, handle_id: str, *, mount_id: str, path: str,
                   inode: int, generation: int = 1,
                   kind: str = "file") -> str:
        raise NotImplementedError

    def rename(self, handle_id: str, new_path: str) -> None:
        raise NotImplementedError

    def unlink(self, handle_id: str) -> None:
        raise NotImplementedError

    def recycle(self, handle_id: str, *, path: str,
                inode: int | None = None) -> int:
        raise NotImplementedError

    def resolve(self, caller: str, handle_id: str) -> Resolution:
        raise NotImplementedError

    def authorize(self, caller: str, handle_id: str) -> bool:
        raise NotImplementedError

    def describe(self, handle_id: str) -> dict:
        raise NotImplementedError

    def invalidate(self, handle_id: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
