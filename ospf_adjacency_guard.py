"""OSPF adjacency and link-state database guard."""

from __future__ import annotations

import threading
from dataclasses import dataclass

MAX_AGE = 3600.0
VALID_LSA_TYPES = (1, 2, 3, 4, 5)


class OspfError(ValueError):
    """Raised when an adjacency or link-state operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class HelloPacket:
    router_id: str
    area_id: str
    hello_interval: int
    dead_interval: int
    auth_type: int = 0
    auth_data: str = ""
    options: str = ""


@dataclass(frozen=True)
class DbDescription:
    area_id: str
    seq: int
    init: bool = False
    more: bool = True
    master: bool = True


@dataclass(frozen=True)
class Lsa:
    lsa_type: int
    link_state_id: str
    adv_router: str
    seq: int
    checksum: str
    age: float = 0.0
    body: str = ""


@dataclass(frozen=True)
class NeighborState:
    router_id: str
    iface: str
    area_id: str
    state: str
    dead_at: float | None


class OspfAdjacencyGuard:
    """Track neighbors per (router id, interface) and guard the link-state database."""

    NEIGHBOR_STATES = ("down", "init", "2way", "exstart", "exchange", "loading", "full")

    def __init__(self, *, router_id: str = "10.0.0.1", max_lsa: int = 128,
                 clock=None) -> None:
        self.router_id = router_id
        self.max_lsa = max_lsa
        self._clock = clock
        self._lock = threading.RLock()
        self._interfaces: dict[str, dict] = {}
        self._neighbors: dict[tuple[str, str], NeighborState] = {}
        self._lsdb: dict[tuple[int, str, str], tuple[Lsa, float]] = {}
        self._maxage: set[tuple[int, str, str]] = set()
        self._overflow = False
        self._stats = {
            "hellos": 0,
            "neighbors_down": 0,
            "lsa_loaded": 0,
            "lsa_refreshed": 0,
            "lsa_stale": 0,
            "lsa_duplicate": 0,
            "lsa_conflict": 0,
            "lsa_maxage": 0,
            "lsa_flushed": 0,
            "auth_failures": 0,
        }

    def configure_interface(self, iface: str, *, area_id: str,
                            hello_interval: int = 10, dead_interval: int = 40,
                            auth_type: int = 0, auth_data: str = "") -> None:
        raise NotImplementedError

    def process_hello(self, iface: str, hello: HelloPacket, *, now: float | None = None) -> NeighborState:
        raise NotImplementedError

    def verify_auth(self, iface: str, hello: HelloPacket, *, now: float | None = None) -> bool:
        raise NotImplementedError

    def accept_db_description(self, router_id: str, iface: str,
                              dbd: DbDescription, *, now: float | None = None) -> NeighborState:
        raise NotImplementedError

    def neighbor(self, router_id: str, iface: str) -> NeighborState | None:
        raise NotImplementedError

    def neighbors(self) -> list[NeighborState]:
        raise NotImplementedError

    def load_lsa(self, lsa: Lsa, *, now: float | None = None) -> str:
        raise NotImplementedError

    def lookup_lsa(self, lsa_type: int, link_state_id: str, adv_router: str) -> Lsa | None:
        raise NotImplementedError

    def lsdb(self) -> list[Lsa]:
        raise NotImplementedError

    def age_tick(self, *, now: float | None = None) -> int:
        raise NotImplementedError

    def flush_max_age(self, *, now: float | None = None) -> int:
        raise NotImplementedError

    def overflow_state(self) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
