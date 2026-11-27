"""OSPF adjacency and link-state database guard."""

from __future__ import annotations

import copy
import math
import threading
import time
from dataclasses import asdict, dataclass, replace

MAX_AGE = 3600.0
VALID_LSA_TYPES = (1, 2, 3, 4, 5)
SNAPSHOT_VERSION = 1

STAT_KEYS = (
    "hellos",
    "neighbors_down",
    "lsa_loaded",
    "lsa_refreshed",
    "lsa_stale",
    "lsa_duplicate",
    "lsa_conflict",
    "lsa_maxage",
    "lsa_flushed",
    "auth_failures",
)


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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _invalid(detail: object) -> OspfError:
    return OspfError("OSPF_INVALID_ARGUMENT", detail)


class OspfAdjacencyGuard:
    """Track neighbors per (router id, interface) and guard the link-state database."""

    NEIGHBOR_STATES = ("down", "init", "2way", "exstart", "exchange", "loading", "full")

    def __init__(self, *, router_id: str = "10.0.0.1", max_lsa: int = 128,
                 clock=None) -> None:
        if not isinstance(router_id, str) or not router_id.strip():
            raise _invalid({"field": "router_id"})
        if not _is_int(max_lsa) or max_lsa < 0:
            raise _invalid({"field": "max_lsa", "value": max_lsa})
        if clock is not None and not (callable(clock) or hasattr(clock, "now")):
            raise _invalid({"field": "clock"})

        self.router_id = router_id
        self.max_lsa = max_lsa
        self._clock = clock
        self._lock = threading.RLock()
        self._interfaces: dict[str, dict] = {}
        self._neighbors: dict[tuple[str, str], NeighborState] = {}
        self._lsdb: dict[tuple[int, str, str], tuple[Lsa, float]] = {}
        self._maxage: set[tuple[int, str, str]] = set()
        self._overflow = False
        self._stats = {key: 0 for key in STAT_KEYS}

    def _now(self, now: float | None) -> float:
        if now is None:
            if self._clock is None:
                return time.monotonic()
            if callable(self._clock):
                now = self._clock()
            else:
                now = self._clock.now()
        if not _is_number(now):
            raise _invalid({"field": "now", "value": now})
        return float(now)

    def _interface(self, iface: object) -> dict:
        if not isinstance(iface, str) or not iface.strip():
            raise _invalid({"field": "iface", "value": iface})
        config = self._interfaces.get(iface)
        if config is None:
            raise _invalid({"field": "iface", "value": iface, "reason": "unconfigured"})
        return config

    @staticmethod
    def _check_hello(hello: object) -> None:
        if not isinstance(hello, HelloPacket):
            raise _invalid({"field": "hello", "reason": "not a HelloPacket"})
        if not isinstance(hello.router_id, str) or not hello.router_id.strip():
            raise _invalid({"field": "hello.router_id"})
        if not isinstance(hello.area_id, str) or not hello.area_id.strip():
            raise _invalid({"field": "hello.area_id"})
        if not _is_number(hello.hello_interval):
            raise _invalid({"field": "hello.hello_interval"})
        if not _is_number(hello.dead_interval):
            raise _invalid({"field": "hello.dead_interval"})
        if not _is_int(hello.auth_type):
            raise _invalid({"field": "hello.auth_type"})
        if not isinstance(hello.auth_data, str):
            raise _invalid({"field": "hello.auth_data"})

    def _check_auth(self, config: dict, hello: HelloPacket) -> None:
        if (
            hello.auth_type != config["auth_type"]
            or hello.auth_data != config["auth_data"]
        ):
            self._stats["auth_failures"] += 1
            raise OspfError(
                "OSPF_AUTH_FAILED",
                {"auth_type": hello.auth_type, "router_id": hello.router_id},
            )

    @staticmethod
    def _check_dbd(dbd: object) -> None:
        if not isinstance(dbd, DbDescription):
            raise _invalid({"field": "dbd", "reason": "not a DbDescription"})
        if not isinstance(dbd.area_id, str) or not dbd.area_id.strip():
            raise _invalid({"field": "dbd.area_id"})
        if not _is_int(dbd.seq) or dbd.seq < 0:
            raise _invalid({"field": "dbd.seq", "value": dbd.seq})

    @staticmethod
    def _check_lsa(lsa: object, code: str) -> None:
        if not isinstance(lsa, Lsa):
            raise OspfError(code, {"field": "lsa", "reason": "not an Lsa"})
        if not _is_int(lsa.lsa_type) or lsa.lsa_type not in VALID_LSA_TYPES:
            raise OspfError(code, {"field": "lsa_type", "value": lsa.lsa_type})
        if not isinstance(lsa.link_state_id, str) or not lsa.link_state_id.strip():
            raise OspfError(code, {"field": "link_state_id", "value": lsa.link_state_id})
        if not isinstance(lsa.adv_router, str) or not lsa.adv_router.strip():
            raise OspfError(code, {"field": "adv_router", "value": lsa.adv_router})
        if not _is_int(lsa.seq) or lsa.seq < 0:
            raise OspfError(code, {"field": "seq", "value": lsa.seq})
        if not _is_number(lsa.age) or lsa.age < 0:
            raise OspfError(code, {"field": "age", "value": lsa.age})

    @staticmethod
    def _lsa_key(lsa_type: object, link_state_id: object, adv_router: object,
                 code: str = "OSPF_INVALID_ARGUMENT") -> tuple[int, str, str]:
        if not _is_int(lsa_type) or lsa_type not in VALID_LSA_TYPES:
            raise OspfError(code, {"field": "lsa_type", "value": lsa_type})
        if not isinstance(link_state_id, str) or not link_state_id.strip():
            raise OspfError(code, {"field": "link_state_id", "value": link_state_id})
        if not isinstance(adv_router, str) or not adv_router.strip():
            raise OspfError(code, {"field": "adv_router", "value": adv_router})
        return (lsa_type, link_state_id, adv_router)

    def configure_interface(self, iface: str, *, area_id: str,
                            hello_interval: int = 10, dead_interval: int = 40,
                            auth_type: int = 0, auth_data: str = "") -> None:
        if not isinstance(iface, str) or not iface.strip():
            raise _invalid({"field": "iface", "value": iface})
        if not isinstance(area_id, str) or not area_id.strip():
            raise _invalid({"field": "area_id", "value": area_id})
        if not _is_number(hello_interval) or hello_interval <= 0:
            raise _invalid({"field": "hello_interval", "value": hello_interval})
        if not _is_number(dead_interval) or dead_interval <= 0:
            raise _invalid({"field": "dead_interval", "value": dead_interval})
        if not _is_int(auth_type):
            raise _invalid({"field": "auth_type", "value": auth_type})
        if not isinstance(auth_data, str):
            raise _invalid({"field": "auth_data", "value": auth_data})

        with self._lock:
            self._interfaces[iface] = {
                "area_id": area_id,
                "hello_interval": hello_interval,
                "dead_interval": dead_interval,
                "auth_type": auth_type,
                "auth_data": auth_data,
            }

    def process_hello(self, iface: str, hello: HelloPacket, *,
                      now: float | None = None) -> NeighborState:
        with self._lock:
            config = self._interface(iface)
            self._check_hello(hello)
            if (
                hello.hello_interval != config["hello_interval"]
                or hello.dead_interval != config["dead_interval"]
                or hello.area_id != config["area_id"]
            ):
                raise OspfError(
                    "OSPF_HELLO_MISMATCH",
                    {
                        "hello_interval": hello.hello_interval,
                        "dead_interval": hello.dead_interval,
                        "area_id": hello.area_id,
                    },
                )
            self._check_auth(config, hello)
            timestamp = self._now(now)

            key = (hello.router_id, iface)
            current = self._neighbors.get(key)
            if current is None or current.state == "down":
                state = "init"
            else:
                state = current.state
            neighbor = NeighborState(
                router_id=hello.router_id,
                iface=iface,
                area_id=config["area_id"],
                state=state,
                dead_at=timestamp + config["dead_interval"],
            )
            self._neighbors[key] = neighbor
            self._stats["hellos"] += 1
            return neighbor

    def verify_auth(self, iface: str, hello: HelloPacket, *,
                    now: float | None = None) -> bool:
        with self._lock:
            config = self._interface(iface)
            self._check_hello(hello)
            self._check_auth(config, hello)
            return True

    def accept_db_description(self, router_id: str, iface: str,
                              dbd: DbDescription, *,
                              now: float | None = None) -> NeighborState:
        with self._lock:
            config = self._interface(iface)
            if not isinstance(router_id, str) or not router_id.strip():
                raise _invalid({"field": "router_id", "value": router_id})
            self._check_dbd(dbd)

            key = (router_id, iface)
            current = self._neighbors.get(key)
            if current is None:
                raise _invalid(
                    {"field": "router_id", "value": router_id,
                     "reason": "unknown neighbor"}
                )

            if dbd.area_id != config["area_id"]:
                if current.state == "down":
                    return current
                neighbor = replace(current, state="init")
                self._neighbors[key] = neighbor
                return neighbor

            if current.state == "down":
                return current
            if current.state in ("loading", "full"):
                state = "full" if not dbd.more else current.state
            elif current.state == "init" and dbd.init:
                state = "exstart"
            else:
                state = "exchange"
            neighbor = replace(current, state=state)
            self._neighbors[key] = neighbor
            return neighbor

    def neighbor(self, router_id: str, iface: str) -> NeighborState | None:
        with self._lock:
            return self._neighbors.get((router_id, iface))

    def neighbors(self) -> list[NeighborState]:
        with self._lock:
            return list(self._neighbors.values())

    def load_lsa(self, lsa: Lsa, *, now: float | None = None) -> str:
        with self._lock:
            self._check_lsa(lsa, "OSPF_INVALID_ARGUMENT")
            key = (lsa.lsa_type, lsa.link_state_id, lsa.adv_router)
            timestamp = self._now(now)

            existing = self._lsdb.get(key)
            if existing is None:
                if len(self._lsdb) >= self.max_lsa:
                    self._overflow = True
                    raise OspfError(
                        "OSPF_LSDB_OVERFLOW",
                        {"key": key, "max_lsa": self.max_lsa},
                    )
                self._lsdb[key] = (lsa, timestamp)
                self._stats["lsa_loaded"] += 1
                return "loaded"

            stored, _ = existing
            if lsa.seq > stored.seq:
                self._lsdb[key] = (lsa, timestamp)
                self._maxage.discard(key)
                self._stats["lsa_refreshed"] += 1
                return "refreshed"
            if lsa.seq < stored.seq:
                self._stats["lsa_stale"] += 1
                return "stale"
            if lsa.checksum == stored.checksum:
                self._stats["lsa_duplicate"] += 1
                return "duplicate"
            self._stats["lsa_conflict"] += 1
            return "conflict"

    def lookup_lsa(self, lsa_type: int, link_state_id: str,
                   adv_router: str) -> Lsa | None:
        key = self._lsa_key(lsa_type, link_state_id, adv_router)
        with self._lock:
            entry = self._lsdb.get(key)
            return entry[0] if entry is not None else None

    def lsdb(self) -> list[Lsa]:
        with self._lock:
            return [entry[0] for entry in self._lsdb.values()]

    def age_tick(self, *, now: float | None = None) -> int:
        with self._lock:
            timestamp = self._now(now)
            marked = 0
            for key, (lsa, received_at) in self._lsdb.items():
                if key in self._maxage:
                    continue
                effective_age = lsa.age + max(0.0, timestamp - received_at)
                if effective_age >= MAX_AGE:
                    self._maxage.add(key)
                    marked += 1
            if marked:
                self._stats["lsa_maxage"] += marked

            for key, neighbor in list(self._neighbors.items()):
                if (
                    neighbor.state != "down"
                    and neighbor.dead_at is not None
                    and timestamp >= neighbor.dead_at
                ):
                    self._neighbors[key] = replace(neighbor, state="down")
                    self._stats["neighbors_down"] += 1
            return marked

    def flush_max_age(self, *, now: float | None = None) -> int:
        with self._lock:
            flushed = 0
            for key in list(self._maxage):
                if key in self._lsdb:
                    del self._lsdb[key]
                    flushed += 1
                self._maxage.discard(key)
            if flushed:
                self._stats["lsa_flushed"] += flushed
            if len(self._lsdb) < self.max_lsa:
                self._overflow = False
            return flushed

    def overflow_state(self) -> bool:
        with self._lock:
            return self._overflow

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "neighbors": [asdict(neighbor) for neighbor in self._neighbors.values()],
                "lsdb": [
                    {"lsa": asdict(lsa), "received_at": received_at}
                    for lsa, received_at in self._lsdb.values()
                ],
                "maxage": [list(key) for key in sorted(self._maxage)],
                "overflow": self._overflow,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            invalid = OspfError("OSPF_SNAPSHOT_INVALID", {"reason": "malformed state"})
            if not isinstance(state, dict):
                raise invalid
            expected_keys = {"version", "neighbors", "lsdb", "maxage",
                             "overflow", "stats"}
            if set(state) != expected_keys:
                raise invalid
            if not _is_int(state["version"]) or state["version"] != SNAPSHOT_VERSION:
                raise invalid
            if not isinstance(state["neighbors"], list):
                raise invalid
            if not isinstance(state["lsdb"], list):
                raise invalid
            if not isinstance(state["maxage"], list):
                raise invalid
            if not isinstance(state["overflow"], bool):
                raise invalid
            if not isinstance(state["stats"], dict):
                raise invalid

            stats = state["stats"]
            if set(stats) != set(STAT_KEYS):
                raise invalid
            for value in stats.values():
                if not _is_int(value) or value < 0:
                    raise invalid

            neighbors: dict[tuple[str, str], NeighborState] = {}
            for item in state["neighbors"]:
                if isinstance(item, NeighborState):
                    record = {
                        "router_id": item.router_id,
                        "iface": item.iface,
                        "area_id": item.area_id,
                        "state": item.state,
                        "dead_at": item.dead_at,
                    }
                elif isinstance(item, dict):
                    record = item
                else:
                    raise invalid
                if set(record) != {"router_id", "iface", "area_id", "state", "dead_at"}:
                    raise invalid
                router_id = record["router_id"]
                iface = record["iface"]
                area_id = record["area_id"]
                neighbor_state = record["state"]
                dead_at = record["dead_at"]
                if not isinstance(router_id, str) or not router_id.strip():
                    raise invalid
                if not isinstance(iface, str) or not iface.strip():
                    raise invalid
                if not isinstance(area_id, str) or not area_id.strip():
                    raise invalid
                if neighbor_state not in self.NEIGHBOR_STATES:
                    raise invalid
                if dead_at is not None and not _is_number(dead_at):
                    raise invalid
                neighbor = NeighborState(
                    router_id=router_id,
                    iface=iface,
                    area_id=area_id,
                    state=neighbor_state,
                    dead_at=None if dead_at is None else float(dead_at),
                )
                key = (router_id, iface)
                if key in neighbors:
                    raise invalid
                neighbors[key] = neighbor

            lsdb: dict[tuple[int, str, str], tuple[Lsa, float]] = {}
            for item in state["lsdb"]:
                if not isinstance(item, dict):
                    raise invalid
                if "lsa" in item:
                    raw_lsa = item.get("lsa")
                    received_at = item.get("received_at")
                    if set(item) != {"lsa", "received_at"}:
                        raise invalid
                    if not isinstance(raw_lsa, dict):
                        raise invalid
                    lsa_values = raw_lsa
                else:
                    received_at = item.get("received_at")
                    lsa_fields = {
                        "lsa_type", "link_state_id", "adv_router", "seq",
                        "checksum", "age", "body",
                    }
                    if set(item) != lsa_fields | {"received_at"}:
                        raise invalid
                    lsa_values = {
                        key: item[key]
                        for key in lsa_fields
                    }
                    if set(lsa_values) != {
                        "lsa_type", "link_state_id", "adv_router", "seq",
                        "checksum", "age", "body",
                    }:
                        raise invalid
                if not isinstance(lsa_values, dict) or set(lsa_values) != {
                    "lsa_type", "link_state_id", "adv_router", "seq",
                    "checksum", "age", "body",
                }:
                    raise invalid
                if not _is_number(received_at):
                    raise invalid
                try:
                    lsa = Lsa(
                        lsa_type=lsa_values["lsa_type"],
                        link_state_id=lsa_values["link_state_id"],
                        adv_router=lsa_values["adv_router"],
                        seq=lsa_values["seq"],
                        checksum=copy.deepcopy(lsa_values["checksum"]),
                        age=lsa_values["age"],
                        body=copy.deepcopy(lsa_values["body"]),
                    )
                    self._check_lsa(lsa, "OSPF_SNAPSHOT_INVALID")
                except OspfError:
                    raise
                except (KeyError, TypeError, ValueError):
                    raise invalid
                key = (lsa.lsa_type, lsa.link_state_id, lsa.adv_router)
                if key in lsdb:
                    raise invalid
                lsdb[key] = (lsa, float(received_at))

            if len(lsdb) > self.max_lsa:
                raise invalid

            maxage: set[tuple[int, str, str]] = set()
            for raw_key in state["maxage"]:
                if not isinstance(raw_key, (list, tuple)) or len(raw_key) != 3:
                    raise invalid
                key = self._lsa_key(
                    raw_key[0], raw_key[1], raw_key[2],
                    "OSPF_SNAPSHOT_INVALID",
                )
                if key not in lsdb or key in maxage:
                    raise invalid
                maxage.add(key)

            self._neighbors = neighbors
            self._lsdb = lsdb
            self._maxage = maxage
            self._overflow = state["overflow"]
            self._stats = dict(stats)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
