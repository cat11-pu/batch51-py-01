"""Loop device lifecycle guard.

The guard manages loop devices: it binds a backing file, records the file
signature (device, inode, modified time, size), tracks holders, invalidates
partition scans on reconfiguration and reclaims autoclear devices.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace

DEVICE_PREFIX = "loop"
STAT_KEYS = ("attaches", "detaches", "reclaimed", "reused", "drift_refused",
             "touched", "scans", "restores")
SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = ("version", "next_index", "devices", "observations", "stats")


class LoopError(ValueError):
    """Refusal raised while binding, opening or restoring loop devices."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BackingFile:
    """One observed state of a backing file on disk."""

    path: str
    dev: int
    inode: int
    mtime_ns: int
    size: int


@dataclass(frozen=True)
class LoopBinding:
    """A bound loop device."""

    loop: str
    path: str
    dev: int
    inode: int
    size: int
    offset: int
    size_limit: int
    read_only: bool
    autoclear: bool
    generation: int


@dataclass(frozen=True)
class LoopStatus:
    """A detached view of one loop device."""

    loop: str
    attached: bool
    path: str | None = None
    offset: int = 0
    size_limit: int = 0
    read_only: bool = False
    autoclear: bool = False
    holders: tuple = ()
    pending_detach: bool = False
    partitions: tuple = ()
    generation: int = 0
    touched: bool = False


@dataclass
class _DeviceState:
    binding: LoopBinding
    mtime_ns: int
    holders: set
    pending_detach: bool = False
    partitions: tuple = ()
    touched: bool = False


class LoopDeviceGuard:
    """Bind backing files to loop devices and police their lifetime."""

    def __init__(self, *, max_devices: int = 64,
                 max_bindings_per_file: int = 4,
                 autoclear_default: bool = False) -> None:
        self.max_devices = max_devices
        self.max_bindings_per_file = max_bindings_per_file
        self.autoclear_default = autoclear_default
        self._lock = threading.RLock()
        self._next_index = 0
        self._devices = {}
        self._observations = {}
        self._stats = {key: 0 for key in STAT_KEYS}

    def observe_file(self, path: str, *, dev: int, inode: int,
                     mtime_ns: int, size: int) -> BackingFile:
        """Record the current on-disk signature of ``path``."""
        observed = BackingFile(path, dev, inode, mtime_ns, size)
        with self._lock:
            self._observations[path] = observed
        return observed

    def attach(self, path: str, *, offset: int = 0, sizelimit: int | None = None,
               read_only: bool = False,
               autoclear: bool | None = None) -> LoopBinding:
        """Bind ``path`` to the next loop device and return the binding."""
        with self._lock:
            observed = self._observations.get(path)
            if observed is None:
                raise LoopError("LOOP_BACKING_UNKNOWN", {"path": path})

            size_limit = self._checked_size_limit(offset, sizelimit,
                                                  observed.size)
            requested_read_only = bool(read_only)

            duplicate = self._find_duplicate(observed, offset, requested_read_only)
            if duplicate is not None:
                if duplicate.binding.read_only and requested_read_only:
                    self._stats["reused"] += 1
                    return duplicate.binding
                raise LoopError("LOOP_SHARED_CONFLICT",
                                {"loop": duplicate.binding.loop})

            binding_count = sum(
                state.binding.path == path for state in self._devices.values()
            )
            if binding_count >= self.max_bindings_per_file:
                raise LoopError("LOOP_BACKING_LIMIT",
                                {"path": path, "limit": self.max_bindings_per_file})

            if self._next_index >= self.max_devices:
                raise LoopError("LOOP_DEVICE_EXHAUSTED",
                                {"max_devices": self.max_devices})

            loop = f"{DEVICE_PREFIX}{self._next_index}"
            self._next_index += 1
            binding = LoopBinding(
                loop=loop,
                path=path,
                dev=observed.dev,
                inode=observed.inode,
                size=observed.size,
                offset=offset,
                size_limit=size_limit,
                read_only=requested_read_only,
                autoclear=(self.autoclear_default if autoclear is None
                           else bool(autoclear)),
                generation=1,
            )
            self._devices[loop] = _DeviceState(
                binding=binding,
                mtime_ns=observed.mtime_ns,
                holders=set(),
            )
            self._stats["attaches"] += 1
            return binding

    def detach(self, loop: str, *, holder: str | None = None) -> bool:
        """Detach ``loop``; refuse when a manual device is still held."""
        with self._lock:
            state = self._devices.get(loop)
            if state is None:
                return False

            if state.holders:
                holder_names = tuple(sorted(state.holders))
                if state.binding.autoclear:
                    state.pending_detach = True
                    return True
                raise LoopError("LOOP_HELD", {"holders": holder_names})

            self._remove_device(loop)
            self._stats["detaches"] += 1
            return True

    def reconfigure(self, loop: str, *, offset: int | None = None,
                    sizelimit: int | None = None,
                    read_only: bool | None = None) -> LoopBinding:
        """Change the offset, size limit or access mode of ``loop``."""
        with self._lock:
            state = self._require_device(loop)
            if state.holders:
                raise LoopError("LOOP_BUSY",
                                {"holders": tuple(sorted(state.holders))})

            binding = state.binding
            new_offset = binding.offset if offset is None else offset
            new_limit = binding.size_limit if sizelimit is None else sizelimit
            observed = self._observations.get(binding.path)
            size = binding.size if observed is None else observed.size
            checked_limit = self._checked_size_limit(new_offset, new_limit, size)

            updated = replace(
                binding,
                offset=new_offset,
                size_limit=checked_limit,
                read_only=(binding.read_only if read_only is None
                           else bool(read_only)),
                generation=binding.generation + 1,
            )
            state.binding = updated
            state.partitions = ()
            return updated

    def reclaim(self, *, now: int = 0) -> int:
        """Reclaim unheld autoclear devices and return how many were freed."""
        with self._lock:
            reclaimable = [
                loop for loop, state in self._devices.items()
                if state.binding.autoclear and not state.holders
            ]
            for loop in reclaimable:
                self._remove_device(loop)
            self._stats["reclaimed"] += len(reclaimable)
            return len(reclaimable)

    def status(self, loop: str) -> LoopStatus:
        """Return a detached status view, attached=False for unknown loops."""
        with self._lock:
            state = self._devices.get(loop)
            if state is None:
                return LoopStatus(loop=loop, attached=False)
            return self._status_for(state)

    def open_device(self, loop: str, *, holder: str) -> LoopStatus:
        """Re-validate the backing file and register ``holder``."""
        with self._lock:
            state = self._require_device(loop)
            if state.pending_detach:
                raise LoopError("LOOP_BUSY",
                                {"holders": tuple(sorted(state.holders))})

            binding = state.binding
            observed = self._observations.get(binding.path)
            if observed is None:
                raise LoopError("LOOP_BACKING_UNKNOWN",
                                {"path": binding.path})

            if observed.dev != binding.dev or observed.inode != binding.inode:
                self._stats["drift_refused"] += 1
                raise LoopError("LOOP_BACKING_DRIFT", {"reason": "replaced"})

            if observed.size < binding.size:
                self._stats["drift_refused"] += 1
                raise LoopError("LOOP_BACKING_DRIFT", {"reason": "truncated"})

            if observed.size < binding.offset + binding.size_limit:
                self._stats["drift_refused"] += 1
                raise LoopError("LOOP_BACKING_DRIFT", {"reason": "truncated"})

            if observed.mtime_ns != state.mtime_ns:
                state.mtime_ns = observed.mtime_ns
                state.touched = True
                self._stats["touched"] += 1

            state.holders.add(holder)
            return self._status_for(state)

    def close_device(self, loop: str, *, holder: str) -> int:
        """Drop ``holder`` and return the remaining holder count."""
        with self._lock:
            state = self._devices.get(loop)
            if state is None or holder not in state.holders:
                raise LoopError("LOOP_NOT_HELD",
                                {"loop": loop, "holder": holder})

            state.holders.remove(holder)
            remaining = len(state.holders)
            if remaining == 0 and state.pending_detach:
                self._remove_device(loop)
                self._stats["detaches"] += 1
            return remaining

    def holders(self, loop: str) -> tuple:
        """Return the sorted holders of ``loop``."""
        with self._lock:
            state = self._devices.get(loop)
            if state is None:
                return ()
            return tuple(sorted(state.holders))

    def bindings_for(self, path: str) -> tuple:
        """Return the bindings that share one backing path."""
        with self._lock:
            bindings = [
                state.binding for state in self._devices.values()
                if state.binding.path == path
            ]
            return tuple(sorted(bindings, key=lambda item: self._loop_order(item.loop)))

    def record_partitions(self, loop: str, partitions) -> tuple:
        """Store an external partition scan result for ``loop``."""
        with self._lock:
            state = self._require_device(loop)
            state.partitions = tuple(partitions)
            return state.partitions

    def scan_partitions(self, loop: str) -> tuple:
        """Return the cached partition scan result."""
        with self._lock:
            self._stats["scans"] += 1
            state = self._devices.get(loop)
            if state is None:
                return ()
            return tuple(state.partitions)

    def snapshot(self) -> dict:
        """Return a detached snapshot of devices, observations and counters."""
        with self._lock:
            devices = {}
            for loop, state in self._devices.items():
                binding = state.binding
                devices[loop] = {
                    "loop": binding.loop,
                    "path": binding.path,
                    "dev": binding.dev,
                    "inode": binding.inode,
                    "size": binding.size,
                    "offset": binding.offset,
                    "size_limit": binding.size_limit,
                    "read_only": binding.read_only,
                    "autoclear": binding.autoclear,
                    "generation": binding.generation,
                    "mtime_ns": state.mtime_ns,
                    "holders": sorted(state.holders),
                    "pending_detach": state.pending_detach,
                    "partitions": list(state.partitions),
                    "touched": state.touched,
                }

            observations = {
                path: {
                    "path": observed.path,
                    "dev": observed.dev,
                    "inode": observed.inode,
                    "mtime_ns": observed.mtime_ns,
                    "size": observed.size,
                }
                for path, observed in self._observations.items()
            }
            return {
                "version": SNAPSHOT_VERSION,
                "next_index": self._next_index,
                "devices": devices,
                "observations": observations,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        """Replace the live state with ``state`` after validating it."""
        with self._lock:
            devices, observations, stats, next_index = self._validated_snapshot(state)
            stats["restores"] += 1
            self._devices = devices
            self._observations = observations
            self._stats = stats
            self._next_index = next_index

    def stats(self) -> dict:
        """Return the operation counters."""
        with self._lock:
            return dict(self._stats)

    def _require_device(self, loop: str) -> _DeviceState:
        state = self._devices.get(loop)
        if state is None:
            raise LoopError("LOOP_DEVICE_UNKNOWN", {"loop": loop})
        return state

    def _remove_device(self, loop: str) -> None:
        self._devices.pop(loop, None)

    def _status_for(self, state: _DeviceState) -> LoopStatus:
        binding = state.binding
        return LoopStatus(
            loop=binding.loop,
            attached=True,
            path=binding.path,
            offset=binding.offset,
            size_limit=binding.size_limit,
            read_only=binding.read_only,
            autoclear=binding.autoclear,
            holders=tuple(sorted(state.holders)),
            pending_detach=state.pending_detach,
            partitions=tuple(state.partitions),
            generation=binding.generation,
            touched=state.touched,
        )

    @staticmethod
    def _loop_order(loop: str) -> tuple:
        suffix = loop[len(DEVICE_PREFIX):]
        if suffix.isdigit():
            return (0, int(suffix), loop)
        return (1, 0, loop)

    @staticmethod
    def _checked_size_limit(offset: int, size_limit: int | None,
                            size: int) -> int:
        valid_offset = (isinstance(offset, int)
                        and not isinstance(offset, bool))
        valid_size = (isinstance(size, int)
                      and not isinstance(size, bool))
        if not valid_offset or not valid_size:
            raise LoopError("LOOP_RANGE_INVALID",
                            {"offset": offset, "size_limit": size_limit,
                             "size": size})

        effective_limit = size - offset if size_limit is None else size_limit
        valid_limit = (isinstance(effective_limit, int)
                       and not isinstance(effective_limit, bool))
        if (not valid_limit or offset < 0 or effective_limit <= 0
                or offset + effective_limit > size):
            raise LoopError("LOOP_RANGE_INVALID",
                            {"offset": offset, "size_limit": effective_limit,
                             "size": size})
        return effective_limit

    def _find_duplicate(self, observed: BackingFile, offset: int,
                        read_only: bool) -> _DeviceState | None:
        for loop in sorted(self._devices, key=self._loop_order):
            state = self._devices[loop]
            if state.pending_detach:
                continue
            binding = state.binding
            if ((binding.dev, binding.inode, binding.offset, binding.size)
                    == (observed.dev, observed.inode, offset, observed.size)):
                return state
        return None

    def _validated_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "not_mapping"})
        if set(state) != set(SNAPSHOT_KEYS):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "keys"})
        if (not self._valid_int(state["version"])
                or state["version"] != SNAPSHOT_VERSION):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "version"})

        next_index = state["next_index"]
        if not self._valid_int(next_index) or next_index < 0:
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "next_index"})

        raw_devices = state["devices"]
        raw_observations = state["observations"]
        raw_stats = state["stats"]
        if not isinstance(raw_devices, dict):
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "devices"})
        if not isinstance(raw_observations, dict):
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "observations"})
        if not isinstance(raw_stats, dict):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "stats"})

        observations = {}
        for path, item in raw_observations.items():
            observations[path] = self._validated_observation(path, item)

        stats = {}
        if set(raw_stats) != set(STAT_KEYS):
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "stats_keys"})
        for key in STAT_KEYS:
            value = raw_stats[key]
            if not self._valid_int(value) or value < 0:
                raise LoopError("LOOP_SNAPSHOT_INVALID",
                                {"reason": "stats_value"})
            stats[key] = value

        devices = {}
        for loop, item in raw_devices.items():
            device = self._validated_device(loop, item)
            if device.binding.path not in observations:
                raise LoopError("LOOP_SNAPSHOT_INVALID",
                                {"reason": "missing_observation"})
            devices[loop] = device

        for loop in devices:
            order = self._loop_order(loop)
            if order[0] != 0 or next_index <= order[1]:
                raise LoopError("LOOP_SNAPSHOT_INVALID",
                                {"reason": "next_index"})
        if next_index > 0 and not observations:
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "next_index"})

        return devices, observations, stats, next_index

    def _validated_observation(self, path: object, item: object) -> BackingFile:
        if not isinstance(path, str) or not isinstance(item, dict):
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "observation"})
        required = {"path", "dev", "inode", "mtime_ns", "size"}
        if set(item) != required or item["path"] != path:
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "observation"})
        for key in ("dev", "inode", "size"):
            if not self._valid_int(item[key]) or item[key] < 0:
                raise LoopError("LOOP_SNAPSHOT_INVALID",
                                {"reason": "observation"})
        if not self._valid_int(item["mtime_ns"]):
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "observation"})
        return BackingFile(
            path=path,
            dev=item["dev"],
            inode=item["inode"],
            mtime_ns=item["mtime_ns"],
            size=item["size"],
        )

    def _validated_device(self, loop: object, item: object) -> _DeviceState:
        if not isinstance(loop, str) or not isinstance(item, dict):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "device"})
        required = {
            "loop", "path", "dev", "inode", "size", "offset", "size_limit",
            "read_only", "autoclear", "generation", "mtime_ns", "holders",
            "pending_detach", "partitions", "touched",
        }
        if set(item) != required or item["loop"] != loop:
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "device"})
        if not isinstance(item["path"], str):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "device"})
        for key in ("dev", "inode", "size", "offset", "size_limit",
                    "generation", "mtime_ns"):
            if not self._valid_int(item[key]):
                raise LoopError("LOOP_SNAPSHOT_INVALID",
                                {"reason": "device"})
        if (item["dev"] < 0 or item["inode"] < 0 or item["size"] < 0
                or item["offset"] < 0 or item["size_limit"] <= 0
                or item["generation"] < 1
                or item["offset"] + item["size_limit"] > item["size"]):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "device"})
        for key in ("read_only", "autoclear", "pending_detach", "touched"):
            if not isinstance(item[key], bool):
                raise LoopError("LOOP_SNAPSHOT_INVALID",
                                {"reason": "device"})

        raw_holders = item["holders"]
        if (not isinstance(raw_holders, (list, tuple, set))
                or any(not isinstance(holder, str)
                       for holder in raw_holders)):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "holders"})
        holders = list(raw_holders)
        if len(holders) != len(set(holders)):
            raise LoopError("LOOP_SNAPSHOT_INVALID", {"reason": "holders"})

        raw_partitions = item["partitions"]
        if (not isinstance(raw_partitions, (list, tuple))
                or any(not isinstance(partition, str)
                       for partition in raw_partitions)):
            raise LoopError("LOOP_SNAPSHOT_INVALID",
                            {"reason": "partitions"})

        binding = LoopBinding(
            loop=loop,
            path=item["path"],
            dev=item["dev"],
            inode=item["inode"],
            size=item["size"],
            offset=item["offset"],
            size_limit=item["size_limit"],
            read_only=item["read_only"],
            autoclear=item["autoclear"],
            generation=item["generation"],
        )
        return _DeviceState(
            binding=binding,
            mtime_ns=item["mtime_ns"],
            holders=set(holders),
            pending_detach=item["pending_detach"],
            partitions=tuple(raw_partitions),
            touched=item["touched"],
        )

    @staticmethod
    def _valid_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)
