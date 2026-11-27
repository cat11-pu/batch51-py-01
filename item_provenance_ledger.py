"""Item instance provenance ledger: source events, holder chains, duplicate quarantine."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class LedgerError(ValueError):
    """Raised when a provenance operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProvenanceEvent:
    seq: int
    kind: str
    instance: str
    actor: str
    qty: int
    at: str | None
    note: str = ""


@dataclass(frozen=True)
class Conflict:
    instance: str
    holders: tuple[str, ...]
    events: tuple[int, ...]


class ItemProvenanceLedger:
    """Track every item instance from its source event down to the current holder."""

    SOURCE_KINDS = ("drop", "craft", "trade", "mail")
    SNAPSHOT_VERSION = 1

    def __init__(self, *, max_chain: int = 64, max_quarantine: int = 32) -> None:
        self.max_chain = max_chain
        self.max_quarantine = max_quarantine
        self._lock = threading.RLock()
        self._instances: dict[str, dict] = {}
        self._chains: dict[str, list[ProvenanceEvent]] = {}
        self._events: list[ProvenanceEvent] = []
        self._event_keys: dict[str, int] = {}
        self._quarantine: list[Conflict] = []
        self._counters = {
            "next_seq": 1,
            "duplicates": 0,
            "transfers": 0,
            "splits": 0,
            "merges": 0,
        }

    # ------------------------------------------------------------------
    # Internal helpers

    @staticmethod
    def _is_text(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _is_qty(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _fail(self, code: str, detail: object = None) -> None:
        raise LedgerError(code, detail)

    def _state(self, instance: str, *, live: bool = False) -> dict:
        if not self._is_text(instance):
            self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
        state = self._instances.get(instance)
        if state is None:
            self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
        if live and (state["archived"] or state["destroyed"]):
            self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
        return state

    def _next_seq(self) -> int:
        seq = self._counters["next_seq"]
        self._counters["next_seq"] += 1
        return seq

    def _append_event(self, kind: str, instance: str, actor: str, qty: int,
                      at: str | None, note: str = "") -> ProvenanceEvent:
        event = ProvenanceEvent(self._next_seq(), kind, instance, actor, qty, at, note)
        self._events.append(event)
        self._chains[instance].append(event)
        return event

    def _check_chain_room(self, instance: str, extra: int = 1) -> None:
        if len(self._chains.get(instance, ())) + extra > self.max_chain:
            self._fail("LEDGER_CHAIN_LIMIT", instance)

    @staticmethod
    def _add_segment(segments: list[list], label: str, qty: int) -> None:
        if qty <= 0:
            return
        segments.append([label, qty])

    @staticmethod
    def _copy_segments(segments: list[list]) -> list[list]:
        return [[label, qty] for label, qty in segments]

    @staticmethod
    def _allocate_segments(segments: list[list], amount: int,
                           total: int) -> tuple[list[list], list[list]]:
        """Split ``amount`` over segments, returning (child, parent)."""
        if total <= 0:
            return [["unknown", amount]], [["unknown", 0]]
        takes = [0] * len(segments)
        for index, (_, qty) in enumerate(segments):
            takes[index] = (qty * amount) // total

        remainder = amount - sum(takes)
        order = sorted(
            range(len(segments)),
            key=lambda i: (-((segments[i][1] * amount) % total), i),
        )
        cursor = 0
        while remainder > 0:
            index = order[cursor % len(order)]
            if takes[index] < segments[index][1]:
                takes[index] += 1
                remainder -= 1
            cursor += 1
            if cursor > len(order) * (amount + 1):
                break

        child: list[list] = []
        parent: list[list] = []
        for (label, qty), take in zip(segments, takes):
            if take:
                child.append([label, take])
            if qty - take:
                parent.append([label, qty - take])
        return child, parent

    def _stats_locked(self) -> dict:
        return {
            "instances": len(self._instances),
            "live": sum(
                1 for state in self._instances.values()
                if not state["archived"] and not state["destroyed"]
            ),
            "events": len(self._events),
            "duplicates": self._counters["duplicates"],
            "transfers": self._counters["transfers"],
            "splits": self._counters["splits"],
            "merges": self._counters["merges"],
            "quarantined": len(self._quarantine),
        }

    def ingest_event(self, kind: str, instance: str, *, actor: str,
                     qty: int = 1, event_key: str | None = None,
                     at: str | None = None) -> int:
        """Append one source event, or drop it when the event key was seen."""
        if (kind not in self.SOURCE_KINDS or not self._is_text(instance)
                or not self._is_text(actor) or not self._is_qty(qty) or qty <= 0
                or (event_key is not None and not isinstance(event_key, str))):
            self._fail("LEDGER_INVALID_EVENT", {
                "kind": kind,
                "instance": instance,
                "actor": actor,
                "qty": qty,
            })

        with self._lock:
            if event_key is not None and event_key in self._event_keys:
                self._counters["duplicates"] += 1
                return self._event_keys[event_key]
            if instance in self._instances:
                self._fail("LEDGER_DUPLICATE_INSTANCE", instance)
            self._check_chain_room(instance)

            event = ProvenanceEvent(
                self._next_seq(), kind, instance, actor, qty, at, ""
            )
            self._events.append(event)
            self._instances[instance] = {
                "owner": actor,
                "qty": qty,
                "segments": [[event_key if event_key is not None else kind, qty]],
                "archived": False,
                "destroyed": False,
            }
            self._chains[instance] = [event]
            if event_key is not None:
                self._event_keys[event_key] = event.seq
            return event.seq

    def transfer(self, instance: str, from_owner: str, to_owner: str, *,
                 event_key: str | None = None, at: str | None = None) -> int:
        """Append a holder change and return the assigned global event number."""
        if (not self._is_text(instance) or not self._is_text(from_owner)
                or not self._is_text(to_owner)
                or (event_key is not None and not isinstance(event_key, str))):
            self._fail("LEDGER_INVALID_EVENT", {
                "instance": instance,
                "from_owner": from_owner,
                "to_owner": to_owner,
            })

        with self._lock:
            if event_key is not None and event_key in self._event_keys:
                self._counters["duplicates"] += 1
                return self._event_keys[event_key]

            state = self._state(instance, live=True)
            if state["owner"] != from_owner:
                self._fail("LEDGER_STALE_HOLDER", {
                    "instance": instance,
                    "expected": state["owner"],
                    "actual": from_owner,
                })
            self._check_chain_room(instance)

            event = self._append_event(
                "transfer", instance, to_owner, state["qty"], at
            )
            state["owner"] = to_owner
            self._counters["transfers"] += 1
            if event_key is not None:
                self._event_keys[event_key] = event.seq
            return event.seq

    def owner_of(self, instance: str) -> str:
        """Current holder of a live instance."""
        with self._lock:
            return self._state(instance, live=True)["owner"]

    def qty_of(self, instance: str) -> int:
        """Stack size of a live instance."""
        with self._lock:
            return self._state(instance, live=True)["qty"]

    def holdings_of(self, owner: str) -> list[str]:
        """Live instances of one holder, sorted by instance id."""
        with self._lock:
            return sorted(
                instance for instance, state in self._instances.items()
                if state["owner"] == owner
                and not state["archived"] and not state["destroyed"]
            )

    def chain_of(self, instance: str) -> list[ProvenanceEvent]:
        """Full event chain in ascending event-number order."""
        with self._lock:
            if not self._is_text(instance):
                self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
            chain = self._chains.get(instance)
            if chain is None:
                self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
            return sorted(chain, key=lambda event: event.seq)

    def segments_of(self, instance: str) -> list[tuple[str, int]]:
        """Source segments still carried by the instance."""
        with self._lock:
            state = self._state(instance)
            return [(label, qty) for label, qty in state["segments"]]

    def split(self, instance: str, qty: int, *, new_instance: str,
              at: str | None = None) -> str:
        """Split a stack into a child instance that inherits the parent chain."""
        if not self._is_text(instance) or not self._is_text(new_instance):
            self._fail("LEDGER_INVALID_EVENT", {
                "instance": instance,
                "new_instance": new_instance,
            })
        if not self._is_qty(qty):
            self._fail("LEDGER_QTY_INVALID", qty)

        with self._lock:
            state = self._state(instance, live=True)
            if qty <= 0 or qty >= state["qty"]:
                self._fail("LEDGER_QTY_INVALID", qty)
            if new_instance in self._instances:
                self._fail("LEDGER_DUPLICATE_INSTANCE", new_instance)
            self._check_chain_room(instance)
            self._check_chain_room(new_instance)

            child_segments, parent_segments = self._allocate_segments(
                self._copy_segments(state["segments"]), qty, state["qty"]
            )
            inherited = list(self._chains[instance])

            parent_event = ProvenanceEvent(
                self._next_seq(), "split", instance, state["owner"], qty, at,
                f"split-out:{new_instance}",
            )
            child_event = ProvenanceEvent(
                self._next_seq(), "split", new_instance, state["owner"], qty, at,
                f"split-in:{instance}",
            )
            self._events.extend((parent_event, child_event))

            state["qty"] -= qty
            state["segments"] = parent_segments
            self._chains[instance].append(parent_event)

            self._instances[new_instance] = {
                "owner": state["owner"],
                "qty": qty,
                "segments": child_segments,
                "archived": False,
                "destroyed": False,
            }
            self._chains[new_instance] = inherited + [child_event]
            self._counters["splits"] += 1
            return new_instance

    def merge(self, target: str, sources: list[str], *,
              at: str | None = None) -> int:
        """Merge source stacks into the target and archive the sources."""
        if not self._is_text(target) or not isinstance(sources, (list, tuple)):
            self._fail("LEDGER_INVALID_EVENT", {
                "target": target,
                "sources": sources,
            })
        if not sources:
            self._fail("LEDGER_INVALID_EVENT", "sources required")

        unique_sources: list[str] = []
        seen: set[str] = set()
        for source in sources:
            if not self._is_text(source):
                self._fail("LEDGER_INVALID_EVENT", source)
            if source == target or source in seen:
                self._fail("LEDGER_DUPLICATE_INSTANCE", source)
            seen.add(source)
            unique_sources.append(source)

        with self._lock:
            target_state = self._state(target, live=True)
            source_states: list[tuple[str, dict]] = []
            for source in unique_sources:
                source_states.append((source, self._state(source, live=True)))

            self._check_chain_room(target)
            for source, _ in source_states:
                self._check_chain_room(source)

            target_segments = self._copy_segments(target_state["segments"])
            total = target_state["qty"]
            for source, source_state in source_states:
                total += source_state["qty"]
                for label, seg_qty in source_state["segments"]:
                    self._add_segment(target_segments, label, seg_qty)

            target_event = ProvenanceEvent(
                self._next_seq(), "merge", target, target_state["owner"], total,
                at, "merge:" + ",".join(unique_sources),
            )
            source_events: list[tuple[str, ProvenanceEvent]] = []
            for source, source_state in source_states:
                event = ProvenanceEvent(
                    self._next_seq(), "merge", source, target_state["owner"],
                    source_state["qty"], at, "merged-into:" + target,
                )
                source_events.append((source, event))

            self._events.append(target_event)
            self._chains[target].append(target_event)
            target_state["qty"] = total
            target_state["segments"] = target_segments

            states_by_id = dict(source_states)
            for source, event in source_events:
                self._events.append(event)
                self._chains[source].append(event)
                states_by_id[source]["archived"] = True

            self._counters["merges"] += 1
            return total

    def destroy(self, instance: str, *, at: str | None = None) -> bool:
        """Mark an instance as destroyed without dropping its chain."""
        if not self._is_text(instance):
            self._fail("LEDGER_INVALID_EVENT", instance)
        with self._lock:
            state = self._state(instance)
            if state["archived"]:
                self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
            if state["destroyed"]:
                return False
            self._check_chain_room(instance)
            self._append_event(
                "destroy", instance, state["owner"], state["qty"], at
            )
            state["destroyed"] = True
            return True

    def recover(self, instance: str, *, at: str | None = None) -> bool:
        """Append a recovery event to a destroyed instance."""
        if not self._is_text(instance):
            self._fail("LEDGER_INVALID_EVENT", instance)
        with self._lock:
            state = self._state(instance)
            if state["archived"]:
                self._fail("LEDGER_NO_SUCH_INSTANCE", instance)
            if not state["destroyed"]:
                return False
            self._check_chain_room(instance)
            self._append_event(
                "recover", instance, state["owner"], state["qty"], at, "recovery"
            )
            state["destroyed"] = False
            return True

    def scan_duplicates(self, observed: dict[str, list[str]] | None = None) -> list[Conflict]:
        """Detect instances reported under more than one holder."""
        if observed is None:
            return []
        if not isinstance(observed, dict):
            self._fail("LEDGER_INVALID_EVENT", "observed must be a mapping")
        observed = self._observed_claims(observed)

        with self._lock:
            detected: list[Conflict] = []
            existing = {conflict.instance: conflict
                        for conflict in self._quarantine}

            for instance in sorted(observed):
                if not self._is_text(instance):
                    continue
                claims = self._normalise_claims(observed[instance])
                if not claims:
                    continue

                claim_holders: list[str] = []
                claim_seqs: list[int] = []
                for holder, seq in claims:
                    if not self._is_text(holder):
                        continue
                    if holder not in claim_holders:
                        claim_holders.append(holder)
                    if seq is not None and seq not in claim_seqs:
                        claim_seqs.append(seq)

                state = self._instances.get(instance)
                if state is None:
                    if len(claim_holders) < 2:
                        continue
                    holders = tuple(claim_holders)
                    events = tuple(sorted(claim_seqs))
                else:
                    local_owner = state["owner"]
                    late_holders = [
                        holder for holder in claim_holders
                        if holder != local_owner
                    ]
                    if not late_holders:
                        continue
                    holders = (local_owner,) + tuple(late_holders)
                    chain = self._chains[instance]
                    local_seq = min(event.seq for event in chain)
                    events = (local_seq,) + tuple(
                        seq for seq in sorted(claim_seqs) if seq != local_seq
                    )

                conflict = existing.get(instance)
                if conflict is None:
                    conflict = Conflict(instance, holders, events)
                    existing[instance] = conflict
                    detected.append(conflict)
                else:
                    detected.append(conflict)

            new_conflicts = [
                conflict for conflict in detected
                if conflict.instance not in {c.instance for c in self._quarantine}
            ]
            if len(self._quarantine) + len(new_conflicts) > self.max_quarantine:
                self._fail("LEDGER_QUARANTINE_FULL", {
                    "quarantine": len(self._quarantine),
                    "incoming": len(new_conflicts),
                    "max": self.max_quarantine,
                })
            self._quarantine.extend(new_conflicts)
            return sorted(detected, key=lambda conflict: conflict.instance)

    def _observed_claims(self, observed: dict) -> dict:
        raw_instances = observed.get("instances")
        if not isinstance(raw_instances, dict):
            return observed

        chains = observed.get("chains")
        if not isinstance(chains, dict):
            chains = {}
        converted: dict[str, list[dict]] = {}
        for instance, raw in raw_instances.items():
            if not self._is_text(instance):
                continue
            if isinstance(raw, dict):
                holder = raw.get("owner", raw.get("holder", raw.get("actor")))
            elif isinstance(raw, str):
                holder = raw
            else:
                continue
            if not self._is_text(holder):
                continue

            seq = None
            chain = chains.get(instance)
            if isinstance(chain, (list, tuple)) and chain:
                first = chain[0]
                if isinstance(first, ProvenanceEvent):
                    seq = first.seq
                elif isinstance(first, dict):
                    seq = first.get("seq")
            converted[instance] = [{"holder": holder, "seq": seq}]
        return converted

    @staticmethod
    def _normalise_claims(value: object) -> list[tuple[str, int | None]]:
        if value is None:
            return []
        if isinstance(value, (str, bytes)) or isinstance(value, dict):
            values: list[object] = [value]
        elif isinstance(value, (list, tuple)):
            values = list(value)
        else:
            return []

        claims: list[tuple[str, int | None]] = []
        for item in values:
            holder: object = None
            seq: object = None
            if isinstance(item, str):
                holder = item
            elif isinstance(item, dict):
                holder = item.get("holder", item.get("owner", item.get("actor")))
                seq = item.get("seq", item.get("event_seq"))
            elif isinstance(item, (list, tuple)) and item:
                holder = item[0]
                if len(item) > 1:
                    seq = item[1]
            if not isinstance(holder, str):
                continue
            if not isinstance(seq, int) or isinstance(seq, bool):
                seq = None
            claims.append((holder, seq))
        return claims

    def quarantine(self) -> list[Conflict]:
        """Conflicts currently parked in the quarantine area."""
        with self._lock:
            return [
                Conflict(conflict.instance, conflict.holders, conflict.events)
                for conflict in self._quarantine
            ]

    def snapshot(self) -> dict:
        """Deep copy of instances, chains, counters and stats."""
        with self._lock:
            state = {
                "version": self.SNAPSHOT_VERSION,
                "instances": {
                    instance: {
                        "owner": instance_state["owner"],
                        "qty": instance_state["qty"],
                        "segments": [
                            [label, qty]
                            for label, qty in instance_state["segments"]
                        ],
                        "archived": instance_state["archived"],
                        "destroyed": instance_state["destroyed"],
                    }
                    for instance, instance_state in self._instances.items()
                },
                "chains": {
                    instance: list(chain)
                    for instance, chain in self._chains.items()
                },
                "events": list(self._events),
                "counters": {
                    "next_seq": self._counters["next_seq"],
                    "duplicates": self._counters["duplicates"],
                    "transfers": self._counters["transfers"],
                    "splits": self._counters["splits"],
                    "merges": self._counters["merges"],
                    "event_keys": dict(self._event_keys),
                    "quarantine": list(self._quarantine),
                },
                "stats": self._stats_locked(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace live state from a snapshot, refusing malformed input."""
        with self._lock:
            parsed = self._parse_snapshot(state)
            (
                instances, chains, events, event_keys, quarantine, counters,
            ) = parsed

            self._instances = instances
            self._chains = chains
            self._events = events
            self._event_keys = event_keys
            self._quarantine = quarantine
            self._counters = counters

    def stats(self) -> dict:
        """Return the counters exposed to the item operations dashboard."""
        with self._lock:
            return self._stats_locked()

    # ------------------------------------------------------------------
    # Snapshot parsing

    def _snapshot_invalid(self, detail: object) -> None:
        self._fail("LEDGER_SNAPSHOT_INVALID", detail)

    def _parse_event(self, raw: object) -> ProvenanceEvent:
        if isinstance(raw, ProvenanceEvent):
            event = raw
        elif isinstance(raw, dict):
            event = ProvenanceEvent(
                raw.get("seq"),
                raw.get("kind"),
                raw.get("instance"),
                raw.get("actor"),
                raw.get("qty"),
                raw.get("at"),
                raw.get("note", ""),
            )
        else:
            self._snapshot_invalid("invalid event")
            raise AssertionError

        if (not self._is_qty(event.seq) or event.seq <= 0
                or not isinstance(event.kind, str)
                or not isinstance(event.instance, str)
                or not isinstance(event.actor, str)
                or not self._is_qty(event.qty)
                or not isinstance(event.note, str)
                or (event.at is not None and not isinstance(event.at, str))):
            self._snapshot_invalid("invalid event fields")
        return event

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            self._snapshot_invalid("state must be a mapping")
        required = {"version", "instances", "chains", "events",
                    "counters", "stats"}
        if not required.issubset(state):
            self._snapshot_invalid("missing snapshot keys")
        version = state.get("version")
        if (not self._is_qty(version)
                or version != self.SNAPSHOT_VERSION):
            self._snapshot_invalid("unsupported snapshot version")
        if not isinstance(state["instances"], dict):
            self._snapshot_invalid("instances must be a mapping")
        if not isinstance(state["chains"], dict):
            self._snapshot_invalid("chains must be a mapping")
        if not isinstance(state["events"], list):
            self._snapshot_invalid("events must be a list")
        if not isinstance(state["counters"], dict):
            self._snapshot_invalid("counters must be a mapping")
        if not isinstance(state["stats"], dict):
            self._snapshot_invalid("stats must be a mapping")

        instances: dict[str, dict] = {}
        for instance, raw in state["instances"].items():
            if not self._is_text(instance) or not isinstance(raw, dict):
                self._snapshot_invalid("invalid instance record")
            owner = raw.get("owner")
            qty = raw.get("qty")
            segments = raw.get("segments")
            archived = raw.get("archived")
            destroyed = raw.get("destroyed")
            if (not self._is_text(owner) or not self._is_qty(qty) or qty <= 0
                    or not isinstance(segments, list)
                    or not isinstance(archived, bool)
                    or not isinstance(destroyed, bool)
                    or (archived and destroyed)):
                self._snapshot_invalid("invalid instance fields")

            parsed_segments: list[list] = []
            segment_total = 0
            for raw_segment in segments:
                if (not isinstance(raw_segment, (list, tuple))
                        or len(raw_segment) != 2
                        or not isinstance(raw_segment[0], str)
                        or not self._is_qty(raw_segment[1])
                        or raw_segment[1] <= 0):
                    self._snapshot_invalid("invalid segment")
                label, seg_qty = raw_segment
                parsed_segments.append([label, seg_qty])
                segment_total += seg_qty
            if segment_total != qty:
                self._snapshot_invalid("segment quantities do not add up")

            instances[instance] = {
                "owner": owner,
                "qty": qty,
                "segments": parsed_segments,
                "archived": archived,
                "destroyed": destroyed,
            }

        chains: dict[str, list[ProvenanceEvent]] = {}
        for instance, raw_chain in state["chains"].items():
            if not self._is_text(instance) or not isinstance(raw_chain, list):
                self._snapshot_invalid("invalid chain")
            chain = [self._parse_event(raw) for raw in raw_chain]
            chains[instance] = sorted(chain, key=lambda event: event.seq)
        if set(instances) != set(chains):
            self._snapshot_invalid("instances and chains do not match")

        events = [self._parse_event(raw) for raw in state["events"]]
        events.sort(key=lambda event: event.seq)
        if len({event.seq for event in events}) != len(events):
            self._snapshot_invalid("duplicate event sequence")

        counters_raw = state["counters"]
        next_seq = counters_raw.get("next_seq")
        max_seq = max(
            [event.seq for event in events]
            + [event.seq for chain in chains.values() for event in chain],
            default=0,
        )
        if next_seq is None:
            next_seq = max_seq + 1
        if (not self._is_qty(next_seq) or next_seq <= 0
                or next_seq <= max_seq):
            self._snapshot_invalid("invalid next sequence")

        event_keys_raw = counters_raw.get("event_keys", {})
        if not isinstance(event_keys_raw, dict):
            self._snapshot_invalid("invalid event keys")
        event_keys: dict[str, int] = {}
        for key, seq in event_keys_raw.items():
            if not isinstance(key, str) or not self._is_qty(seq) or seq <= 0:
                self._snapshot_invalid("invalid event key")
            event_keys[key] = seq
        if event_keys and next_seq <= max(event_keys.values()):
            self._snapshot_invalid("event key beyond next sequence")

        counter_values = {}
        for name in ("duplicates", "transfers", "splits", "merges"):
            value = counters_raw.get(name, state["stats"].get(name, 0))
            if not self._is_qty(value) or value < 0:
                self._snapshot_invalid("invalid counter")
            counter_values[name] = value

        quarantine_raw = counters_raw.get("quarantine", [])
        if not isinstance(quarantine_raw, list):
            self._snapshot_invalid("invalid quarantine")
        quarantine: list[Conflict] = []
        for raw in quarantine_raw:
            if isinstance(raw, Conflict):
                conflict = raw
            elif isinstance(raw, dict):
                conflict = Conflict(
                    raw.get("instance"),
                    tuple(raw.get("holders", ())),
                    tuple(raw.get("events", ())),
                )
            else:
                self._snapshot_invalid("invalid quarantined conflict")
                raise AssertionError
            if (not self._is_text(conflict.instance)
                    or not isinstance(conflict.holders, tuple)
                    or not all(isinstance(holder, str) for holder in conflict.holders)
                    or not isinstance(conflict.events, tuple)
                    or not all(self._is_qty(seq) for seq in conflict.events)):
                self._snapshot_invalid("invalid quarantined fields")
            quarantine.append(
                Conflict(conflict.instance, conflict.holders, conflict.events)
            )

        counters = {
            "next_seq": next_seq,
            **counter_values,
        }
        return instances, chains, events, event_keys, quarantine, counters
