"""Wardrobe transmog guard: account collection, dye channels, atomic set application."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass

SLOTS = ("head", "chest", "legs", "feet", "weapon")
DYE_CHANNELS = ("primary", "secondary", "accent")
DEFAULT_DYE = 0
MAX_COLLECTION = 2000
MAX_COLOR = 255
STAT_KEYS = ("unlocks", "dyes", "transmogs", "sets", "applies")
SNAPSHOT_VERSION = 1


class WardrobeError(ValueError):
    """Raised when a wardrobe operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Appearance:
    """One cosmetic appearance unlocked on an account."""

    appearance_id: str
    slot: str
    armor_class: str
    source: str


@dataclass(frozen=True)
class Character:
    """One game character that can wear a transmog."""

    account_id: str
    character_id: str
    armor_class: str


@dataclass
class _SetState:
    version: int
    slots: dict[str, str]


@dataclass
class _AccountState:
    collection: set[str]
    dyes: dict[str, dict[str, int]]
    characters: dict[str, Character]
    transmogs: dict[str, dict[str, str]]
    sets: dict[str, _SetState]


class WardrobeTransmogGuard:
    """Keep account collections, dye channels and transmog sets consistent."""

    def __init__(self, *, max_collection: int = MAX_COLLECTION,
                 dye_channels=DYE_CHANNELS) -> None:
        self.max_collection = max_collection
        self.dye_channels = tuple(dye_channels)
        self._lock = threading.RLock()
        self._appearances: dict[str, Appearance] = {}
        self._accounts: dict[str, _AccountState] = {}
        self._stats = {key: 0 for key in STAT_KEYS}

    @staticmethod
    def _valid_id(value) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _valid_text(value) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _armor_matches(appearance_class: str, character_class: str) -> bool:
        return appearance_class.strip().casefold() == character_class.strip().casefold()

    def _require_character(self, account_id, character_id) -> tuple[_AccountState, Character]:
        if not self._valid_id(character_id):
            raise WardrobeError("WD_INVALID_CHARACTER", character_id)
        state = self._accounts.get(account_id)
        character = state.characters.get(character_id) if state is not None else None
        if character is None:
            raise WardrobeError("WD_UNKNOWN_CHARACTER", {
                "account_id": account_id,
                "character_id": character_id,
            })
        return state, character

    def _require_unlocked(self, account_id, appearance_id) -> tuple[_AccountState, Appearance]:
        if not self._valid_id(appearance_id):
            raise WardrobeError("WD_INVALID_APPEARANCE", appearance_id)
        appearance = self._appearances.get(appearance_id)
        state = self._accounts.get(account_id)
        if (appearance is None or state is None
                or appearance_id not in state.collection):
            raise WardrobeError("WD_NOT_UNLOCKED", appearance_id)
        return state, appearance

    def _ordered_dyes(self, channels: Mapping[str, int]) -> dict[str, int]:
        ordered = {
            channel: channels[channel]
            for channel in self.dye_channels
            if channel in channels
        }
        for channel, color in channels.items():
            if channel not in ordered:
                ordered[channel] = color
        return ordered

    def _inherit_dyes(self, dyes: dict[str, dict[str, int]],
                      old_appearance: str, new_appearance: str) -> None:
        if old_appearance == new_appearance:
            return
        inherited = dyes.get(old_appearance, {})
        if not inherited:
            return
        target = dict(dyes.get(new_appearance, {}))
        target.update(inherited)
        dyes[new_appearance] = target

    def unlock(self, account_id, appearance_id, *, slot, armor_class, source):
        """Add an appearance to the account collection; False if already there."""
        if (not self._valid_id(appearance_id) or slot not in SLOTS
                or not isinstance(armor_class, str)
                or not isinstance(source, str)):
            raise WardrobeError("WD_INVALID_APPEARANCE", {
                "appearance_id": appearance_id,
                "slot": slot,
            })

        with self._lock:
            requested = Appearance(appearance_id, slot, armor_class, source)
            registered = self._appearances.get(appearance_id)
            if registered is not None and registered != requested:
                raise WardrobeError("WD_APPEARANCE_CONFLICT", {
                    "registered": registered,
                    "requested": requested,
                })

            state = self._accounts.get(account_id)
            if registered is not None and state is not None \
                    and appearance_id in state.collection:
                return False

            collection_size = len(state.collection) if state is not None else 0
            if collection_size >= self.max_collection:
                raise WardrobeError("WD_COLLECTION_FULL", {
                    "account_id": account_id,
                    "max_collection": self.max_collection,
                })

            if state is None:
                state = _AccountState(set(), {}, {}, {}, {})
                self._accounts[account_id] = state
            if registered is None:
                self._appearances[appearance_id] = requested
            state.collection.add(appearance_id)
            self._stats["unlocks"] += 1
            return True

    def collection(self, account_id):
        """Return the account collection as a sorted tuple of appearance ids."""
        with self._lock:
            state = self._accounts.get(account_id)
            if state is None:
                return ()
            return tuple(sorted(state.collection))

    def appearance_of(self, appearance_id):
        """Return the metadata recorded for one appearance."""
        if not self._valid_id(appearance_id):
            raise WardrobeError("WD_INVALID_APPEARANCE", appearance_id)
        with self._lock:
            appearance = self._appearances.get(appearance_id)
            if appearance is None:
                raise WardrobeError("WD_NOT_UNLOCKED", appearance_id)
            return appearance

    def register_character(self, account_id, character_id, *, armor_class):
        """Register a character that may wear transmogs."""
        if not self._valid_id(character_id) or not self._valid_text(armor_class):
            raise WardrobeError("WD_INVALID_CHARACTER", {
                "character_id": character_id,
                "armor_class": armor_class,
            })

        with self._lock:
            state = self._accounts.get(account_id)
            if state is not None and character_id in state.characters:
                raise WardrobeError("WD_CHARACTER_EXISTS", character_id)
            character = Character(account_id, character_id, armor_class)
            if state is None:
                state = _AccountState(set(), {}, {}, {}, {})
                self._accounts[account_id] = state
            state.characters[character_id] = character
            return character

    def dye(self, account_id, appearance_id, channel, color_id):
        """Set one dye channel and return the remaining non-default channels."""
        if channel not in self.dye_channels:
            raise WardrobeError("WD_UNKNOWN_CHANNEL", channel)
        if (not isinstance(color_id, int) or isinstance(color_id, bool)
                or color_id < DEFAULT_DYE or color_id > MAX_COLOR):
            raise WardrobeError("WD_INVALID_COLOR", color_id)

        with self._lock:
            state, _ = self._require_unlocked(account_id, appearance_id)
            channels = dict(state.dyes.get(appearance_id, {}))
            if color_id == DEFAULT_DYE:
                channels.pop(channel, None)
            else:
                channels[channel] = color_id
                self._stats["dyes"] += 1

            if channels:
                state.dyes[appearance_id] = channels
            else:
                state.dyes.pop(appearance_id, None)
            return self._ordered_dyes(channels)

    def dye_channels_of(self, account_id, appearance_id):
        """Return the non-default dye channels recorded on one appearance."""
        with self._lock:
            state, _ = self._require_unlocked(account_id, appearance_id)
            return self._ordered_dyes(state.dyes.get(appearance_id, {}))

    def slot_dyes_of(self, account_id, character_id):
        """Return the dye channels carried by each worn slot."""
        with self._lock:
            state, _ = self._require_character(account_id, character_id)
            worn = state.transmogs.get(character_id, {})
            result = {}
            for slot in SLOTS:
                if slot in worn:
                    result[slot] = self._ordered_dyes(
                        state.dyes.get(worn[slot], {})
                    )
            return result

    def transmog(self, account_id, character_id, slot, appearance_id):
        """Wear one appearance in a slot and return the replaced appearance id."""
        if slot not in SLOTS:
            raise WardrobeError("WD_UNKNOWN_SLOT", slot)

        with self._lock:
            state, character = self._require_character(account_id, character_id)
            _, appearance = self._require_unlocked(account_id, appearance_id)
            if appearance.slot != slot:
                raise WardrobeError("WD_SLOT_MISMATCH", {
                    "appearance_slot": appearance.slot,
                    "target_slot": slot,
                })
            if not self._armor_matches(appearance.armor_class, character.armor_class):
                raise WardrobeError("WD_ARMOR_MISMATCH", {
                    "appearance_armor_class": appearance.armor_class,
                    "character_armor_class": character.armor_class,
                })

            worn = state.transmogs.setdefault(character_id, {})
            replaced = worn.get(slot, "")
            if replaced:
                self._inherit_dyes(state.dyes, replaced, appearance_id)
            worn[slot] = appearance_id
            self._stats["transmogs"] += 1
            return replaced

    def transmog_of(self, account_id, character_id):
        """Return the appearance currently worn in each occupied slot."""
        with self._lock:
            state, _ = self._require_character(account_id, character_id)
            worn = state.transmogs.get(character_id, {})
            return {
                slot: worn[slot]
                for slot in SLOTS
                if slot in worn
            }

    def save_set(self, account_id, set_id, entries):
        """Store a named set and return its new version number."""
        if not self._valid_id(set_id):
            raise WardrobeError("WD_INVALID_SET", set_id)

        if isinstance(entries, Mapping):
            raw_entries = list(entries.items())
        elif isinstance(entries, (str, bytes)):
            raise WardrobeError("WD_INVALID_SET", "entries")
        else:
            try:
                raw_entries = list(entries)
            except TypeError as exc:
                raise WardrobeError("WD_INVALID_SET", "entries") from exc

        if not raw_entries:
            raise WardrobeError("WD_INVALID_SET", "empty")

        slots: dict[str, str] = {}
        for entry in raw_entries:
            if isinstance(entry, Mapping):
                slot = entry.get("slot")
                appearance_id = entry.get("appearance_id")
            elif isinstance(entry, (tuple, list)) and len(entry) == 2:
                slot, appearance_id = entry
            else:
                raise WardrobeError("WD_INVALID_SET", "entry")

            if slot not in SLOTS:
                raise WardrobeError("WD_UNKNOWN_SLOT", slot)
            if not self._valid_id(appearance_id):
                raise WardrobeError("WD_INVALID_APPEARANCE", appearance_id)
            if slot in slots:
                raise WardrobeError("WD_DUPLICATE_SLOT", slot)
            slots[slot] = appearance_id

        with self._lock:
            state = self._accounts.get(account_id)
            if state is None:
                state = _AccountState(set(), {}, {}, {}, {})
                self._accounts[account_id] = state
            previous = state.sets.get(set_id)
            version = previous.version + 1 if previous is not None else 1
            state.sets[set_id] = _SetState(version, dict(slots))
            self._stats["sets"] += 1
            return version

    def preview(self, account_id, character_id, set_id):
        """Report what a set would apply without touching the character."""
        with self._lock:
            state, _ = self._require_character(account_id, character_id)
            stored_set = state.sets.get(set_id)
            if stored_set is None:
                raise WardrobeError("WD_UNKNOWN_SET", set_id)
            missing = tuple(sorted({
                appearance_id
                for appearance_id in stored_set.slots.values()
                if appearance_id not in state.collection
            }))
            slots = {
                slot: stored_set.slots[slot]
                for slot in SLOTS
                if slot in stored_set.slots
            }
            return {
                "set_id": set_id,
                "version": stored_set.version,
                "slots": slots,
                "missing": missing,
            }

    def apply_set(self, account_id, character_id, set_id):
        """Apply a whole set or refuse it without partial effects."""
        with self._lock:
            state, character = self._require_character(account_id, character_id)
            stored_set = state.sets.get(set_id)
            if stored_set is None:
                raise WardrobeError("WD_UNKNOWN_SET", set_id)

            missing = tuple(sorted({
                appearance_id
                for appearance_id in stored_set.slots.values()
                if appearance_id not in state.collection
            }))
            if missing:
                raise WardrobeError("WD_SET_INCOMPLETE", {"missing": missing})

            ordered_slots = [
                (slot, stored_set.slots[slot])
                for slot in SLOTS
                if slot in stored_set.slots
            ]
            for slot, appearance_id in ordered_slots:
                appearance = self._appearances[appearance_id]
                if appearance.slot != slot:
                    raise WardrobeError("WD_SLOT_MISMATCH", {
                        "appearance_id": appearance_id,
                        "appearance_slot": appearance.slot,
                        "target_slot": slot,
                    })
                if not self._armor_matches(
                        appearance.armor_class, character.armor_class):
                    raise WardrobeError("WD_ARMOR_MISMATCH", {
                        "appearance_id": appearance_id,
                        "appearance_armor_class": appearance.armor_class,
                        "character_armor_class": character.armor_class,
                    })

            dyes = {
                appearance_id: dict(channels)
                for appearance_id, channels in state.dyes.items()
            }
            worn = dict(state.transmogs.get(character_id, {}))
            for slot, appearance_id in ordered_slots:
                replaced = worn.get(slot)
                if replaced:
                    self._inherit_dyes(dyes, replaced, appearance_id)
                worn[slot] = appearance_id

            state.dyes = dyes
            state.transmogs[character_id] = worn
            self._stats["applies"] += 1
            return tuple(sorted({
                appearance_id for _, appearance_id in ordered_slots
            }))

    def snapshot(self):
        """Return a detached state dictionary for the whole wardrobe."""
        with self._lock:
            appearances = {
                appearance_id: {
                    "appearance_id": appearance.appearance_id,
                    "slot": appearance.slot,
                    "armor_class": appearance.armor_class,
                    "source": appearance.source,
                }
                for appearance_id, appearance in sorted(self._appearances.items())
            }
            accounts = {}
            for account_id, state in sorted(self._accounts.items()):
                characters = {
                    character_id: {
                        "account_id": character.account_id,
                        "character_id": character.character_id,
                        "armor_class": character.armor_class,
                    }
                    for character_id, character in sorted(state.characters.items())
                }
                transmogs = {
                    character_id: {
                        slot: worn[slot]
                        for slot in SLOTS
                        if slot in worn
                    }
                    for character_id, worn in sorted(state.transmogs.items())
                }
                sets = {
                    set_id: {
                        "version": stored_set.version,
                        "slots": {
                            slot: stored_set.slots[slot]
                            for slot in SLOTS
                            if slot in stored_set.slots
                        },
                    }
                    for set_id, stored_set in sorted(state.sets.items())
                }
                accounts[account_id] = {
                    "collection": sorted(state.collection),
                    "dyes": {
                        appearance_id: self._ordered_dyes(channels)
                        for appearance_id, channels in sorted(state.dyes.items())
                    },
                    "characters": characters,
                    "transmogs": transmogs,
                    "sets": sets,
                }
            return {
                "version": SNAPSHOT_VERSION,
                "max_collection": self.max_collection,
                "dye_channels": list(self.dye_channels),
                "appearances": appearances,
                "accounts": accounts,
                "stats": dict(self._stats),
            }

    def restore(self, state):
        """Replace the wardrobe with a previously taken snapshot."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except WardrobeError as exc:
                if exc.code == "WD_SNAPSHOT_INVALID":
                    raise
                raise WardrobeError("WD_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:
                raise WardrobeError("WD_SNAPSHOT_INVALID", str(exc)) from exc

            max_collection, dye_channels, appearances, accounts, stats = parsed
            self.max_collection = max_collection
            self.dye_channels = dye_channels
            self._appearances = appearances
            self._accounts = accounts
            self._stats = stats

    def stats(self):
        """Return collection, dye, transmog and set counters."""
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _snapshot_invalid(detail):
        raise WardrobeError("WD_SNAPSHOT_INVALID", detail)

    @staticmethod
    def _snapshot_int(value, detail):
        if not isinstance(value, int) or isinstance(value, bool):
            WardrobeTransmogGuard._snapshot_invalid(detail)
        return value

    def _parse_snapshot(self, state):
        if not isinstance(state, Mapping):
            self._snapshot_invalid("root")
        version = self._snapshot_int(state.get("version"), "version")
        if version != SNAPSHOT_VERSION:
            self._snapshot_invalid("version")

        max_collection = self._snapshot_int(
            state.get("max_collection"), "max_collection"
        )
        if max_collection < 0:
            self._snapshot_invalid("max_collection")

        raw_channels = state.get("dye_channels")
        if not isinstance(raw_channels, (list, tuple)):
            self._snapshot_invalid("dye_channels")
        dye_channels = tuple(raw_channels)
        if any(not self._valid_text(channel) for channel in dye_channels):
            self._snapshot_invalid("dye_channels")
        if len(set(dye_channels)) != len(dye_channels):
            self._snapshot_invalid("dye_channels")
        allowed_channels = set(dye_channels)

        raw_stats = state.get("stats")
        if not isinstance(raw_stats, Mapping):
            self._snapshot_invalid("stats")
        stats = {}
        for key in STAT_KEYS:
            value = self._snapshot_int(raw_stats.get(key), "stats")
            if value < 0:
                self._snapshot_invalid("stats")
            stats[key] = value

        raw_appearances = state.get("appearances")
        if not isinstance(raw_appearances, Mapping):
            self._snapshot_invalid("appearances")
        appearances = {}
        for appearance_id, raw in raw_appearances.items():
            if not self._valid_id(appearance_id) or not isinstance(raw, Mapping):
                self._snapshot_invalid("appearances")
            if raw.get("appearance_id") != appearance_id:
                self._snapshot_invalid("appearances")
            slot = raw.get("slot")
            armor_class = raw.get("armor_class")
            source = raw.get("source")
            if (slot not in SLOTS or not isinstance(armor_class, str)
                    or not isinstance(source, str)):
                self._snapshot_invalid("appearances")
            appearances[appearance_id] = Appearance(
                appearance_id, slot, armor_class, source
            )

        raw_accounts = state.get("accounts")
        if not isinstance(raw_accounts, Mapping):
            self._snapshot_invalid("accounts")
        accounts = {}
        for account_id, raw in raw_accounts.items():
            if not isinstance(account_id, str) or not isinstance(raw, Mapping):
                self._snapshot_invalid("accounts")

            raw_collection = raw.get("collection")
            if not isinstance(raw_collection, (list, tuple)):
                self._snapshot_invalid("collection")
            collection = set()
            for appearance_id in raw_collection:
                if not self._valid_id(appearance_id):
                    self._snapshot_invalid("collection")
                if appearance_id not in appearances:
                    self._snapshot_invalid("collection")
                if appearance_id in collection:
                    self._snapshot_invalid("collection")
                collection.add(appearance_id)
            if len(collection) > max_collection:
                self._snapshot_invalid("collection")

            raw_dyes = raw.get("dyes")
            if not isinstance(raw_dyes, Mapping):
                self._snapshot_invalid("dyes")
            dyes = {}
            for appearance_id, raw_channels_for_appearance in raw_dyes.items():
                if (appearance_id not in collection
                        or not isinstance(raw_channels_for_appearance, Mapping)):
                    self._snapshot_invalid("dyes")
                channels = {}
                for channel, color_id in raw_channels_for_appearance.items():
                    color_id = self._snapshot_int(color_id, "dyes")
                    if (channel not in allowed_channels
                            or color_id <= DEFAULT_DYE
                            or color_id > MAX_COLOR):
                        self._snapshot_invalid("dyes")
                    channels[channel] = color_id
                if channels:
                    dyes[appearance_id] = channels

            raw_characters = raw.get("characters")
            if not isinstance(raw_characters, Mapping):
                self._snapshot_invalid("characters")
            characters = {}
            for character_id, raw_character in raw_characters.items():
                if (not self._valid_id(character_id)
                        or not isinstance(raw_character, Mapping)):
                    self._snapshot_invalid("characters")
                armor_class = raw_character.get("armor_class")
                if (raw_character.get("account_id") != account_id
                        or raw_character.get("character_id") != character_id
                        or not self._valid_text(armor_class)):
                    self._snapshot_invalid("characters")
                characters[character_id] = Character(
                    account_id, character_id, armor_class
                )

            raw_transmogs = raw.get("transmogs")
            if not isinstance(raw_transmogs, Mapping):
                self._snapshot_invalid("transmogs")
            transmogs = {}
            for character_id, raw_worn in raw_transmogs.items():
                if (character_id not in characters
                        or not isinstance(raw_worn, Mapping)):
                    self._snapshot_invalid("transmogs")
                worn = {}
                for slot, appearance_id in raw_worn.items():
                    if (slot not in SLOTS
                            or appearance_id not in collection):
                        self._snapshot_invalid("transmogs")
                    appearance = appearances[appearance_id]
                    if (appearance.slot != slot
                            or not self._armor_matches(
                                appearance.armor_class,
                                characters[character_id].armor_class,
                            )):
                        self._snapshot_invalid("transmogs")
                    worn[slot] = appearance_id
                if worn:
                    transmogs[character_id] = worn

            raw_sets = raw.get("sets")
            if not isinstance(raw_sets, Mapping):
                self._snapshot_invalid("sets")
            sets = {}
            for set_id, raw_set in raw_sets.items():
                if not self._valid_id(set_id) or not isinstance(raw_set, Mapping):
                    self._snapshot_invalid("sets")
                version = self._snapshot_int(raw_set.get("version"), "sets")
                raw_slots = raw_set.get("slots")
                if version <= 0 or not isinstance(raw_slots, Mapping) or not raw_slots:
                    self._snapshot_invalid("sets")
                slots = {}
                for slot, appearance_id in raw_slots.items():
                    if slot not in SLOTS or not self._valid_id(appearance_id):
                        self._snapshot_invalid("sets")
                    slots[slot] = appearance_id
                sets[set_id] = _SetState(version, slots)

            accounts[account_id] = _AccountState(
                collection, dyes, characters, transmogs, sets
            )

        return max_collection, dye_channels, appearances, accounts, stats
