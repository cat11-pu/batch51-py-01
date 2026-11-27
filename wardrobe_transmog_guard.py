"""Wardrobe transmog guard: account collection, dye channels, atomic set application."""

from __future__ import annotations

import threading
from dataclasses import dataclass

SLOTS = ("head", "chest", "legs", "feet", "weapon")
DYE_CHANNELS = ("primary", "secondary", "accent")
DEFAULT_DYE = 0
MAX_COLLECTION = 2000
MAX_COLOR = 255


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


class WardrobeTransmogGuard:
    """Keep account collections, dye channels and transmog sets consistent."""

    def __init__(self, *, max_collection: int = MAX_COLLECTION,
                 dye_channels=DYE_CHANNELS) -> None:
        self.max_collection = max_collection
        self.dye_channels = tuple(dye_channels)
        self._lock = threading.RLock()

    def unlock(self, account_id, appearance_id, *, slot, armor_class, source):
        """Add an appearance to the account collection; False if already there."""
        raise NotImplementedError

    def collection(self, account_id):
        """Return the account collection as a sorted tuple of appearance ids."""
        raise NotImplementedError

    def appearance_of(self, appearance_id):
        """Return the metadata recorded for one appearance."""
        raise NotImplementedError

    def register_character(self, account_id, character_id, *, armor_class):
        """Register a character that may wear transmogs."""
        raise NotImplementedError

    def dye(self, account_id, appearance_id, channel, color_id):
        """Set one dye channel and return the remaining non-default channels."""
        raise NotImplementedError

    def dye_channels_of(self, account_id, appearance_id):
        """Return the non-default dye channels recorded on one appearance."""
        raise NotImplementedError

    def slot_dyes_of(self, account_id, character_id):
        """Return the dye channels carried by each worn slot."""
        raise NotImplementedError

    def transmog(self, account_id, character_id, slot, appearance_id):
        """Wear one appearance in a slot and return the replaced appearance id."""
        raise NotImplementedError

    def transmog_of(self, account_id, character_id):
        """Return the appearance currently worn in each occupied slot."""
        raise NotImplementedError

    def save_set(self, account_id, set_id, entries):
        """Store a named set and return its new version number."""
        raise NotImplementedError

    def preview(self, account_id, character_id, set_id):
        """Report what a set would apply without touching the character."""
        raise NotImplementedError

    def apply_set(self, account_id, character_id, set_id):
        """Apply a whole set or refuse it without partial effects."""
        raise NotImplementedError

    def snapshot(self):
        """Return a detached state dictionary for the whole wardrobe."""
        raise NotImplementedError

    def restore(self, state):
        """Replace the wardrobe with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self):
        """Return collection, dye, transmog and set counters."""
        raise NotImplementedError
