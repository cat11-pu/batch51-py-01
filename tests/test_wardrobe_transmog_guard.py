import pytest

import wardrobe_transmog_guard as wg


def guard(**kwargs):
    return wg.WardrobeTransmogGuard(**kwargs)


def add(obj, appearance_id, *, slot="chest", account="a1", armor="cloth", source="vendor"):
    return obj.unlock(account, appearance_id, slot=slot, armor_class=armor, source=source)


def ready(**kwargs):
    obj = guard(**kwargs)
    add(obj, "ap-head", slot="head")
    add(obj, "ap-head-2", slot="head")
    add(obj, "ap-chest", slot="chest")
    add(obj, "ap-legs", slot="legs")
    add(obj, "ap-feet", slot="feet")
    obj.register_character("a1", "c1", armor_class="cloth")
    return obj


def test_unlock_is_idempotent_and_collection_is_sorted():
    obj = guard()
    assert add(obj, "ap-chest-b") is True
    assert add(obj, "ap-chest-a") is True
    assert add(obj, "ap-chest-a") is False
    assert obj.collection("a1") == ("ap-chest-a", "ap-chest-b")
    assert obj.collection("a2") == ()
    assert obj.stats()["unlocks"] == 2


def test_unlock_rejects_conflicting_metadata():
    obj = guard()
    add(obj, "ap-1")
    with pytest.raises(wg.WardrobeError) as exc:
        obj.unlock("a1", "ap-1", slot="head", armor_class="cloth", source="vendor")
    assert exc.value.code == "WD_APPEARANCE_CONFLICT"
    assert obj.appearance_of("ap-1").slot == "chest"


def test_unlock_rejects_invalid_metadata():
    obj = guard()
    with pytest.raises(wg.WardrobeError) as exc:
        obj.unlock("a1", "ap-x", slot="tail", armor_class="cloth", source="vendor")
    assert exc.value.code == "WD_INVALID_APPEARANCE"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.unlock("a1", "", slot="chest", armor_class="cloth", source="vendor")
    assert exc.value.code == "WD_INVALID_APPEARANCE"
    assert obj.collection("a1") == ()


def test_collection_cap_is_per_account():
    obj = guard(max_collection=2)
    add(obj, "ap-1")
    add(obj, "ap-2")
    with pytest.raises(wg.WardrobeError) as exc:
        add(obj, "ap-3")
    assert exc.value.code == "WD_COLLECTION_FULL"
    assert obj.collection("a1") == ("ap-1", "ap-2")
    add(obj, "ap-3", account="a2")
    assert obj.collection("a2") == ("ap-3",)


def test_dye_records_channels_and_drops_default():
    obj = ready()
    assert obj.dye("a1", "ap-head", "primary", 7) == {"primary": 7}
    assert obj.dye("a1", "ap-head", "accent", 9) == {"accent": 9, "primary": 7}
    assert obj.dye("a1", "ap-head", "primary", 0) == {"accent": 9}
    assert obj.dye_channels_of("a1", "ap-head") == {"accent": 9}
    assert obj.stats()["dyes"] == 2


def test_dye_rejects_unknown_channel_and_bad_color():
    obj = ready()
    with pytest.raises(wg.WardrobeError) as exc:
        obj.dye("a1", "ap-head", "glow", 5)
    assert exc.value.code == "WD_UNKNOWN_CHANNEL"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.dye("a1", "ap-head", "primary", wg.MAX_COLOR + 1)
    assert exc.value.code == "WD_INVALID_COLOR"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.dye("a1", "ap-head", "primary", -1)
    assert exc.value.code == "WD_INVALID_COLOR"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.dye("a1", "ap-ghost", "primary", 5)
    assert exc.value.code == "WD_NOT_UNLOCKED"


def test_register_character_rejects_duplicate_and_blank_class():
    obj = guard()
    char = obj.register_character("a1", "c1", armor_class="cloth")
    assert (char.account_id, char.character_id, char.armor_class) == ("a1", "c1", "cloth")
    with pytest.raises(wg.WardrobeError) as exc:
        obj.register_character("a1", "c1", armor_class="cloth")
    assert exc.value.code == "WD_CHARACTER_EXISTS"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.register_character("a1", "c2", armor_class="")
    assert exc.value.code == "WD_INVALID_CHARACTER"


def test_transmog_requires_unlocked_appearance():
    obj = ready()
    with pytest.raises(wg.WardrobeError) as exc:
        obj.transmog("a1", "c1", "chest", "ap-ghost")
    assert exc.value.code == "WD_NOT_UNLOCKED"
    assert obj.transmog_of("a1", "c1") == {}


def test_transmog_rejects_slot_mismatch():
    obj = ready()
    with pytest.raises(wg.WardrobeError) as exc:
        obj.transmog("a1", "c1", "head", "ap-chest")
    assert exc.value.code == "WD_SLOT_MISMATCH"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.transmog("a1", "c1", "tail", "ap-chest")
    assert exc.value.code == "WD_UNKNOWN_SLOT"
    assert obj.transmog_of("a1", "c1") == {}


def test_transmog_keeps_one_appearance_per_slot():
    obj = ready()
    assert obj.transmog("a1", "c1", "head", "ap-head") == ""
    assert obj.transmog_of("a1", "c1") == {"head": "ap-head"}
    assert obj.transmog("a1", "c1", "head", "ap-head-2") == "ap-head"
    assert obj.transmog_of("a1", "c1") == {"head": "ap-head-2"}
    assert obj.stats()["transmogs"] == 2


def test_save_set_bumps_version_and_preview_is_read_only():
    obj = ready()
    entries = [{"slot": "head", "appearance_id": "ap-head"},
               {"slot": "chest", "appearance_id": "ap-chest"}]
    assert obj.save_set("a1", "set-1", entries) == 1
    assert obj.save_set("a1", "set-1", entries) == 2
    preview = obj.preview("a1", "c1", "set-1")
    assert preview["set_id"] == "set-1"
    assert preview["version"] == 2
    assert preview["slots"] == {"chest": "ap-chest", "head": "ap-head"}
    assert preview["missing"] == ()
    assert obj.transmog_of("a1", "c1") == {}
    assert obj.stats()["sets"] == 2


def test_save_set_rejects_duplicate_slot():
    obj = ready()
    entries = [{"slot": "head", "appearance_id": "ap-head"},
               {"slot": "head", "appearance_id": "ap-head-2"}]
    with pytest.raises(wg.WardrobeError) as exc:
        obj.save_set("a1", "set-bad", entries)
    assert exc.value.code == "WD_DUPLICATE_SLOT"
    with pytest.raises(wg.WardrobeError) as exc:
        obj.save_set("a1", "set-bad", [])
    assert exc.value.code == "WD_INVALID_SET"


def test_apply_set_fills_every_slot_atomically():
    obj = ready()
    entries = [{"slot": "head", "appearance_id": "ap-head"},
               {"slot": "chest", "appearance_id": "ap-chest"},
               {"slot": "legs", "appearance_id": "ap-legs"}]
    obj.save_set("a1", "set-1", entries)
    applied = obj.apply_set("a1", "c1", "set-1")
    assert applied == ("ap-chest", "ap-head", "ap-legs")
    assert obj.transmog_of("a1", "c1") == {"head": "ap-head",
                                           "chest": "ap-chest",
                                           "legs": "ap-legs"}
    assert obj.stats()["applies"] == 1


def test_apply_set_rejects_missing_items_and_rolls_back():
    obj = ready()
    obj.transmog("a1", "c1", "feet", "ap-feet")
    entries = [{"slot": "head", "appearance_id": "ap-head"},
               {"slot": "chest", "appearance_id": "ap-missing"}]
    obj.save_set("a1", "set-bad", entries)
    preview = obj.preview("a1", "c1", "set-bad")
    assert preview["missing"] == ("ap-missing",)
    with pytest.raises(wg.WardrobeError) as exc:
        obj.apply_set("a1", "c1", "set-bad")
    assert exc.value.code == "WD_SET_INCOMPLETE"
    assert tuple(exc.value.detail["missing"]) == ("ap-missing",)
    assert obj.transmog_of("a1", "c1") == {"feet": "ap-feet"}
    assert obj.stats()["applies"] == 0


def test_snapshot_restore_preserves_collection_dyes_and_sets():
    obj = ready()
    obj.dye("a1", "ap-head", "primary", 7)
    obj.save_set("a1", "set-1", [{"slot": "head", "appearance_id": "ap-head"}])
    obj.transmog("a1", "c1", "head", "ap-head")
    state = obj.snapshot()

    clone = guard()
    clone.restore(state)
    assert clone.collection("a1") == ("ap-chest", "ap-feet", "ap-head", "ap-head-2", "ap-legs")
    assert clone.dye_channels_of("a1", "ap-head") == {"primary": 7}
    assert clone.transmog_of("a1", "c1") == {"head": "ap-head"}
    assert clone.preview("a1", "c1", "set-1")["version"] == 1

    with pytest.raises(wg.WardrobeError) as exc:
        clone.restore({"version": 1})
    assert exc.value.code == "WD_SNAPSHOT_INVALID"
    assert clone.collection("a1") == ("ap-chest", "ap-feet", "ap-head", "ap-head-2", "ap-legs")
