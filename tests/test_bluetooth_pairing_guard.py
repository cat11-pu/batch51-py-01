import copy

import pytest

import bluetooth_pairing_guard as bp

NOW = 1_800_000_000
ADDR = "AA:BB:CC:00:11:22"


def guard(**kwargs):
    return bp.BluetoothPairingGuard(**kwargs)


def adapter(g, adapter_id="hci-a", *, io_caps=None, max_bonds=4, powered=True):
    return g.register_adapter(adapter_id, powered=powered, io_caps=io_caps,
                              max_bonds=max_bonds)


def pair(g, adapter_id="hci-a", address=ADDR, *, transport="le", peer_caps=None,
         requires_mitm=False, now=NOW):
    return g.pair_request(adapter_id, address, transport=transport,
                          peer_caps=peer_caps, requires_mitm=requires_mitm, now=now)


def test_register_adapter_is_idempotent_and_rejects_blank_id():
    g = guard()
    info = adapter(g, io_caps={"display": True, "keyboard": True}, max_bonds=2)
    assert info.adapter_id == "hci-a"
    assert info.powered is True
    assert info.io_caps == ("display", "keyboard")
    assert info.max_bonds == 2

    again = adapter(g, io_caps={"display": True}, max_bonds=2, powered=False)
    assert again.powered is False
    assert again.io_caps == ("display",)
    assert g.stats() == {"adapters": 1, "sessions": 0, "confirmed": 0, "bonds": 0,
                         "removed": 0, "cooldowns": 0, "rejected": 0}

    with pytest.raises(bp.PairingError) as exc:
        adapter(g, adapter_id="")
    assert exc.value.code == "PAIRING_INVALID_REQUEST"


def test_unpowered_or_unknown_adapter_cannot_start_pairing():
    g = guard()
    adapter(g, powered=False)
    with pytest.raises(bp.PairingError) as exc:
        pair(g)
    assert exc.value.code == "PAIRING_ADAPTER_OFFLINE"
    assert g.stats()["rejected"] == 1

    with pytest.raises(bp.PairingError) as exc:
        pair(g, adapter_id="hci-z")
    assert exc.value.code == "PAIRING_ADAPTER_UNKNOWN"


def test_io_capability_matrix_selects_method():
    g = guard()
    adapter(g, "hci-a", io_caps={"display": True, "keyboard": True})
    adapter(g, "hci-b", io_caps={"display": True})
    adapter(g, "hci-c", io_caps={"keyboard": True})

    both = pair(g, "hci-a", peer_caps={"display": True, "keyboard": True})
    assert both.method == bp.NUMERIC_COMPARISON
    local_display = pair(g, "hci-b", peer_caps={"keyboard": True})
    assert local_display.method == bp.PASSKEY_DISPLAY
    peer_display = pair(g, "hci-c", peer_caps={"display": True})
    assert peer_display.method == bp.PASSKEY_ENTRY


def test_just_works_only_when_neither_side_has_io():
    g = guard()
    adapter(g, "hci-a")
    plain = pair(g, "hci-a", peer_caps={})
    assert plain.method == bp.JUST_WORKS

    adapter(g, "hci-b", io_caps={"display": True})
    with pytest.raises(bp.PairingError) as exc:
        pair(g, "hci-b", address="AA:BB:CC:00:11:33", peer_caps={})
    assert exc.value.code == "PAIRING_IO_INSUFFICIENT"

    adapter(g, "hci-c")
    with pytest.raises(bp.PairingError) as exc:
        pair(g, "hci-c", address="AA:BB:CC:00:11:44", peer_caps={"keyboard": True})
    assert exc.value.code == "PAIRING_IO_INSUFFICIENT"


def test_mitm_requirement_blocks_just_works_only():
    g = guard()
    adapter(g, "hci-a")
    with pytest.raises(bp.PairingError) as exc:
        pair(g, "hci-a", peer_caps={}, requires_mitm=True)
    assert exc.value.code == "PAIRING_MITM_REQUIRED"
    assert g.pending_sessions() == []

    adapter(g, "hci-b", io_caps={"display": True, "keyboard": True})
    session = pair(g, "hci-b", peer_caps={"display": True, "keyboard": True},
                   requires_mitm=True)
    assert session.method == bp.NUMERIC_COMPARISON
    assert session.requires_mitm is True


def test_session_shape_and_pending_order():
    g = guard()
    adapter(g, "hci-a")
    first = pair(g, "hci-a", transport="le", peer_caps={})
    second = pair(g, "hci-a", address="AA:BB:CC:00:11:99", transport="classic", peer_caps={})
    assert (first.session_id, second.session_id) == ("s1", "s2")
    assert first.transport == "le" and second.transport == "classic"
    assert len(first.passkey) == 6 and first.passkey.isdigit()
    assert first.attempts == 0
    assert first.deadline == NOW + 60
    assert [row.session_id for row in g.pending_sessions()] == ["s1", "s2"]


def test_duplicate_active_session_is_refused_per_transport():
    g = guard()
    adapter(g, "hci-a")
    pair(g, "hci-a", transport="le", peer_caps={})
    with pytest.raises(bp.PairingError) as exc:
        pair(g, "hci-a", transport="le", peer_caps={})
    assert exc.value.code == "PAIRING_SESSION_EXISTS"

    other = pair(g, "hci-a", transport="classic", peer_caps={})
    assert other.transport == "classic"
    assert len(g.pending_sessions()) == 2


def test_passkey_mismatch_counts_attempts_then_accepts_correct_value():
    g = guard()
    adapter(g, "hci-a", io_caps={"display": True})
    session = pair(g, "hci-a", peer_caps={"keyboard": True})
    wrong = "000000" if session.passkey != "000000" else "111111"

    with pytest.raises(bp.PairingError) as exc:
        g.confirm_passkey(session.session_id, wrong, now=NOW)
    assert exc.value.code == "PAIRING_PASSKEY_MISMATCH"
    assert exc.value.detail == {"attempts": 1, "remaining": 2}

    with pytest.raises(bp.PairingError) as exc:
        g.confirm_passkey(session.session_id, wrong, now=NOW)
    assert exc.value.detail == {"attempts": 2, "remaining": 1}

    out = g.confirm_passkey(session.session_id, session.passkey, now=NOW)
    assert out == {"status": "confirmed", "attempts": 2}
    assert g.stats()["confirmed"] == 1


def test_exhausted_attempts_open_a_cooldown_window():
    g = guard()
    adapter(g, "hci-a", io_caps={"display": True})
    session = pair(g, "hci-a", peer_caps={"keyboard": True})
    wrong = "000000" if session.passkey != "000000" else "111111"
    for _ in range(2):
        with pytest.raises(bp.PairingError):
            g.confirm_passkey(session.session_id, wrong, now=NOW)
    with pytest.raises(bp.PairingError) as exc:
        g.confirm_passkey(session.session_id, wrong, now=NOW)
    assert exc.value.code == "PAIRING_ATTEMPTS_EXHAUSTED"
    assert exc.value.detail == {"attempts": 3}
    assert g.stats()["cooldowns"] == 1

    with pytest.raises(bp.PairingError) as exc:
        pair(g, "hci-a", now=NOW + 10, peer_caps={"keyboard": True})
    assert exc.value.code == "PAIRING_COOLDOWN"
    assert exc.value.detail == {"retry_after": 20}

    resumed = pair(g, "hci-a", now=NOW + 30, peer_caps={"keyboard": True})
    assert resumed.session_id == "s2"


def test_completion_requires_confirmation_for_non_just_works():
    g = guard()
    adapter(g, "hci-a", io_caps={"display": True})
    session = pair(g, "hci-a", peer_caps={"keyboard": True})
    with pytest.raises(bp.PairingError) as exc:
        g.complete_pairing(session.session_id, now=NOW)
    assert exc.value.code == "PAIRING_NOT_CONFIRMED"
    assert g.bonds("hci-a") == []


def test_completion_after_window_is_refused():
    g = guard()
    adapter(g, "hci-a")
    session = pair(g, "hci-a", peer_caps={})
    with pytest.raises(bp.PairingError) as exc:
        g.complete_pairing(session.session_id, now=NOW + 61)
    assert exc.value.code == "PAIRING_SESSION_EXPIRED"
    assert g.bonds("hci-a") == []

    fresh = pair(g, "hci-a", peer_caps={}, now=NOW + 61)
    bond = g.complete_pairing(fresh.session_id, now=NOW + 61)
    assert bond.address == ADDR


def test_bond_is_scoped_to_adapter_and_removable():
    g = guard()
    adapter(g, "hci-a")
    adapter(g, "hci-b")
    session = pair(g, "hci-a", transport="le", peer_caps={})
    bond = g.complete_pairing(session.session_id, now=NOW)
    assert (bond.adapter_id, bond.address, bond.transport) == ("hci-a", ADDR, "le")
    assert bond.method == bp.JUST_WORKS
    assert bond.key.startswith("key-hci-a-")
    assert bond.created_at == NOW
    assert g.bond_for("hci-a", ADDR) == bond
    assert g.bond_for("hci-b", ADDR) is None
    assert g.bonds("hci-b") == []
    assert g.pending_sessions() == []

    assert g.remove_bond("hci-a", ADDR) == 1
    assert g.remove_bond("hci-a", ADDR) == 0
    assert g.bond_for("hci-a", ADDR) is None
    assert g.stats()["removed"] == 1


def test_repairing_same_peer_replaces_bond_and_rotates_key():
    g = guard()
    adapter(g, "hci-a")
    first = g.complete_pairing(pair(g, "hci-a", peer_caps={}).session_id, now=NOW)
    second = g.complete_pairing(pair(g, "hci-a", peer_caps={}, now=NOW + 100).session_id,
                                now=NOW + 100)
    assert second.key != first.key
    assert second.created_at == NOW + 100
    assert len(g.bonds("hci-a")) == 1
    assert g.bond_for("hci-a", ADDR) == second
    assert g.stats()["bonds"] == 1


def test_bond_capacity_rejects_new_peers_but_allows_overwrite():
    g = guard()
    adapter(g, "hci-a", max_bonds=2)
    for index in range(2):
        address = f"AA:BB:CC:00:22:{index:02d}"
        g.complete_pairing(pair(g, "hci-a", address=address, peer_caps={}).session_id, now=NOW)

    with pytest.raises(bp.PairingError) as exc:
        g.complete_pairing(
            pair(g, "hci-a", address="AA:BB:CC:00:22:99", peer_caps={}).session_id, now=NOW)
    assert exc.value.code == "PAIRING_BOND_LIMIT"

    again = g.complete_pairing(
        pair(g, "hci-a", address="AA:BB:CC:00:22:00", peer_caps={}, now=NOW + 5).session_id,
        now=NOW + 5)
    assert again.address == "AA:BB:CC:00:22:00"
    assert len(g.bonds("hci-a")) == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    adapter(g, "hci-a")
    bonded = g.complete_pairing(pair(g, "hci-a", peer_caps={}).session_id, now=NOW)
    pending = pair(g, "hci-a", address="AA:BB:CC:00:33:44", peer_caps={}, now=NOW + 1)
    state = g.snapshot()
    assert set(state) == {"version", "adapters", "sessions", "bonds", "cooldowns"}
    pristine = copy.deepcopy(state)

    state["bonds"].clear()
    state["adapters"].clear()
    assert g.bond_for("hci-a", ADDR) == bonded
    assert [row.session_id for row in g.pending_sessions()] == [pending.session_id]

    clone = guard()
    clone.restore(pristine)
    assert clone.bond_for("hci-a", ADDR) == bonded
    assert [row.session_id for row in clone.pending_sessions()] == [pending.session_id]
    assert clone.complete_pairing(pending.session_id, now=NOW + 2).address == "AA:BB:CC:00:33:44"

    for bad in (None, {}, {"version": 1, "adapters": [], "sessions": [], "bonds": []},
                {"version": 1, "adapters": [], "sessions": [], "bonds": [],
                 "cooldowns": []}):
        with pytest.raises(bp.PairingError) as exc:
            g.restore(bad)
        assert exc.value.code == "PAIRING_SNAPSHOT_INVALID"
    assert g.bond_for("hci-a", ADDR) == bonded
