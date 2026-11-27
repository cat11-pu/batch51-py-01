import copy
import threading

import pytest

import client_version_gate as cvg

NOW = "2026-11-27T08:00:00+00:00"
LATER = "2026-11-27T08:10:00+00:00"


def gate(**kwargs):
    return cvg.ClientVersionGate(**kwargs)


def policy(g, *, platform="android", channel="ch-3", min_version="1.9.0",
           protocol_min=2, protocol_max=3, allow_prerelease=False):
    return g.set_policy(platform, channel, min_version=min_version,
                        recommended_version="2.4.0", protocol_min=protocol_min,
                        protocol_max=protocol_max, allow_prerelease=allow_prerelease)


def admit(g, client_version, protocol_version=2, *, account="acc-1",
          platform="android", channel="ch-3", now=NOW):
    return g.admit(account, platform=platform, channel=channel,
                   client_version=client_version,
                   protocol_version=protocol_version, now=now)


def test_set_policy_returns_increasing_generation_and_exposes_fields():
    g = gate()
    first = policy(g)
    second = g.set_policy("ios", "appstore", min_version="1.4.0")
    assert (first, second) == (1, 2)
    current = g.policy_of("android", "ch-3")
    assert (current.platform, current.channel) == ("android", "ch-3")
    assert current.min_version == "1.9.0"
    assert current.recommended_version == "2.4.0"
    assert (current.protocol_min, current.protocol_max) == (2, 3)
    assert current.allow_prerelease is False
    assert current.version == 1
    fallback = g.policy_of("ios", "appstore")
    assert fallback.recommended_version == "1.4.0"
    assert fallback.version == 2
    assert g.stats()["policy_updates"] == 2


def test_version_comparison_walks_numeric_segments():
    g = gate()
    policy(g, min_version="1.9.0")
    assert admit(g, "1.10.0").allowed is True
    assert admit(g, "1.9.10").allowed is True
    assert admit(g, "1.10").allowed is True
    below = admit(g, "1.8.99")
    assert (below.allowed, below.reason) == (False, "BELOW_MIN_VERSION")
    assert admit(g, "1.9.0").allowed is True


def test_invalid_requests_and_version_strings_are_refused():
    g = gate()
    policy(g)
    for kwargs in (
        dict(account="", platform="android", channel="ch-3",
             client_version="2.0.0", protocol_version=2),
        dict(account="acc-1", platform=" ", channel="ch-3",
             client_version="2.0.0", protocol_version=2),
        dict(account="acc-1", platform="android", channel="",
             client_version="2.0.0", protocol_version=2),
        dict(account="acc-1", platform="android", channel="ch-3",
             client_version="2.0.0", protocol_version=0),
    ):
        with pytest.raises(cvg.GateError) as exc:
            g.admit(now=NOW, **kwargs)
        assert exc.value.code == "GATE_INVALID_REQUEST"
    for bad in ("1.2.3.4", "v1.2.3", "1..0", "1.x.0"):
        with pytest.raises(cvg.GateError) as exc:
            admit(g, bad)
        assert exc.value.code == "GATE_INVALID_VERSION"
    assert g.stats()["admissions"] == 0


def test_low_version_is_refused_with_reason_and_policy_version():
    g = gate()
    policy(g, min_version="1.5.0")
    out = admit(g, "1.4.9")
    assert (out.allowed, out.gray, out.reason) == (False, False, "BELOW_MIN_VERSION")
    assert out.policy_version == 1
    assert (out.platform, out.channel) == ("android", "ch-3")
    assert out.client_version == "1.4.9"
    assert g.stats()["rejected"] == 1
    assert g.stats()["allowed"] == 0


def test_protocol_window_rejects_versions_outside_the_interval():
    g = gate()
    policy(g, min_version="1.0.0", protocol_min=2, protocol_max=3)
    for offered in (1, 4, 9):
        out = admit(g, "2.0.0", protocol_version=offered)
        assert (out.allowed, out.reason) == (False, "PROTOCOL_MISMATCH")
        assert out.policy_version == 1
    for offered in (2, 3):
        assert admit(g, "2.0.0", protocol_version=offered).reason == "VERSION_OK"


def test_negotiate_picks_the_highest_shared_protocol():
    g = gate()
    policy(g, min_version="1.0.0", protocol_min=2, protocol_max=4)
    picked = g.negotiate("acc-1", platform="android", channel="ch-3",
                         client_version="2.0.0", protocol_versions=[1, 3, 5],
                         now=NOW)
    assert picked.accepted_protocol == 3
    assert (picked.allowed, picked.reason) == (True, "PROTOCOL_OK")
    assert picked.policy_version == 1

    missing = g.negotiate("acc-1", platform="android", channel="ch-3",
                          client_version="2.0.0", protocol_versions=[1, 5],
                          now=NOW)
    assert missing.accepted_protocol is None
    assert (missing.allowed, missing.reason) == (False, "PROTOCOL_MISMATCH")

    stale = g.negotiate("acc-1", platform="android", channel="ch-3",
                        client_version="0.9.0", protocol_versions=[2],
                        now=NOW)
    assert stale.accepted_protocol is None
    assert (stale.allowed, stale.reason) == (False, "BELOW_MIN_VERSION")


def test_gray_account_passes_low_version_without_moving_the_policy():
    g = gate()
    policy(g, min_version="1.9.0")
    assert g.grant_gray("acc-9", "android", "ch-3") is True
    out = admit(g, "1.4.0", account="acc-9")
    assert (out.allowed, out.gray, out.reason) == (True, True, "GRAY_PASS")
    assert out.policy_version == 1
    assert g.policy_of("android", "ch-3").min_version == "1.9.0"
    assert g.policy_of("android", "ch-3").version == 1
    assert g.stats()["gray_grants"] == 1
    assert g.stats()["gray_active"] == 1


def test_gray_does_not_bypass_the_protocol_window():
    g = gate()
    policy(g, min_version="1.9.0", protocol_min=2, protocol_max=3)
    g.grant_gray("acc-9", "android", "ch-3")
    out = admit(g, "1.4.0", protocol_version=8, account="acc-9")
    assert (out.allowed, out.gray, out.reason) == (False, False, "PROTOCOL_MISMATCH")


def test_gray_grant_and_revoke_are_idempotent():
    g = gate()
    policy(g)
    assert g.grant_gray("acc-1", "android", "ch-3") is True
    assert g.grant_gray("acc-1", "android", "ch-3") is False
    assert g.stats()["gray_grants"] == 1
    assert g.stats()["gray_active"] == 1
    assert g.revoke_gray("acc-1", "android", "ch-3") is True
    assert g.revoke_gray("acc-1", "android", "ch-3") is False
    assert g.stats()["gray_active"] == 0
    assert admit(g, "1.0.0").reason == "BELOW_MIN_VERSION"


def test_history_is_bounded_and_reason_tracks_the_last_attempt():
    g = gate(max_history=3)
    policy(g, min_version="1.0.0")
    for version in ("1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"):
        admit(g, version)
    rows = g.history_of("acc-1")
    assert len(rows) == 3
    assert [row.client_version for row in rows] == ["1.2.0", "1.3.0", "1.4.0"]
    assert g.reason_of("acc-1") == "VERSION_OK"
    assert g.history_of("ghost") == []
    assert g.reason_of("ghost") is None


def test_concurrent_policy_writes_yield_unique_generations():
    g = gate()
    results = []
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            results.append(g.set_policy("android", f"ch-{index}",
                                        min_version="1.0.0"))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(results) == list(range(1, 9))
    assert g.stats()["policy_updates"] == 8
    assert g.stats()["policies"] == 8


def test_snapshot_is_detached_and_restore_roundtrips():
    g = gate()
    policy(g, min_version="1.9.0")
    g.grant_gray("acc-9", "android", "ch-3")
    admit(g, "2.0.0", account="acc-9")
    state = g.snapshot()
    assert set(state) == {"version", "policies", "gray", "history", "stats"}
    pristine = copy.deepcopy(state)

    state["policies"].clear()
    state["stats"]["admissions"] = 999
    assert g.stats()["admissions"] == 1
    assert g.policy_of("android", "ch-3").min_version == "1.9.0"

    clone = gate()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.policy_of("android", "ch-3").version == 1
    assert clone.grant_gray("acc-9", "android", "ch-3") is False
    assert admit(clone, "1.4.0", account="acc-9").reason == "GRAY_PASS"
    assert len(clone.history_of("acc-9")) == 1


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = gate()
    policy(g, min_version="1.9.0")
    admit(g, "2.0.0")
    bad_states = [
        None,
        {},
        {"version": 1, "policies": [], "gray": [], "history": {}},
        {"version": "1", "policies": [], "gray": [], "history": {}, "stats": {}},
        {"version": 1, "policies": {}, "gray": [], "history": {}, "stats": {}},
        {"version": 1, "policies": [], "gray": {}, "history": {}, "stats": {}},
        {"version": 1, "policies": [], "gray": [], "history": [], "stats": {}},
        {"version": 1, "policies": [], "gray": [], "history": {},
         "stats": {"policies": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(cvg.GateError) as exc:
            g.restore(bad)
        assert exc.value.code == "GATE_SNAPSHOT_INVALID"
    assert g.stats()["admissions"] == 1
    assert g.policy_of("android", "ch-3").min_version == "1.9.0"
    assert admit(g, "2.1.0").allowed is True


def test_drop_policy_bumps_generation_and_unknown_policy_is_refused():
    g = gate()
    policy(g)
    assert g.drop_policy("android", "ch-3") == 2
    with pytest.raises(cvg.GateError) as exc:
        g.policy_of("android", "ch-3")
    assert exc.value.code == "GATE_UNKNOWN_POLICY"
    with pytest.raises(cvg.GateError) as exc:
        g.drop_policy("android", "ch-3")
    assert exc.value.code == "GATE_UNKNOWN_POLICY"
    assert g.stats()["policies"] == 0
    assert g.stats()["policy_updates"] == 2


def test_stats_count_each_outcome_once():
    g = gate()
    policy(g, min_version="1.9.0", protocol_min=2, protocol_max=3)
    admit(g, "2.0.0")
    admit(g, "1.0.0")
    admit(g, "2.0.0", protocol_version=9)
    g.grant_gray("acc-7", "android", "ch-3")
    g.revoke_gray("acc-7", "android", "ch-3")
    assert g.stats() == {"policies": 1, "policy_updates": 1, "admissions": 3,
                         "allowed": 1, "rejected": 2, "gray_grants": 1,
                         "gray_active": 0}
