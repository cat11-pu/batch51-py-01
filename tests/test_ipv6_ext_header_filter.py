import threading

import pytest

import ipv6_ext_header_filter as eh


def guard(**kwargs):
    return eh.ExtHeaderFilter(**kwargs)


def hop(options=("pad1",)):
    return {"kind": "hop", "length": 8, "options": list(options)}


def dest(options=("pad1",)):
    return {"kind": "dest", "length": 8, "options": list(options)}


def routing(kind=1):
    return {"kind": "routing", "length": 8, "options": [], "routing_type": kind}


def fragment():
    return {"kind": "fragment", "length": 8, "options": []}


def ah():
    return {"kind": "ah", "length": 8, "options": []}


def esp():
    return {"kind": "esp", "length": 8, "options": []}


def packet(headers, packet_id="p1"):
    return {"packet_id": packet_id, "source": "2001:db8::1",
            "headers": list(headers)}


def test_interface_policy_is_normalized_copy():
    g = guard()
    policy = g.register_interface("wan", {
        "allow_hop_by_hop": False,
        "hop_options": ("router-alert", "pad1", "pad1"),
        "routing_types": (3, 1, 1),
    })
    assert policy["allow_hop_by_hop"] is False
    assert policy["hop_options"] == ("pad1", "router-alert")
    assert policy["routing_types"] == (1, 3)
    assert policy["dest_options"] == ("pad1", "padn")
    assert policy["strip_hop_by_hop"] is False
    assert g.policy_for("wan") == policy
    assert g.remove_interface("wan") is True
    assert g.remove_interface("wan") is False
    assert g.policy_for("wan")["allow_hop_by_hop"] is True


def test_parse_chain_indexes_headers_and_rejects_garbage():
    g = guard()
    headers = g.parse_chain([hop(), dest(), routing(2)])
    assert [row.index for row in headers] == [0, 1, 2]
    assert [row.kind for row in headers] == ["hop", "dest", "routing"]
    assert headers[0].options == ("pad1",)
    assert headers[2].routing_type == 2
    assert headers[1].routing_type is None
    assert headers[0].length == 8
    for bad in ("nope", None, [{"kind": "hop"}], [{"length": 8}]):
        with pytest.raises(eh.ExtHeaderError) as exc:
            g.parse_chain(bad)
        assert exc.value.code == "EXT_INVALID_PACKET"


def test_clean_chain_is_forwarded():
    g = guard()
    verdict = g.evaluate(packet([hop(), dest(), routing(1)]))
    assert verdict.action == "forward"
    assert verdict.reason == "ok"
    assert verdict.header_index is None
    assert verdict.chain_length == 24
    assert verdict.packet_id == "p1"
    assert g.stats()["forwarded"] == 1


def test_hop_by_hop_can_be_denied_by_policy():
    g = guard()
    g.register_interface("wan", {"allow_hop_by_hop": False})
    verdict = g.evaluate(packet([hop(), dest()]), "wan")
    assert verdict.action == "drop"
    assert verdict.reason == "hop_not_allowed"
    assert verdict.header_index == 0
    assert g.stats()["dropped"] == 1


def test_strip_policy_removes_hop_header_and_keeps_rest():
    g = guard()
    g.register_interface("wan", {"allow_hop_by_hop": False,
                                 "strip_hop_by_hop": True})
    verdict = g.evaluate(packet([hop(), dest()]), "wan")
    assert verdict.action == "strip"
    assert verdict.reason == "hop_stripped"
    assert verdict.header_index == 0
    kept = g.strip(packet([hop(), dest()]), "wan")
    assert [row.kind for row in kept] == ["dest"]
    assert [row.index for row in kept] == [1]
    assert g.stats()["stripped"] == 1
    assert g.stats()["headers_removed"] == 1


def test_hop_options_must_be_in_whitelist():
    g = guard()
    verdict = g.evaluate(packet([hop(options=("jumbo",))]))
    assert verdict.action == "drop"
    assert verdict.reason == "hop_option_denied"
    assert verdict.header_index == 0


def test_destination_options_must_be_in_whitelist():
    g = guard()
    verdict = g.evaluate(packet([dest(options=("pad1", "jumbo"))]))
    assert verdict.action == "drop"
    assert verdict.reason == "dest_option_denied"
    assert verdict.header_index == 0


def test_routing_type_uses_whitelist():
    g = guard()
    good = g.evaluate(packet([routing(2)]))
    bad = g.evaluate(packet([routing(5)], packet_id="p2"))
    assert good.action == "forward" and good.reason == "ok"
    assert bad.action == "drop"
    assert bad.reason == "routing_type_denied"
    assert bad.header_index == 0


def test_header_order_rules_drop_packet():
    g = guard()
    after_fragment = g.evaluate(packet([fragment(), hop()]))
    after_esp = g.evaluate(packet([esp(), dest()], packet_id="p2"))
    assert (after_fragment.action, after_fragment.reason) == ("drop", "hop_after_fragment")
    assert after_fragment.header_index == 1
    assert (after_esp.action, after_esp.reason) == ("drop", "esp_not_last")
    assert after_esp.header_index == 0


def test_header_count_limit_drops_whole_packet():
    g = guard(max_headers=8)
    verdict = g.evaluate(packet([ah() for _ in range(9)]))
    assert verdict.action == "drop"
    assert verdict.reason == "too_many_headers"
    assert verdict.header_index is None
    assert verdict.chain_length == 72
    assert g.stats()["dropped"] == 1


def test_audit_trail_and_latest_verdict_lookup():
    g = guard()
    g.register_interface("wan", {"allow_hop_by_hop": False})
    g.evaluate(packet([dest()], packet_id="p1"))
    g.evaluate(packet([hop()], packet_id="p2"), "wan")
    g.evaluate(packet([routing(1)], packet_id="p3"))
    trail = g.audit_trail()
    assert [row.packet_id for row in trail] == ["p1", "p2", "p3"]
    assert [row.action for row in trail] == ["forward", "drop", "forward"]
    assert [row.packet_id for row in g.audit_trail(2)] == ["p2", "p3"]
    assert g.verdict_for("p2").reason == "hop_not_allowed"
    assert g.verdict_for("p9") is None


def test_stats_count_verdicts_and_policy_updates():
    g = guard()
    g.register_interface("wan", {"allow_hop_by_hop": False,
                                 "strip_hop_by_hop": True})
    g.evaluate(packet([dest()], packet_id="p1"))
    g.evaluate(packet([hop(), dest()], packet_id="p2"), "wan")
    g.evaluate(packet([dest(options=("jumbo",))], packet_id="p3"), "wan")
    assert g.stats() == {
        "forwarded": 1,
        "stripped": 1,
        "dropped": 1,
        "headers_removed": 1,
        "policy_updates": 1,
    }


def test_snapshot_restore_keeps_policies_and_audit():
    g = guard()
    policy = g.register_interface("wan", {"allow_hop_by_hop": False})
    g.evaluate(packet([dest()], packet_id="p1"))
    g.evaluate(packet([hop()], packet_id="p2"), "wan")
    state = g.snapshot()
    assert set(state) == {"version", "policies", "audit", "stats"}
    state["policies"].clear()
    assert g.policy_for("wan") == policy

    clone = guard()
    clone.restore(g.snapshot())
    assert clone.policy_for("wan") == policy
    assert [row.packet_id for row in clone.audit_trail()] == ["p1", "p2"]
    assert clone.stats() == g.stats()
    assert clone.verdict_for("p2").action == "drop"


def test_restore_rejects_malformed_state_without_touching_live_state():
    g = guard()
    policy = g.register_interface("wan", {"allow_hop_by_hop": False})
    g.evaluate(packet([hop()], packet_id="p1"), "wan")
    bad_states = [
        None,
        {},
        {"version": 2, "policies": {}, "audit": [], "stats": {}},
        {"version": 1, "policies": [], "audit": [], "stats": {}},
        {"version": 1, "policies": {}, "audit": "nope", "stats": {}},
        {"version": 1, "policies": {}, "audit": []},
    ]
    for bad in bad_states:
        with pytest.raises(eh.ExtHeaderError) as exc:
            g.restore(bad)
        assert exc.value.code == "EXT_SNAPSHOT_INVALID"
    assert g.policy_for("wan") == policy
    assert g.stats()["dropped"] == 1


def test_concurrent_policy_swap_keeps_every_verdict_complete():
    g = guard()
    open_policy = {"allow_hop_by_hop": True, "strip_hop_by_hop": False}
    strict_policy = {"allow_hop_by_hop": False, "strip_hop_by_hop": True}
    g.register_interface("wan", open_policy)
    errors = []
    verdicts = []
    stop = threading.Event()

    def swapper():
        try:
            while not stop.is_set():
                g.register_interface("wan", strict_policy)
                g.register_interface("wan", open_policy)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    def worker():
        try:
            for index in range(40):
                verdicts.append(g.evaluate(packet([hop(), dest()],
                                                  packet_id=f"w{index}"), "wan"))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=swapper)]
    threads += [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads[1:]:
        thread.join()
    stop.set()
    threads[0].join()

    assert errors == []
    assert len(verdicts) == 160
    allowed = {
        ("forward", "ok"),
        ("strip", "hop_stripped"),
        ("drop", "hop_not_allowed"),
    }
    assert {(row.action, row.reason) for row in verdicts} <= allowed
    live = g.policy_for("wan")
    live["hop_options"] = ("tampered",)
    assert g.policy_for("wan")["hop_options"] == ("pad1", "router-alert")
