import copy
import threading

import pytest

import udev_rule_synthesizer as udev


def new_synth(**kwargs):
    return udev.UdevRuleSynthesizer(**kwargs)


def test_add_rule_normalizes_match_and_returns_record():
    synth = new_synth()
    rule = synth.add_rule({"SUBSYSTEM": "usb", "idVendor": "1234"},
                          mode="0660", owner="lab", group="usb", priority=80)
    assert rule.rule_id == "rule-0001"
    assert rule.match == (("SUBSYSTEM", "usb"), ("idVendor", "1234"))
    assert (rule.mode, rule.owner, rule.group, rule.priority) == (
        "0660", "lab", "usb", 80)
    assert synth.rule("rule-0001") == rule
    assert synth.rule("missing") is None
    assert synth.rules() == (rule,)
    assert synth.stats()["added"] == 1


def test_add_rule_rejects_duplicate_and_invalid_fields():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, rule_id="r1")
    with pytest.raises(udev.UdevError) as exc:
        synth.add_rule({"SUBSYSTEM": "block"}, rule_id="r1")
    assert exc.value.code == "UDEV_RULE_EXISTS"

    bad_calls = [
        dict(match={}, mode="0660"),
        dict(match={"SUBSYSTEM": "usb"}, mode="660"),
        dict(match={"SUBSYSTEM": "usb"}, mode="0668"),
        dict(match={"SUBSYSTEM": "usb"}, priority=-1),
        dict(match={"SUBSYSTEM": "usb"}, owner=""),
        dict(match={"SUBSYSTEM": "usb"}, group="usb group"),
        dict(match={"SUBSYSTEM": 5}),
        dict(match={"SUBSYSTEM": "usb"}, rule_id=""),
    ]
    for kwargs in bad_calls:
        match = kwargs.pop("match")
        with pytest.raises(udev.UdevError) as exc:
            synth.add_rule(match, **kwargs)
        assert exc.value.code == "UDEV_INVALID_RULE"

    assert len(synth.rules()) == 1
    assert synth.stats()["added"] == 1
    assert synth.stats()["refused"] == 9


def test_effective_applies_highest_priority_matching_rule():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0666", rule_id="slow",
                   priority=40)
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0640", rule_id="shigh",
                   priority=60)
    spec = synth.effective("sda", {"SUBSYSTEM": "usb", "idVendor": "1234"})
    assert spec == udev.NodeSpec(device="sda", mode="0640", owner="root",
                                 group="root", rule_id="shigh")

    synth.add_rule({"SUBSYSTEM": "usb", "idVendor": "9999"}, mode="0600",
                   rule_id="sother", priority=90)
    still = synth.effective("sdb", {"SUBSYSTEM": "usb", "idVendor": "1234"})
    assert still.rule_id == "shigh"

    default = synth.effective("sdc", {"SUBSYSTEM": "block"})
    assert (default.mode, default.owner, default.group,
            default.rule_id) == ("0600", "root", "root", "")


def test_effective_tie_breaks_by_specificity_then_rule_id():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0600", rule_id="a-broad",
                   priority=50)
    spec = synth.effective("sda", {"SUBSYSTEM": "usb", "idVendor": "1234"})
    assert spec.rule_id == "a-broad"

    synth.add_rule({"SUBSYSTEM": "usb", "idVendor": "1234"}, mode="0644",
                   rule_id="b-specific", priority=50)
    spec = synth.effective("sda", {"SUBSYSTEM": "usb", "idVendor": "1234"})
    assert (spec.mode, spec.rule_id) == ("0644", "b-specific")

    synth.add_rule({"SUBSYSTEM": "usb", "idVendor": "1234"}, mode="0640",
                   rule_id="c-specific", priority=50)
    spec = synth.effective("sda", {"SUBSYSTEM": "usb", "idVendor": "1234"})
    assert (spec.mode, spec.rule_id) == ("0640", "c-specific")
    assert [row.rule_id for row in synth.rules()] == [
        "a-broad", "b-specific", "c-specific"]


def test_synthesize_sorts_devices_and_defaults_unmatched():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb", "idVendor": "1234"}, mode="0660",
                   owner="lab", rule_id="usb-vendor")
    first = synth.synthesize({"sdb": {"SUBSYSTEM": "usb",
                                      "idVendor": "1234"},
                              "sda": {"SUBSYSTEM": "block"}})
    second = synth.synthesize({"sda": {"SUBSYSTEM": "block"},
                               "sdb": {"SUBSYSTEM": "usb",
                                       "idVendor": "1234"}})
    assert first == second
    assert [spec.device for spec in first] == ["sda", "sdb"]
    assert (first[0].mode, first[0].rule_id) == ("0600", "")
    assert (first[1].mode, first[1].owner, first[1].rule_id) == (
        "0660", "lab", "usb-vendor")
    assert synth.stats()["synthesized"] == 2


def test_remove_rule_is_idempotent_and_updates_synthesis():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0660", rule_id="only")
    assert synth.effective("sda", {"SUBSYSTEM": "usb"}).rule_id == "only"
    assert synth.remove_rule("only") is True
    assert synth.remove_rule("only") is False
    assert synth.remove_rule("ghost") is False
    assert synth.effective("sda", {"SUBSYSTEM": "usb"}).rule_id == ""
    assert synth.stats()["removed"] == 1


def test_apply_hotplug_only_touches_new_devices():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0660", owner="lab",
                   rule_id="usb")
    devices = {"sda": {"SUBSYSTEM": "block"},
               "sdb": {"SUBSYSTEM": "usb"},
               "sdc": {"SUBSYSTEM": "usb"}}
    applied = synth.apply_hotplug(devices, existing=("sda",))
    assert [spec.device for spec in applied] == ["sdb", "sdc"]
    assert all(spec.rule_id == "usb" for spec in applied)
    assert synth.stats()["hotplugged"] == 2
    assert synth.stats()["skipped"] == 1
    assert synth.apply_hotplug(devices,
                               existing=("sda", "sdb", "sdc")) == ()
    assert synth.stats()["hotplugged"] == 2
    assert synth.stats()["skipped"] == 4


def test_reconcile_reports_mismatch_and_missing_nodes():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0660", owner="lab",
                   group="usb", rule_id="usb")
    devices = {"sda": {"SUBSYSTEM": "usb"},
               "sdb": {"SUBSYSTEM": "usb"},
               "sdc": {"SUBSYSTEM": "block"}}
    actual = {"sda": ("0660", "lab", "usb"),
              "sdb": ("0600", "root", "root")}
    assert synth.reconcile(devices, actual) == ("sdb", "sdc")
    assert synth.reconcile(devices,
                           {"sda": ("0660", "lab", "usb"),
                            "sdb": ("0660", "lab", "usb"),
                            "sdc": ("0600", "root", "root")}) == ()


def test_render_and_parse_roundtrip_simple_rule():
    synth = new_synth()
    rule = synth.add_rule({"SUBSYSTEM": "usb", "idVendor": "1234"},
                          mode="0660", owner="lab", group="usb", priority=80,
                          rule_id="r7")
    text = synth.render_rule("r7")
    assert isinstance(text, str)
    assert text != ""
    assert synth.parse_rule(text, rule_id="r7") == rule
    with pytest.raises(udev.UdevError) as exc:
        synth.render_rule("ghost")
    assert exc.value.code == "UDEV_RULE_UNKNOWN"


def test_synthesis_does_not_depend_on_insertion_order():
    first = new_synth()
    first.add_rule({"SUBSYSTEM": "usb"}, mode="0666", rule_id="r1",
                   priority=40)
    first.add_rule({"SUBSYSTEM": "usb"}, mode="0640", rule_id="r2",
                   priority=70)
    second = new_synth()
    second.add_rule({"SUBSYSTEM": "usb"}, mode="0640", rule_id="r2",
                    priority=70)
    second.add_rule({"SUBSYSTEM": "usb"}, mode="0666", rule_id="r1",
                    priority=40)
    devices = {"sda": {"SUBSYSTEM": "usb"}, "sdb": {"SUBSYSTEM": "block"}}
    assert first.rules() == second.rules()
    assert first.synthesize(devices) == second.synthesize(devices)
    assert first.effective("sda", {"SUBSYSTEM": "usb"}) == (
        second.effective("sda", {"SUBSYSTEM": "usb"}))


def test_snapshot_is_detached_and_restore_roundtrips():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0660", owner="lab",
                   rule_id="r1")
    synth.synthesize({"sda": {"SUBSYSTEM": "usb"}})
    state = synth.snapshot()
    assert set(state) == {"version", "rules", "next_id", "synth", "stats"}
    pristine = copy.deepcopy(state)
    state["rules"].clear()
    state["stats"]["added"] = 99
    assert synth.rule("r1") is not None
    assert synth.stats()["added"] == 1

    clone = new_synth()
    clone.restore(pristine)
    assert clone.rule("r1") == synth.rule("r1")
    assert clone.effective("sda", {"SUBSYSTEM": "usb"}).rule_id == "r1"
    assert clone.stats()["added"] == 1
    assert clone.stats()["synthesized"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, mode="0660", rule_id="r1")
    good = synth.snapshot()

    bad_states = [None, {}]
    case = copy.deepcopy(good)
    case["version"] = 2
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["rules"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["rules"]["r1"] = {"mode": "0660"}
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["rules"]["r1"] = "not-a-rule"
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["stats"].pop("added")
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["next_id"] = 0
    bad_states.append(case)

    for bad in bad_states:
        with pytest.raises(udev.UdevError) as exc:
            synth.restore(bad)
        assert exc.value.code == "UDEV_SNAPSHOT_INVALID"

    assert synth.rule("r1") is not None
    assert synth.effective("sda", {"SUBSYSTEM": "usb"}).rule_id == "r1"
    assert synth.stats()["added"] == 1


def test_rule_limit_is_enforced():
    synth = new_synth(max_rules=2)
    synth.add_rule({"SUBSYSTEM": "usb"}, rule_id="r1")
    synth.add_rule({"SUBSYSTEM": "block"}, rule_id="r2")
    with pytest.raises(udev.UdevError) as exc:
        synth.add_rule({"SUBSYSTEM": "net"}, rule_id="r3")
    assert exc.value.code == "UDEV_RULE_LIMIT"
    assert len(synth.rules()) == 2
    assert synth.stats()["refused"] == 1


def test_concurrent_rule_adds_are_all_kept():
    synth = new_synth(max_rules=32)
    errors = []
    barrier = threading.Barrier(16)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            synth.add_rule({"SUBSYSTEM": "usb", "idVendor": f"{index:04d}"},
                           mode="0660", priority=10 + index, rule_id=f"r{index}")
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(synth.rules()) == 16
    assert synth.stats()["added"] == 16
    ordered = [row.rule_id for row in synth.rules()]
    assert ordered == sorted(ordered, key=lambda rid: (
        synth.rule(rid).priority, len(synth.rule(rid).match), rid))
    assert synth.effective("sda", {"SUBSYSTEM": "usb",
                                   "idVendor": "0003"}).rule_id == "r3"


def test_stats_track_each_operation_exactly():
    synth = new_synth()
    synth.add_rule({"SUBSYSTEM": "usb"}, rule_id="r1")
    synth.add_rule({"SUBSYSTEM": "block"}, rule_id="r2")
    synth.remove_rule("r2")
    synth.synthesize({"sda": {"SUBSYSTEM": "usb"}})
    synth.apply_hotplug({"sdb": {"SUBSYSTEM": "usb"}})
    synth.apply_hotplug({"sdb": {"SUBSYSTEM": "usb"}}, existing=("sdb",))
    with pytest.raises(udev.UdevError):
        synth.add_rule({}, rule_id="bad")
    assert synth.stats() == {"added": 2, "removed": 1, "synthesized": 1,
                             "hotplugged": 1, "skipped": 1, "refused": 1}
