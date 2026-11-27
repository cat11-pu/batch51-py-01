import copy
import threading

import pytest

import udev_rule_guard as ug


def guard(**kwargs):
    return ug.UdevRuleGuard(**kwargs)


def test_load_parses_one_rule_with_index_and_line():
    g = guard()
    text = ('SUBSYSTEM=="usb", NAME="ttyUSB0", MODE="0660", '
            'OWNER="root", GROUP="dialout"\n')
    rules = g.load_rules([ug.RuleFile("50-usb.rules", 0o644, text)])
    assert len(rules) == 1
    rule = rules[0]
    assert (rule.index, rule.source, rule.line) == (0, "50-usb.rules", 1)
    assert rule.matches == (ug.MatchClaim("SUBSYSTEM", "usb"),)
    assert rule.assignments == (
        ug.Assignment("NAME", "=", "ttyUSB0"),
        ug.Assignment("MODE", "=", "0660"),
        ug.Assignment("OWNER", "=", "root"),
        ug.Assignment("GROUP", "=", "dialout"),
    )
    assert g.rules() == rules
    assert g.stats()["rules"] == 1
    assert g.stats()["reloads"] == 1


def test_match_rule_compares_single_claim():
    g = guard()
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644, 'SUBSYSTEM=="usb"\n')])
    rule = g.rules()[0]
    assert g.match_rule(rule, {"SUBSYSTEM": "usb"}) is True
    assert g.match_rule(rule, {"SUBSYSTEM": "pci"}) is False
    assert g.match_rule(rule, {}) is False


def test_evaluate_returns_final_attributes_and_counts():
    g = guard()
    text = ('SUBSYSTEM=="usb", NAME="ttyUSB0", MODE="0660", '
            'OWNER="root", GROUP="dialout"\n')
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644, text)])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert (result.name, result.mode, result.owner, result.group) == (
        "ttyUSB0", 0o660, "root", "dialout")
    assert result.tags == ()
    assert result.symlinks == ()
    assert result.commands == ()
    assert result.matched_rules == (0,)
    assert g.stats()["evaluations"] == 1
    assert g.stats()["matches"] == 1


def test_later_line_overrides_earlier_assignment():
    g = guard()
    text = 'SUBSYSTEM=="usb", MODE="0600"\nSUBSYSTEM=="usb", MODE="0640"\n'
    g.load_rules([ug.RuleFile("60-mode.rules", 0o644, text)])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert result.mode == 0o640
    assert result.matched_rules == (0, 1)


def test_later_file_wins_over_earlier_file():
    g = guard()
    g.load_rules([
        ug.RuleFile("50-base.rules", 0o644, 'SUBSYSTEM=="usb", MODE="0600"\n'),
        ug.RuleFile("70-site.rules", 0o644, 'SUBSYSTEM=="usb", MODE="0660"\n'),
    ])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert result.mode == 0o660
    assert [rule.source for rule in g.rules()] == ["50-base.rules", "70-site.rules"]
    assert result.matched_rules == (0, 1)


def test_run_assignment_is_denied_by_default():
    g = guard()
    g.load_rules([ug.RuleFile("80-run.rules", 0o644,
                              'SUBSYSTEM=="usb", NAME="ttyUSB0", '
                              'RUN+="/usr/bin/usb-reset"\n')])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert result.name == "ttyUSB0"
    assert result.commands == ()
    assert g.stats()["run_denied"] == 1


def test_run_assignment_is_collected_when_enabled():
    g = guard(allow_run=True)
    g.load_rules([ug.RuleFile("80-run.rules", 0o644,
                              'SUBSYSTEM=="usb", '
                              'RUN+="/usr/bin/usb-reset"\n')])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert result.commands == ("/usr/bin/usb-reset",)
    assert g.stats()["run_denied"] == 0


def test_simulate_does_not_touch_counters_or_audit():
    g = guard()
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644,
                              'SUBSYSTEM=="usb", NAME="ttyUSB0"\n')])
    before = g.stats()
    results = g.simulate([("d1", {"SUBSYSTEM": "usb"}),
                          ("d2", {"SUBSYSTEM": "pci"})])
    assert [row.name for row in results] == ["ttyUSB0", None]
    assert g.stats() == before
    assert g.audit() == ()


def test_tag_accumulates_in_first_seen_order():
    g = guard()
    g.load_rules([ug.RuleFile("90-tags.rules", 0o644,
                              'SUBSYSTEM=="usb", TAG+="uaccess", '
                              'TAG+="seat", TAG+="uaccess"\n')])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert result.tags == ("uaccess", "seat")


def test_symlink_accumulates_in_order():
    g = guard()
    g.load_rules([ug.RuleFile("90-links.rules", 0o644,
                              'SUBSYSTEM=="usb", SYMLINK+="mydev", '
                              'SYMLINK+="mydev-alt"\n')])
    result = g.evaluate("usb-1", {"SUBSYSTEM": "usb"})
    assert result.symlinks == ("mydev", "mydev-alt")


def test_bad_mode_rejects_whole_load_and_keeps_previous_rules():
    g = guard()
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644,
                              'SUBSYSTEM=="usb", NAME="ttyUSB0"\n')])
    with pytest.raises(ug.UdevError) as exc:
        g.load_rules([ug.RuleFile("60-bad.rules", 0o644,
                                  'SUBSYSTEM=="usb", MODE="rw", NAME="tty9"\n')])
    assert exc.value.code == "UDEV_RULE_SYNTAX"
    assert [rule.source for rule in g.rules()] == ["50-usb.rules"]
    assert g.evaluate("usb-1", {"SUBSYSTEM": "usb"}).name == "ttyUSB0"


def test_audit_records_each_evaluation():
    g = guard()
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644,
                              'SUBSYSTEM=="usb", NAME="ttyUSB0", MODE="0600"\n')])
    g.evaluate("d1", {"SUBSYSTEM": "usb"})
    g.evaluate("d2", {"SUBSYSTEM": "pci"})

    entries = g.audit()
    assert len(entries) == 2
    assert entries[0].device_id == "d1"
    assert entries[0].matched_rules == (0,)
    assert entries[0].applied_keys == ("NAME", "MODE")
    assert entries[0].run_denied == 0
    assert entries[1].device_id == "d2"
    assert entries[1].matched_rules == ()
    assert entries[1].applied_keys == ()


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644,
                              'SUBSYSTEM=="usb", NAME="ttyUSB0", MODE="0600"\n')])
    g.set_allow_run(True)
    g.evaluate("d1", {"SUBSYSTEM": "usb"})

    state = g.snapshot()
    assert set(state) == {"version", "rules", "allow_run", "counters",
                          "audit", "conflicts"}
    pristine = copy.deepcopy(state)
    state["rules"].clear()
    state["counters"]["evaluations"] = 99
    assert len(g.rules()) == 1
    assert g.stats()["evaluations"] == 1

    before = g.stats()
    clone = guard()
    clone.restore(copy.deepcopy(pristine))
    assert [rule.source for rule in clone.rules()] == ["50-usb.rules"]
    assert clone.stats() == before
    assert len(clone.audit()) == 1
    assert clone.evaluate("d2", {"SUBSYSTEM": "usb"}).name == "ttyUSB0"


def test_restore_rejects_malformed_state_without_touching_live_data():
    g = guard()
    g.load_rules([ug.RuleFile("50-usb.rules", 0o644,
                              'SUBSYSTEM=="usb", NAME="ttyUSB0"\n')])
    bad_states = [
        None,
        {},
        {"version": 1, "rules": [], "allow_run": False,
         "counters": {}, "audit": [], "conflicts": []},
        {"version": 1, "rules": "nope", "allow_run": False,
         "counters": g.stats(), "audit": [], "conflicts": []},
    ]
    for bad in bad_states:
        with pytest.raises(ug.UdevError) as exc:
            g.restore(bad)
        assert exc.value.code == "UDEV_SNAPSHOT_INVALID"
    assert g.evaluate("d1", {"SUBSYSTEM": "usb"}).name == "ttyUSB0"
    assert g.stats()["rules"] == 1


def test_concurrent_reload_and_evaluate_sees_one_complete_rule_set():
    g = guard()
    set_a = [ug.RuleFile("a.rules", 0o644, 'SUBSYSTEM=="usb", NAME="pool-a", MODE="0600"\n')]
    set_b = [ug.RuleFile("b.rules", 0o644, 'SUBSYSTEM=="usb", NAME="pool-b", MODE="0660"\n')]
    g.load_rules(set_a)

    violations = []
    errors = []
    started = threading.Event()

    def reader():
        try:
            started.wait(timeout=5)
            for _ in range(40):
                result = g.evaluate("dev", {"SUBSYSTEM": "usb"})
                pair = (result.name, result.mode)
                if pair not in {("pool-a", 0o600), ("pool-b", 0o660)}:
                    violations.append(pair)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    def loader():
        try:
            started.wait(timeout=5)
            for index in range(40):
                g.load_rules(set_b if index % 2 else set_a)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=reader) for _ in range(6)]
    threads.append(threading.Thread(target=loader))
    for thread in threads:
        thread.start()
    started.set()
    for thread in threads:
        thread.join()

    assert errors == []
    assert violations == []
    assert [rule.source for rule in g.rules()] in (["a.rules"], ["b.rules"])
