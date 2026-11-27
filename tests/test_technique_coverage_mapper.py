import copy
import threading

import pytest

import technique_coverage_mapper as tcm

TECHNIQUES = {
    "T1001": {"name": "Command Interpreter", "weight": 2.0},
    "T1002": {"name": "Credential Dumping", "weight": 1.0},
    "T1003": {"name": "OS Credential Dumping", "weight": 3.0},
    "T1004": {"name": "Archive via Utility", "weight": 1.5},
}


def build(techniques=None, **kwargs):
    kwargs.setdefault("techniques", TECHNIQUES if techniques is None else techniques)
    return tcm.TechniqueCoverageMapper(**kwargs)


def add_rule(mapper, rule_id, **kwargs):
    kwargs.setdefault("name", f"detect {rule_id}")
    kwargs.setdefault("source", "sigma")
    return mapper.register_rule(rule_id, **kwargs)


def entry_for(report, technique_id):
    matches = [row for row in report["techniques"] if row.technique_id == technique_id]
    assert len(matches) == 1
    return matches[0]


def test_register_rule_normalises_and_counts():
    mapper = build()
    rule = add_rule(mapper, "R-001", name="suspicious shell spawn", source="sigma")
    assert (rule.rule_id, rule.name, rule.source, rule.retired) == (
        "R-001", "suspicious shell spawn", "sigma", False
    )
    assert mapper.stats() == {
        "rules": 1,
        "mappings": 0,
        "techniques": 4,
        "retired_rules": 0,
        "retired_techniques": 0,
    }
    with pytest.raises(tcm.MappingError) as exc:
        add_rule(mapper, "R-001")
    assert exc.value.code == "MAPPING_RULE_DUPLICATE"
    assert mapper.stats()["rules"] == 1


def test_register_rule_rejects_malformed_identity():
    mapper = build()
    bad_calls = [
        dict(rule_id="", name="x", source="sigma"),
        dict(rule_id="R-1", name="   ", source="sigma"),
        dict(rule_id="R-1", name="x", source=""),
        dict(rule_id=7, name="x", source="sigma"),
    ]
    for kwargs in bad_calls:
        with pytest.raises(tcm.MappingError) as exc:
            mapper.register_rule(**kwargs)
        assert exc.value.code == "MAPPING_INVALID_REQUEST"
    assert mapper.stats()["rules"] == 0


def test_map_technique_returns_mapping_and_links_both_ways():
    mapper = build()
    add_rule(mapper, "R-001")
    mapping = mapper.map_technique("R-001", "T1001", confidence=0.8, source="threat-intel")
    assert (mapping.rule_id, mapping.technique_id, mapping.confidence, mapping.source) == (
        "R-001", "T1001", 0.8, "threat-intel"
    )
    assert mapper.mappings_for("R-001") == (mapping,)
    assert [row.rule_id for row in mapper.rules_for("T1001")] == ["R-001"]
    assert mapper.stats()["mappings"] == 1


def test_map_technique_rejects_unknown_rule_and_technique():
    mapper = build()
    with pytest.raises(tcm.MappingError) as exc:
        mapper.map_technique("R-missing", "T1001", confidence=0.5, source="sigma")
    assert exc.value.code == "MAPPING_RULE_UNKNOWN"
    add_rule(mapper, "R-001")
    with pytest.raises(tcm.MappingError) as exc:
        mapper.map_technique("R-001", "T9999", confidence=0.5, source="sigma")
    assert exc.value.code == "MAPPING_TECHNIQUE_UNKNOWN"
    assert mapper.stats()["mappings"] == 0


def test_confidence_and_source_are_validated():
    mapper = build()
    add_rule(mapper, "R-001")
    for bad in (0, 0.0, 1.5, -0.2, "0.5", None):
        with pytest.raises(tcm.MappingError) as exc:
            mapper.map_technique("R-001", "T1001", confidence=bad, source="sigma")
        assert exc.value.code == "MAPPING_CONFIDENCE_INVALID"
    with pytest.raises(tcm.MappingError) as exc:
        mapper.map_technique("R-001", "T1001", confidence=0.5, source="  ")
    assert exc.value.code == "MAPPING_INVALID_REQUEST"
    accepted = mapper.map_technique("R-001", "T1001", confidence=1.0, source="sigma")
    assert accepted.confidence == 1.0


def test_identical_mapping_is_idempotent():
    mapper = build()
    add_rule(mapper, "R-001")
    first = mapper.map_technique("R-001", "T1001", confidence=0.6, source="sigma")
    second = mapper.map_technique("R-001", "T1001", confidence=0.6, source="sigma")
    assert second == first
    assert len(mapper.mappings_for("R-001")) == 1
    assert mapper.stats()["mappings"] == 1
    assert entry_for(mapper.coverage_report(), "T1001").mapping_count == 1


def test_weighted_coverage_uses_technique_weights():
    techniques = {
        "T1001": {"name": "Command Interpreter", "weight": 2.0},
        "T1002": {"name": "Credential Dumping", "weight": 1.0},
    }
    mapper = build(techniques)
    add_rule(mapper, "R-001")
    add_rule(mapper, "R-002")
    mapper.map_technique("R-001", "T1001", confidence=0.5, source="sigma")
    mapper.map_technique("R-002", "T1002", confidence=1.0, source="sigma")

    report = mapper.coverage_report()
    assert set(report) == {"weighted_coverage", "techniques", "exempt", "retired", "counts"}
    assert report["weighted_coverage"] == 0.6667
    assert entry_for(report, "T1001").coverage == 0.5
    assert entry_for(report, "T1002").coverage == 1.0
    assert report["counts"] == {"rules": 2, "mappings": 2, "techniques": 2}


def test_technique_coverage_is_max_confidence_not_mapping_count():
    techniques = {"T1001": {"name": "Command Interpreter", "weight": 1.0}}
    mapper = build(techniques)
    add_rule(mapper, "R-001")
    add_rule(mapper, "R-002")
    mapper.map_technique("R-001", "T1001", confidence=0.4, source="sigma")
    mapper.map_technique("R-002", "T1001", confidence=0.9, source="edr")

    entry = entry_for(mapper.coverage_report(), "T1001")
    assert entry.coverage == 0.9
    assert entry.mapping_count == 2
    assert entry.rules == ("R-001", "R-002")


def test_gaps_are_sorted_by_weight_and_explain_reason():
    techniques = {
        "T2001": {"name": "A", "weight": 3.0},
        "T2002": {"name": "B", "weight": 1.0},
        "T2003": {"name": "C", "weight": 2.0},
        "T2004": {"name": "D", "weight": 1.5},
    }
    mapper = build(techniques)
    add_rule(mapper, "R-001")
    add_rule(mapper, "R-002")
    mapper.map_technique("R-001", "T2002", confidence=0.5, source="sigma")
    mapper.map_technique("R-002", "T2003", confidence=1.0, source="sigma")

    gaps = mapper.gaps()
    assert [(gap.technique_id, gap.weight, gap.coverage, gap.reason) for gap in gaps] == [
        ("T2001", 3.0, 0.0, "no_coverage"),
        ("T2004", 1.5, 0.0, "no_coverage"),
        ("T2002", 1.0, 0.5, "partial_coverage"),
    ]


def test_exempt_techniques_are_reported_separately():
    techniques = {
        "T1001": {"name": "Command Interpreter", "weight": 3.0},
        "T1002": {"name": "Credential Dumping", "weight": 1.0},
    }
    mapper = build(techniques, exempt=("T1001",))
    add_rule(mapper, "R-001")
    mapper.map_technique("R-001", "T1002", confidence=1.0, source="sigma")

    report = mapper.coverage_report()
    assert report["exempt"] == ("T1001",)
    assert report["weighted_coverage"] == 1.0
    assert mapper.gaps() == ()
    assert entry_for(report, "T1001").exempt is True


def test_retired_rule_stops_counting_but_stays_visible():
    techniques = {"T1001": {"name": "Command Interpreter", "weight": 2.0}}
    mapper = build(techniques)
    add_rule(mapper, "R-001")
    add_rule(mapper, "R-002")
    mapper.map_technique("R-001", "T1001", confidence=1.0, source="sigma")
    mapper.map_technique("R-002", "T1001", confidence=0.5, source="sigma")

    retired = mapper.retire_rule("R-001")
    assert retired.retired is True
    assert {rule.rule_id: rule.retired for rule in mapper.rules_for("T1001")} == {
        "R-001": True,
        "R-002": False,
    }
    report = mapper.coverage_report()
    assert entry_for(report, "T1001").coverage == 0.5
    assert report["counts"]["rules"] == 2
    assert mapper.stats()["retired_rules"] == 1
    assert mapper.gaps()[0].reason == "partial_coverage"

    with pytest.raises(tcm.MappingError) as exc:
        mapper.map_technique("R-001", "T1001", confidence=0.9, source="sigma")
    assert exc.value.code == "MAPPING_RULE_RETIRED"


def test_retire_technique_is_idempotent_and_reported():
    mapper = build()
    add_rule(mapper, "R-001")
    mapper.map_technique("R-001", "T1001", confidence=0.9, source="sigma")

    first = mapper.retire_technique("T1001")
    second = mapper.retire_technique("T1001")
    assert first.retired is True
    assert second == first
    assert mapper.coverage_report()["retired"] == ("T1001",)
    assert mapper.stats()["retired_techniques"] == 1
    with pytest.raises(tcm.MappingError) as exc:
        mapper.retire_technique("T9999")
    assert exc.value.code == "MAPPING_TECHNIQUE_UNKNOWN"


def test_rule_and_mapping_caps_are_enforced():
    techniques = {"T1001": {"name": "Command Interpreter", "weight": 1.0}}
    mapper = build(techniques, max_rules=2, max_mappings=1)
    add_rule(mapper, "R-001")
    add_rule(mapper, "R-002")
    with pytest.raises(tcm.MappingError) as exc:
        add_rule(mapper, "R-003")
    assert exc.value.code == "MAPPING_CAPACITY_EXCEEDED"
    assert mapper.stats()["rules"] == 2

    mapper.map_technique("R-001", "T1001", confidence=0.5, source="sigma")
    with pytest.raises(tcm.MappingError) as exc:
        mapper.map_technique("R-002", "T1001", confidence=0.5, source="sigma")
    assert exc.value.code == "MAPPING_CAPACITY_EXCEEDED"
    assert mapper.stats()["mappings"] == 1

    with pytest.raises(tcm.MappingError) as exc:
        build(techniques, max_techniques=0)
    assert exc.value.code == "MAPPING_CAPACITY_EXCEEDED"


def test_concurrent_mappings_do_not_lose_updates():
    techniques = {"T1001": {"name": "Command Interpreter", "weight": 1.0}}
    mapper = build(techniques)
    for index in range(12):
        add_rule(mapper, f"R-{index:02d}")

    barrier = threading.Barrier(12)
    errors = []

    def worker(index):
        try:
            barrier.wait(timeout=5)
            mapper.map_technique(
                f"R-{index:02d}", "T1001", confidence=(index + 1) / 12, source="sigma"
            )
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert mapper.stats()["mappings"] == 12
    assert entry_for(mapper.coverage_report(), "T1001").coverage == 1.0
    assert len(mapper.rules_for("T1001")) == 12


def test_snapshot_restore_roundtrip_and_invalid_state():
    techniques = {"T1001": {"name": "Command Interpreter", "weight": 2.0}}
    mapper = build(techniques)
    add_rule(mapper, "R-001")
    add_rule(mapper, "R-002")
    mapper.map_technique("R-001", "T1001", confidence=0.7, source="sigma")
    mapper.retire_rule("R-002")

    state = mapper.snapshot()
    assert set(state) == {"version", "rules", "techniques", "mappings", "stats"}
    pristine = copy.deepcopy(state)
    state["rules"].clear()
    state["stats"]["mappings"] = 99
    assert mapper.stats()["mappings"] == 1
    assert entry_for(mapper.coverage_report(), "T1001").coverage == 0.7

    clone = build(techniques)
    clone.restore(pristine)
    assert clone.stats() == mapper.stats()
    assert [rule.rule_id for rule in clone.rules_for("T1001")] == ["R-001"]
    assert entry_for(clone.coverage_report(), "T1001").coverage == 0.7

    for bad in ({}, None, {"version": 1}, {"version": 1, "rules": [],
                                         "techniques": {}, "mappings": "nope",
                                         "stats": {}}):
        with pytest.raises(tcm.MappingError) as exc:
            clone.restore(bad)
        assert exc.value.code == "MAPPING_SNAPSHOT_INVALID"
    assert clone.stats()["mappings"] == 1
