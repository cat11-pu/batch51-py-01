import pytest

import xxe_entity_guard as xg


SMALL = (
    '<!ENTITY e0 "abcde">\n'
    '<!ENTITY e1 "&e0;!">\n'
    '<r a="&e0;">&e1;</r>'
)


def guard(**kwargs):
    return xg.XxeEntityGuard(**kwargs)


def test_inspect_reports_declaration_kinds():
    doc = (
        '<!DOCTYPE root SYSTEM "https://dtd.internal/root.dtd">\n'
        '<!ENTITY e0 "alpha">\n'
        '<!ENTITY ext SYSTEM "https://dtd.internal/ext.dtd">\n'
        '<!ENTITY % p "beta">\n'
        "<root>&e0;</root>"
    )
    out = guard().inspect_dtd(doc)
    assert out.declarations == 3
    assert out.internal == ("e0",)
    assert out.external == ("ext",)
    assert out.parameter == ("p",)
    assert out.external_subset == "https://dtd.internal/root.dtd"


def test_inspect_duplicate_declaration_rejected():
    doc = '<!ENTITY e0 "a">\n<!ENTITY e0 "b">\n<r>&e0;</r>'
    with pytest.raises(xg.XxeError) as excinfo:
        guard().inspect_dtd(doc)
    assert excinfo.value.code == "XXE_DTD_INVALID"
    assert excinfo.value.detail == {"entity": "e0"}


def test_inspect_rejects_empty_document():
    with pytest.raises(xg.XxeError) as excinfo:
        guard().inspect_dtd("   \n\t ")
    assert excinfo.value.code == "XXE_DTD_INVALID"


def test_expand_budget_reports_entity_sizes():
    out = guard().expand_budget(SMALL)
    assert out["per_entity"] == {"e0": 5, "e1": 6}
    assert out["max_depth"] == 2
    assert out["declared"] == 2


def test_depth_limit_aborts_with_trigger():
    doc = (
        '<!ENTITY e0 "x">\n'
        '<!ENTITY e1 "&e0;">\n'
        '<!ENTITY e2 "&e1;">\n'
        "<r>&e2;</r>"
    )
    with pytest.raises(xg.XxeError) as excinfo:
        guard(max_depth=2).expand_budget(doc)
    assert excinfo.value.code == "XXE_DEPTH_EXCEEDED"
    assert excinfo.value.detail == {"entity": "e2", "depth": 3}


def test_byte_budget_aborts_with_trigger():
    doc = (
        '<!ENTITY e0 "12345">\n'
        '<!ENTITY e1 "&e0;&e0;&e0;">\n'
        "<r>&e1;</r>"
    )
    with pytest.raises(xg.XxeError) as excinfo:
        guard(max_bytes=10).expand_budget(doc)
    assert excinfo.value.code == "XXE_BUDGET_EXCEEDED"
    assert excinfo.value.detail == {"entity": "e1", "bytes": 15}


def test_parse_report_accepts_small_document():
    out = guard().parse_report(SMALL)
    assert out["accepted"] is True
    assert out["code"] is None
    assert out["trigger"] is None
    assert out["references"] == 2
    assert out["expanded_bytes"] == 11
    assert out["external"] == []


def test_parse_report_reports_rejection_with_code():
    doc = (
        '<!ENTITY e0 "1234567890123456">\n'
        '<!ENTITY e1 "&e0;&e0;&e0;">\n'
        "<r>&e1;</r>"
    )
    g = guard(max_bytes=30)
    out = g.parse_report(doc)
    assert out["accepted"] is False
    assert out["code"] == "XXE_BUDGET_EXCEEDED"
    assert out["trigger"] == "e1"
    assert g.stats()["rejected"] == 1
    assert g.stats()["accepted"] == 0


def test_unknown_entity_reference_reported():
    doc = '<!ENTITY e0 "x">\n<r>&ghost;</r>'
    g = guard()
    out = g.parse_report(doc)
    assert out["code"] == "XXE_UNKNOWN_ENTITY"
    assert out["trigger"] == "ghost"
    with pytest.raises(xg.XxeError) as excinfo:
        guard().expand_budget(doc)
    assert excinfo.value.code == "XXE_UNKNOWN_ENTITY"


def test_external_entity_blocked_by_default():
    doc = (
        '<!ENTITY ext SYSTEM "https://evil.example/ext.dtd">\n'
        "<r>&ext;</r>"
    )
    out = guard().parse_report(doc)
    assert out["accepted"] is False
    assert out["code"] == "XXE_EXTERNAL_BLOCKED"
    assert out["trigger"] == "ext"
    assert out["external"] == ["https://evil.example/ext.dtd"]


def test_external_subset_blocked_by_default():
    doc = '<!DOCTYPE root SYSTEM "https://evil.example/root.dtd">\n<r/>'
    out = guard().parse_report(doc)
    assert out["accepted"] is False
    assert out["code"] == "XXE_EXTERNAL_BLOCKED"
    assert out["trigger"] is None
    assert out["external"] == ["https://evil.example/root.dtd"]


def test_namespace_allowlist_permits_external():
    g = guard()
    g.declare_namespace("vendor", prefix="https://dtd.vendor/")
    assert g.block_external("vendor", allow=True) is False
    doc = (
        '<!ENTITY ext SYSTEM "https://dtd.vendor/schema.dtd">\n'
        "<r>&ext;</r>"
    )
    out = g.parse_report(doc)
    assert out["accepted"] is True
    assert out["code"] is None
    assert out["external"] == ["https://dtd.vendor/schema.dtd"]
    assert out["references"] == 1
    assert out["expanded_bytes"] == 0
    assert g.stats()["blocked_external"] == 0


def test_block_external_unknown_namespace_raises():
    g = guard()
    with pytest.raises(xg.XxeError) as excinfo:
        g.block_external("nope", allow=True)
    assert excinfo.value.code == "XXE_UNKNOWN_NAMESPACE"


def test_snapshot_restore_roundtrip():
    g = guard(max_depth=5)
    g.declare_namespace("vendor", prefix="https://dtd.vendor/")
    g.block_external("vendor", allow=True)
    good = (
        '<!ENTITY ext SYSTEM "https://dtd.vendor/schema.dtd">\n'
        "<r>&ext;</r>"
    )
    assert g.parse_report(good)["accepted"] is True
    before = g.stats()["parses"]
    snap = g.snapshot()

    g.declare_namespace("late", prefix="https://late.example/")
    g.block_external("late", allow=True)
    late = (
        '<!ENTITY ext SYSTEM "https://late.example/schema.dtd">\n'
        "<r>&ext;</r>"
    )
    assert g.parse_report(late)["accepted"] is True

    g.restore(snap)
    assert g.stats()["parses"] == before
    assert g.parse_report(late)["code"] == "XXE_EXTERNAL_BLOCKED"
    assert g.parse_report(good)["accepted"] is True
    snap["stats"]["parses"] = 999
    assert g.stats()["parses"] != 999


def test_restore_rejects_malformed_state_and_keeps_state():
    g = guard()
    g.declare_namespace("vendor", prefix="https://dtd.vendor/")
    g.block_external("vendor", allow=True)
    with pytest.raises(xg.XxeError) as excinfo:
        g.restore({"limits": {"max_depth": 1}})
    assert excinfo.value.code == "XXE_SNAPSHOT_INVALID"
    doc = (
        '<!ENTITY ext SYSTEM "https://dtd.vendor/schema.dtd">\n'
        "<r>&ext;</r>"
    )
    assert g.parse_report(doc)["accepted"] is True
