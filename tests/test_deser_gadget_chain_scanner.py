import json
import struct

import pytest

import deser_gadget_chain_scanner as ds


def make_stream(magic, root, objects):
    lines = [json.dumps({"root": root})]
    for obj in objects:
        lines.append(json.dumps(obj, sort_keys=True))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    return magic + struct.pack(">I", len(body)) + body


def tree_stream():
    return make_stream(
        b"JSE1",
        "o1",
        [
            {"id": "o1", "type": "java.util.HashMap", "fields": {"b": "o2", "a": "o3"}},
            {"id": "o2", "type": "java.lang.Runtime", "fields": {}},
            {"id": "o3", "type": "java.util.ArrayList", "fields": {"x": "o4"}},
            {"id": "o4", "type": "java.lang.String", "fields": {}},
        ],
    )


def registered(types=("java.util.HashMap", "java.util.ArrayList", "java.lang.String",
                      "java.lang.Runtime")):
    scanner = ds.DeserGadgetChainScanner()
    for name in types:
        scanner.register_type(name, origin="local", purpose="data")
    return scanner


def test_sniff_format_recognizes_headers():
    scanner = registered()
    assert scanner.sniff_format(b"JSE1" + b"\x00" * 12) == "java-serial-v1"
    assert scanner.sniff_format(b"PKL2" + b"\x00" * 12) == "pickle-proto2"
    assert scanner.sniff_format(b"MPK1" + b"\x00" * 12) == "msgpack-map"


def test_sniff_format_rejects_unknown_header():
    scanner = registered()
    with pytest.raises(ds.DeserError) as excinfo:
        scanner.sniff_format(b"ZZZZ" + b"\x00" * 12)
    assert excinfo.value.code == "DESER_UNKNOWN_FORMAT"


def test_walk_visits_depth_first_in_field_order():
    out = registered().walk_objects(tree_stream())
    assert out.format == "java-serial-v1"
    assert out.root == "o1"
    assert out.visited == ("o1", "o3", "o4", "o2")
    assert out.depth == 3
    assert out.truncated is False


def test_walk_reports_single_object_depth():
    stream = make_stream(
        b"PKL2",
        "o1",
        [{"id": "o1", "type": "java.util.HashMap", "fields": {}}],
    )
    out = registered().walk_objects(stream)
    assert out.visited == ("o1",)
    assert out.depth == 1


def test_register_type_grades():
    scanner = ds.DeserGadgetChainScanner()
    assert scanner.register_type("com.acme.Data", origin="local", purpose="data") == "trusted"
    assert scanner.register_type("com.acme.Tool", origin="local", purpose="exec") == "reviewed"
    assert scanner.register_type("com.acme.Vendor", origin="vendor", purpose="data") == "reviewed"
    with pytest.raises(ds.DeserError) as excinfo:
        scanner.register_type("com.acme.Cloud", origin="cloud", purpose="data")
    assert excinfo.value.code == "DESER_INVALID_ARGUMENT"


def test_unregistered_type_is_denied():
    scanner = ds.DeserGadgetChainScanner()
    with pytest.raises(ds.DeserError) as excinfo:
        scanner.check_allowlist("com.acme.Nope")
    assert excinfo.value.code == "DESER_TYPE_DENIED"
    assert excinfo.value.detail == "com.acme.Nope"


def test_vendor_exec_registration_denied():
    scanner = ds.DeserGadgetChainScanner()
    with pytest.raises(ds.DeserError) as excinfo:
        scanner.register_type("com.acme.Boom", origin="vendor", purpose="exec")
    assert excinfo.value.code == "DESER_TYPE_DENIED"


def test_report_marks_denied_types():
    stream = make_stream(
        b"MPK1",
        "n1",
        [
            {"id": "n1", "type": "com.acme.Node", "fields": {"a": "n2"}},
            {"id": "n2", "type": "com.acme.Unknown", "fields": {}},
        ],
    )
    scanner = ds.DeserGadgetChainScanner()
    scanner.register_type("com.acme.Node", origin="local", purpose="data")
    out = scanner.report(stream)
    assert out["allowed"] is False
    assert out["denied_types"] == ["com.acme.Unknown"]
    assert out["objects"] == 2


def test_dangerous_starts_in_traversal_order():
    stream = make_stream(
        b"JSE1",
        "d1",
        [
            {"id": "d1", "type": "java.util.HashMap", "fields": {"a": "d2", "b": "d3"}},
            {"id": "d2", "type": "java.lang.reflect.Method", "fields": {}},
            {"id": "d3", "type": "java.lang.ProcessBuilder", "fields": {}},
        ],
    )
    assert registered().dangerous_starts(stream) == ("d2", "d3")


def test_chain_depth_counts_nodes_from_start():
    stream = make_stream(
        b"JSE1",
        "k1",
        [
            {"id": "k1", "type": "java.util.HashMap", "fields": {"a": "k2"}},
            {"id": "k2", "type": "java.lang.Runtime", "fields": {"exec": "k3"}},
            {"id": "k3", "type": "java.util.PriorityQueue", "fields": {"q": "k4"}},
            {"id": "k4", "type": "java.lang.String", "fields": {}},
        ],
    )
    scanner = registered()
    assert scanner.chain_depth(stream) == 3
    assert scanner.chain_depth(stream, "k2") == 3


def test_chain_depth_without_start_is_zero():
    stream = make_stream(
        b"JSE1",
        "o1",
        [
            {"id": "o1", "type": "java.util.HashMap", "fields": {"a": "o2"}},
            {"id": "o2", "type": "java.lang.String", "fields": {}},
        ],
    )
    scanner = registered()
    assert scanner.dangerous_starts(stream) == ()
    assert scanner.chain_depth(stream) == 0


def test_report_summary_fields():
    stream = make_stream(
        b"JSE1",
        "o1",
        [
            {"id": "o1", "type": "com.acme.Node", "fields": {"a": "o2"}},
            {"id": "o2", "type": "com.acme.Node", "fields": {}},
        ],
    )
    scanner = ds.DeserGadgetChainScanner()
    scanner.register_type("com.acme.Node", origin="local", purpose="data")
    out = scanner.report(stream)
    assert out["format"] == "java-serial-v1"
    assert out["objects"] == 2
    assert out["depth"] == 2
    assert out["chain_depth"] == 0
    assert out["starts"] == []
    assert out["denied_types"] == []
    assert out["dangling"] == []
    assert out["truncated"] is False
    assert out["allowed"] is True


def test_report_lists_dangling_references():
    stream = make_stream(
        b"JSE1",
        "o1",
        [{"id": "o1", "type": "com.acme.Node", "fields": {"a": "missing"}}],
    )
    scanner = ds.DeserGadgetChainScanner()
    scanner.register_type("com.acme.Node", origin="local", purpose="data")
    out = scanner.report(stream)
    assert out["dangling"] == ["missing"]
    assert out["objects"] == 1
    assert out["depth"] == 1


def test_snapshot_restore_roundtrip():
    scanner = ds.DeserGadgetChainScanner()
    scanner.register_type("com.acme.Node", origin="local", purpose="data")
    scanner.register_type("com.acme.Tool", origin="local", purpose="exec")
    scanner.walk_objects(
        make_stream(
            b"JSE1",
            "o1",
            [{"id": "o1", "type": "com.acme.Node", "fields": {}}],
        )
    )
    before = scanner.stats()["walks"]
    snap = scanner.snapshot()

    assert scanner.revoke_type("com.acme.Tool") is True
    scanner.register_type("com.acme.Late", origin="vendor", purpose="data")
    with pytest.raises(ds.DeserError):
        scanner.check_allowlist("com.acme.Tool")

    scanner.restore(snap)
    assert scanner.check_allowlist("com.acme.Tool") == "reviewed"
    assert scanner.stats()["walks"] == before
    with pytest.raises(ds.DeserError):
        scanner.check_allowlist("com.acme.Late")
    snap["stats"]["walks"] = 999
    assert scanner.stats()["walks"] != 999


def test_restore_rejects_malformed_state():
    scanner = ds.DeserGadgetChainScanner()
    scanner.register_type("com.acme.Node", origin="local", purpose="data")
    with pytest.raises(ds.DeserError) as excinfo:
        scanner.restore({"allowlist": []})
    assert excinfo.value.code == "DESER_SNAPSHOT_INVALID"
    assert scanner.check_allowlist("com.acme.Node") == "trusted"
