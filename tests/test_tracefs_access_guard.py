import copy

import pytest

import tracefs_access_guard as tf


def guard(**kwargs):
    return tf.TracefsAccessGuard(**kwargs)


def instance(g, name="sched-lat", *, tenant="team-a", buffer_size_kb=1024, filter=None):
    return g.create_instance(name, tenant=tenant, buffer_size_kb=buffer_size_kb,
                             filter=filter)


def probe(g, instance_name="sched-lat", *, symbol="vfs_read", kind="kprobe",
          offset=0, filter=""):
    return g.register_probe(instance_name, symbol=symbol, kind=kind,
                            offset=offset, filter=filter)


def test_create_instance_reports_fields_and_lists_per_tenant():
    g = guard()
    created = instance(g, filter="common_pid == 100", buffer_size_kb=2048)
    assert created.name == "sched-lat"
    assert created.tenant == "team-a"
    assert created.buffer_size_kb == 2048
    assert created.filter == "common_pid == 100"
    assert created.active is True

    instance(g, "net-io", tenant="team-b")
    assert [row.name for row in g.instances()] == ["net-io", "sched-lat"]
    assert [row.name for row in g.instances(tenant="team-a")] == ["sched-lat"]
    assert [row.name for row in g.instances(tenant="team-c")] == []
    assert g.stats()["instances"] == 2


def test_instance_name_and_tenant_are_validated():
    g = guard()
    for bad in ("", "Bad Name", "name.with.dot", "x" * 33):
        with pytest.raises(tf.TraceError) as exc:
            g.create_instance(bad, tenant="team-a")
        assert exc.value.code == "TRACE_INSTANCE_INVALID"
    with pytest.raises(tf.TraceError) as exc:
        g.create_instance("ok-name", tenant="")
    assert exc.value.code == "TRACE_INVALID_REQUEST"

    instance(g, "ok-name")
    with pytest.raises(tf.TraceError) as exc:
        g.create_instance("ok-name", tenant="team-b")
    assert exc.value.code == "TRACE_INSTANCE_EXISTS"
    assert g.stats()["instances"] == 1


def test_buffer_size_bounds():
    g = guard()
    for bad in (0, -1, 16385):
        with pytest.raises(tf.TraceError) as exc:
            instance(g, "buf", buffer_size_kb=bad)
        assert exc.value.code == "TRACE_BUFFER_INVALID"
    assert instance(g, "low", buffer_size_kb=1).buffer_size_kb == 1
    assert instance(g, "high", buffer_size_kb=16384).buffer_size_kb == 16384


def test_filter_expression_is_validated_atomically():
    g = guard()
    good = instance(g, "good", filter="common_pid == 100")
    assert good.filter == "common_pid == 100"
    assert instance(g, "none", filter=None).filter is None
    with pytest.raises(tf.TraceError) as exc:
        instance(g, "open-paren", filter="common_pid == (100")
    assert exc.value.code == "TRACE_FILTER_INVALID"
    with pytest.raises(tf.TraceError) as exc:
        instance(g, "inject", filter="common_pid == 100; rm -rf /")
    assert exc.value.code == "TRACE_FILTER_INVALID"
    assert [row.name for row in g.instances()] == ["good", "none"]


def test_instance_capacity_is_capped():
    g = guard(max_instances=2)
    instance(g, "one", tenant="t")
    instance(g, "two", tenant="t")
    with pytest.raises(tf.TraceError) as exc:
        instance(g, "three", tenant="t")
    assert exc.value.code == "TRACE_LIMIT_EXCEEDED"
    assert len(g.instances()) == 2


def test_probe_symbol_must_be_whitelisted_and_instance_known():
    g = guard()
    instance(g)
    assert probe(g, symbol="vfs_read").symbol == "vfs_read"
    with pytest.raises(tf.TraceError) as exc:
        probe(g, symbol="commit_creds")
    assert exc.value.code == "TRACE_PROBE_SYMBOL_DENIED"
    with pytest.raises(tf.TraceError) as exc:
        probe(g, instance_name="missing-instance")
    assert exc.value.code == "TRACE_INSTANCE_UNKNOWN"
    assert len(g.probes("sched-lat")) == 1


def test_probe_offset_window_is_enforced():
    g = guard()
    instance(g)
    with pytest.raises(tf.TraceError) as exc:
        probe(g, symbol="vfs_read", offset=65)
    assert exc.value.code == "TRACE_PROBE_OFFSET_INVALID"
    with pytest.raises(tf.TraceError) as exc:
        probe(g, symbol="vfs_read", offset=-1)
    assert exc.value.code == "TRACE_PROBE_OFFSET_INVALID"
    assert probe(g, symbol="vfs_read", offset=64).offset == 64
    assert probe(g, symbol="__x64_sys_write", offset=0).offset == 0


def test_uprobe_requires_absolute_path_and_known_kind():
    g = guard()
    instance(g)
    with pytest.raises(tf.TraceError) as exc:
        probe(g, kind="uprobe", symbol="bin/app")
    assert exc.value.code == "TRACE_PROBE_SYMBOL_DENIED"
    with pytest.raises(tf.TraceError) as exc:
        probe(g, kind="uprobe", symbol="/opt/../etc/app")
    assert exc.value.code == "TRACE_PROBE_SYMBOL_DENIED"

    created = probe(g, kind="uprobe", symbol="/opt/app/bin/server", offset=16)
    assert created.kind == "uprobe"
    assert created.symbol == "/opt/app/bin/server"
    with pytest.raises(tf.TraceError) as exc:
        probe(g, kind="tracepoint", symbol="vfs_read")
    assert exc.value.code == "TRACE_INVALID_REQUEST"


def test_describe_masks_kernel_address():
    g = guard()
    instance(g)
    created = probe(g, symbol="tcp_sendmsg", offset=8, filter="common_pid == 1")
    assert g.describe(created.probe_id) == {
        "probe_id": "p1",
        "instance": "sched-lat",
        "symbol": "tcp_sendmsg",
        "offset": 8,
        "filter": "common_pid == 1",
        "address": "0x***",
    }
    with pytest.raises(tf.TraceError) as exc:
        g.describe("p404")
    assert exc.value.code == "TRACE_PROBE_UNKNOWN"


def test_per_instance_probe_capacity():
    g = guard(max_probes_per_instance=2)
    instance(g)
    probe(g, symbol="vfs_read", offset=0)
    probe(g, symbol="vfs_read", offset=8)
    with pytest.raises(tf.TraceError) as exc:
        probe(g, symbol="vfs_read", offset=16)
    assert exc.value.code == "TRACE_LIMIT_EXCEEDED"
    assert len(g.probes("sched-lat")) == 2


def test_enable_event_flips_matching_probes_only():
    g = guard()
    instance(g)
    first = probe(g, symbol="vfs_read", offset=0)
    second = probe(g, symbol="vfs_read", offset=8)
    other = probe(g, symbol="tcp_sendmsg", offset=0)

    assert g.enable_event("sched-lat", "vfs_read") == 2
    flags = {row.probe_id: row.enabled for row in g.probes("sched-lat")}
    assert flags == {first.probe_id: True, second.probe_id: True, other.probe_id: False}
    assert g.stats()["enabled_probes"] == 2

    assert g.enable_event("sched-lat", "vfs_read", enable=False) == 2
    assert g.stats()["enabled_probes"] == 0
    with pytest.raises(tf.TraceError) as exc:
        g.enable_event("sched-lat", "commit_creds")
    assert exc.value.code == "TRACE_EVENT_UNKNOWN"


def test_reader_tenant_isolation_and_capacity():
    g = guard(max_readers_per_instance=2)
    instance(g, tenant="team-a")
    with pytest.raises(tf.TraceError) as exc:
        g.attach_reader("sched-lat", tenant="team-b")
    assert exc.value.code == "TRACE_TENANT_MISMATCH"

    first = g.attach_reader("sched-lat", tenant="team-a")
    second = g.attach_reader("sched-lat", tenant="team-a")
    assert (first.reader_id, second.reader_id) == ("r1", "r2")
    assert (first.closed, second.closed) == (False, False)
    with pytest.raises(tf.TraceError) as exc:
        g.attach_reader("sched-lat", tenant="team-a")
    assert exc.value.code == "TRACE_LIMIT_EXCEEDED"
    assert g.stats()["readers"] == 2


def test_emit_event_fills_reader_and_drops_overflow():
    g = guard(reader_capacity=4)
    instance(g)
    probe(g, symbol="vfs_read")
    g.enable_event("sched-lat", "vfs_read")
    reader = g.attach_reader("sched-lat", tenant="team-a")

    assert g.emit_event("sched-lat", "vfs_read", count=6) == {
        "delivered": 4, "dropped": 2}
    assert g.read(reader.reader_id, max_events=10) == ["vfs_read"] * 4
    assert g.read(reader.reader_id) == []
    assert g.stats()["emitted"] == 6
    assert g.stats()["dropped"] == 2

    with pytest.raises(tf.TraceError) as exc:
        g.emit_event("sched-lat", "tcp_sendmsg", count=1)
    assert exc.value.code == "TRACE_EVENT_UNKNOWN"
    with pytest.raises(tf.TraceError) as exc:
        g.emit_event("sched-lat", "vfs_read", count=0)
    assert exc.value.code == "TRACE_INVALID_REQUEST"


def test_destroy_instance_releases_probes_and_scopes_by_tenant():
    g = guard()
    instance(g, "gone", tenant="team-a")
    instance(g, "kept", tenant="team-b")
    probe(g, "gone", symbol="vfs_read")
    probe(g, "kept", symbol="tcp_sendmsg")
    g.enable_event("gone", "vfs_read")

    assert g.destroy_instance("gone") == {"probes": 1, "readers": 0}
    assert [row.name for row in g.instances()] == ["kept"]
    assert g.instances(tenant="team-a") == []
    with pytest.raises(tf.TraceError) as exc:
        probe(g, "gone", symbol="vfs_read")
    assert exc.value.code == "TRACE_INSTANCE_UNKNOWN"
    with pytest.raises(tf.TraceError) as exc:
        g.destroy_instance("gone")
    assert exc.value.code == "TRACE_INSTANCE_UNKNOWN"
    assert len(g.probes("kept")) == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    instance(g)
    created = probe(g, symbol="vfs_read")
    g.enable_event("sched-lat", "vfs_read")
    reader = g.attach_reader("sched-lat", tenant="team-a")
    g.emit_event("sched-lat", "vfs_read", count=2)

    state = g.snapshot()
    assert set(state) == {"version", "instances", "probes", "readers", "counters"}
    pristine = copy.deepcopy(state)

    state["instances"].clear()
    state["readers"].clear()
    assert [row.name for row in g.instances()] == ["sched-lat"]
    assert g.read(reader.reader_id) == ["vfs_read", "vfs_read"]

    clone = guard()
    clone.restore(pristine)
    assert [row.name for row in clone.instances()] == ["sched-lat"]
    assert [row.probe_id for row in clone.probes("sched-lat")] == [created.probe_id]
    assert clone.stats()["emitted"] == 2

    for bad in (None, {},
                {"version": 1, "instances": [], "probes": [], "readers": []},
                {"version": 1, "instances": [], "probes": [], "readers": [],
                 "counters": []}):
        with pytest.raises(tf.TraceError) as exc:
            g.restore(bad)
        assert exc.value.code == "TRACE_SNAPSHOT_INVALID"
    assert [row.name for row in g.instances()] == ["sched-lat"]
