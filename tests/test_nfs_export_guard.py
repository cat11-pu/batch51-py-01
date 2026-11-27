import copy
import threading

import pytest

import nfs_export_guard as nfs

LAB = """# lab exports
/srv/data  10.0.0.0/8(rw,sync)  192.168.1.5(ro)
/srv/log   *(ro)
"""


def guard(**kwargs):
    return nfs.NfsExportGuard(**kwargs)


def sorted_options(*names):
    return tuple(sorted(names))


def test_load_exports_parses_paths_clients_and_options():
    inst = guard()
    assert inst.current_version() == 0
    assert inst.entries() == ()
    assert inst.load_exports(LAB) == 1
    rows = inst.entries()
    assert [row.path for row in rows] == ["/srv/data", "/srv/log"]
    assert [row.line for row in rows] == [2, 3]
    first = rows[0]
    assert [spec.pattern for spec in first.clients] == ["10.0.0.0/8", "192.168.1.5"]
    assert [spec.options for spec in first.clients] == [("rw", "sync"), ("ro",)]
    assert [spec.pattern for spec in rows[1].clients] == ["*"]
    assert rows[1].clients[0].options == ("ro",)


def test_malformed_lines_are_refused_and_old_table_survives():
    inst = guard()
    inst.load_exports("/srv/keep *(ro)\n")
    bad_lines = ["srv/data *(ro)\n", "/srv/data 10.0.0.0/33(ro)\n",
                 "/srv/data *(bogus)\n"]
    for text in bad_lines:
        with pytest.raises(nfs.NfsExportError) as exc:
            inst.load_exports(text)
        assert exc.value.code == "NFS_PARSE_FAILED"
        assert exc.value.detail["line"] == 1
    assert inst.current_version() == 1
    assert [row.path for row in inst.entries()] == ["/srv/keep"]
    assert inst.stats()["failed_loads"] == 3


def test_pseudo_filesystem_paths_cannot_be_exported():
    inst = guard()
    inst.load_exports("/srv/keep *(ro)\n")
    for line in ("/proc/sys *(ro)\n", "/sys/fs/cgroup *(ro)\n", "/dev/shm *(rw)\n"):
        with pytest.raises(nfs.NfsExportError) as exc:
            inst.load_exports(line)
        assert exc.value.code == "NFS_PSEUDO_PATH"
    assert inst.current_version() == 1
    assert [row.path for row in inst.entries()] == ["/srv/keep"]


def test_version_and_load_counters_advance_per_successful_load():
    inst = guard()
    assert inst.load_exports(LAB) == 1
    assert inst.load_exports("/srv/other *(ro)\n") == 2
    assert inst.current_version() == 2
    assert inst.stats()["loads"] == 2
    assert inst.stats()["failed_loads"] == 0


def test_longest_matching_prefix_wins():
    inst = guard()
    inst.load_exports("/srv 10.0.0.0/8(ro)\n/srv/data 10.0.0.0/8(rw,sync)\n")
    deep = inst.match_export("/srv/data/project", "10.9.9.9")
    shallow = inst.match_export("/srv/log/current", "10.9.9.9")
    assert deep.path == "/srv/data"
    assert shallow.path == "/srv"
    assert "rw" in inst.effective_options("/srv/data/project", "10.9.9.9")
    assert "rw" not in inst.effective_options("/srv/log/current", "10.9.9.9")


def test_unmatched_request_is_denied_with_no_export():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(ro)\n")
    decision = inst.authorize(path="/srv/secret/x", client_ip="10.1.1.1")
    assert isinstance(decision, nfs.MountDecision)
    assert decision.allowed is False
    assert decision.reason == "NO_EXPORT"
    assert decision.export_path is None
    assert decision.options == ()
    assert decision.path == "/srv/secret/x"
    assert inst.stats()["denials"] == 1


def test_defaults_fill_missing_option_categories():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8\n")
    options = inst.effective_options("/srv/data", "10.1.1.1")
    assert options == sorted_options("ro", "sync", "root_squash", "subtree_check")
    assert list(options) == sorted(options)


def test_explicit_options_override_defaults():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(rw,async,nosuid)\n")
    options = inst.effective_options("/srv/data", "10.1.1.1")
    assert options == sorted_options("rw", "async", "nosuid", "root_squash",
                                     "subtree_check")
    assert "ro" not in options
    assert "sync" not in options


def test_authorize_allows_read_only_mount_inside_export():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(ro,sync)\n")
    decision = inst.authorize(path="/srv/data/project", client_ip="10.1.2.3")
    assert decision.allowed is True
    assert decision.reason == "OK"
    assert decision.export_path == "/srv/data"
    assert decision.path == "/srv/data/project"
    assert decision.client_ip == "10.1.2.3"
    assert decision.options == sorted_options("ro", "sync", "root_squash",
                                             "subtree_check")
    assert inst.stats()["authorizations"] == 1


def test_read_write_request_is_denied_on_read_only_export():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(ro,sync)\n")
    denied = inst.authorize(path="/srv/data", client_ip="10.1.2.3", request="rw")
    assert denied.allowed is False
    assert denied.reason == "READ_ONLY"
    assert denied.export_path == "/srv/data"
    assert inst.stats()["denials"] == 1

    inst.load_exports("/srv/data 10.0.0.0/8(rw,sync)\n")
    allowed = inst.authorize(path="/srv/data", client_ip="10.1.2.3", request="rw")
    assert allowed.allowed is True
    assert allowed.reason == "OK"
    assert inst.stats()["authorizations"] == 1


def test_cidr_membership_and_path_segment_boundaries():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(ro)\n/srv/other *(ro)\n")
    assert inst.match_export("/srv/data/x", "10.5.6.7").path == "/srv/data"
    assert inst.match_export("/srv/data/x", "11.0.0.1") is None
    assert inst.match_export("/srv/other/y", "11.0.0.1").path == "/srv/other"
    assert inst.match_export("/srv/database", "10.5.6.7") is None


def test_mount_registry_records_and_verifies_entries():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(rw,sync)\n")
    inst.register_mount(client_ip="10.1.2.3", path="/srv/data/project")
    assert inst.mounts() == (("10.1.2.3", "/srv/data/project"),)
    assert inst.stats()["mounts"] == 1
    assert inst.verify_mount(client_ip="10.1.2.3",
                             path="/srv/data/project") is True
    assert inst.verify_mount(client_ip="10.1.2.3", path="/srv/data/other") is False
    assert inst.verify_mount(client_ip="192.168.1.9",
                             path="/srv/data/project") is False


def test_snapshot_is_detached_and_restore_roundtrips():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(rw,sync)\n/srv/log *(ro)\n")
    inst.register_mount(client_ip="10.1.2.3", path="/srv/data/project")
    state = inst.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "entries", "mounts", "stats"}

    state["entries"] = []
    state["stats"]["loads"] = 99
    assert [row.path for row in inst.entries()] == ["/srv/data", "/srv/log"]
    assert inst.stats()["loads"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.current_version() == 1
    assert [row.path for row in clone.entries()] == ["/srv/data", "/srv/log"]
    assert clone.mounts() == (("10.1.2.3", "/srv/data/project"),)
    assert clone.verify_mount(client_ip="10.1.2.3",
                              path="/srv/data/project") is True
    assert clone.stats()["loads"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    inst = guard()
    inst.load_exports("/srv/data 10.0.0.0/8(ro)\n")
    good_stats = {"loads": 1, "failed_loads": 0, "authorizations": 0,
                  "denials": 0, "mounts": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"version": "1", "entries": [], "mounts": [], "stats": good_stats},
        {"version": 1, "entries": "nope", "mounts": [], "stats": good_stats},
        {"version": 1, "entries": [], "mounts": [], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(nfs.NfsExportError) as exc:
            inst.restore(bad)
        assert exc.value.code == "NFS_SNAPSHOT_INVALID"
    assert inst.current_version() == 1
    assert [row.path for row in inst.entries()] == ["/srv/data"]


def test_concurrent_reload_and_authorize_see_one_table():
    inst = guard()
    read_only = "/srv/shared 0.0.0.0/0(ro,sync)\n"
    read_write = "/srv/shared 0.0.0.0/0(rw,sync)\n"
    inst.load_exports(read_only)

    errors = []
    ready = threading.Event()
    stop = threading.Event()

    def reloader():
        try:
            for text in [read_write, read_only] * 6:
                inst.load_exports(text)
                ready.set()
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))
            ready.set()
        finally:
            stop.set()

    seen = []

    def watcher():
        ready.wait(5)
        try:
            while True:
                decision = inst.authorize(path="/srv/shared/x",
                                          client_ip="10.1.2.3")
                seen.append(decision)
                if stop.is_set():
                    break
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=reloader), threading.Thread(target=watcher)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert errors == []
    assert seen
    for decision in seen:
        assert decision.version >= 1
        assert decision.allowed is True
        assert ("rw" in decision.options) == (decision.version % 2 == 0)
    assert inst.current_version() == 13
