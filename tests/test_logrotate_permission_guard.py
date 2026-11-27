import copy
import threading

import pytest

import logrotate_permission_guard as lr

LOG = "/var/log/payments/app.log"


def guard(**kwargs):
    return lr.LogrotatePermissionGuard(**kwargs)


def register(g, path, **kwargs):
    options = dict(owner="root", group="root", mode=0o640, size=1024)
    options.update(kwargs)
    return g.register_logfile(path, **options)


def test_plan_create_mode_inherits_owner_group_and_mode():
    g = guard()
    state = register(g, LOG, size=1024)
    assert state.generation == 0
    assert state.inode > 0
    entries = g.plan(LOG)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.archive == LOG + ".1"
    assert entry.rotation == "create"
    assert (entry.owner, entry.group, entry.mode) == ("root", "root", 0o640)
    assert (entry.size, entry.compress) == (1024, True)
    assert g.stat(LOG + ".1") is None
    assert g.generation(LOG) == 0
    assert g.report()["planned"] == 1


def test_plan_and_rotate_refuse_symbolic_link_targets():
    g = guard()
    register(g, "/var/log/link.log", symlink_target="/etc/passwd")
    for call in (lambda: g.plan("/var/log/link.log"),
                 lambda: g.rotate("/var/log/link.log")):
        with pytest.raises(lr.RotateError) as exc:
            call()
        assert exc.value.code == "ROTATE_SYMLINK_REFUSED"
        assert exc.value.detail["path"] == "/var/log/link.log"
        assert exc.value.detail["target"] == "/etc/passwd"
    assert g.stat("/var/log/link.log").symlink_target == "/etc/passwd"
    assert g.generation("/var/log/link.log") == 0


def test_copytruncate_keeps_inode_and_archives_the_content():
    g = guard()
    state = register(g, LOG, rotation="copytruncate", size=2048, mode=0o644)
    result = g.rotate(LOG)
    assert result.generation == 1
    assert result.inode == state.inode
    current = g.stat(LOG)
    assert current.inode == state.inode
    assert current.size == 0
    archive = g.stat(LOG + ".1")
    assert archive.size == 2048
    assert archive.inode != state.inode


def test_create_mode_replaces_the_inode_and_truncates_the_log():
    g = guard()
    state = register(g, LOG, size=4096)
    result = g.rotate(LOG)
    assert result.archive == LOG + ".1"
    assert result.generation == 1
    assert result.compress is True
    assert g.stat(LOG).inode != state.inode
    assert g.stat(LOG).size == 0
    archived = g.stat(LOG + ".1")
    assert archived.size == 4096
    assert archived.mode == 0o640


def test_immutable_logfile_fails_without_leaving_an_archive():
    g = guard()
    register(g, LOG, immutable=True, size=100, mode=0o600)
    with pytest.raises(lr.RotateError) as exc:
        g.rotate(LOG)
    assert exc.value.code == "ROTATE_FAILED"
    assert exc.value.detail["reason"] == "immutable"
    current = g.stat(LOG)
    assert current.size == 100
    assert current.generation == 0
    assert g.stat(LOG + ".1") is None
    report = g.report()
    assert report["rotated"] == 0
    assert report["failed"] == 1


def test_world_writable_directory_tightens_mode_with_umask():
    g = guard(umask=0o022)
    register(g, LOG, mode=0o666, world_writable_dir=True)
    assert g.plan(LOG)[0].mode == 0o644
    result = g.rotate(LOG)
    assert result.mode == 0o644
    assert g.stat(LOG).mode == 0o644


def test_plain_directory_keeps_the_original_mode():
    g = guard(umask=0o022)
    register(g, LOG, mode=0o666)
    assert g.plan(LOG)[0].mode == 0o666
    g.rotate(LOG)
    assert g.stat(LOG).mode == 0o666


def test_su_directive_switches_owner_and_group():
    g = guard()
    register(g, LOG, mode=0o600, su_user="svc-app", su_group="svc-app")
    entry = g.plan(LOG)[0]
    assert (entry.owner, entry.group) == ("svc-app", "svc-app")
    g.rotate(LOG)
    current = g.stat(LOG)
    assert (current.owner, current.group) == ("svc-app", "svc-app")


def test_compress_narrows_mode_and_removes_the_plain_archive():
    g = guard()
    register(g, LOG, mode=0o644, size=5000)
    g.rotate(LOG)
    out = g.compress(LOG)
    assert out["archive"] == LOG + ".1.gz"
    assert out["mode"] == 0o600
    assert out["owner"] == "root"
    assert g.stat(LOG + ".1") is None
    packed = g.stat(LOG + ".1.gz")
    assert packed.mode == 0o600
    assert packed.size == 5000
    assert g.generation(LOG) == 1
    assert g.report()["compressed"] == 1


def test_verify_flags_a_compressed_archive_that_is_looser():
    g = guard()
    register(g, LOG, mode=0o640, size=100)
    g.rotate(LOG)
    g.compress(LOG)
    assert g.verify(LOG) == ()
    g.place_file(LOG + ".1.gz", owner="root", group="root", mode=0o666,
                 size=100)
    codes = [finding["code"] for finding in g.verify(LOG)]
    assert codes == ["ROT_PERM_LOOSER"]
    assert g.verify(LOG)[0]["detail"]["path"] == LOG + ".1.gz"


def test_plan_refuses_runs_over_file_and_byte_caps():
    g = guard(max_files_per_run=2)
    paths = [f"/var/log/cap-{index}.log" for index in range(3)]
    for path in paths:
        register(g, path, size=10)
    with pytest.raises(lr.RotateError) as exc:
        g.plan(paths)
    assert exc.value.code == "ROTATE_CAPACITY"
    assert exc.value.detail["limit"] == 2
    assert all(g.generation(path) == 0 for path in paths)

    small = guard(max_bytes_per_run=1000)
    register(small, "/var/log/big-a.log", size=600)
    register(small, "/var/log/big-b.log", size=600)
    with pytest.raises(lr.RotateError) as exc:
        small.plan(["/var/log/big-a.log", "/var/log/big-b.log"])
    assert exc.value.code == "ROTATE_CAPACITY"
    assert exc.value.detail["limit"] == 1000


def test_concurrent_rotate_on_one_path_keeps_generations_contiguous():
    g = guard()
    register(g, LOG, size=100, mode=0o600)
    errors = []

    def worker():
        try:
            g.rotate(LOG)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.generation(LOG) == 8
    assert g.report()["rotated"] == 8
    for number in range(1, 9):
        assert g.stat(f"{LOG}.{number}") is not None


def test_verify_reports_clean_files_and_owner_mismatch():
    g = guard()
    register(g, LOG, mode=0o640, size=10)
    g.rotate(LOG)
    assert g.verify(LOG) == ()
    g.place_file(LOG, owner="svc-app", group="root", mode=0o640, size=0)
    codes = [finding["code"] for finding in g.verify(LOG)]
    assert codes == ["ROT_OWNER_MISMATCH"]


def test_report_counts_each_outcome_separately():
    g = guard()
    register(g, "/var/log/ok.log", size=10)
    g.rotate("/var/log/ok.log")
    register(g, "/var/log/link.log", symlink_target="/etc/shadow")
    with pytest.raises(lr.RotateError):
        g.rotate("/var/log/link.log")
    register(g, "/var/log/frozen.log", immutable=True)
    with pytest.raises(lr.RotateError):
        g.rotate("/var/log/frozen.log")
    report = g.report()
    assert (report["rotated"], report["compressed"], report["refused"],
            report["failed"]) == (1, 0, 1, 1)
    assert report["findings"] == {}


def test_snapshot_is_detached_and_restore_roundtrips():
    g = guard()
    register(g, LOG, mode=0o644, size=100)
    g.rotate(LOG)
    g.compress(LOG)
    state = g.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "files", "logs", "findings",
                             "counters"}
    state["files"].clear()
    state["counters"]["rotated"] = 999
    assert g.stat(LOG).generation == 1
    assert g.report()["rotated"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.report() == g.report()
    assert clone.generation(LOG) == 1
    assert clone.stat(LOG + ".1.gz").mode == 0o600
    assert clone.verify(LOG) == ()

    bad_states = [
        None,
        {},
        {"version": 2, "files": [], "logs": [], "findings": {},
         "counters": dict(g.report())},
        {"version": 1, "files": {}, "logs": [], "findings": {},
         "counters": dict(g.report())},
        {"version": 1, "files": [], "logs": [], "findings": {},
         "counters": {"rotated": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(lr.RotateError) as exc:
            g.restore(bad)
        assert exc.value.code == "ROTATE_SNAPSHOT_INVALID"
    assert g.report()["rotated"] == 1
    assert g.generation(LOG) == 1
