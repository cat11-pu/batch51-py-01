import pytest

import git_blob_secret_sweeper as gs


SECRET_TEXT = (
    "# deploy notes\n"
    "aws AKIAIOSFODNN7EXAMPLE\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "token = 0123456789abcdef0123456789abcdef\n"
)


def sweeper(**kwargs):
    return gs.GitBlobSecretSweeper(**kwargs)


def test_add_commit_reports_object_count():
    s = sweeper()
    out = s.add_commit(
        "c1",
        objects=(("app/a.py", "b1"), ("app/b.py", "b2")),
    )
    assert out["commit"] == "c1"
    assert out["objects"] == 2
    assert out["parents"] == 0
    assert s.describe_commit("c1")["objects"] == 2


def test_duplicate_path_in_commit_rejected():
    s = sweeper()
    with pytest.raises(gs.SweepError) as excinfo:
        s.add_commit(
            "c1",
            objects=(("app/a.py", "b1"), ("app/a.py", "b2")),
        )
    assert excinfo.value.code == "SWEEP_DUPLICATE_PATH"
    assert excinfo.value.detail == "app/a.py"


def test_invalid_and_duplicate_commit_rejected():
    s = sweeper()
    with pytest.raises(gs.SweepError) as excinfo:
        s.add_commit("")
    assert excinfo.value.code == "SWEEP_INVALID_COMMIT"
    s.add_commit("c1")
    with pytest.raises(gs.SweepError) as again:
        s.add_commit("c1")
    assert again.value.code == "SWEEP_DUPLICATE_COMMIT"


def test_walk_commits_preorder_with_merge():
    s = sweeper()
    s.add_commit("c1")
    s.add_commit("c2", parents=("c1",))
    s.add_commit("c3", parents=("c1",))
    s.add_commit("c4", parents=("c2", "c3"))
    assert s.walk_commits() == ("c4", "c2", "c1", "c3")
    assert s.walk_commits(from_commit="c2") == ("c2", "c1")


def test_walk_unknown_commit_raises():
    s = sweeper()
    s.add_commit("c1")
    with pytest.raises(gs.SweepError) as excinfo:
        s.walk_commits(from_commit="nope")
    assert excinfo.value.code == "SWEEP_UNKNOWN_COMMIT"


def test_scan_object_detects_all_three_kinds():
    s = sweeper()
    s.register_blob("b1", content=SECRET_TEXT)
    out = s.scan_object("b1")
    assert out["oid"] == "b1"
    pairs = [(item["kind"], item["line"]) for item in out["findings"]]
    assert pairs == [
        ("aws_access_key_id", 2),
        ("private_key_block", 3),
        ("hex_secret_assignment", 4),
    ]
    assert out["cached"] is False


def test_scan_object_clean_content_has_no_findings():
    s = sweeper()
    out = s.scan_object("b9", content="def main():\n    return 0\n")
    assert out["findings"] == ()
    assert out["bytes"] == 25


def test_scan_object_second_call_is_cached():
    s = sweeper()
    s.register_blob("b1", content=SECRET_TEXT)
    first = s.scan_object("b1")
    second = s.scan_object("b1")
    assert second["cached"] is True
    assert second["findings"] == first["findings"]
    assert s.stats()["scans"] == 1


def test_sweep_backfills_results_to_every_path():
    s = sweeper()
    s.add_commit("c1", objects=(("app/a.py", "b1"),))
    s.add_commit(
        "c2",
        parents=("c1",),
        objects=(("app/a.py", "b1"), ("app/copy.py", "b1")),
    )
    s.register_blob("b1", content=SECRET_TEXT)
    out = s.sweep("c2")
    assert out["commits"] == 2
    assert out["objects"] == 1
    assert out["cached"] == 2
    assert s.results_for_path("app/a.py") == ("aws_access_key_id",)
    assert s.results_for_path("app/copy.py") == ("aws_access_key_id",)


def test_follow_renames_by_identical_blob():
    s = sweeper()
    s.add_commit("c1", objects=(("app/legacy.py", "x1"),))
    s.add_commit("c2", parents=("c1",), objects=(("app/modern.py", "x1"),))
    assert s.follow_renames("c2") == {"app/legacy.py": "app/modern.py"}


def test_follow_renames_by_similar_path():
    s = sweeper()
    s.add_commit("c1", objects=(("src/app/config.py", "x1"),))
    s.add_commit("c2", parents=("c1",), objects=(("src/app/config2.py", "x2"),))
    assert s.follow_renames("c2") == {"src/app/config.py": "src/app/config2.py"}


def test_follow_renames_ignores_unrelated_paths():
    s = sweeper()
    s.add_commit("c1", objects=(("docs/guide.md", "x1"),))
    s.add_commit("c2", parents=("c1",), objects=(("src/kernel.c", "x2"),))
    assert s.follow_renames("c2") == {}


def test_checkpoint_and_resume_without_double_count():
    s = sweeper()
    s.add_commit("c1", objects=(("app/a.py", "b1"),))
    s.add_commit("c2", parents=("c1",), objects=(("app/a.py", "b1"),))
    s.register_blob("b1", content=SECRET_TEXT)
    out = s.sweep("c2")
    assert out["commits"] == 2
    assert out["objects"] == 1
    cp = s.checkpoint()
    assert cp["commit"] == "c1"
    assert cp["objects"] == 1

    s.add_commit("c3", parents=("c2",), objects=(("app/new.py", "b2"),))
    s.register_blob("b2", content="print('ok')\n")
    visited = s.resume(cp)
    assert visited == 1
    assert s.stats()["objects"] == 2
    assert s.stats()["cached"] == 1
    assert s.results_for_path("app/new.py") == ()


def test_snapshot_restore_roundtrip():
    s = sweeper()
    s.add_commit("c1", objects=(("app/a.py", "b1"),))
    s.add_commit("c2", parents=("c1",), objects=(("app/a.py", "b1"),))
    s.register_blob("b1", content=SECRET_TEXT)
    s.sweep("c2")
    before = s.stats()["objects"]
    snap = s.snapshot()

    s.add_commit("c9", objects=(("app/z.py", "b9"),))
    s.register_blob("b9", content=SECRET_TEXT)
    s.sweep()

    s.restore(snap)
    assert s.stats()["objects"] == before
    assert s.walk_commits() == ("c2", "c1")
    assert s.results_for_path("app/a.py") == ("aws_access_key_id",)
    with pytest.raises(gs.SweepError):
        s.describe_commit("c9")
    snap["stats"]["objects"] = 999
    assert s.stats()["objects"] != 999


def test_restore_rejects_malformed_state():
    s = sweeper()
    s.add_commit("c1", objects=(("app/a.py", "b1"),))
    with pytest.raises(gs.SweepError) as excinfo:
        s.restore({"commits": []})
    assert excinfo.value.code == "SWEEP_SNAPSHOT_INVALID"
    assert s.walk_commits() == ("c1",)
