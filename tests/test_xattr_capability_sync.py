import copy
import threading

import pytest

import xattr_capability_sync as xattr


def new_sync(**kwargs):
    return xattr.XattrCapabilitySync(**kwargs)


def test_apply_writes_trusted_allowed_attribute():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/note.txt"
    assert sync.inspect(path) is None
    result = sync.apply(path, {"user.note": "hello"}, source="archive")
    assert result == (("user.note", "hello"),)
    assert sync.inspect(path) == (("user.note", "hello"),)
    assert sync.operations() == (("write", path, "user.note", "hello"),
                                 ("replace", path))
    assert sync.stats()["applied"] == 1
    assert sync.stats()["written"] == 1
    assert sync.stats()["replaced"] == 1


def test_untrusted_source_keeps_user_attrs_and_drops_capability():
    sync = new_sync()
    path = "/srv/a/bin/tool"
    attrs = {"security.capability": "cap_net_raw", "user.note": "n"}
    plan = sync.plan_xattr(path, attrs, source="download")
    assert plan.path == path
    assert plan.keep == (("user.note", "n"),)
    assert plan.strip == ("security.capability",)
    result = sync.apply(path, attrs, source="download")
    assert result == (("user.note", "n"),)
    assert sync.inspect(path) == (("user.note", "n"),)
    assert sync.stats()["plans"] == 1


def test_path_policy_uses_longest_prefix_and_allow_list():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    sync.set_path_policy("/srv/upload/", allow=("user.notes",))
    sync.set_path_policy("/srv/upload/restricted/", allow=())

    global_plan = sync.plan_xattr("/srv/other/a",
                                  {"security.selinux": "ctx",
                                   "user.notes": "n"}, source="archive")
    assert global_plan.keep == (("security.selinux", "ctx"),
                                ("user.notes", "n"))

    upload_plan = sync.plan_xattr("/srv/upload/a",
                                  {"security.selinux": "ctx",
                                   "user.notes": "n",
                                   "user.other": "o"}, source="archive")
    assert upload_plan.keep == (("user.notes", "n"),)
    assert upload_plan.strip == ("security.selinux", "user.other")

    restricted = sync.plan_xattr("/srv/upload/restricted/b",
                                 {"security.selinux": "ctx",
                                  "user.notes": "n"}, source="archive")
    assert restricted.keep == ()
    assert restricted.strip == ("security.selinux", "user.notes")
    assert sync.stats()["plans"] == 3


def test_conflict_resolution_follows_policy_setting():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/cfg"
    sync.apply(path, {"user.tag": "old"}, source="archive")
    sync.apply(path, {"user.tag": "new"}, source="archive")
    assert sync.inspect(path) == (("user.tag", "old"),)
    assert ("write", path, "user.tag", "new") not in sync.operations()

    sync.set_path_policy("/srv/a/", allow=("*",), conflict="source")
    sync.apply(path, {"user.tag": "new"}, source="archive")
    assert sync.inspect(path) == (("user.tag", "new"),)
    assert sync.operations()[-2:] == (("write", path, "user.tag", "new"),
                                      ("replace", path))


def test_strip_happens_before_write_in_one_apply():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/cap"
    sync.apply(path, {"security.capability": "cap1", "user.note": "n1"},
               source="archive")
    assert sync.inspect(path) == (("security.capability", "cap1"),
                                  ("user.note", "n1"))
    sync.set_path_policy("/srv/a/", allow=("*",), conflict="source")
    sync.apply(path, {"security.capability": "cap2", "user.note": "n2"},
               source="download")

    ops = sync.operations()
    strip_index = ops.index(("strip", path, "security.capability"))
    write_index = ops.index(("write", path, "user.note", "n2"))
    assert strip_index < write_index
    assert ops[strip_index + 1] == ("write", path, "user.note", "n2")
    assert sync.inspect(path) == (("user.note", "n2"),)


def test_strip_removes_only_named_attributes():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/s"
    sync.apply(path, {"user.a": "1", "user.b": "2"}, source="archive")
    assert sync.strip(path, ["user.a", "user.missing"]) == 1
    assert sync.inspect(path) == (("user.b", "2"),)
    assert sync.strip(path, ["user.a"]) == 0
    assert sync.stats()["stripped"] == 1


def test_hardlink_bookkeeping_shares_one_object():
    sync = new_sync()
    assert sync.touch("/srv/h/a") is True
    assert sync.touch("/srv/h/a") is False
    assert sync.add_hardlink("/srv/h/b", "/srv/h/a") is None
    assert sync.inspect("/srv/h/b") == ()
    assert sync.link_targets("/srv/h/a") == ("/srv/h/a", "/srv/h/b")
    assert sync.link_targets("/srv/h/b") == ("/srv/h/a", "/srv/h/b")
    assert sync.link_targets("/srv/h/missing") == ()
    assert sync.remove_path("/srv/h/a") is True
    assert sync.remove_path("/srv/h/a") is False
    assert sync.link_targets("/srv/h/b") == ("/srv/h/b",)
    assert sync.inspect("/srv/h/b") == ()


def test_invalid_requests_leave_state_untouched():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/atomic"
    sync.apply(path, {"user.keep": "v"}, source="archive")
    before = sync.operations()

    bad_calls = [
        lambda: sync.apply(path, {"user.ok": "1", "security.capability": 5},
                           source="archive"),
        lambda: sync.apply("relative/path", {"user.a": "1"},
                           source="archive"),
        lambda: sync.apply(path, {"user.a": "1"}, source=""),
        lambda: sync.set_source_trust("archive", "root"),
        lambda: sync.set_path_policy("srv/", allow=("*",)),
        lambda: sync.set_path_policy("/srv/", allow=("*",), conflict="last"),
    ]
    for call in bad_calls:
        with pytest.raises(xattr.XattrError) as exc:
            call()
        assert exc.value.code == "XATTR_INVALID_REQUEST"

    assert sync.inspect(path) == (("user.keep", "v"),)
    assert sync.operations() == before
    assert sync.stats()["applied"] == 1
    assert sync.stats()["refused"] == len(bad_calls)


def test_plan_xattr_is_pure_and_reports_decisions():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    sync.touch("/srv/a/p")
    before = sync.operations()
    plan = sync.plan_xattr("/srv/a/p",
                           {"user.x": "1", "security.selinux": "s"},
                           source="download")
    assert isinstance(plan, xattr.AttrPlan)
    assert plan.keep == (("user.x", "1"),)
    assert plan.strip == ("security.selinux",)
    assert sync.inspect("/srv/a/p") == ()
    assert sync.operations() == before
    assert sync.stats()["plans"] == 1


def test_attribute_limit_is_enforced_before_writing():
    sync = new_sync(max_attrs=2)
    attrs = {"user.a": "1", "user.b": "2", "user.c": "3"}
    with pytest.raises(xattr.XattrError) as exc:
        sync.apply("/srv/a/limit", attrs, source="archive")
    assert exc.value.code == "XATTR_ATTR_LIMIT"
    assert sync.inspect("/srv/a/limit") is None
    assert sync.operations() == ()
    assert sync.stats()["refused"] == 1


def test_apply_is_idempotent_for_identical_values():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/idem"
    sync.apply(path, {"user.a": "1"}, source="archive")
    first = sync.operations()
    sync.apply(path, {"user.a": "1"}, source="archive")
    assert sync.inspect(path) == (("user.a", "1"),)
    assert sync.operations() == first + (("replace", path),)
    assert sync.stats()["written"] == 1
    assert sync.stats()["applied"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    sync.set_path_policy("/srv/upload/", allow=("user.notes",))
    path = "/srv/a/snap"
    sync.apply(path, {"user.a": "1"}, source="archive")
    sync.touch("/srv/a/empty")
    sync.add_hardlink("/srv/a/link", "/srv/a/empty")
    temp = sync.begin_write("/srv/a/pending", {"user.t": "9"},
                            source="archive")
    state = sync.snapshot()
    assert set(state) == {"version", "objects", "paths", "next_object",
                          "trust", "policies", "operations", "temps",
                          "next_temp", "stats"}
    pristine = copy.deepcopy(state)
    state["paths"].clear()
    state["stats"]["applied"] = 99
    assert sync.inspect(path) == (("user.a", "1"),)
    assert sync.stats()["applied"] == 1

    clone = new_sync()
    clone.restore(pristine)
    assert clone.inspect(path) == (("user.a", "1"),)
    assert clone.link_targets("/srv/a/empty") == ("/srv/a/empty",
                                                  "/srv/a/link")
    assert clone.pending_temp_files() == (temp,)
    assert clone.stats()["applied"] == 1
    assert clone.plan_xattr("/srv/upload/x", {"security.selinux": "s"},
                            source="archive").strip == ("security.selinux",)


def test_restore_rejects_malformed_state_without_touching_live_data():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    sync.apply("/srv/a/keep", {"user.a": "1"}, source="archive")
    good = sync.snapshot()

    bad_states = [None, {}]
    case = copy.deepcopy(good)
    case["version"] = 9
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["objects"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    key = next(iter(case["objects"]))
    case["objects"][key]["user.a"] = 5
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["paths"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["trust"] = {"archive": "root"}
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["policies"] = []
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["stats"].pop("applied")
    bad_states.append(case)
    case = copy.deepcopy(good)
    case["next_object"] = 0
    bad_states.append(case)

    for bad in bad_states:
        with pytest.raises(xattr.XattrError) as exc:
            sync.restore(bad)
        assert exc.value.code == "XATTR_SNAPSHOT_INVALID"

    assert sync.inspect("/srv/a/keep") == (("user.a", "1"),)
    assert sync.stats()["applied"] == 1


def test_concurrent_applies_to_one_path_keep_every_attribute():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/bulk"
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            sync.apply(path, {f"user.k{index:02d}": f"v{index:02d}"},
                       source="archive")
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sync.inspect(path) == tuple(
        (f"user.k{index:02d}", f"v{index:02d}") for index in range(12))
    assert sync.stats()["applied"] == 12
    assert sync.stats()["written"] == 12


def test_stats_track_each_operation_exactly():
    sync = new_sync()
    sync.set_source_trust("archive", "trusted")
    path = "/srv/a/stats"
    sync.apply(path, {"security.capability": "cap", "user.a": "1"},
               source="archive")
    sync.apply(path, {"security.capability": "cap-new", "user.b": "2"},
               source="download")
    assert sync.strip(path, ["user.a", "user.none"]) == 1
    sync.plan_xattr(path, {"user.c": "3"}, source="download")
    with pytest.raises(xattr.XattrError):
        sync.apply(path, {"user.bad": 5}, source="archive")
    assert sync.inspect(path) == (("user.b", "2"),)
    assert sync.stats() == {"applied": 2, "written": 3, "stripped": 2,
                            "replaced": 2, "plans": 1, "refused": 1}
