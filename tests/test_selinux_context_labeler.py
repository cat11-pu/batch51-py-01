import copy
import threading

import pytest

import selinux_context_labeler as sc

CTX_A = "system_u:object_r:app_content_t:s0"
CTX_B = "system_u:object_r:app_cache_t:s0"
CTX_SITE = "system_u:object_r:httpd_sys_content_t:s0-s0:c0.c1023"


def labeler(**kwargs):
    return sc.SelinuxContextLabeler(**kwargs)


def rule(pattern, context, file_type="-d"):
    return {"pattern": pattern, "context": context, "type": file_type}


def test_load_rules_installs_valid_rules_and_counts_rejections():
    g = labeler()
    accepted = g.load_rules([
        rule("/srv/appx(/.*)?", CTX_A),
        rule("/srv/broken", "system_u:object_r"),
        rule("/srv/bady", CTX_B, "--"),
    ])
    assert accepted == 2
    assert [row.pattern for row in g.rules()] == ["/srv/appx(/.*)?",
                                                  "/srv/bady"]
    assert [row.source for row in g.rules()] == ["distro", "distro"]
    assert g.stats()["loaded"] == 2
    assert g.stats()["rejected"] == 1


def test_invalid_rule_shapes_are_rejected_without_partial_install():
    g = labeler()
    rejected = g.load_rules([
        rule("(", CTX_A),
        rule("/srv/space", "system_u:object_r:bad ctx:s0"),
        rule("/srv/typed", CTX_A, "xx"),
        rule("", CTX_A),
    ])
    assert rejected == 0
    assert g.rules() == ()
    assert g.stats()["rejected"] == 4
    assert g.stats()["loaded"] == 0


def test_equal_specificity_chooses_the_later_declaration():
    g = labeler()
    g.load_rules([rule("/srv/app[0-9]", CTX_A),
                  rule("/srv/app[0-3]", CTX_B)])
    installed = g.rules()
    assert installed[0].specificity == installed[1].specificity == 8
    assert g.resolve_context("/srv/app1") == CTX_B


def test_local_block_wins_and_borrows_distribution_mls():
    g = labeler()
    g.load_rules([rule("/srv/www(/.*)?", CTX_SITE)])
    g.load_rules([rule("/srv/www(/.*)?", "system_u:object_r:httpd_var_t")],
                 source="local")
    assert g.resolve_context("/srv/www/index.html") == \
        "system_u:object_r:httpd_var_t:s0-s0:c0.c1023"

    g.load_rules([rule("/srv/www(/.*)?",
                       "system_u:object_r:httpd_var_t:s0-s0:c1.c2")],
                 source="local")
    with pytest.raises(sc.LabelError) as exc:
        g.resolve_context("/srv/www/index.html")
    assert exc.value.code == "LABEL_MLS_WIDENED"
    assert exc.value.detail["path"] == "/srv/www/index.html"


def test_unmatched_path_is_reported_as_unlabeled():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    assert g.resolve_context("/opt/other") is None
    plan = g.plan_relabel(["/opt/other"])
    assert len(plan) == 1
    assert plan[0].action == "unlabeled"
    assert plan[0].context == ""
    assert plan[0].detail == "no matching rule"
    assert g.apply(plan) == 0
    assert g.watermark() == 0


def test_already_correct_path_is_unchanged_and_not_rewritten():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    g.observe_path("/srv/app", current=CTX_A)
    plan = g.plan_relabel(["/srv/app"])
    assert [entry.action for entry in plan] == ["unchanged"]
    assert plan[0].context == CTX_A
    assert g.stats()["unchanged"] == 1
    assert g.stats()["planned"] == 0
    assert g.apply(plan) == 0
    assert g.watermark() == 0


def test_missing_path_is_kept_pending_and_apply_skips_it():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    g.observe_path("/srv/app", exists=False)
    plan = g.plan_relabel(["/srv/app"])
    assert [entry.action for entry in plan] == ["pending"]
    assert plan[0].detail == "missing"
    assert plan[0].context == CTX_A
    assert g.apply(plan) == 0
    checks = g.verify(["/srv/app"])
    assert checks[0]["ok"] is False
    assert checks[0]["actual"] is None


def test_apply_writes_plan_and_verify_confirms_each_path():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    g.observe_path("/srv/app")
    g.observe_path("/srv/app/cache")
    plan = g.plan_relabel(["/srv/app", "/srv/app/cache"])
    assert [entry.action for entry in plan] == ["relabel", "relabel"]
    assert g.apply(plan) == 2
    assert g.watermark() == 2
    checks = g.verify(["/srv/app", "/srv/app/cache"])
    assert [row["actual"] for row in checks] == [CTX_A, CTX_A]
    assert all(row["ok"] for row in checks)
    assert g.stats()["applied"] == 2


def test_plan_built_on_older_rules_is_refused_atomically():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    g.observe_path("/srv/app")
    plan = g.plan_relabel(["/srv/app"])
    g.load_rules([rule("/srv/other(/.*)?", CTX_B)])
    with pytest.raises(sc.LabelError) as exc:
        g.apply(plan)
    assert exc.value.code == "LABEL_STALE_PLAN"
    assert g.watermark() == 0
    assert g.verify(["/srv/app"])[0]["ok"] is False


def test_equivalence_class_emits_one_alias_entry_only():
    g = labeler()
    g.load_rules([rule("/srv/www(/.*)?", CTX_A)])
    g.add_equivalence("/srv/www", "/srv/www/html")
    assert g.equivalence_of("/srv/www/html") == "/srv/www"
    plan = g.plan_relabel(["/srv/www", "/srv/www/html"])
    assert [entry.action for entry in plan] == ["relabel", "alias"]
    assert plan[1].path == "/srv/www/html"
    assert plan[1].detail == "/srv/www"
    assert plan[0].context == plan[1].context == CTX_A
    assert g.apply(plan) == 2
    checks = g.verify(["/srv/www", "/srv/www/html"])
    assert [row["actual"] for row in checks] == [CTX_A, CTX_A]


def test_plan_entry_cap_refuses_oversized_plan():
    g = labeler(max_plan_entries=3)
    g.load_rules([rule("/srv/bulk/[0-9]", CTX_A)])
    paths = [f"/srv/bulk/{index}" for index in range(5)]
    with pytest.raises(sc.LabelError) as exc:
        g.plan_relabel(paths)
    assert exc.value.code == "LABEL_PLAN_TOO_LARGE"
    assert exc.value.detail["limit"] == 3
    assert g.watermark() == 0


def test_rule_cap_refuses_reload_and_keeps_previous_block():
    g = labeler(max_rules=2)
    assert g.load_rules([rule("/srv/one", CTX_A)]) == 1
    with pytest.raises(sc.LabelError) as exc:
        g.load_rules([rule("/srv/a", CTX_A), rule("/srv/b", CTX_B),
                      rule("/srv/c", CTX_A)])
    assert exc.value.code == "LABEL_CAPACITY_EXCEEDED"
    assert exc.value.detail["limit"] == 2
    assert [row.pattern for row in g.rules()] == ["/srv/one"]
    assert g.stats()["loaded"] == 1


def test_remove_rule_reports_whether_the_pattern_existed():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    assert g.resolve_context("/srv/app") == CTX_A
    assert g.remove_rule("/srv/app(/.*)?") is True
    assert g.resolve_context("/srv/app") is None
    assert g.remove_rule("/srv/app(/.*)?") is False
    with pytest.raises(sc.LabelError) as exc:
        g.remove_rule("/srv/app", source="sidecar")
    assert exc.value.code == "LABEL_INVALID_REQUEST"


def test_concurrent_apply_labels_every_path_exactly_once():
    g = labeler(max_plan_entries=100)
    g.load_rules([rule("/srv/bulk/[0-9][0-9]", CTX_A)])
    paths = [f"/srv/bulk/{index:02d}" for index in range(40)]
    for path in paths:
        g.observe_path(path)
    plan = g.plan_relabel(paths)
    assert len(plan) == 40
    parts = [plan[index::8] for index in range(8)]
    errors = []
    barrier = threading.Barrier(len(parts))

    def worker(part):
        try:
            barrier.wait(timeout=5)
            g.apply(part)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(part,)) for part in parts]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.watermark() == 40
    assert g.stats()["applied"] == 40
    assert all(row["ok"] for row in g.verify(paths))


def test_snapshot_is_detached_and_restore_roundtrips():
    g = labeler()
    g.load_rules([rule("/srv/app(/.*)?", CTX_A)])
    g.add_equivalence("/srv/app", "/srv/app/html")
    g.observe_path("/srv/app")
    plan = g.plan_relabel(["/srv/app", "/srv/app/html"])
    g.apply(plan)
    state = g.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "distro", "local", "equivalences",
                             "paths", "watermark", "stats"}

    state["distro"].clear()
    state["stats"]["applied"] = 999
    assert g.resolve_context("/srv/app") == CTX_A
    assert g.watermark() == 2
    assert g.stats()["applied"] == 2

    clone = labeler()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.watermark() == 2
    assert clone.resolve_context("/srv/app") == CTX_A
    checks = clone.verify(["/srv/app", "/srv/app/html"])
    assert [row["ok"] for row in checks] == [True, True]

    bad_states = [
        None,
        {},
        {"version": 2, "distro": [], "local": [], "equivalences": {},
         "paths": {}, "watermark": 0, "stats": dict(g.stats())},
        {"version": 1, "distro": {}, "local": [], "equivalences": {},
         "paths": {}, "watermark": 0, "stats": dict(g.stats())},
        {"version": 1, "distro": [], "local": [], "equivalences": {},
         "paths": {}, "watermark": 0, "stats": {"applied": 2}},
    ]
    for bad in bad_states:
        with pytest.raises(sc.LabelError) as exc:
            g.restore(bad)
        assert exc.value.code == "LABEL_SNAPSHOT_INVALID"
    assert g.watermark() == 2
