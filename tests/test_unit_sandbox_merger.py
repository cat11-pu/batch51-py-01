import copy
import threading

import pytest

import unit_sandbox_merger as us

UNIT_WITH_COMMENTS = """
# sandbox baseline for the log agent
[Service]
ProtectSystem=strict
PrivateTmp=yes

ReadWritePaths=/var/lib/app
"""


def merger(**kwargs):
    return us.UnitSandboxMerger(**kwargs)


def raw(result):
    return {row.name: row for row in result.directives}


def test_load_unit_skips_comments_and_sections():
    g = merger()
    assert g.load_unit(UNIT_WITH_COMMENTS) == 3
    result = g.merge()
    assert [row.name for row in result.directives] == [
        "PrivateTmp", "ProtectSystem", "ReadWritePaths"]
    rows = raw(result)
    assert rows["ProtectSystem"].value == "strict"
    assert rows["ReadWritePaths"].value == "/var/lib/app"
    assert result.warnings == ()
    assert result.conflicts == ()
    assert g.stats()["parses"] == 1


def test_repeated_scalar_in_same_file_keeps_last_value():
    g = merger()
    assert g.load_unit("ProtectHome=yes\nProtectHome=no\n") == 2
    assert g.effective("ProtectHome") == "no"
    assert g.origins("ProtectHome") == ("unit",)
    assert g.conflicts() == ()


def test_dropins_apply_in_filename_order():
    g = merger()
    g.load_unit("ProtectSystem=yes\n")
    g.add_dropin("10-early.conf", "ProtectSystem=full\n")
    g.add_dropin("20-late.conf", "ProtectSystem=strict\n")
    assert g.effective("ProtectSystem") == "strict"
    assert g.origins("ProtectSystem") == ("unit", "10-early.conf", "20-late.conf")
    assert g.conflicts() == ("ProtectSystem",)
    rows = raw(g.merge())
    assert rows["ProtectSystem"].origin == "20-late.conf"
    assert rows["ProtectSystem"].value == "strict"


def test_invalid_dropin_name_is_rejected_and_same_name_replaces():
    g = merger()
    g.load_unit("ProtectSystem=yes\n")
    for bad in ("dropin.conf", "1-a.conf", "10-A.conf", "10-a.txt"):
        with pytest.raises(us.SandboxUnitError) as exc:
            g.add_dropin(bad, "ProtectSystem=no")
        assert exc.value.code == "SANDBOX_DROPIN_INVALID"
    assert g.stats()["dropins"] == 0

    assert g.add_dropin("10-a.conf", "ProtectSystem=no\nPrivateTmp=yes") == 2
    assert g.add_dropin("10-a.conf", "ProtectSystem=full") == 1
    assert g.stats()["dropins"] == 1
    assert g.effective("ProtectSystem") == "full"


def test_dropin_capacity_is_capped():
    g = merger(max_dropins=1)
    g.load_unit("ProtectSystem=yes\n")
    g.add_dropin("10-a.conf", "PrivateTmp=yes\n")
    with pytest.raises(us.SandboxUnitError) as exc:
        g.add_dropin("20-b.conf", "PrivateTmp=no\n")
    assert exc.value.code == "SANDBOX_LIMIT_EXCEEDED"
    assert g.stats()["dropins"] == 1


def test_directive_capacity_rejects_whole_file():
    g = merger(max_directives=3)
    text = "ProtectSystem=yes\nPrivateTmp=yes\nProtectHome=no\nNoNewPrivileges=yes\n"
    with pytest.raises(us.SandboxUnitError) as exc:
        g.load_unit(text)
    assert exc.value.code == "SANDBOX_LIMIT_EXCEEDED"
    assert g.stats()["parses"] == 0
    assert g.merge().directives == ()

    ok = merger(max_directives=3)
    assert ok.load_unit("ProtectSystem=yes\nPrivateTmp=yes\nProtectHome=no\n") == 3


def test_list_directives_accumulate_in_first_seen_order():
    g = merger()
    g.load_unit("ReadWritePaths=/var/lib/app\n")
    g.add_dropin("10-a.conf", "ReadWritePaths=/var/log/app /var/lib/app\n")
    g.add_dropin("20-b.conf", "ReadWritePaths=/srv/data\n")
    assert g.effective("ReadWritePaths") == "/var/lib/app /var/log/app /srv/data"
    assert raw(g.merge())["ReadWritePaths"].value == "/var/lib/app /var/log/app /srv/data"
    assert g.origins("ReadWritePaths") == ("unit", "10-a.conf", "20-b.conf")


def test_address_families_intersect_instead_of_union():
    g = merger()
    g.load_unit("RestrictAddressFamilies=AF_UNIX AF_INET\n")
    g.add_dropin("10-a.conf", "RestrictAddressFamilies=AF_INET AF_INET6\n")
    assert g.effective("RestrictAddressFamilies") == "AF_INET"
    assert raw(g.merge())["RestrictAddressFamilies"].value == "AF_INET"


def test_boolean_directives_take_last_assignment_and_reject_garbage():
    g = merger()
    g.load_unit("PrivateTmp=yes\nProtectHome=true\n")
    g.add_dropin("10-a.conf", "PrivateTmp=no\n")
    assert g.effective("PrivateTmp") == "no"
    assert g.effective("ProtectHome") == "true"
    assert g.stats()["dropins"] == 1

    with pytest.raises(us.SandboxUnitError) as exc:
        g.add_dropin("20-b.conf", "ProtectHome=maybe\n")
    assert exc.value.code == "SANDBOX_INVALID_VALUE"
    assert exc.value.detail == "ProtectHome=maybe"
    assert g.stats()["dropins"] == 1


def test_unknown_directive_is_kept_with_warning():
    g = merger()
    g.load_unit("ProtectSystem=yes\nMadeUpKnob=1\n")
    result = g.merge()
    rows = raw(result)
    assert rows["MadeUpKnob"].value == "1"
    assert rows["MadeUpKnob"].origin == "unit"
    assert result.warnings == ("unknown directive: MadeUpKnob",)
    assert g.effective("MadeUpKnob") == "1"


def test_conflicts_flag_names_set_by_several_origins():
    g = merger()
    g.load_unit("ProtectSystem=yes\nPrivateTmp=yes\n")
    g.add_dropin("10-a.conf", "ProtectSystem=strict\n")
    assert g.conflicts() == ("ProtectSystem",)
    result = g.merge()
    assert result.conflicts == ("ProtectSystem",)
    rows = raw(result)
    assert rows["ProtectSystem"].conflict is True
    assert rows["PrivateTmp"].conflict is False


def test_resolve_paths_normalises_and_sorts():
    g = merger()
    g.load_unit("ReadWritePaths=/var/log/app/ /var/lib/app\n")
    assert g.resolve_paths("ReadWritePaths") == (
        ("/var/lib/app", False), ("/var/log/app", False))
    assert g.resolve_paths("ReadOnlyPaths") == ()

    with pytest.raises(us.SandboxUnitError) as exc:
        g.resolve_paths("ProtectSystem")
    assert exc.value.code == "SANDBOX_NOT_PATH_DIRECTIVE"
    with pytest.raises(us.SandboxUnitError) as exc:
        g.resolve_paths("NoSuchKnob")
    assert exc.value.code == "SANDBOX_UNKNOWN_DIRECTIVE"


def test_validate_rejects_paths_outside_protected_tree():
    g = merger()
    g.load_unit("ProtectSystem=strict\nReadWritePaths=/var/lib/app\n")
    assert g.validate() == ()

    g.add_dropin("10-a.conf", "ReadWritePaths=/srv/data\n")
    with pytest.raises(us.SandboxUnitError) as exc:
        g.validate()
    assert exc.value.code == "SANDBOX_PATH_ESCAPE"
    assert exc.value.detail == "/srv/data"

    inside = merger()
    inside.load_unit("ProtectSystem=strict\nReadWritePaths=/etc/app\n")
    assert inside.validate() == ()


def test_concurrent_merge_returns_identical_results():
    g = merger()
    g.load_unit("ProtectSystem=strict\nReadWritePaths=/var/lib/app\n")
    g.add_dropin("10-a.conf", "PrivateTmp=yes\n")
    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(g.merge())
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert all(result == results[0] for result in results)
    assert [row.name for row in results[0].directives] == [
        "PrivateTmp", "ProtectSystem", "ReadWritePaths"]


def test_snapshot_is_detached_and_restore_roundtrips():
    g = merger()
    g.load_unit("ProtectSystem=yes\n")
    g.add_dropin("10-a.conf", "PrivateTmp=yes\n")
    state = g.snapshot()
    assert set(state) == {"version", "unit", "dropins", "counters"}
    pristine = copy.deepcopy(state)

    state["dropins"].clear()
    state["unit"]["lines"].clear()
    assert g.effective("PrivateTmp") == "yes"
    assert g.effective("ProtectSystem") == "yes"

    clone = merger()
    clone.restore(pristine)
    assert clone.effective("PrivateTmp") == "yes"
    assert clone.merge() == g.merge()

    for bad in (None, {},
                {"version": 1, "unit": {}, "dropins": [], "counters": {}},
                {"version": 1, "unit": {"name": "unit", "lines": []},
                 "dropins": {}}):
        with pytest.raises(us.SandboxUnitError) as exc:
            g.restore(bad)
        assert exc.value.code == "SANDBOX_SNAPSHOT_INVALID"
    assert g.effective("PrivateTmp") == "yes"
