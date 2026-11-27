import copy
import threading

import pytest

import loader_path_guard as lpg

HINT = lpg.BinaryHint(path="/opt/app/bin/runner", needed=("libx.so",))


def guard(**kwargs):
    return lpg.LoaderPathGuard(**kwargs)


def test_load_config_normalises_dirs_and_bumps_version():
    inst = guard()
    assert inst.current_version() == 0
    assert inst.config_dirs() == ()
    version = inst.load_config([" /usr/lib/ ", "/opt/app/lib/"],
                               source="/etc/ld.so.conf")
    assert version == 1
    assert inst.current_version() == 1
    assert inst.config_dirs() == ("/usr/lib", "/opt/app/lib")
    assert inst.load_config(["/srv/lib"]) == 2


def test_load_config_rejects_bad_table_and_keeps_old_dirs():
    inst = guard()
    inst.load_config(["/usr/lib"])
    for bad in (["usr/local/lib"], [], [""], [5]):
        with pytest.raises(lpg.LoaderPathError) as exc:
            inst.load_config(bad)
        assert exc.value.code == "LDG_CONFIG_INVALID"
    assert inst.current_version() == 1
    assert inst.config_dirs() == ("/usr/lib",)
    assert inst.stats()["failed_loads"] == 4
    assert inst.stats()["config_loads"] == 1


def test_resolve_places_env_before_config_without_binary_hints():
    inst = guard()
    inst.load_config(["/usr/lib", "/opt/app/lib"])
    resolved = inst.resolve_search_path(HINT, env=["/opt/env", "/srv/lib"])
    assert resolved == ("/opt/env", "/srv/lib", "/usr/lib", "/opt/app/lib")


def test_relative_env_entry_is_rejected_while_others_survive():
    inst = guard()
    inst.load_config(["/usr/lib"])
    decision = inst.check_binary(HINT, env=["lib", "/opt/env"])
    assert decision.allowed is False
    assert decision.version == 1
    assert decision.path == ("/opt/env", "/usr/lib")
    assert [(r.path, r.code) for r in decision.rejections] == [
        ("lib", "RELATIVE_PATH")]


def test_world_writable_directory_is_rejected():
    inst = guard()
    inst.load_config(["/usr/lib", "/opt/shared"])
    assert inst.is_world_writable("/opt/shared") is False
    inst.mark_world_writable("/opt/shared")
    assert inst.is_world_writable("/opt/shared") is True
    assert inst.is_world_writable("/usr/lib") is False
    decision = inst.check_binary(HINT)
    assert decision.allowed is False
    assert decision.path == ("/usr/lib",)
    assert [(r.path, r.code) for r in decision.rejections] == [
        ("/opt/shared", "WORLD_WRITABLE")]


def test_origin_pattern_expands_against_binary_directory():
    inst = guard()
    assert inst.expand_origin("$ORIGIN/../lib",
                              binary_path="/opt/app/bin/runner") == "/opt/app/lib"
    assert inst.expand_origin("${ORIGIN}/plugins",
                              binary_path="/opt/app/bin/runner") == "/opt/app/bin/plugins"


def test_decision_allows_fully_trusted_search_path():
    inst = guard()
    inst.load_config(["/usr/lib", "/opt/app/lib"])
    decision = inst.check_binary(HINT, env=())
    assert decision.allowed is True
    assert decision.rejections == ()
    assert decision.path == ("/usr/lib", "/opt/app/lib")
    assert decision.version == 1


def test_multiple_rejections_keep_scan_order():
    inst = guard()
    inst.load_config(["/usr/lib", "/opt/world"])
    inst.mark_world_writable("/opt/world")
    decision = inst.check_binary(HINT, env=["deps", "/opt/other"])
    assert [(r.path, r.code) for r in decision.rejections] == [
        ("deps", "RELATIVE_PATH"), ("/opt/world", "WORLD_WRITABLE")]
    assert decision.path == ("/opt/other", "/usr/lib")
    assert decision.allowed is False


def test_second_identical_check_hits_cache_and_version_change_misses():
    inst = guard()
    inst.load_config(["/usr/lib"])
    first = inst.check_binary(HINT, env=("/opt/env",))
    second = inst.check_binary(HINT, env=("/opt/env",))
    assert second.path == first.path == ("/opt/env", "/usr/lib")
    assert inst.stats()["resolutions"] == 1
    assert inst.stats()["cache_hits"] == 1

    inst.load_config(["/usr/lib", "/opt/app/lib"])
    third = inst.check_binary(HINT, env=("/opt/env",))
    assert third.version == 2
    assert third.path == ("/opt/env", "/usr/lib", "/opt/app/lib")
    assert inst.stats()["resolutions"] == 2
    assert inst.stats()["cache_hits"] == 1


def test_invalidate_cache_drops_entries_and_reports_count():
    inst = guard()
    inst.load_config(["/usr/lib"])
    inst.check_binary(HINT)
    inst.check_binary(HINT)
    assert inst.stats()["cache_hits"] == 1
    assert inst.invalidate_cache() == 1
    assert inst.invalidate_cache() == 0
    inst.check_binary(HINT)
    assert inst.stats()["resolutions"] == 2
    assert inst.stats()["cache_hits"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    inst = guard()
    inst.load_config(["/usr/lib", "/opt/app/lib"])
    inst.check_binary(HINT, env=("/opt/env",))
    inst.mark_world_writable("/opt/shared")
    state = inst.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "dirs", "world_writable", "stats"}

    state["dirs"] = []
    state["stats"]["config_loads"] = 99
    assert inst.config_dirs() == ("/usr/lib", "/opt/app/lib")
    assert inst.stats()["config_loads"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.current_version() == 1
    assert clone.config_dirs() == ("/usr/lib", "/opt/app/lib")
    assert clone.is_world_writable("/opt/shared") is True
    assert clone.stats()["resolutions"] == 1
    assert clone.check_binary(HINT, env=()).path == ("/opt/env", "/usr/lib",
                                                     "/opt/app/lib")


def test_restore_rejects_malformed_state_without_touching_live_data():
    inst = guard()
    inst.load_config(["/usr/lib"])
    good_stats = {"config_loads": 1, "failed_loads": 0, "resolutions": 0,
                  "cache_hits": 0, "rejections": 0, "restores": 0}
    bad_states = [
        None,
        {},
        {"version": "1", "dirs": [], "world_writable": [], "stats": good_stats},
        {"version": 1, "dirs": None, "world_writable": [], "stats": good_stats},
        {"version": 1, "dirs": [], "world_writable": [], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(lpg.LoaderPathError) as exc:
            inst.restore(bad)
        assert exc.value.code == "LDG_SNAPSHOT_INVALID"
    assert inst.current_version() == 1
    assert inst.config_dirs() == ("/usr/lib",)


def test_stats_count_every_event_exactly():
    inst = guard()
    inst.load_config(["/usr/lib", "/opt/world"])
    inst.mark_world_writable("/opt/world")
    inst.check_binary(HINT, env=("deps",))
    inst.check_binary(HINT, env=("deps",))
    with pytest.raises(lpg.LoaderPathError):
        inst.load_config(["relative"])
    assert inst.stats() == {"config_loads": 1, "failed_loads": 1,
                            "resolutions": 1, "cache_hits": 1,
                            "rejections": 2, "restores": 0}


def test_explain_splits_contributions_by_source():
    inst = guard()
    inst.load_config(["/usr/lib"])
    hint = lpg.BinaryHint(path="/opt/app/bin/runner",
                          runpath=("$ORIGIN/../lib",), rpath=())
    explained = inst.explain(hint, env=("/opt/env",))
    assert explained["env"] == ("/opt/env",)
    assert explained["runpath"] == ("/opt/app/lib",)
    assert explained["rpath"] == ()
    assert explained["config"] == ("/usr/lib",)


def test_concurrent_reload_and_resolve_never_mix_tables():
    inst = guard()
    inst.load_config(["/opt/a"])
    errors = []
    ready = threading.Event()
    stop = threading.Event()

    def reloader():
        try:
            for name in ["/opt/b", "/opt/a"] * 6:
                inst.load_config([name])
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
                decision = inst.check_binary(HINT)
                seen.append((decision.version, decision.path))
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
    for version, path in seen:
        assert version >= 1
        assert path == (("/opt/a",) if version % 2 == 1 else ("/opt/b",))
    assert inst.current_version() == 13
