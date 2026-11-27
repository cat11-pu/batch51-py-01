import copy
import threading

import pytest

import match_highlight_selector as mh


def selector(**kwargs):
    return mh.HighlightSelector(**kwargs)


def open_match(g, match_id="m-1", *, end_at=120.0):
    return g.open_match(match_id, end_at=end_at)


def event(g, event_id, at, *, kind="multi_kill", player="p-1", priority=0,
          duration=1.0, match_id="m-1"):
    return g.ingest(match_id, event_id, kind=kind, player=player, at=at,
                    priority=priority, duration=duration)


def test_open_match_registers_timeline_and_refuses_duplicates():
    g = selector()
    info = open_match(g, "m-1", end_at=60.0)
    assert (info.match_id, info.end_at, info.merge_gap) == ("m-1", 60.0, 2.5)
    with pytest.raises(mh.HighlightError) as exc:
        open_match(g, "m-1")
    assert exc.value.code == "HL_MATCH_EXISTS"
    with pytest.raises(mh.HighlightError) as exc:
        g.open_match("  ", end_at=60.0)
    assert exc.value.code == "HL_INVALID_REQUEST"
    assert g.stats()["matches"] == 1


def test_ingest_deduplicates_by_event_id():
    g = selector()
    open_match(g)
    assert event(g, "e1", 1.0) is True
    assert event(g, "e1", 1.0) is False
    assert g.stats()["events"] == 1
    assert g.stats()["duplicates"] == 1


def test_ingest_validates_match_kind_player_and_timing():
    g = selector()
    open_match(g, end_at=60.0)
    with pytest.raises(mh.HighlightError) as exc:
        event(g, "e1", 1.0, match_id="m-404")
    assert exc.value.code == "HL_UNKNOWN_MATCH"
    for kwargs in (
        dict(kind="quad_kill"),
        dict(player="  "),
        dict(at=-0.5),
        dict(at=60.0),
        dict(duration=0.0),
        dict(priority=101),
    ):
        with pytest.raises(mh.HighlightError) as exc:
            event(g, "e-bad", **kwargs)
        assert exc.value.code == "HL_INVALID_EVENT"
    with pytest.raises(mh.HighlightError) as exc:
        event(g, "", 1.0)
    assert exc.value.code == "HL_INVALID_EVENT"
    assert g.stats()["events"] == 0


def test_merge_window_combines_overlapping_events():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e1", 1.0, duration=2.0, player="p-1")
    event(g, "e2", 2.0, duration=1.0, player="p-2")
    event(g, "e3", 2.5, duration=1.0, player="p-1")
    clips = g.merge_window("m-1")
    assert len(clips) == 1
    clip = clips[0]
    assert clip.clip_id == "c0"
    assert (clip.start, clip.end) == (1.0, 3.5)
    assert clip.events == ("e1", "e2", "e3")
    assert clip.players == ("p-1", "p-2")
    assert clip.match_id == "m-1"


def test_merge_window_splits_events_further_apart_than_the_gap():
    g = selector()
    open_match(g, end_at=120.0)
    event(g, "e1", 1.0)
    event(g, "e2", 30.0)
    clips = g.merge_window("m-1")
    assert [clip.clip_id for clip in clips] == ["c0", "c1"]
    assert [clip.start for clip in clips] == [1.0, 30.0]
    assert [clip.events for clip in clips] == [("e1",), ("e2",)]


def test_merge_window_is_deterministic_across_repeated_calls():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e1", 1.0)
    event(g, "e2", 2.0)
    event(g, "e3", 40.0)
    first = g.merge_window("m-1")
    second = g.merge_window("m-1")
    assert first == second
    assert [clip.clip_id for clip in first] == ["c0", "c1"]


def test_clip_aggregates_top_priority_and_sorted_participants():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e1", 1.0, player="p-b", priority=10, duration=2.0)
    event(g, "e2", 1.5, player="p-a", priority=7, duration=1.0,
          kind="low_hp_clash")
    clip = g.merge_window("m-1")[0]
    assert clip.priority == 10
    assert clip.players == ("p-a", "p-b")
    assert clip.events == ("e1", "e2")


def test_select_orders_by_priority_then_start_time():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e-a", 1.0, player="p-a", priority=5)
    event(g, "e-b", 10.0, player="p-b", priority=9)
    event(g, "e-c", 20.0, player="p-c", priority=5)
    picked = g.select("m-1", limit=3)
    assert [(clip.priority, clip.start) for clip in picked] == [
        (9, 10.0), (5, 1.0), (5, 20.0)]
    assert [clip.clip_id for clip in picked] == ["c1", "c0", "c2"]


def test_select_validates_the_limit_and_supports_zero():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e-a", 1.0, player="p-a", priority=5)
    event(g, "e-b", 10.0, player="p-b", priority=9)
    assert g.select("m-1", limit=0) == ()
    with pytest.raises(mh.HighlightError) as exc:
        g.select("m-1", limit=-1)
    assert exc.value.code == "HL_INVALID_REQUEST"
    assert len(g.select("m-1", limit=2)) == 2


def test_export_and_clips_of_expose_the_same_ordered_clips():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e-b", 10.0, player="p-b", priority=9)
    event(g, "e-a", 1.0, player="p-a", priority=5)
    clips = g.merge_window("m-1")
    assert g.clips_of("m-1") == clips
    exported = g.export("m-1")
    assert set(exported) == {"match_id", "count", "clips"}
    assert exported["count"] == 2
    assert [row["clip_id"] for row in exported["clips"]] == ["c0", "c1"]
    assert [row["start"] for row in exported["clips"]] == [1.0, 10.0]
    assert set(exported["clips"][0]) == {"clip_id", "start", "end", "priority",
                                         "players", "events"}
    with pytest.raises(mh.HighlightError) as exc:
        g.export("m-404")
    assert exc.value.code == "HL_UNKNOWN_MATCH"
    with pytest.raises(mh.HighlightError) as exc:
        g.clips_of("m-404")
    assert exc.value.code == "HL_UNKNOWN_MATCH"


def test_quota_of_counts_stored_clips_per_player():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e1", 1.0, player="p-1")
    event(g, "e2", 20.0, player="p-1")
    g.merge_window("m-1")
    assert g.quota_of("p-1") == 2
    assert g.quota_of("p-2") == 0
    assert g.quota_of("ghost") == 0


def test_quota_of_sums_across_matches():
    g = selector()
    open_match(g, "m-1", end_at=60.0)
    open_match(g, "m-2", end_at=60.0)
    event(g, "e1", 1.0, player="p-1", match_id="m-1")
    event(g, "e2", 1.0, player="p-1", match_id="m-2")
    g.merge_window("m-1")
    g.merge_window("m-2")
    assert g.quota_of("p-1") == 2


def test_concurrent_ingest_keeps_every_event():
    g = selector()
    open_match(g, end_at=30.0)
    errors = []
    barrier = threading.Barrier(20)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            event(g, f"e-{index:02d}", index * 0.1, player=f"p-{index:02d}",
                  duration=0.05)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.stats()["events"] == 20
    assert g.stats()["duplicates"] == 0
    clips = g.merge_window("m-1")
    assert len(clips) == 1
    assert len(clips[0].events) == 20
    assert len(clips[0].players) == 20


def test_snapshot_is_detached_and_restore_roundtrips():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e1", 1.0, player="p-1", priority=4)
    event(g, "e2", 20.0, player="p-1", priority=6)
    g.merge_window("m-1")
    state = g.snapshot()
    assert set(state) == {"version", "matches", "events", "clips", "counters",
                          "stats"}
    pristine = copy.deepcopy(state)

    state["clips"].clear()
    state["stats"]["events"] = 99
    assert len(g.clips_of("m-1")) == 2
    assert g.stats()["events"] == 2

    clone = selector()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.clips_of("m-1") == g.clips_of("m-1")
    assert clone.quota_of("p-1") == 2
    assert event(clone, "e1", 1.0, player="p-1") is False


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = selector()
    open_match(g, end_at=60.0)
    event(g, "e1", 1.0, player="p-1", priority=4)
    g.merge_window("m-1")
    bad_states = [
        None,
        {},
        {"version": 1, "matches": [], "events": {}, "clips": {},
         "counters": {}},
        {"version": "1", "matches": [], "events": {}, "clips": {},
         "counters": {}, "stats": {}},
        {"version": 1, "matches": {}, "events": {}, "clips": {},
         "counters": {}, "stats": {}},
        {"version": 1, "matches": [], "events": [], "clips": {},
         "counters": {}, "stats": {}},
        {"version": 1, "matches": [], "events": {}, "clips": [],
         "counters": {}, "stats": {}},
        {"version": 1, "matches": [], "events": {}, "clips": {},
         "counters": {}, "stats": {"events": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(mh.HighlightError) as exc:
            g.restore(bad)
        assert exc.value.code == "HL_SNAPSHOT_INVALID"
    assert len(g.clips_of("m-1")) == 1
    assert g.stats()["events"] == 1
