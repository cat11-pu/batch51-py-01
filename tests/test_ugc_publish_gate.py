import copy
import threading

import pytest

import ugc_publish_gate as ug

NOW = "2026-11-27T09:00:00+00:00"
LATER = "2026-11-27T09:30:00+00:00"


def gate(**kwargs):
    return ug.UgcPublishGate(**kwargs)


def save(g, content, *, level="lv-1", player="p-1", now=NOW):
    return g.save_draft(level, player, content, now=now)


def publish_level(g, content=None):
    if content is not None:
        save(g, content)
    ticket = g.submit_review("lv-1", "p-1", now=NOW)
    g.review(ticket.ticket_id, "mod-1", approved=True, note="ok", now=LATER)
    return g.publish(ticket.ticket_id, "p-1", now=LATER), ticket


def test_save_draft_creates_versions_and_stable_fingerprint():
    g = gate()
    first = save(g, {"name": "harbor", "tiles": [1, 2, 3]})
    assert (first.level_id, first.player, first.version) == ("lv-1", "p-1", 1)
    assert g.fingerprint_of({"tiles": [1, 2, 3], "name": "harbor"}) == first.fingerprint
    second = save(g, {"tiles": [1, 2, 3], "name": "harbor"}, now=LATER)
    assert second.version == 2
    assert second.fingerprint == first.fingerprint
    status = g.version_of("lv-1")
    assert (status.state, status.draft_version) == ("draft", 2)
    assert (status.online_version, status.review_state) == (0, "none")
    assert status.fingerprint == first.fingerprint


def test_fingerprint_is_sha256_and_changes_with_content():
    g = gate()
    one = g.fingerprint_of({"a": 1})
    two = g.fingerprint_of({"a": 2})
    assert one != two
    assert len(one) == 64
    assert all(char in "0123456789abcdef" for char in one)
    assert g.fingerprint_of({"a": 1, "b": [True, None]}) == g.fingerprint_of(
        {"b": [True, None], "a": 1})


def test_submit_and_review_move_the_ticket_through_states():
    g = gate()
    save(g, {"n": 1})
    ticket = g.submit_review("lv-1", "p-1", now=NOW)
    assert ticket.state == "pending"
    assert ticket.reviewer is None
    assert ticket.version == 1
    assert g.version_of("lv-1").review_state == "pending"

    closed = g.review(ticket.ticket_id, "mod-1", approved=True, note="looks fine",
                      now=LATER)
    assert (closed.state, closed.reviewer, closed.note) == ("approved", "mod-1",
                                                            "looks fine")
    assert g.version_of("lv-1").review_state == "approved"
    with pytest.raises(ug.UgcError) as exc:
        g.review(ticket.ticket_id, "mod-1", approved=True)
    assert exc.value.code == "UGC_TICKET_CLOSED"
    with pytest.raises(ug.UgcError) as exc:
        g.review("t-404", "mod-1", approved=False)
    assert exc.value.code == "UGC_UNKNOWN_TICKET"


def test_rejected_review_keeps_draft_editable_and_allows_resubmit():
    g = gate()
    save(g, {"v": 1})
    first = g.submit_review("lv-1", "p-1")
    g.review(first.ticket_id, "mod-1", approved=False, note="blocked tiles")
    assert g.version_of("lv-1").review_state == "rejected"

    second_draft = save(g, {"v": 2}, now=LATER)
    assert second_draft.version == 2
    second = g.submit_review("lv-1", "p-1", now=LATER)
    assert second.ticket_id != first.ticket_id
    assert second.state == "pending"
    assert second.fingerprint == second_draft.fingerprint


def test_publish_requires_an_approved_ticket():
    g = gate()
    save(g, {"v": 1})
    ticket = g.submit_review("lv-1", "p-1")
    with pytest.raises(ug.UgcError) as exc:
        g.publish(ticket.ticket_id, "p-1")
    assert exc.value.code == "UGC_NOT_APPROVED"
    with pytest.raises(ug.UgcError) as exc:
        g.publish("t-404", "p-1")
    assert exc.value.code == "UGC_UNKNOWN_TICKET"

    g.review(ticket.ticket_id, "mod-1", approved=True)
    published = g.publish(ticket.ticket_id, "p-1", now=LATER)
    assert published.version == 1
    assert published.fingerprint == ticket.fingerprint
    assert published.reviewer == "mod-1"
    status = g.version_of("lv-1")
    assert (status.state, status.review_state) == ("published", "none")


def test_publish_freezes_online_copy_and_later_drafts_do_not_touch_it():
    g = gate()
    published, _ticket = publish_level(g, {"v": 1})
    assert published.version == 1
    assert g.content_of("lv-1") == {"v": 1}

    fresh = save(g, {"v": 2}, now=LATER)
    assert fresh.version == 2
    status = g.version_of("lv-1")
    assert (status.state, status.draft_version, status.online_version) == (
        "published", 2, 1)
    assert status.fingerprint == fresh.fingerprint
    assert g.content_of("lv-1") == {"v": 1}


def test_takedown_hides_the_online_copy_and_is_not_repeatable():
    g = gate()
    publish_level(g, {"v": 1})
    assert g.takedown("lv-1", "gm-1", reason="player report", now=LATER) is True
    status = g.version_of("lv-1")
    assert status.state == "taken_down"
    with pytest.raises(ug.UgcError) as exc:
        g.content_of("lv-1")
    assert exc.value.code == "UGC_NOT_PUBLISHED"
    with pytest.raises(ug.UgcError) as exc:
        g.takedown("lv-1", "gm-1")
    assert exc.value.code == "UGC_NOT_PUBLISHED"
    assert [row["kind"] for row in g.audit_of("lv-1")] == [
        "save", "submit", "review", "publish", "takedown"]


def test_pending_ticket_blocks_a_different_draft_submission():
    g = gate()
    save(g, {"v": 1})
    first = g.submit_review("lv-1", "p-1")
    save(g, {"v": 2}, now=LATER)
    with pytest.raises(ug.UgcError) as exc:
        g.submit_review("lv-1", "p-1", now=LATER)
    assert exc.value.code == "UGC_REVIEW_PENDING"
    assert exc.value.detail == first.ticket_id
    assert g.version_of("lv-1").review_state == "pending"


def test_unknown_level_and_invalid_requests_are_refused():
    g = gate()
    for call in (
        lambda: g.version_of("ghost"),
        lambda: g.submit_review("ghost", "p-1"),
        lambda: g.content_of("ghost"),
    ):
        with pytest.raises(ug.UgcError) as exc:
            call()
        assert exc.value.code == "UGC_UNKNOWN_LEVEL"

    with pytest.raises(ug.UgcError) as exc:
        save(g, {"a": 1}, level="")
    assert exc.value.code == "UGC_INVALID_REQUEST"
    with pytest.raises(ug.UgcError) as exc:
        save(g, {"a": 1}, player="  ")
    assert exc.value.code == "UGC_INVALID_REQUEST"
    with pytest.raises(ug.UgcError) as exc:
        save(g, None)
    assert exc.value.code == "UGC_INVALID_REQUEST"
    assert g.stats()["drafts"] == 0


def test_audit_is_bounded_and_keeps_the_newest_transitions():
    g = gate(max_audit=3)
    save(g, {"v": 1})
    save(g, {"v": 2}, now=LATER)
    ticket = g.submit_review("lv-1", "p-1", now=LATER)
    g.review(ticket.ticket_id, "mod-1", approved=True, now=LATER)
    g.publish(ticket.ticket_id, "p-1", now=LATER)
    rows = g.audit_of("lv-1")
    assert [row["kind"] for row in rows] == ["submit", "review", "publish"]
    assert [row["seq"] for row in rows] == [3, 4, 5]
    assert [row["version"] for row in rows] == [2, 2, 2]
    assert g.audit_of("ghost") == []


def test_concurrent_saves_serialize_and_keep_every_revision():
    g = gate()
    errors = []
    barrier = threading.Barrier(6)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            save(g, {"tiles": [index] * 4}, now=NOW)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    status = g.version_of("lv-1")
    assert status.draft_version == 6
    assert len(g.audit_of("lv-1")) == 6
    assert [row["version"] for row in g.audit_of("lv-1")] == [1, 2, 3, 4, 5, 6]


def test_level_capacity_caps_new_levels_but_not_edits():
    g = gate(max_levels=2)
    save(g, {"v": 1}, level="lv-1")
    save(g, {"v": 1}, level="lv-2")
    with pytest.raises(ug.UgcError) as exc:
        save(g, {"v": 1}, level="lv-3")
    assert exc.value.code == "UGC_CAPACITY_EXCEEDED"
    assert save(g, {"v": 2}, level="lv-1").version == 2
    assert g.stats()["levels"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    g = gate()
    publish_level(g, {"v": 1})
    state = g.snapshot()
    assert set(state) == {"version", "levels", "tickets", "audit", "counters",
                          "stats"}
    pristine = copy.deepcopy(state)

    state["levels"].clear()
    state["stats"]["published"] = 99
    assert g.stats()["published"] == 1
    assert g.content_of("lv-1") == {"v": 1}

    clone = gate()
    clone.restore(pristine)
    assert clone.stats() == g.stats()
    assert clone.content_of("lv-1") == {"v": 1}
    assert clone.version_of("lv-1") == g.version_of("lv-1")
    assert len(clone.audit_of("lv-1")) == len(g.audit_of("lv-1"))


def test_restore_rejects_malformed_state_and_keeps_live_data():
    g = gate()
    publish_level(g, {"v": 1})
    bad_states = [
        None,
        {},
        {"version": 1, "levels": [], "tickets": [], "audit": [],
         "counters": {}},
        {"version": "1", "levels": [], "tickets": [], "audit": [],
         "counters": {}, "stats": {}},
        {"version": 1, "levels": {}, "tickets": [], "audit": [],
         "counters": {}, "stats": {}},
        {"version": 1, "levels": [], "tickets": {}, "audit": [],
         "counters": {}, "stats": {}},
        {"version": 1, "levels": [], "tickets": [], "audit": [],
         "counters": [], "stats": {}},
        {"version": 1, "levels": [], "tickets": [], "audit": [],
         "counters": {}, "stats": {"published": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ug.UgcError) as exc:
            g.restore(bad)
        assert exc.value.code == "UGC_SNAPSHOT_INVALID"
    assert g.stats()["published"] == 1
    assert g.content_of("lv-1") == {"v": 1}


def test_stats_count_each_transition_once():
    g = gate()
    save(g, {"v": 1})
    save(g, {"v": 2}, now=LATER)
    ticket = g.submit_review("lv-1", "p-1", now=LATER)
    g.review(ticket.ticket_id, "mod-1", approved=True, now=LATER)
    g.publish(ticket.ticket_id, "p-1", now=LATER)
    g.takedown("lv-1", "gm-1", now=LATER)
    assert g.stats() == {"levels": 1, "drafts": 2, "submitted": 1, "approved": 1,
                         "rejected": 0, "published": 1, "taken_down": 1,
                         "pending": 0}
