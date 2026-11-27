import copy

import pytest

import dns_tcp_pipeline_guard as pg

NOW = 1000


def guard(**kwargs):
    return pg.DnsTcpPipelineGuard(**kwargs)


def wire(qid, qname, qtype=1):
    """Build one length-prefixed DNS response carrying the given question."""
    question = b""
    for label in qname.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    header = qid.to_bytes(2, "big") + b"\x81\x80\x00\x01" + b"\x00\x00" * 3
    body = header + question
    return len(body).to_bytes(2, "big") + body


def connected(**kwargs):
    g = guard(**kwargs)
    g.attach_connection("c1", NOW)
    return g


def error_code(callable_obj, *args, **kwargs):
    with pytest.raises(pg.PipelineError) as exc:
        callable_obj(*args, **kwargs)
    return exc.value.code


def test_attach_reports_empty_open_connection():
    g = guard()
    view = g.attach_connection("c1", NOW)
    assert view == pg.ConnectionView("c1", True, 0, 0)
    assert g.connections() == ("c1",)
    assert error_code(g.attach_connection, "c1", NOW) == "PIPELINE_CONNECTION_EXISTS"
    assert error_code(g.attach_connection, "", NOW) == "PIPELINE_INVALID_CONNECTION"


def test_connection_limit_is_enforced():
    g = guard(max_connections=1)
    g.attach_connection("c1", NOW)
    assert error_code(g.attach_connection, "c2", NOW) == "PIPELINE_CONNECTION_LIMIT"
    assert g.connections() == ("c1",)


def test_submit_records_query_and_deadline():
    g = connected(query_timeout=10)
    view = g.submit_query("c1", 7, "example.com", 1, NOW)
    assert (view.conn_id, view.qid, view.qname, view.qtype) == ("c1", 7, "example.com", 1)
    assert view.deadline == NOW + 10
    assert isinstance(view.ticket, str)
    pending = g.in_flight("c1")
    assert len(pending) == 1
    assert pending[0].ticket == view.ticket
    assert g.stats()["queries"] == 1


def test_same_id_is_refused_until_previous_query_finishes():
    g = connected()
    g.submit_query("c1", 7, "example.com", 1, NOW)
    assert error_code(g.submit_query, "c1", 7, "example.com", 1, NOW) == "PIPELINE_ID_IN_USE"
    g.accept_response("c1", wire(7, "example.com"), NOW)
    again = g.submit_query("c1", 7, "example.com", 1, NOW)
    assert again.qid == 7
    assert len(g.in_flight("c1")) == 1


def test_in_flight_limit_is_enforced():
    g = connected(max_in_flight=2)
    g.submit_query("c1", 1, "a.example", 1, NOW)
    g.submit_query("c1", 2, "b.example", 1, NOW)
    assert error_code(g.submit_query, "c1", 3, "c.example", 1, NOW) == "PIPELINE_IN_FLIGHT_LIMIT"
    assert len(g.in_flight("c1")) == 2


def test_invalid_query_parameters_are_rejected():
    g = connected()
    bad = [
        (-1, "a.example", 1),
        (70000, "a.example", 1),
        (1, "", 1),
        (1, "x" * 300, 1),
        (1, "a.example", 0),
        (1, "a.example", 999),
    ]
    for qid, qname, qtype in bad:
        assert error_code(g.submit_query, "c1", qid, qname, qtype, NOW) == "PIPELINE_INVALID_QUERY"
    assert g.stats()["queries"] == 0
    assert g.in_flight("c1") == ()


def test_complete_response_is_delivered_and_frees_slot():
    g = connected()
    g.submit_query("c1", 7, "example.com", 1, NOW)
    delivery = g.accept_response("c1", wire(7, "example.com"), NOW + 1)
    assert delivery == pg.Delivery("c1", 7, "example.com", 1, "delivered")
    assert g.in_flight("c1") == ()
    assert g.framing_stats("c1")["complete_frames"] == 1
    assert g.stats()["delivered"] == 1


def test_feed_reassembles_frame_split_across_chunks():
    g = connected()
    g.submit_query("c1", 8, "split.example", 1, NOW)
    message = wire(8, "split.example")
    assert g.feed("c1", message[:5], NOW) == ()
    assert g.framing_stats("c1")["pending_bytes"] == 5
    deliveries = g.feed("c1", message[5:], NOW)
    assert len(deliveries) == 1
    assert deliveries[0].status == "delivered"
    assert g.framing_stats("c1")["pending_bytes"] == 0


def test_short_frame_is_an_error_and_closes_connection():
    g = connected()
    bogus = (100).to_bytes(2, "big") + b"abc"
    assert error_code(g.accept_response, "c1", bogus, NOW) == "PIPELINE_FRAME_ERROR"
    assert g.connection_view("c1").open is False
    assert error_code(g.submit_query, "c1", 1, "a.example", 1, NOW) == "PIPELINE_CONNECTION_CLOSED"
    assert g.stats()["frame_errors"] == 1


def test_empty_frame_is_rejected():
    g = connected()
    assert error_code(g.feed, "c1", b"\x00\x00", NOW) == "PIPELINE_FRAME_ERROR"
    assert g.connection_view("c1").open is False


def test_frame_above_limit_is_rejected():
    g = connected(max_frame=64)
    oversized = (100).to_bytes(2, "big") + b"\x00" * 100
    assert error_code(g.feed, "c1", oversized, NOW) == "PIPELINE_FRAME_TOO_LARGE"
    assert g.connection_view("c1").open is False


def test_duplicate_response_is_delivered_once():
    g = connected()
    g.submit_query("c1", 9, "dup.example", 1, NOW)
    message = wire(9, "dup.example")
    assert g.accept_response("c1", message, NOW).status == "delivered"
    assert g.accept_response("c1", message, NOW).status == "duplicate"
    assert g.stats()["delivered"] == 1
    assert g.stats()["duplicates"] == 1


def test_response_for_unknown_id_is_unmatched():
    g = connected()
    g.submit_query("c1", 5, "keep.example", 1, NOW)
    delivery = g.accept_response("c1", wire(999, "keep.example"), NOW)
    assert delivery.status == "unmatched"
    assert g.stats()["unmatched"] == 1
    assert len(g.in_flight("c1")) == 1


def test_query_timeout_returns_servfail_and_idle_reaps_connections():
    g = guard(idle_timeout=20, query_timeout=5)
    g.attach_connection("c1", NOW)
    g.attach_connection("c2", NOW)
    g.submit_query("c1", 1, "slow.example", 1, NOW)
    g.submit_query("c2", 2, "fast.example", 1, NOW + 10)

    timeouts = g.expire_queries(NOW + 6)
    assert len(timeouts) == 1
    assert (timeouts[0].conn_id, timeouts[0].qid, timeouts[0].status) == ("c1", 1, "servfail")
    assert g.in_flight("c1") == ()
    assert g.stats()["timeouts"] == 1

    assert g.expire_idle(NOW + 21) == ("c1",)
    assert g.connection_view("c2").open is True
    assert g.stats()["idle_closed"] == 1


def test_snapshot_is_detached_and_restore_keeps_partial_frame():
    g = connected()
    g.submit_query("c1", 11, "snap.example", 1, NOW)
    message = wire(11, "snap.example")
    assert g.feed("c1", message[:7], NOW) == ()
    state = g.snapshot()
    pristine = copy.deepcopy(state)

    state["connections"] = {}
    assert g.framing_stats("c1")["pending_bytes"] == 7

    clone = guard()
    clone.restore(pristine)
    assert clone.framing_stats("c1")["pending_bytes"] == 7
    assert len(clone.in_flight("c1")) == 1
    assert clone.feed("c1", message[7:], NOW)[0].status == "delivered"

    assert error_code(clone.restore, {"version": 2}) == "PIPELINE_SNAPSHOT_INVALID"
    assert clone.stats()["delivered"] == 1
