"""Reproducible local checks for DNS TCP pipeline ordering and recovery."""

from __future__ import annotations

import json
import threading

import dns_tcp_pipeline_guard as pg

NOW = 1000


def wire(qid: int, qname: str, qtype: int = 1) -> bytes:
    question = b"".join(
        bytes([len(part)]) + part.encode("ascii")
        for part in qname.split(".")
    )
    question += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    header = qid.to_bytes(2, "big") + b"\x81\x80\x00\x01" + b"\x00\x00" * 3
    body = header + question
    return len(body).to_bytes(2, "big") + body


def compressed_wire(qid: int, qname: str, qtype: int = 1) -> bytes:
    pointer_target = 20
    labels = b"".join(
        bytes([len(part)]) + part.encode("ascii")
        for part in qname.split(".")
    ) + b"\x00"
    header = qid.to_bytes(2, "big") + b"\x81\x80\x00\x01" + b"\x00\x00" * 3
    question = (
        b"\xc0"
        + bytes([pointer_target])
        + qtype.to_bytes(2, "big")
        + b"\x00\x01"
    )
    body = header + question + b"\x00\x00" + labels
    assert len(header) + len(question) + 2 == pointer_target
    return len(body).to_bytes(2, "big") + body


def attached(**kwargs) -> pg.DnsTcpPipelineGuard:
    guard = pg.DnsTcpPipelineGuard(**kwargs)
    guard.attach_connection("c1", NOW)
    return guard


def error_code(callable_obj, *args) -> str:
    try:
        callable_obj(*args)
    except pg.PipelineError as exc:
        return exc.code
    raise AssertionError("expected PipelineError")


def check_out_of_order() -> None:
    guard = attached()
    guard.submit_query("c1", 1, "a.example", 1, NOW)
    guard.submit_query("c1", 2, "b.example", 1, NOW)
    deliveries = guard.feed(
        "c1",
        wire(2, "b.example") + wire(1, "a.example"),
        NOW + 1,
    )
    assert [(item.qid, item.qname, item.status) for item in deliveries] == [
        (2, "b.example", "delivered"),
        (1, "a.example", "delivered"),
    ]
    print("out_of_order: ok", [(item.qid, item.qname) for item in deliveries])


def check_case_and_compression() -> None:
    guard = attached()
    guard.submit_query("c1", 3, "MiXeD.Example", 1, NOW)
    delivery = guard.accept_response(
        "c1", wire(3, "mIxEd.eXaMpLe"), NOW + 1
    )
    assert delivery.status == "delivered"
    assert delivery.qname == "MiXeD.Example"

    guard.submit_query("c1", 4, "compressed.example", 1, NOW)
    compressed = guard.accept_response(
        "c1", compressed_wire(4, "COMPRESSED.example"), NOW + 1
    )
    assert compressed.status == "delivered"
    print("case_insensitive: ok", delivery)
    print("compression_pointer: ok", compressed)


def check_timeout_id_reuse() -> None:
    guard = attached(query_timeout=5)
    guard.submit_query("c1", 7, "old.example", 1, NOW)
    timeouts = guard.expire_queries(NOW + 5)
    assert [(item.qid, item.status) for item in timeouts] == [
        (7, "servfail")
    ]
    guard.submit_query("c1", 7, "new.example", 1, NOW + 6)
    late = guard.accept_response("c1", wire(7, "old.example"), NOW + 7)
    assert late.status == "unmatched"
    assert len(guard.in_flight("c1")) == 1
    current = guard.accept_response("c1", wire(7, "new.example"), NOW + 8)
    assert current.status == "delivered"
    print("timeout_id_reuse: ok", late.status, current.status)


def check_half_close() -> None:
    guard = attached()
    guard.submit_query("c1", 10, "first.example", 1, NOW)
    guard.submit_query("c1", 11, "second.example", 1, NOW)
    first = wire(10, "first.example")
    second = wire(11, "second.example")
    deliveries = guard.feed("c1", first + second[:3], NOW + 1)
    assert [(item.qid, item.status) for item in deliveries] == [
        (10, "delivered")
    ]
    assert guard.framing_stats("c1")["pending_bytes"] == 3
    assert guard.half_close("c1", NOW + 2) == ()
    assert guard.framing_stats("c1")["pending_bytes"] == 3
    assert guard.stats()["unmatched"] == 0
    servfails = guard.close_connection("c1", NOW + 3)
    assert [(item.qid, item.status) for item in servfails] == [
        (11, "servfail")
    ]
    print("half_close_partial: ok pending=3, no bogus delivery")


def check_snapshot_restore() -> None:
    guard = attached(query_timeout=9, max_frame=512)
    guard.submit_query("c1", 12, "snap.example", 1, NOW)
    message = wire(12, "snap.example")
    assert guard.feed("c1", message[:7], NOW + 1) == ()
    encoded = json.dumps(guard.snapshot())

    clone = pg.DnsTcpPipelineGuard()
    clone.restore(json.loads(encoded))
    assert clone.framing_stats("c1")["pending_bytes"] == 7
    assert len(clone.in_flight("c1")) == 1
    assert error_code(
        clone.submit_query,
        "c1",
        12,
        "other.example",
        1,
        NOW + 2,
    ) == "PIPELINE_ID_IN_USE"

    deliveries = clone.feed("c1", message[7:], NOW + 2)
    assert deliveries[0].status == "delivered"
    before = clone.snapshot()
    assert error_code(clone.restore, {"version": 2}) == (
        "PIPELINE_SNAPSHOT_INVALID"
    )
    assert clone.snapshot() == before
    print("snapshot_restore: ok", deliveries[0], clone.stats())


def check_concurrent_duplicate() -> None:
    guard = attached()
    guard.submit_query("c1", 13, "race.example", 1, NOW)
    message = wire(13, "race.example")
    barrier = threading.Barrier(3)
    results: list[str] = []
    errors: list[str] = []

    def worker() -> None:
        try:
            barrier.wait()
            results.append(
                guard.accept_response("c1", message, NOW + 1).status
            )
        except BaseException as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    assert not errors
    assert sorted(results) == ["delivered", "duplicate"]
    assert guard.stats()["delivered"] == 1
    assert guard.stats()["duplicates"] == 1
    print("concurrent_duplicate: ok", sorted(results))


def check_concurrent_feed_close() -> None:
    for _ in range(100):
        guard = attached()
        guard.submit_query("c1", 14, "close-race.example", 1, NOW)
        message = wire(14, "close-race.example")
        barrier = threading.Barrier(3)
        deliveries: list[pg.Delivery] = []
        errors: list[str] = []

        def feeder() -> None:
            try:
                barrier.wait()
                deliveries.extend(guard.feed("c1", message, NOW + 1))
            except pg.PipelineError as exc:
                errors.append(exc.code)

        def closer() -> None:
            try:
                barrier.wait()
                deliveries.extend(guard.close_connection("c1", NOW + 1))
            except pg.PipelineError as exc:
                errors.append(exc.code)

        threads = [
            threading.Thread(target=feeder),
            threading.Thread(target=closer),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        statuses = sorted(item.status for item in deliveries)
        assert statuses in (["delivered"], ["servfail"])
        assert errors in ([], ["PIPELINE_CONNECTION_CLOSED"])
    print("concurrent_feed_close: ok (100 iterations)")


def main() -> None:
    check_out_of_order()
    check_case_and_compression()
    check_timeout_id_reuse()
    check_half_close()
    check_snapshot_restore()
    check_concurrent_duplicate()
    check_concurrent_feed_close()
    print("all_extended_scenarios: ok")


if __name__ == "__main__":
    main()
