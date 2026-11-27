import copy
import threading
import time

import pytest

import upload_filter_bypass_prober as ubp

TARGET = "https://files.example.com/upload"

EXPECTED_FILENAMES = {
    "double_ext": ("shell.php.jpg", "image/jpeg"),
    "uppercase": ("shell.PHP", "application/x-php"),
    "trailing_dot": ("shell.php.", "application/octet-stream"),
    "trailing_space": ("shell.php ", "application/octet-stream"),
    "unicode": ("shell\uff0ephp", "application/octet-stream"),
    "null_byte": ("shell.php\x00.jpg", "image/jpeg"),
    "htaccess": (".htaccess", "text/plain"),
    "user_ini": (".user.ini", "text/plain"),
    "ct_mismatch": ("shell.jpg", "application/x-php"),
    "polyglot": ("shell.jpg", "image/jpeg"),
}


def recording_transport(record):
    def transport(target, part):
        record.append((target, part))
        return {
            "status": 201,
            "url": target + "/files/abc123",
            "stored_path": "/var/www/uploads/abc123",
            "headers": {"X-Upload-Id": "abc123"},
        }

    return transport


def build(transport=None, **kwargs):
    kwargs.setdefault("transport", transport or recording_transport([]))
    return ubp.UploadBypassProber(**kwargs)


def submission(**overrides):
    base = dict(
        target=TARGET,
        variant_id="uppercase@shell",
        status=200,
        url="https://files.example.com/files/shell.PHP",
        stored_path="/var/www/uploads/shell.PHP",
        headers=(),
    )
    base.update(overrides)
    return ubp.SubmitResult(**base)


def fetch_page(**overrides):
    page = {"status": 200, "headers": {}, "body": "hello"}
    page.update(overrides)
    return page


def test_plan_emits_ten_variants_in_fixed_order():
    prober = build()
    variants = prober.plan("shell")
    order = [
        "double_ext",
        "uppercase",
        "trailing_dot",
        "trailing_space",
        "unicode",
        "null_byte",
        "htaccess",
        "user_ini",
        "ct_mismatch",
        "polyglot",
    ]
    assert [variant.kind for variant in variants] == order
    assert [
        (variant.filename, variant.content_type) for variant in variants
    ] == [EXPECTED_FILENAMES[kind] for kind in order]
    assert len({variant.variant_id for variant in variants}) == 10
    assert prober.stats()["uploads"] == 0


def test_plan_filters_kinds_and_honours_variant_cap():
    prober = build()
    subset = prober.plan("shell", kinds=("polyglot", "uppercase"))
    assert [variant.kind for variant in subset] == ["uppercase", "polyglot"]

    capped = build(max_variants=3).plan("shell")
    assert [variant.kind for variant in capped] == [
        "double_ext", "uppercase", "trailing_dot"
    ]

    with pytest.raises(ubp.UploadError) as exc:
        prober.plan("shell", kinds=("nope",))
    assert exc.value.code == "UPLOAD_INVALID_REQUEST"


def test_plan_rejects_path_like_base_names():
    prober = build()
    for base in ("", "   ", "a/b", "../shell", "a\\b"):
        with pytest.raises(ubp.UploadError) as exc:
            prober.plan(base)
        assert exc.value.code == "UPLOAD_INVALID_REQUEST"


def test_build_part_produces_closed_multipart_body():
    prober = build()
    variants = {variant.kind: variant for variant in prober.plan("payload")}
    variant = variants["double_ext"]
    part = prober.build_part(variant)
    assert part.filename == "payload.php.jpg"
    assert part.content_type == "image/jpeg"
    assert part.boundary
    prefix = ("--" + part.boundary).encode()
    closing = ("--" + part.boundary + "--").encode()
    assert part.body.startswith(prefix)
    assert part.body.rstrip().endswith(closing)
    assert b'filename="payload.php.jpg"' in part.body
    assert b"Content-Type: image/jpeg" in part.body
    assert variant.magic in part.body
    assert variants["htaccess"].executable is True
    assert variants["polyglot"].executable is False
    assert prober.build_part(variants["htaccess"]).body.rstrip().endswith(
        ("--" + prober.build_part(variants["htaccess"]).boundary + "--").encode()
    )


def test_submit_records_result_and_normalises_headers():
    calls = []
    prober = build(recording_transport(calls))
    variant = prober.plan("shell")[0]
    result = prober.submit(TARGET, variant)
    assert len(calls) == 1
    assert calls[0][0] == TARGET
    assert result.target == TARGET
    assert result.variant_id == variant.variant_id
    assert result.status == 201
    assert result.url == TARGET + "/files/abc123"
    assert result.stored_path == "/var/www/uploads/abc123"
    assert dict(result.headers)["x-upload-id"] == "abc123"
    assert prober.submissions_for(TARGET) == (result,)
    assert prober.stats()["uploads"] == 1


def test_submit_rejects_unknown_variant_kind():
    prober = build()
    bogus = ubp.Variant(
        variant_id="mystery@shell",
        kind="mystery",
        filename="shell.php",
        content_type="application/x-php",
        magic=b"",
        payload=b"",
        executable=True,
        notes="",
    )
    with pytest.raises(ubp.UploadError) as exc:
        prober.submit(TARGET, bogus)
    assert exc.value.code == "UPLOAD_VARIANT_UNKNOWN"
    assert prober.stats()["uploads"] == 0


def test_submit_enforces_file_size_before_transport():
    calls = []
    prober = build(recording_transport(calls), max_bytes=8)
    variant = prober.plan("shell")[0]
    with pytest.raises(ubp.UploadError) as exc:
        prober.submit(TARGET, variant)
    assert exc.value.code == "UPLOAD_LIMIT_EXCEEDED"
    assert calls == []
    assert prober.stats()["uploads"] == 0


def test_judge_marks_bypass_only_when_execution_marker_is_read_back():
    prober = build()
    item = submission(status=201)
    verdict = prober.judge(
        item, fetch=lambda url: fetch_page(body="prefix UPLOAD_EXEC_MARK suffix")
    )
    assert verdict.status == "bypass"
    assert verdict.reason == "executed"
    assert verdict.evidence["url"] == item.url
    assert prober.stats()["judgements"] == 1
    assert prober.stats()["bypass"] == 1


def test_judge_reports_unreachable_file_as_blocked():
    prober = build()
    verdict = prober.judge(submission(), fetch=lambda url: fetch_page(status=404, body=""))
    assert (verdict.status, verdict.reason) == ("blocked", "not_reachable")


def test_judge_separates_waf_and_policy_rejections():
    prober = build()
    rejected = prober.judge(submission(status=415), fetch=lambda url: fetch_page())
    assert (rejected.status, rejected.reason) == ("blocked", "rejected")

    waf = prober.judge(submission(status=403), fetch=lambda url: fetch_page())
    assert (waf.status, waf.reason) == ("inconclusive", "waf_block")

    broken = prober.judge(submission(status=500), fetch=lambda url: fetch_page())
    assert (broken.status, broken.reason) == ("inconclusive", "server_error")


def test_judge_without_fetch_is_inconclusive():
    prober = build()
    verdict = prober.judge(submission(status=200), fetch=None)
    assert (verdict.status, verdict.reason) == ("inconclusive", "unverified")


def test_concurrent_submits_to_one_target_are_serialised():
    state = {"inflight": 0, "peak": 0}
    guard = threading.Lock()

    def transport(target, part):
        with guard:
            state["inflight"] += 1
            state["peak"] = max(state["peak"], state["inflight"])
        time.sleep(0.01)
        with guard:
            state["inflight"] -= 1
        return {"status": 201, "url": target + "/files/x", "stored_path": "/tmp/x", "headers": {}}

    prober = ubp.UploadBypassProber(transport=transport, max_uploads_per_target=8)
    variants = prober.plan("shell")[:6]
    barrier = threading.Barrier(6)
    errors = []

    def worker(index):
        try:
            barrier.wait(timeout=5)
            prober.submit(TARGET, variants[index])
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert state["peak"] == 1
    assert prober.stats()["uploads"] == 6
    assert len(prober.submissions_for(TARGET)) == 6


def test_uploads_per_target_cap_is_enforced():
    prober = build(max_uploads_per_target=2)
    variants = prober.plan("shell")
    prober.submit(TARGET, variants[0])
    prober.submit(TARGET, variants[1])
    with pytest.raises(ubp.UploadError) as exc:
        prober.submit(TARGET, variants[2])
    assert exc.value.code == "UPLOAD_LIMIT_EXCEEDED"
    assert len(prober.submissions_for(TARGET)) == 2
    assert prober.stats()["uploads"] == 2


def test_report_aggregates_verdicts_and_stats():
    prober = build()
    variants = prober.plan("shell")
    first = prober.submit(TARGET, variants[0])
    second = prober.submit(TARGET, variants[1])
    prober.judge(first, fetch=lambda url: fetch_page(body="UPLOAD_EXEC_MARK"))
    prober.judge(second, fetch=lambda url: fetch_page(status=404))

    report = prober.report()
    assert set(report) == {"targets", "submissions", "counts", "bypass"}
    assert report["targets"] == (TARGET,)
    assert report["submissions"] == 2
    assert report["counts"] == {"bypass": 1, "partial": 0, "blocked": 1, "inconclusive": 0}
    assert report["bypass"] == (variants[0].variant_id,)

    stats = prober.stats()
    assert stats["uploads"] == 2
    assert stats["judgements"] == 2
    assert stats["bypass"] == 1
    assert stats["blocked"] == 1


def test_snapshot_restore_roundtrip_and_invalid_state():
    prober = build()
    variant = prober.plan("shell")[0]
    item = prober.submit(TARGET, variant)
    prober.judge(item, fetch=lambda url: fetch_page(body="UPLOAD_EXEC_MARK"))

    state = prober.snapshot()
    assert set(state) == {"version", "submissions", "verdicts", "stats"}
    pristine = copy.deepcopy(state)
    state["submissions"].clear()
    state["stats"]["uploads"] = 99
    assert prober.stats()["uploads"] == 1
    assert len(prober.submissions_for(TARGET)) == 1

    clone = build()
    clone.restore(pristine)
    assert clone.stats() == prober.stats()
    assert len(clone.submissions_for(TARGET)) == 1
    assert clone.report()["counts"] == {
        "bypass": 1, "partial": 0, "blocked": 0, "inconclusive": 0
    }

    for bad in ({}, None, {"version": 1}, {"version": 1, "submissions": "nope",
                                         "verdicts": {}, "stats": {}}):
        with pytest.raises(ubp.UploadError) as exc:
            clone.restore(bad)
        assert exc.value.code == "UPLOAD_SNAPSHOT_INVALID"
    assert clone.stats()["uploads"] == 1
