import copy
import io
import zipfile

import pytest

import upload_polyglot_quota as ug

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
PDF = b"%PDF-1.7\n" + b"0" * 16


def build(**kwargs):
    return ug.UploadPolyglotQuota(**kwargs)


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def test_sniff_png_and_pdf_magic():
    guard = build()

    png = guard.sniff(PNG)
    assert (png.primary, png.matched, png.polyglot, png.severity) == ("png", ("png",), False, "ok")

    pdf = guard.sniff(PDF)
    assert pdf.primary == "pdf"
    assert pdf.matched == ("pdf",)
    assert pdf.polyglot is False
    assert pdf.severity == "ok"


def test_sniff_unknown_and_html_content():
    guard = build()

    unknown = guard.sniff(b"just some plain text")
    assert unknown.primary == "unknown"
    assert unknown.matched == ()
    assert unknown.polyglot is False
    assert unknown.severity == "suspicious"

    html = guard.sniff(b"<html><body><script>alert(1)</script></body></html>")
    assert html.primary == "html"
    assert html.matched == ("html",)
    assert html.polyglot is False
    assert html.severity == "reject"


def test_sniff_zip_and_executable_content():
    guard = build()

    archive = guard.sniff(b"PK\x03\x04" + b"\x00" * 26)
    assert archive.primary == "zip"
    assert archive.severity == "ok"

    elf = guard.sniff(b"\x7fELF" + b"\x02" * 60)
    assert elf.primary == "elf"
    assert elf.severity == "reject"

    verdict = guard.screen(filename="logo.pdf", declared_type="application/pdf",
                           data=b"\x7fELF" + b"\x02" * 60)
    assert verdict.allowed is False
    assert verdict.reason == "UPLOAD_EXECUTABLE_REJECTED"
    assert verdict.sniffed.primary == "elf"


def test_normalize_filename_lowercases_and_strips_edges():
    guard = build()

    assert guard.normalize_filename("  Photo.PNG.  ") == "photo.png"
    assert guard.normalize_filename("\tDoc.PDF \n") == "doc.pdf"
    assert guard.normalize_filename("a\x00b.png") == "ab.png"
    assert guard.normalize_filename("shell.php.png") == "shell.php.png"


def test_normalize_filename_rejects_empty_and_separators():
    guard = build()
    for raw in ("", "   ", "...", "dir/a.png", "dir\\a.png"):
        with pytest.raises(ug.UploadError) as exc:
            guard.normalize_filename(raw)
        assert exc.value.code == "UPLOAD_FILENAME_REJECTED"


def test_double_extension_rejected():
    guard = build()
    verdict = guard.screen(filename="shell.php.png", declared_type="image/png", data=PNG)

    assert verdict.allowed is False
    assert verdict.reason == "UPLOAD_DOUBLE_EXTENSION"
    assert verdict.filename == "shell.php.png"
    assert verdict.extension == "png"
    assert guard.stats()["rejected"] == 1
    assert guard.stats()["screened"] == 0


def test_declared_type_must_match_sniffed_content():
    guard = build()
    verdict = guard.screen(filename="pic.png", declared_type="application/pdf", data=PNG)

    assert verdict.allowed is False
    assert verdict.reason == "UPLOAD_TYPE_MISMATCH"
    assert verdict.declared_type == "application/pdf"
    assert verdict.sniffed.primary == "png"


def test_type_outside_allowlist_rejected():
    guard = build(allowed_types=("png",))
    payload = make_zip({"a.txt": b"a"})
    verdict = guard.screen(filename="bundle.zip", declared_type="application/zip", data=payload)

    assert verdict.allowed is False
    assert verdict.reason == "UPLOAD_UNSUPPORTED_TYPE"
    assert verdict.sniffed.primary == "zip"


def test_screen_accepts_clean_image_and_reports_reservation():
    guard = build()
    verdict = guard.screen(filename="  Photo.PNG ", declared_type="image/png", data=PNG)

    assert verdict.filename == "photo.png"
    assert verdict.extension == "png"
    assert verdict.allowed is True
    assert verdict.reason == "UPLOAD_OK"
    assert verdict.reserved_bytes == len(PNG)
    assert guard.stats()["screened"] == 1
    assert guard.stats()["rejected"] == 0


def test_reserve_respects_inflight_budget():
    guard = build(max_inflight_bytes=1000)

    assert guard.reserve("u1", byte_count=600) == 600
    assert guard.pending_reservations() == {"u1": 600}

    with pytest.raises(ug.UploadError) as exc:
        guard.reserve("u2", byte_count=600)
    assert exc.value.code == "UPLOAD_QUOTA_EXCEEDED"
    assert guard.pending_reservations() == {"u1": 600}

    assert guard.release("u1") == 600
    assert guard.release("u1") == 0
    assert guard.reserve("u2", byte_count=600) == 600
    assert guard.stats()["reserved_bytes"] == 600


def test_reserve_is_idempotent_per_upload():
    guard = build(max_inflight_bytes=1000)

    assert guard.reserve("u1", byte_count=600) == 600
    assert guard.reserve("u1", byte_count=600) == 600
    assert guard.stats()["reserved_bytes"] == 600
    assert guard.pending_reservations() == {"u1": 600}

    with pytest.raises(ug.UploadError) as exc:
        guard.reserve("u1", byte_count=10)
    assert exc.value.code == "UPLOAD_INVALID_REQUEST"
    assert guard.stats()["reserved_bytes"] == 600


def test_expand_counts_entries_and_bytes():
    guard = build()
    payload = make_zip({"a.txt": b"x" * 60, "b.txt": b"y" * 60})
    guard.reserve("u1", byte_count=len(payload))

    report = guard.expand("u1", payload)
    assert (report.entries, report.bytes_written, report.depth) == (2, 120, 0)
    assert report.rejected is False
    assert report.reason == "UPLOAD_OK"
    assert guard.stats()["reserved_bytes"] == 0
    assert guard.stats()["expanded_bytes"] == 120


def test_expand_rejects_entry_count_and_rolls_back_reservation():
    guard = build(max_entries=2)
    payload = make_zip({f"f{index}.txt": b"z" for index in range(3)})
    guard.reserve("u1", byte_count=len(payload))

    report = guard.expand("u1", payload)
    assert report.rejected is True
    assert report.reason == "UPLOAD_ENTRY_REJECTED"
    assert report.bytes_written == 0
    assert guard.stats()["reserved_bytes"] == 0
    assert guard.stats()["rollbacks"] == 1
    assert guard.stats()["expanded_bytes"] == 0


def test_expand_rejects_expanded_bytes_and_rolls_back_reservation():
    guard = build(max_expanded_bytes=100)
    payload = make_zip({"a.txt": b"x" * 60, "b.txt": b"y" * 60})
    guard.reserve("u1", byte_count=len(payload))

    report = guard.expand("u1", payload)
    assert report.rejected is True
    assert report.reason == "UPLOAD_QUOTA_EXCEEDED"
    assert report.entries == 2
    assert guard.stats()["reserved_bytes"] == 0
    assert guard.stats()["rollbacks"] == 1
    assert guard.stats()["expanded_bytes"] == 0


def test_snapshot_detached_and_restore_roundtrip():
    guard = build()
    guard.reserve("u1", byte_count=300)

    state = guard.snapshot()
    assert set(state) == {"version", "reservations", "expanded_bytes", "audit", "stats"}
    pristine = copy.deepcopy(state)

    state["reservations"].clear()
    state["stats"]["screened"] = 9
    assert guard.pending_reservations() == {"u1": 300}
    assert guard.stats()["screened"] == 0

    clone = ug.UploadPolyglotQuota()
    clone.restore(pristine)
    assert clone.stats()["restores"] == 1
    assert clone.pending_reservations() == {"u1": 300}
    assert clone.stats()["reserved_bytes"] == 300
    assert clone.release("u1") == 300

    for bad in (
        None,
        {},
        {"version": 1, "reservations": [], "expanded_bytes": 0, "audit": [], "stats": {}},
        {"version": 1, "reservations": {}, "expanded_bytes": 0, "audit": [],
         "stats": {"screened": 0}},
    ):
        with pytest.raises(ug.UploadError) as exc:
            clone.restore(bad)
        assert exc.value.code == "UPLOAD_SNAPSHOT_INVALID"

    assert clone.stats()["restores"] == 1
