import copy
import hashlib
import struct
import threading

import pytest

import elf_hardening_auditor as elf

STACK = (elf.PT_GNU_STACK, elf.PF_R | elf.PF_W, 0)
LOAD_RX = (elf.PT_LOAD, elf.PF_R | elf.PF_X, 0x200)


def build_elf(*, file_type=elf.ET_DYN, entry=0x401000, segments=(),
              dynamic=(), magic=b"\x7fELF"):
    phnum = len(segments)
    phoff = elf.EHDR_SIZE
    phentsize = elf.PHDR_SIZE
    dyn = b"".join(struct.pack("<QQ", tag, val) for tag, val in dynamic)
    dyn_off = phoff + phentsize * phnum
    header = bytearray(b"\x00" * elf.EHDR_SIZE)
    header[0:4] = magic
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 16, file_type)
    struct.pack_into("<Q", header, 24, entry)
    struct.pack_into("<Q", header, 32, phoff)
    struct.pack_into("<H", header, 54, phentsize)
    struct.pack_into("<H", header, 56, phnum)
    blob = bytes(header)
    for seg_type, seg_flags, seg_size in segments:
        offset = dyn_off if seg_type == elf.PT_DYNAMIC else 0
        blob += struct.pack("<IIQQQQQQ", seg_type, seg_flags, offset, 0, 0,
                            seg_size, seg_size, 8)
    return blob + dyn


def hardened(*, file_type=elf.ET_DYN, dynamic=((elf.DT_BIND_NOW, 0),)):
    segments = [LOAD_RX, (elf.PT_GNU_RELRO, elf.PF_R, 0x20),
                (elf.PT_DYNAMIC, elf.PF_R | elf.PF_W, 16), STACK]
    return build_elf(file_type=file_type, segments=segments, dynamic=dynamic)


def unrelroed():
    segments = [LOAD_RX, (elf.PT_DYNAMIC, elf.PF_R | elf.PF_W, 16), STACK]
    return build_elf(segments=segments, dynamic=((elf.DT_BIND_NOW, 0),))


def items_of(result):
    return {item.name: item for item in result.items}


def auditor():
    return elf.ElfHardeningAuditor()


def test_parse_image_reads_elf64_header_fields():
    data = build_elf(file_type=elf.ET_DYN, entry=0x401234,
                     segments=[LOAD_RX, STACK])
    info = auditor().parse_image(data)
    assert info.file_type == elf.ET_DYN
    assert info.entry == 0x401234
    assert info.phentsize == 56
    assert info.phnum == 2
    assert info.size == len(data)
    assert info.digest == hashlib.sha256(data).hexdigest()
    assert info.dynamic == ()


def test_parse_image_rejects_unknown_magic():
    data = build_elf(segments=[LOAD_RX], magic=b"\x7fELG")
    with pytest.raises(elf.ElfAuditError) as exc:
        auditor().parse_image(data)
    assert exc.value.code == "ELF_BAD_MAGIC"


def test_parse_image_keeps_program_header_order_and_flags():
    segments = [LOAD_RX, (elf.PT_GNU_RELRO, elf.PF_R, 0x40), STACK]
    info = auditor().parse_image(build_elf(segments=segments))
    assert [seg.type for seg in info.segments] == [elf.PT_LOAD, elf.PT_GNU_RELRO,
                                                  elf.PT_GNU_STACK]
    assert [seg.flags for seg in info.segments] == [elf.PF_R | elf.PF_X, elf.PF_R,
                                                    elf.PF_R | elf.PF_W]
    assert [seg.filesz for seg in info.segments] == [0x200, 0x40, 0]


def test_pie_item_follows_elf_type():
    inst = auditor()
    dynamic_image = items_of(inst.check_image(inst.parse_image(hardened())))
    exec_image = items_of(inst.check_image(
        inst.parse_image(hardened(file_type=elf.ET_EXEC))))
    assert dynamic_image["pie"].status == "ok"
    assert exec_image["pie"].status == "fail"


def test_nx_stack_is_ok_without_execute_flag():
    inst = auditor()
    items = items_of(inst.check_image(inst.parse_image(hardened())))
    assert items["nx_stack"].status == "ok"


def test_nx_stack_fails_when_segment_is_executable():
    inst = auditor()
    segments = [LOAD_RX, (elf.PT_GNU_RELRO, elf.PF_R, 0x20),
                (elf.PT_DYNAMIC, elf.PF_R | elf.PF_W, 16),
                (elf.PT_GNU_STACK, elf.PF_R | elf.PF_W | elf.PF_X, 0)]
    data = build_elf(segments=segments, dynamic=((elf.DT_BIND_NOW, 0),))
    items = items_of(inst.check_image(inst.parse_image(data)))
    assert items["nx_stack"].status == "fail"


def test_relro_and_bind_now_pass_for_hardened_image():
    inst = auditor()
    items = items_of(inst.check_image(
        inst.parse_image(hardened()), symbols=("__stack_chk_fail",)))
    assert [name for name in items] == list(elf.ITEM_ORDER)
    assert items["relro"].status == "ok"
    assert items["bind_now"].status == "ok"
    assert items["stack_canary"].status == "ok"


def test_bind_now_fails_when_dynamic_flags_lack_now():
    inst = auditor()
    data = hardened(dynamic=((elf.DT_FLAGS, 0),))
    items = items_of(inst.check_image(inst.parse_image(data),
                                      symbols=("__stack_chk_fail",)))
    assert items["relro"].status == "ok"
    assert items["bind_now"].status == "fail"


def test_stack_canary_depends_on_reported_symbols():
    inst = auditor()
    info = inst.parse_image(hardened())
    bare = items_of(inst.check_image(info))
    guarded = items_of(inst.check_image(info, symbols=("write", "__stack_chk_fail")))
    assert bare["stack_canary"].status == "fail"
    assert guarded["stack_canary"].status == "ok"


def test_verdict_for_aggregates_failing_items_in_item_order():
    inst = auditor()
    clean = inst.check_image(inst.parse_image(hardened()),
                             symbols=("__stack_chk_fail",))
    assert inst.verdict_for(clean) == "pass"

    broken = inst.check_image(inst.parse_image(
        build_elf(file_type=elf.ET_EXEC,
                  segments=[LOAD_RX, (elf.PT_DYNAMIC, elf.PF_R | elf.PF_W, 16),
                            STACK],
                  dynamic=((elf.DT_BIND_NOW, 0),))))
    assert inst.verdict_for(broken) == "fail"
    assert tuple(item.name for item in broken if item.status == "fail") == (
        "pie", "relro", "stack_canary")


def test_baseline_tolerates_named_items_per_package():
    inst = auditor()
    data = hardened(file_type=elf.ET_EXEC)
    first = inst.scan("/usr/bin/legacy", data, package="pkg-legacy",
                      symbols=("__stack_chk_fail",))
    assert first.verdict == "fail"
    assert first.failing == ("pie",)

    inst.set_baseline("pkg-legacy", ("pie",))
    assert inst.baseline_for("pkg-legacy") == ("pie",)
    assert inst.baseline_for("pkg-other") == ()

    second = inst.scan("/usr/bin/legacy", data, package="pkg-legacy",
                       symbols=("__stack_chk_fail",))
    assert second.verdict == "pass"
    assert second.failing == ()
    assert items_of(second)["pie"].status == "fail"


def test_exemption_applies_only_to_the_recorded_digest():
    inst = auditor()
    data = unrelroed()
    first = inst.scan("/usr/bin/app", data, package="pkg-a",
                      symbols=("__stack_chk_fail",))
    assert first.failing == ("relro",)

    inst.add_exemption("/usr/bin/app", first.digest, ("relro",),
                       expires_at="2027-03-01T00:00:00+00:00")
    assert inst.is_exempt("/usr/bin/app", first.digest, "relro",
                          now="2026-12-31T00:00:00+00:00") is True
    assert inst.is_exempt("/usr/bin/app", first.digest, "pie",
                          now="2026-12-31T00:00:00+00:00") is False

    second = inst.scan("/usr/bin/app", data, package="pkg-a",
                       symbols=("__stack_chk_fail",),
                       now="2026-12-31T00:00:00+00:00")
    assert second.verdict == "pass"
    assert second.failing == ()

    rebuilt = unrelroed() + b"\x00tail"
    third = inst.scan("/usr/bin/app", rebuilt, package="pkg-a",
                      symbols=("__stack_chk_fail",),
                      now="2026-12-31T00:00:00+00:00")
    assert third.digest != first.digest
    assert third.failing == ("relro",)
    assert third.verdict == "fail"


def test_concurrent_scan_parses_each_image_once():
    inst = auditor()
    data = hardened()
    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(5)
            results.append(inst.scan("/usr/bin/app", data, package="pkg-a",
                                     symbols=("__stack_chk_fail",)))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert errors == []
    assert len(results) == 8
    assert {(row.digest, row.verdict) for row in results} == {
        (hashlib.sha256(data).hexdigest(), "pass")}
    assert inst.stats()["parses"] == 1
    assert inst.stats()["scans"] == 8


def test_report_groups_images_by_package_and_failing_item():
    inst = auditor()
    inst.scan("/usr/bin/a1", hardened(), package="pkg-a",
              symbols=("__stack_chk_fail",))
    inst.scan("/usr/bin/a2", unrelroed(), package="pkg-a",
              symbols=("__stack_chk_fail",))
    inst.scan("/opt/b1", unrelroed(), package="pkg-b",
              symbols=("__stack_chk_fail",))
    report = inst.report()
    assert report["images"] == 3
    assert report["packages"]["pkg-a"]["images"] == 2
    assert report["packages"]["pkg-a"]["failing"] == ("relro",)
    assert report["packages"]["pkg-b"]["images"] == 1
    assert report["packages"]["pkg-b"]["failing"] == ("relro",)
    assert report["failing_items"] == {"relro": 2}


def test_snapshot_is_detached_and_restore_roundtrips():
    inst = auditor()
    data = unrelroed()
    first = inst.scan("/usr/bin/app", data, package="pkg-a")
    assert first.failing == ("relro", "stack_canary")
    inst.set_baseline("pkg-a", ("relro",))
    inst.add_exemption("/usr/bin/app", first.digest, ("stack_canary",))
    assert inst.scan("/usr/bin/app", data, package="pkg-a").verdict == "pass"

    state = inst.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"images", "exemptions", "baselines", "stats"}

    state["baselines"].clear()
    state["stats"]["parses"] = 99
    assert inst.baseline_for("pkg-a") == ("relro",)
    assert inst.stats()["parses"] == 1

    clone = auditor()
    clone.restore(pristine)
    assert clone.baseline_for("pkg-a") == ("relro",)
    assert clone.stats()["parses"] == 1
    restored = clone.scan("/usr/bin/app", data, package="pkg-a")
    assert restored.verdict == "pass"
    assert restored.failing == ()
