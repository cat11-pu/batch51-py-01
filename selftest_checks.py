"""交付前本地自测：覆盖题面硬性约束与误判单场景（不进 tests，不参与验收）。"""

import copy
import threading

import sandbox_evasion_classifier as sec


def expect_error(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except sec.SandboxError as exc:
        assert exc.code == code, (code, exc.code)
        return
    raise AssertionError(f"expected {code}")


def main():
    # 样本 C：200ms 轮询只计 timing_poll 一次，且不会变成 sleep_long 信号
    box = sec.SandboxEvasionClassifier(window_ms=5000)
    first = None
    for idx in range(20):
        hit = box.ingest_event("c", "timing_poll", key="kbd", ts_ms=idx * 200)
        if first is None:
            first = hit
        else:
            assert hit == first
    stats = box.stats()
    assert stats["hits"] == 1 and stats["duplicates"] == 19, stats
    verdict = box.evaluate("c")
    assert verdict.score == 10 and verdict.verdict == "clean", verdict

    # 窗口边界：差值达到 window_ms 重新计一次；不同 key 独立计数
    edge = sec.SandboxEvasionClassifier(window_ms=1000)
    h0 = edge.ingest_event("s", "sleep_long", key="k", ts_ms=0)
    hd = edge.ingest_event("s", "sleep_long", key="k", ts_ms=999)
    h1 = edge.ingest_event("s", "sleep_long", key="k", ts_ms=1000)
    h_other = edge.ingest_event("s", "sleep_long", key="k2", ts_ms=1000)
    assert hd == h0 and h1.ts_ms == 1000 and h1 != h0 and h_other.key == "k2"
    assert edge.stats()["hits"] == 3 and edge.stats()["duplicates"] == 1

    # 样本 A：长睡眠单类别即使分高也只能 suspicious，且与轮询分开计分
    sample_a = sec.SandboxEvasionClassifier()
    sample_a.ingest_event("a", "sleep_long", key="stall", ts_ms=120_000)
    sample_a.ingest_event("a", "timing_poll", key="kbd", ts_ms=120_200)
    va = sample_a.evaluate("a")
    assert va.categories == ("timing",) and va.verdict == "clean", va
    assert va.score == 15  # max(15, 10)，轮询不累加成睡眠

    # 单类别即使满分也只能 suspicious
    single = sec.SandboxEvasionClassifier()
    single.add_indicator("heavy_timing", "timing", 100, 1.0)
    single.ingest_event("a", "heavy_timing", key="k", ts_ms=0)
    assert single.evaluate("a").verdict == "suspicious"

    # 样本 B：轨迹截断 -> uncertain，分数照算
    sample_b = sec.SandboxEvasionClassifier()
    sample_b.ingest_event("b", "env_vm", key="vmware", ts_ms=0)
    sample_b.mark_truncated("b", reason="agent crashed")
    vb = sample_b.evaluate("b")
    assert vb.truncated is True and vb.verdict == "uncertain" and vb.score == 20
    assert sec.classify_score(90, ("a", "b"), truncated=True) == "uncertain"
    assert sample_b.stats()["truncated"] == 1
    sample_b.mark_truncated("b", reason="again")
    assert sample_b.stats()["truncated"] == 1  # 重复标记不重复计数

    # 分类边界
    assert sec.classify_score(19, ("x",)) == "clean"
    assert sec.classify_score(20, ("x",)) == "suspicious"
    assert sec.classify_score(69, ("x", "y")) == "suspicious"
    assert sec.classify_score(70, ("x", "y")) == "evasive"
    assert sec.classify_score(100, ("x",)) == "suspicious"

    # 有效分向下取整
    assert sec.effective_score(30, 0.5) == 15
    assert sec.effective_score(35, 0.9) == 31

    # 并发同信号：同一 (indicator,key) 只允许一条命中，去重计数不丢
    par = sec.SandboxEvasionClassifier(window_ms=5000, max_events=1024)
    barrier = threading.Barrier(32)
    errors = []

    def worker_same():
        try:
            barrier.wait(timeout=10)
            par.ingest_event("p", "no_input", key="same", ts_ms=5)
        except Exception as exc:  # pragma: no cover
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker_same) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    pstats = par.stats()
    assert pstats["hits"] == 1 and pstats["duplicates"] == 31, pstats

    # 并发不同 key：每个 key 各一次
    multi = sec.SandboxEvasionClassifier(max_events=1024)
    barrier = threading.Barrier(32)

    def worker_multi(index):
        barrier.wait(timeout=10)
        multi.ingest_event("m", "no_input", key=f"k-{index}", ts_ms=index)

    threads = [threading.Thread(target=worker_multi, args=(i,))
               for i in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    mstats = multi.stats()
    assert mstats["hits"] == 32 and mstats["duplicates"] == 0, mstats

    # 样本隔离 + reset 不影响其它样本
    iso = sec.SandboxEvasionClassifier()
    iso.ingest_event("x", "env_vm", key="v", ts_ms=0)
    iso.ingest_event("y", "name_blocklist", key="n", ts_ms=0)
    assert iso.reset("x") == 1
    assert iso.evaluate("x").hits == 0
    assert iso.evaluate("y").score == 36
    assert iso.stats()["resets"] == 1 and iso.stats()["samples"] == 2
    expect_error("SANDBOX_SAMPLE_UNKNOWN", iso.reset, "ghost")

    # 重复评估确定性
    assert iso.evaluate("y") == iso.evaluate("y")

    # 事件硬顶：重复不占额度
    cap = sec.SandboxEvasionClassifier(max_events=2)
    cap.ingest_event("z", "no_input", key="a", ts_ms=0)
    cap.ingest_event("z", "no_input", key="a", ts_ms=1)  # 窗口内重复
    cap.ingest_event("z", "no_input", key="b", ts_ms=2)
    expect_error("SANDBOX_TRACE_LIMIT", cap.ingest_event,
                 "z", "no_input", key="c", ts_ms=3)

    # 参数校验错误码
    expect_error("SANDBOX_SAMPLE_INVALID", box.ingest_event, "", "no_input")
    expect_error("SANDBOX_SAMPLE_INVALID", box.ingest_event, 7, "no_input")
    expect_error("SANDBOX_EVENT_INVALID", box.ingest_event,
                 "s", "no_input", ts_ms=-1)
    expect_error("SANDBOX_EVENT_INVALID", box.ingest_event,
                 "s", "no_input", key=3)
    expect_error("SANDBOX_UNKNOWN_INDICATOR", box.ingest_event, "s", "ghost")
    expect_error("SANDBOX_SAMPLE_UNKNOWN", box.evaluate, "ghost")
    expect_error("SANDBOX_SAMPLE_UNKNOWN", box.explain, "ghost")

    # 指标校验
    expect_error("SANDBOX_INDICATOR_EXISTS",
                 box.add_indicator, "no_input", "c", 10, 0.5)
    invalid_indicators = [
        ("x", "c", 0, 0.5), ("x", "c", 101, 0.5),
        ("x", "c", True, 0.5), ("x", "c", 10, 0),
        ("x", "c", 10, 1.1), ("x", "c", 10, True),
        (" ", "c", 10, 0.5), ("x", "  ", 10, 0.5),
        ("noname", "c", 10, 0.5), (9, "c", 10, 0.5),
    ]
    for bad in invalid_indicators:
        expect_error("SANDBOX_INDICATOR_INVALID", box.add_indicator, *bad)
    limited = sec.SandboxEvasionClassifier(max_indicators=8)
    limited.add_indicator("extra", "cat", 10, 0.5)
    expect_error("SANDBOX_INDICATOR_LIMIT",
                 limited.add_indicator, "overflow", "cat", 10, 0.5)

    # 构造期内建超限
    expect_error("SANDBOX_INDICATOR_LIMIT",
                 sec.SandboxEvasionClassifier, max_indicators=3)

    # 自定义 indicators 入参（替代内建）
    custom = sec.SandboxEvasionClassifier(
        indicators=[("only", "custom", 50, 1.0)])
    assert custom.ingest_event("s", "only", key="k", ts_ms=0).effective == 50
    expect_error("SANDBOX_UNKNOWN_INDICATOR",
                 custom.ingest_event, "s", "no_input")

    # explain 结构与 top 排序（同分按名称升序）
    explained_box = sec.SandboxEvasionClassifier()
    explained_box.ingest_event("s", "env_vm", key="v", ts_ms=0)   # 20
    explained_box.ingest_event("s", "no_input", key="m", ts_ms=1)  # 12
    explained_box.ingest_event("s", "no_input", key="m2", ts_ms=2)
    explained = explained_box.explain("s")
    assert list(explained["categories"]) == ["environment", "interaction"]
    assert explained["categories"]["interaction"]["hits"] == 2
    assert explained["categories"]["interaction"]["indicators"] == ["no_input"]
    assert explained["top"] == ["env_vm", "no_input"]
    tie = sec.SandboxEvasionClassifier()
    tie.add_indicator("zeta", "c1", 25, 0.8)   # 20
    tie.add_indicator("alpha", "c2", 25, 0.8)  # 20
    tie.ingest_event("s", "zeta", key="k", ts_ms=0)
    tie.ingest_event("s", "alpha", key="k", ts_ms=1)
    assert tie.explain("s")["top"] == ["alpha", "zeta"]

    # 快照深拷贝隔离 + 恢复往返 + 非法结构不动现状
    snap = explained_box.snapshot()
    pristine = copy.deepcopy(snap)
    snap["samples"].clear()
    snap["counters"]["hits"] = 999
    assert explained_box.stats()["hits"] == 3
    clone = sec.SandboxEvasionClassifier()
    clone.restore(pristine)
    assert clone.explain("s") == explained_box.explain("s")
    assert clone.stats() == explained_box.stats()
    before = clone.stats()
    bad_snapshots = (
        None, {},
        {"samples": [], "indicators": {}, "counters": {}},
        {"indicators": {}, "samples": {}, "counters": {"hits": -1}},
    )
    for bad in bad_snapshots:
        expect_error("SANDBOX_SNAPSHOT_INVALID", clone.restore, bad)
    assert clone.stats() == before
    # 恢复后可继续去重，说明 last_seen 也往返了
    again = clone.ingest_event("s", "no_input", key="m", ts_ms=2)
    assert again.ts_ms == 1
    assert clone.stats()["duplicates"] == explained_box.stats()["duplicates"] + 1

    # 二次快照往返等价
    clone2 = sec.SandboxEvasionClassifier()
    clone2.restore(clone.snapshot())
    assert clone2.explain("s") == clone.explain("s")

    print("all self-test checks passed")


if __name__ == "__main__":
    main()
