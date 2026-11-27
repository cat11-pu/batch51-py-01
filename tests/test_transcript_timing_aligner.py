import threading

import pytest

import transcript_timing_aligner as ta

TWO = [(0, 1000, "s1", 1), (1200, 2000, "s2", 1)]


def aligner(**kwargs):
    return ta.TranscriptTimingAligner(**kwargs)


def loaded(words=("hello", "world"), segments=TWO):
    a = aligner()
    a.load_transcript(list(words))
    a.load_segments(list(segments))
    return a


def test_load_transcript_validates_words():
    a = aligner()
    for bad in (["ok", ""], ["ok", 3], ["ok", "a b"]):
        with pytest.raises(ta.TranscriptError) as exc:
            a.load_transcript(bad)
        assert exc.value.code == "TRANSCRIPT_INVALID_WORD"
    assert a.load_transcript(["hello", "world"]) == 2
    small = aligner(max_words=2)
    with pytest.raises(ta.TranscriptError) as exc:
        small.load_transcript(["a", "b", "c"])
    assert exc.value.code == "TRANSCRIPT_LIMIT"


def test_load_segments_validates_spans():
    a = aligner()
    for bad in ([(1000, 1000, "s", 1)], [(-1, 500, "s", 1)],
                [(0, 500, "", 1)], [(0, 500, "s", -1)]):
        with pytest.raises(ta.TranscriptError) as exc:
            a.load_segments(bad)
        assert exc.value.code == "TRANSCRIPT_INVALID_SEGMENT"
    with pytest.raises(ta.TranscriptError) as exc:
        a.load_segments([(1000, 2000, "s", 1), (0, 500, "s", 1)])
    assert exc.value.code == "TRANSCRIPT_UNSORTED_SEGMENTS"
    small = aligner(max_segments=1)
    with pytest.raises(ta.TranscriptError) as exc:
        small.load_segments([(0, 100, "s", 1), (200, 300, "s", 1)])
    assert exc.value.code == "TRANSCRIPT_LIMIT"
    assert a.load_segments(TWO) == 2


def test_align_requires_loaded_input():
    a = aligner()
    with pytest.raises(ta.TranscriptError) as exc:
        a.align()
    assert exc.value.code == "TRANSCRIPT_NOT_LOADED"


def test_align_places_one_word_per_segment():
    a = loaded()
    assert a.align() == 2
    timings = a.word_timings()
    assert [w.word for w in timings] == ["hello", "world"]
    assert [w.speaker for w in timings] == ["s1", "s2"]
    assert (timings[0].start_ms, timings[0].end_ms) == (0, 1000)
    assert (timings[1].start_ms, timings[1].end_ms) == (1200, 2000)
    for word in timings:
        assert word.start_ms < word.end_ms


def test_align_keeps_words_inside_a_multi_word_segment():
    words = ["alpha", "beta", "gamma", "delta", "epsilon"]
    a = aligner()
    a.load_transcript(words)
    a.load_segments([(0, 900, "s", 5)])
    assert a.align() == 5
    timings = a.word_timings()
    assert len(timings) == 5
    assert timings[0].start_ms == 0
    assert all(0 <= w.start_ms <= w.end_ms <= 900 for w in timings)
    assert [w.start_ms for w in timings] == sorted(w.start_ms for w in timings)


def test_align_skips_silence_between_segments():
    a = loaded(words=["one", "two"],
               segments=[(0, 800, "s1", 1), (1500, 2000, "s2", 1)])
    a.align()
    timings = a.word_timings()
    assert (timings[0].start_ms, timings[0].end_ms) == (0, 800)
    assert (timings[1].start_ms, timings[1].end_ms) == (1500, 2000)
    assert timings[1].start_ms >= 1500


def test_align_is_repeatable():
    a = loaded()
    a.align()
    first = a.word_timings()
    assert a.align() == 2
    assert a.word_timings() == first
    assert a.stats()["aligns"] == 2


def test_align_rejects_mismatch_and_empty_input():
    a = aligner()
    a.load_transcript(["a", "b"])
    a.load_segments([(0, 100, "s", 1)])
    with pytest.raises(ta.TranscriptError) as exc:
        a.align()
    assert exc.value.code == "TRANSCRIPT_MISMATCH"
    b = aligner()
    b.load_transcript([])
    b.load_segments([(0, 100, "s", 1)])
    with pytest.raises(ta.TranscriptError) as exc:
        b.align()
    assert exc.value.code == "TRANSCRIPT_EMPTY"
    c = aligner()
    c.load_transcript(["a"])
    c.load_segments([])
    with pytest.raises(ta.TranscriptError) as exc:
        c.align()
    assert exc.value.code == "TRANSCRIPT_EMPTY"


def test_shift_moves_words_and_segments():
    a = loaded()
    a.align()
    assert a.shift(250) == 2
    timings = a.word_timings()
    assert (timings[0].start_ms, timings[0].end_ms) == (250, 1250)
    assert (timings[1].start_ms, timings[1].end_ms) == (1450, 2250)
    assert a.segments()[0].start_ms == 250
    before = a.word_timings()
    with pytest.raises(ta.TranscriptError) as exc:
        a.shift(-10000)
    assert exc.value.code == "TRANSCRIPT_NEGATIVE_TIME"
    assert a.word_timings() == before


def test_merge_speakers_respects_gaps():
    a = aligner()
    a.load_segments([(0, 500, "a", 1), (500, 900, "a", 1),
                     (1000, 1400, "a", 1), (1400, 1800, "b", 1)])
    assert a.merge_speakers() == 1
    assert [(s.start_ms, s.end_ms, s.speaker) for s in a.segments()] == [
        (0, 900, "a"), (1000, 1400, "a"), (1400, 1800, "b")]
    assert a.merge_speakers() == 0


def test_export_cues_groups_one_line():
    a = loaded(words=["hello", "world"],
               segments=[(0, 500, "s", 1), (500, 1000, "s", 1)])
    a.align()
    cues = a.export_cues()
    assert len(cues) == 1
    cue = cues[0]
    assert cue.text == "hello world"
    assert cue.speaker == "s"
    assert (cue.index, cue.start_ms, cue.end_ms) == (0, 0, 1000)


def test_export_cues_splits_on_character_limit():
    a = aligner()
    a.load_transcript(["aa", "bb", "cc"])
    a.load_segments([(0, 100, "s", 1), (100, 200, "s", 1), (200, 300, "s", 1)])
    a.align()
    cues = a.export_cues(max_chars=5)
    assert [cue.text for cue in cues] == ["aa bb", "cc"]
    assert [cue.index for cue in cues] == [0, 1]
    assert cues[1].start_ms == 200


def test_stats_reports_alignment_shape():
    a = loaded(words=["a", "b"])
    a.align()
    a.export_cues()
    assert a.stats() == {"words": 2, "segments": 2, "cues": 1,
                         "aligned": True, "duration_ms": 2000}


def test_snapshot_is_deep_copy_and_restore_resumes():
    a = loaded()
    a.align()
    a.export_cues()
    snap = a.snapshot()
    assert snap["version"] == 1
    assert snap["words"] == ["hello", "world"]
    assert len(snap["timings"]) == 2
    snap["words"].append("extra")
    assert len(a.snapshot()["words"]) == 2
    q = aligner()
    q.restore(a.snapshot())
    assert q.word_timings() == a.word_timings()
    assert q.segments() == a.segments()
    assert q.export_cues() == a.export_cues()
    before = q.snapshot()
    with pytest.raises(ta.TranscriptError) as exc:
        q.restore({"version": 2})
    assert exc.value.code == "TRANSCRIPT_SNAPSHOT_INVALID"
    assert q.snapshot() == before


def test_parallel_alignments_are_deterministic():
    results = []

    def worker():
        a = aligner()
        a.load_transcript(["alpha", "beta", "gamma"])
        a.load_segments([(0, 300, "s", 1), (300, 700, "s", 2)])
        a.align()
        results.append(a.word_timings())

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 2
    assert results[0] == results[1]
    assert len(results[0]) == 3
