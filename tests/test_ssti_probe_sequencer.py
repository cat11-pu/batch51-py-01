import copy

import pytest

import ssti_probe_sequencer as sp

GENERIC = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]


def sequencer(**kwargs):
    return sp.SstiProbeSequencer(**kwargs)


def point(seq, param="q", **kwargs):
    return seq.register_point(param, **kwargs)


def test_register_point_returns_normalized_identifier():
    seq = sequencer()
    assert point(seq, "  q  ") == "q"
    assert point(seq, "filter") == "filter"
    assert point(seq, "q") == "q"
    assert seq.points() == ["filter", "q"]
    assert seq.stats()["points_registered"] == 2


def test_register_point_rejects_blank_and_non_string():
    seq = sequencer()
    for bad in ["", "   ", None, 7]:
        with pytest.raises(sp.SstiError) as exc:
            seq.register_point(bad)
        assert exc.value.code == "SSTI_INVALID_POINT"
    assert seq.points() == []


def test_engine_ladders_are_selected_per_point():
    seq = sequencer()
    seq.register_point("q")
    seq.register_point("view", engine="jinja2")
    assert seq.ladder_for("q") == GENERIC
    assert seq.ladder_for("view") == ["{{7*7}}", "{{'7'*7}}"]
    capped = sequencer(max_escalations=1)
    capped.register_point("tiny")
    assert capped.ladder_for("tiny") == ["{{7*7}}"]
    with pytest.raises(sp.SstiError) as exc:
        seq.register_point("nope", engine="unknown-engine")
    assert exc.value.code == "SSTI_ENGINE_UNKNOWN"


def test_next_payload_walks_ladder_in_order():
    seq = sequencer()
    seq.register_point("q")
    assert seq.next_payload("q") == {"point": "q", "step": 1, "payload": "{{7*7}}"}
    assert seq.next_payload("q") == {"point": "q", "step": 2, "payload": "${7*7}"}
    assert seq.next_payload("q")["payload"] == "<%= 7*7 %>"
    assert seq.next_payload("q")["step"] == 4


def test_ladder_exhaustion_reports_none():
    seq = sequencer()
    seq.register_point("q")
    for _ in range(4):
        assert seq.next_payload("q") is not None
    assert seq.is_exhausted("q") is True
    assert seq.next_payload("q") is None
    assert seq.stats()["payloads_issued"] == 4


def test_expected_marker_derives_arithmetic_and_repeat():
    seq = sequencer()
    assert seq.expected_marker("{{7*7}}") == "49"
    assert seq.expected_marker("<%= 8*6 %>") == "48"
    repeated = seq.expected_marker("{{'7'*7}}")
    assert repeated == "7777777"
    with pytest.raises(sp.SstiError) as exc:
        seq.expected_marker("plain-text")
    assert exc.value.code == "SSTI_PAYLOAD_OPAQUE"


def test_evaluate_echo_reports_evaluated():
    seq = sequencer()
    seq.register_point("q")
    assert seq.evaluate_echo("q", "{{7*7}}", "total is 49 items") == sp.ECHO_EVALUATED
    assert seq.stats()["hits"] == 1


def test_evaluate_echo_reports_raw_reflection():
    seq = sequencer()
    seq.register_point("q")
    assert seq.evaluate_echo("q", "{{7*7}}", "echo: {{7*7}}") == sp.ECHO_RAW
    assert seq.stats()["raw"] == 1
    assert seq.stats()["hits"] == 0
    assert seq.next_payload("q") is not None


def test_evaluate_echo_reports_escaped_entities():
    seq = sequencer()
    seq.register_point("q")
    assert seq.evaluate_echo("q", "<%= 7*7 %>", "&lt;%= 7*7 %&gt;") == sp.ECHO_ESCAPED
    assert seq.stats()["escaped"] == 1
    assert seq.stats()["hits"] == 0


def test_evaluate_echo_reports_absent():
    seq = sequencer()
    seq.register_point("q")
    assert seq.evaluate_echo("q", "{{7*7}}", "nothing to see") == sp.ECHO_ABSENT
    assert seq.stats()["hits"] == 0
    assert seq.stats()["raw"] == 0


def test_evaluated_echo_closes_point():
    seq = sequencer()
    seq.register_point("q")
    assert seq.evaluate_echo("q", "{{7*7}}", "49") == sp.ECHO_EVALUATED
    assert seq.mark_hit("q") is False
    assert seq.next_payload("q") is None
    with pytest.raises(sp.SstiError) as exc:
        seq.escalate("q")
    assert exc.value.code == "SSTI_POINT_CLOSED"


def test_escalate_advances_step_and_rejects_exhausted():
    seq = sequencer()
    seq.register_point("q", engine="jinja2")
    assert seq.next_payload("q")["step"] == 1
    assert seq.escalate("q") == 2
    with pytest.raises(sp.SstiError) as exc:
        seq.escalate("q")
    assert exc.value.code == "SSTI_LADDER_EXHAUSTED"
    assert seq.is_exhausted("q") is True
    assert seq.stats()["escalations"] == 1


def test_point_capacity_is_hard_limit():
    seq = sequencer(max_points=2)
    seq.register_point("a")
    seq.register_point("b")
    with pytest.raises(sp.SstiError) as exc:
        seq.register_point("c")
    assert exc.value.code == "SSTI_POINT_LIMIT"
    assert seq.points() == ["a", "b"]
    assert seq.register_point("a") == "a"


def test_detect_context_labels_reflection_site():
    seq = sequencer()
    seq.register_point("q")
    assert seq.context_for("q") == sp.CONTEXT_UNKNOWN
    assert seq.detect_context("q", 'value="{{7*7}}"') == sp.CONTEXT_ATTR
    assert seq.context_for("q") == sp.CONTEXT_ATTR
    seq.register_point("body")
    assert seq.detect_context("body", "<div>{{7*7}}</div>") == sp.CONTEXT_TEXT
    seq.register_point("inline")
    assert seq.detect_context("inline", "<script>var a = '{{7*7}}';</script>") == sp.CONTEXT_SCRIPT
    seq.register_point("blank")
    assert seq.detect_context("blank", "no reflection here") == sp.CONTEXT_UNKNOWN
    with pytest.raises(sp.SstiError) as exc:
        seq.context_for("missing")
    assert exc.value.code == "SSTI_POINT_UNKNOWN"


def test_snapshot_roundtrip_and_counters():
    seq = sequencer()
    seq.register_point("q")
    seq.evaluate_echo("q", "{{7*7}}", "49")
    seq.register_point("view", engine="jinja2")
    seq.next_payload("view")
    state = seq.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "points", "stats", "ladders"}
    assert pristine["points"]["q"]["hit"] is True
    assert pristine["points"]["view"]["step"] == 1
    assert pristine["points"]["view"]["engine"] == "jinja2"

    state["points"].clear()
    state["stats"]["hits"] = 999
    assert seq.is_exhausted("view") is False
    assert seq.stats()["hits"] == 1

    base = seq.stats()
    clone = sequencer()
    clone.restore(pristine)
    restored = clone.stats()
    assert restored["hits"] == base["hits"] == 1
    assert restored["payloads_issued"] == base["payloads_issued"] == 1
    assert restored["restores"] == 1
    assert base["restores"] == 0
    assert clone.context_for("q") == sp.CONTEXT_UNKNOWN
    assert clone.next_payload("q") is None
    assert clone.points() == ["q", "view"]

    for bad in [None, {}, {"version": 2, "points": {}, "stats": {}, "ladders": {}}]:
        with pytest.raises(sp.SstiError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SSTI_SNAPSHOT_INVALID"
    assert clone.stats()["restores"] == 1
    assert clone.points() == ["q", "view"]
