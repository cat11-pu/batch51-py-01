import copy
import math
from collections import Counter

import pytest

import secret_entropy_scanner as se

AWS = "AKIA7Q2W9E4R6T8Y1U3I"
SLACK = "xoxb-9Q2W4E6R8T1Y3U5I7O"
GENERIC = "d4F7h2J9k1L6m3N8p5Q0r7S2t9V4"
LOW_ENTROPY = "AKIAAAAAAAAAAAAAAAAA"
CUSTOM = "int-9Q2W4E6R8T1Y3U5"


def scanner(**kwargs):
    return se.SecretEntropyScanner(**kwargs)


def shannon(text):
    size = len(text)
    return round(-sum(count / size * math.log2(count / size)
                      for count in Counter(text).values()), 6)


def test_entropy_of_uniform_distributions():
    gen = scanner()
    assert gen.entropy("a" * 16) == 0.0
    assert gen.entropy("ab" * 8) == 1.0
    assert gen.entropy("abcdefghijklmnop") == 4.0


def test_entropy_matches_shannon_formula():
    gen = scanner()
    for sample in (GENERIC, SLACK, "s3cr3t-Value_2026"):
        assert gen.entropy(sample) == shannon(sample)


def test_tokenize_reports_line_and_column():
    gen = scanner()
    tokens = gen.tokenize("key=" + AWS + "\nnext " + AWS + "\n")
    assert [(tok.value, tok.line, tok.column) for tok in tokens] == [
        (AWS, 1, 5),
        (AWS, 2, 6),
    ]


def test_tokenize_drops_short_runs_and_empty_text():
    gen = scanner()
    assert gen.tokenize("ab=cd ef") == []
    assert gen.tokenize("") == []


def test_placeholder_detection_covers_vocabulary_and_degenerate_runs():
    gen = scanner()
    assert gen.is_placeholder("changeme") is True
    assert gen.is_placeholder("CHANGEME") is True
    assert gen.is_placeholder("your_key_here") is True
    assert gen.is_placeholder("aaaaaaaaaaaa") is True
    assert gen.is_placeholder(AWS) is False


def test_match_rule_picks_prefix_rules_in_order():
    gen = scanner()
    assert gen.match_rule(AWS).name == "aws_access_key"
    assert gen.match_rule(AWS).severity == "high"
    assert gen.match_rule(SLACK).name == "slack_bot_token"
    assert gen.match_rule(GENERIC).name == "generic_api_key"


def test_match_rule_rejects_low_entropy_token_with_prefix():
    gen = scanner()
    assert gen.entropy(LOW_ENTROPY) < 3.0
    assert gen.match_rule(LOW_ENTROPY) is None


def test_scan_text_reports_masked_finding_with_position():
    gen = scanner()
    findings = gen.scan_text("token: " + AWS + "\n", path="app/config.py")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "aws_access_key"
    assert finding.severity == "high"
    assert finding.path == "app/config.py"
    assert finding.line == 1
    assert finding.column == 8
    assert finding.preview == "AKIA***"
    assert AWS not in finding.preview
    assert gen.stats()["findings"] == 1


def test_scan_text_suppresses_placeholder_values():
    gen = scanner()
    findings = gen.scan_text("changeme\n" + AWS + "\n", path="app/settings.py")
    assert len(findings) == 1
    assert findings[0].rule == "aws_access_key"
    assert gen.stats()["suppressed"] == 1


def test_scan_text_ignores_tokens_matching_no_rule():
    gen = scanner()
    assert gen.scan_text("configuration microservice\n", path="app/notes.py") == []
    assert gen.stats()["tokens"] == 2
    assert gen.stats()["findings"] == 0


def test_repeat_in_same_file_merges_to_earliest_position():
    gen = scanner()
    findings = gen.scan_text("a\n" + AWS + "\nb " + AWS + "\n", path="app/keys.py")
    assert len(findings) == 1
    assert findings[0].line == 2
    assert gen.stats()["duplicates"] == 1


def test_two_rules_fire_independently():
    gen = scanner()
    findings = gen.scan_text(AWS + "\n" + SLACK + "\n", path="app/creds.py")
    assert [finding.rule for finding in findings] == ["aws_access_key", "slack_bot_token"]
    assert len(gen.findings_for("slack_bot_token")) == 1
    assert gen.findings_for("missing_rule") == ()


def test_cross_file_repeat_keeps_first_scanned_path():
    gen = scanner()
    gen.scan_files({"a.py": "k=" + AWS + "\n", "b.py": "k=" + AWS + "\n"})
    assert [finding.path for finding in gen.findings()] == ["a.py"]
    assert gen.stats()["duplicates"] == 1
    assert gen.stats()["scans"] == 2


def test_custom_rule_and_severity_ordered_report():
    gen = scanner()
    gen.add_rule("internal_hex", prefix="int-", min_length=18, max_length=40,
                 min_entropy=2.5, severity="low")
    text = AWS + "\n" + SLACK + "\n" + CUSTOM + "\n" + GENERIC + "\n"
    gen.scan_text(text, path="z.py")
    assert [finding.rule for finding in gen.report()] == [
        "aws_access_key",
        "slack_bot_token",
        "generic_api_key",
        "internal_hex",
    ]


def test_snapshot_restore_roundtrip_and_invalid_state():
    gen = scanner()
    gen.scan_text("k=" + AWS + "\n", path="a.py")
    state = gen.snapshot()
    assert set(state) == {"version", "rules", "findings", "seen", "counters"}
    pristine = copy.deepcopy(state)

    state["findings"].clear()
    assert len(gen.findings()) == 1

    clone = scanner()
    clone.restore(pristine)
    assert len(clone.findings()) == 1
    assert clone.findings()[0].path == "a.py"
    assert clone.stats()["findings"] == 1
    assert clone.stats()["restored"] == 1

    with pytest.raises(se.ScanError) as exc:
        clone.restore({"version": 1})
    assert exc.value.code == "SCAN_SNAPSHOT_INVALID"
    assert len(clone.findings()) == 1
    assert clone.stats()["restored"] == 1
