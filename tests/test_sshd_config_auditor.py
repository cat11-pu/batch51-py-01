import copy
import threading

import pytest

import sshd_config_auditor as ssh

DEFAULTS = {"ciphers": ("c1", "c2", "c3"), "macs": ("m1", "m2"),
            "kexalgorithms": ("k1",)}

FLEET = """# fleet baseline
Port 22

Match User=deploy Address=10.0.0.0/8
  PermitRootLogin no
  MaxAuthTries 2
  X11Forwarding no
"""


def auditor(**kwargs):
    params = {"defaults": dict(DEFAULTS), "strict_ciphers": ("c1", "c2", "c3")}
    params.update(kwargs)
    return ssh.SshdConfigAuditor(**params)


def loaded(text, **kwargs):
    inst = auditor(**kwargs)
    inst.reload(text, source="unit-test")
    return inst


def test_parse_registers_lowercase_keywords_with_lines():
    cfg = auditor().parse_config(FLEET, source="/etc/ssh/sshd_config")
    assert isinstance(cfg, ssh.ParsedConfig)
    assert cfg.source == "/etc/ssh/sshd_config"
    assert [d.keyword for d in cfg.directives] == [
        "port", "permitrootlogin", "maxauthtries", "x11forwarding"]
    assert [d.line for d in cfg.directives] == [2, 5, 6, 7]
    assert [d.block for d in cfg.directives] == [-1, 0, 0, 0]
    assert [d.value for d in cfg.directives] == ["22", "no", "2", "no"]
    assert len(cfg.matches) == 1
    assert cfg.matches[0].index == 0
    assert cfg.matches[0].line == 4
    assert cfg.matches[0].criteria == (("user", "deploy"), ("address", "10.0.0.0/8"))


def test_parse_rejects_unknown_match_criterion():
    text = "Port 22\nMatch User=deploy Realm=internal\n  X11Forwarding no\n"
    with pytest.raises(ssh.SshdAuditError) as exc:
        auditor().parse_config(text)
    assert exc.value.code == "SSHD_PARSE_FAILED"
    assert exc.value.detail["line"] == 2
    assert "realm" in exc.value.detail["message"]


def test_parse_rejects_directive_without_value():
    with pytest.raises(ssh.SshdAuditError) as exc:
        auditor().parse_config("Port 22\nBanner\n")
    assert exc.value.code == "SSHD_PARSE_FAILED"
    assert exc.value.detail["line"] == 2


def test_last_global_directive_wins_and_absent_keyword_is_none():
    inst = loaded("Port 22\nMaxAuthTries 6\nPort 2222\n")
    assert inst.effective_value("port") == "2222"
    assert inst.effective_value("MAXAUTHTRIES") == "6"
    assert inst.effective_value("banner") is None
    assert inst.effective_config() == {"port": "2222", "maxauthtries": "6"}


def test_effective_list_dedupes_and_keeps_first_occurrence_order():
    inst = loaded("Ciphers c3,c1,c3,c2\n")
    assert inst.effective_list("ciphers") == ("c3", "c1", "c2")
    inst.reload("Ciphers c1\n")
    assert inst.effective_list("ciphers") == ("c1",)


def test_match_directive_is_visible_only_inside_matching_context():
    inst = loaded(FLEET)
    deploy = {"user": "deploy", "address": "10.1.2.3"}
    elsewhere = {"user": "deploy", "address": "192.168.1.5"}
    assert inst.effective_value("permitrootlogin", context=deploy) == "no"
    assert inst.effective_value("permitrootlogin", context=elsewhere) is None
    assert inst.effective_value("permitrootlogin", context={}) is None
    assert inst.effective_value("port", context=deploy) == "22"


def test_match_applies_requires_every_criterion_to_hold():
    text = ("Match User=deploy-* Address=10.0.0.0/8 LocalPort=2222\n"
            "  X11Forwarding no\n")
    inst = loaded(text)
    assert inst.match_applies(0, context={
        "user": "deploy-prod", "address": "10.9.9.9", "localport": "2222"}) is True
    assert inst.match_applies(0, context={
        "user": "deploy-prod", "address": "10.9.9.9", "localport": "22"}) is False
    assert inst.match_applies(0, context={
        "user": "auditor", "address": "10.9.9.9", "localport": "2222"}) is False


def test_audit_allows_hardened_configuration():
    inst = loaded("PermitRootLogin no\nPasswordAuthentication no\n"
                  "MaxAuthTries 3\nCiphers c2,c1\n")
    report = inst.audit()
    assert isinstance(report, ssh.AuditReport)
    assert report.version == 1
    assert report.context == {}
    assert report.verdict == "allow"
    assert report.counts == {"ok": 4, "deny": 0}
    assert [f.keyword for f in report.findings] == list(ssh.CHECK_ORDER)
    assert [f.verdict for f in report.findings] == ["ok", "ok", "ok", "ok"]
    assert report.findings[0].effective == "no"


def test_audit_denies_every_regressed_check():
    inst = loaded("PermitRootLogin yes\nPasswordAuthentication yes\n"
                  "MaxAuthTries 6\nCiphers c1,c3\n",
                  strict_ciphers=("c1", "c2"))
    report = inst.audit()
    assert report.verdict == "deny"
    assert report.counts == {"ok": 0, "deny": 4}
    assert [f.verdict for f in report.findings] == ["deny"] * 4
    assert report.findings[3].effective == "c1,c3"


def test_require_compliant_raises_policy_refusal_with_failed_keywords():
    inst = loaded("PermitRootLogin yes\nPasswordAuthentication no\n"
                  "MaxAuthTries 3\nCiphers c1\n")
    with pytest.raises(ssh.SshdAuditError) as exc:
        inst.require_compliant()
    assert exc.value.code == "SSHD_POLICY_REFUSED"
    assert tuple(exc.value.detail["failed"]) == ("permitrootlogin",)

    inst.reload("PermitRootLogin no\nPasswordAuthentication no\n"
                "MaxAuthTries 3\nCiphers c1\n")
    report = inst.require_compliant()
    assert report.verdict == "allow"
    assert report.version == 2


def test_failed_reload_keeps_old_configuration_and_counts_failure():
    inst = loaded("Port 22\n")
    assert inst.current_version() == 1
    with pytest.raises(ssh.SshdAuditError) as exc:
        inst.reload("Port\n")
    assert exc.value.code == "SSHD_PARSE_FAILED"
    assert inst.current_version() == 1
    assert inst.effective_value("port") == "22"
    assert inst.stats() == {"parses": 2, "reloads": 1, "failed_reloads": 1,
                            "audits": 0, "restores": 0}
    assert inst.reload("Port 2200\n") == 2


def test_diff_reports_global_changes_sorted_by_keyword():
    inst = loaded("Port 22\nMaxAuthTries 6\nPermitRootLogin no\n")
    other = inst.parse_config("Port 2222\nMaxAuthTries 6\nPermitRootLogin no\n"
                              "PasswordAuthentication no\n")
    changes = inst.diff(other)
    assert [type(c) for c in changes] == [ssh.ConfigChange, ssh.ConfigChange]
    assert [(c.keyword, c.before, c.after) for c in changes] == [
        ("passwordauthentication", None, "no"),
        ("port", "22", "2222"),
    ]


def test_snapshot_is_detached_and_restore_roundtrips():
    inst = loaded("Port 22\nCiphers c2,c1\n")
    state = inst.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "config", "stats"}

    state["config"].clear()
    state["stats"]["parses"] = 999
    assert inst.effective_value("port") == "22"
    assert inst.stats()["parses"] == 1

    clone = auditor()
    clone.restore(pristine)
    assert clone.current_version() == 1
    assert clone.effective_value("port") == "22"
    assert clone.effective_list("ciphers") == ("c2", "c1")
    assert clone.stats()["parses"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    inst = loaded("Port 22\n")
    bad_states = [
        None,
        {},
        {"version": 1, "config": None, "stats": {}},
        {"version": "1", "config": {}, "stats": {}},
        {"version": 1, "config": {}, "stats": []},
    ]
    for bad in bad_states:
        with pytest.raises(ssh.SshdAuditError) as exc:
            inst.restore(bad)
        assert exc.value.code == "SSHD_SNAPSHOT_INVALID"
    assert inst.current_version() == 1
    assert inst.effective_value("port") == "22"


def test_concurrent_reload_and_audit_observe_a_single_version():
    inst = auditor()
    allow_text = ("PermitRootLogin no\nPasswordAuthentication no\n"
                  "MaxAuthTries 3\nCiphers c1\n")
    deny_text = ("PermitRootLogin yes\nPasswordAuthentication no\n"
                 "MaxAuthTries 3\nCiphers c1\n")
    inst.reload(allow_text, source="v1")

    errors = []
    ready = threading.Event()
    stop = threading.Event()

    def reloader():
        try:
            for name, text in [("deny", deny_text), ("allow", allow_text)] * 6:
                inst.reload(text, source=name)
                ready.set()
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))
            ready.set()
        finally:
            stop.set()

    seen = []

    def watcher():
        ready.wait(5)
        try:
            while True:
                report = inst.audit()
                seen.append((report.version, report.verdict))
                if stop.is_set():
                    break
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=reloader), threading.Thread(target=watcher)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)

    assert errors == []
    assert seen
    for version, verdict in seen:
        assert version >= 1
        assert verdict == ("allow" if version % 2 == 1 else "deny")
    assert inst.current_version() == 13
