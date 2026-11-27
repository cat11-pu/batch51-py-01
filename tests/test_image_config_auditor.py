import copy
import dataclasses
import json
import threading

import pytest

import image_config_auditor as ica

DIGEST = "sha256:" + "a" * 64


def payload(**overrides):
    base = {
        "image": "registry.local/app:1.3",
        "digest": DIGEST,
        "user": "app",
        "entrypoint": ["/usr/bin/app", "--serve"],
        "env": {"GREETING": "hi"},
        "exposed_ports": [8080],
        "volumes": [],
        "healthcheck": {"test": ["CMD", "true"]},
        "stage": "final",
        "layers": [],
    }
    base.update(overrides)
    return base


def load(**overrides):
    auditor = ica.ImageConfigAuditor()
    return auditor, auditor.load_config(payload(**overrides))


def test_load_config_normalises_final_stage():
    auditor, config = load(
        env={"DB_PASSWORD": "s3cr3t-value", "GREETING": "hi"},
        exposed_ports=[80, "8443/tcp"],
        volumes=["/data"],
        layers=[
            {
                "index": 0,
                "stage": "build",
                "created_by": "RUN make",
                "env": {"OLD_TOKEN": "abc"},
                "deleted_files": ["/app/.env"],
            }
        ],
    )
    assert config.image == "registry.local/app:1.3"
    assert config.digest == DIGEST
    assert config.user == "app"
    assert config.entrypoint == ("/usr/bin/app", "--serve")
    assert [(entry.key, entry.layer, entry.source) for entry in config.env] == [
        ("DB_PASSWORD", None, "config"),
        ("GREETING", None, "config"),
    ]
    assert config.exposed_ports == (80, 8443)
    assert config.volumes == ("/data",)
    assert len(config.layers) == 1
    assert config.layers[0].env == (("OLD_TOKEN", "abc"),)
    assert config.layers[0].deleted_files == ("/app/.env",)
    assert auditor.stats()["loads"] == 1


def test_load_config_keeps_shell_entrypoint_and_pair_list_env():
    auditor, config = load(
        entrypoint="sh -c '/usr/bin/app'",
        env=[["A", "1"], ["B", "2"]],
        exposed_ports=["8080"],
    )
    assert config.entrypoint == "sh -c '/usr/bin/app'"
    assert [(entry.key, entry.value) for entry in config.env] == [("A", "1"), ("B", "2")]
    assert config.exposed_ports == (8080,)


def test_load_config_rejects_malformed_payloads():
    cases = [
        {"image": ""},
        {"image": 5},
        {"digest": "sha256:xyz"},
        {"digest": "md5:" + "a" * 32},
        {"exposed_ports": ["22/http"]},
        {"env": [["A"]]},
        {"env": "A=1"},
        {"entrypoint": [1, 2]},
        {"layers": [{"index": 0}]},
    ]
    for overrides in cases:
        with pytest.raises(ica.ImageAuditError) as exc:
            ica.ImageConfigAuditor().load_config(payload(**overrides))
        assert exc.value.code == "IMAGE_CONFIG_INVALID"


def test_layer_and_size_limits_are_enforced():
    layers = [
        {"index": index, "stage": "build", "created_by": f"RUN step {index}"}
        for index in range(3)
    ]
    with pytest.raises(ica.ImageAuditError) as exc:
        ica.ImageConfigAuditor(max_layers=2).load_config(payload(layers=layers))
    assert exc.value.code == "IMAGE_LIMIT_EXCEEDED"

    with pytest.raises(ica.ImageAuditError) as exc:
        ica.ImageConfigAuditor(max_config_bytes=10).load_config(payload())
    assert exc.value.code == "IMAGE_LIMIT_EXCEEDED"


def test_root_user_variants_are_high_severity():
    auditor = ica.ImageConfigAuditor()
    for user in ("root", "", "   "):
        findings = auditor.audit_user(user)
        assert [(finding.code, finding.severity) for finding in findings] == [
            ("IMAGE_ROOT_USER", "high")
        ]

    loaded, _ = load(user=None)
    assert [finding.code for finding in loaded.audit_user()] == ["IMAGE_ROOT_USER"]


def test_non_root_users_pass_audit():
    auditor, _ = load(user="app")
    assert auditor.audit_user() == ()
    assert auditor.audit_user("app") == ()
    assert auditor.audit_user("1000") == ()


def test_env_secret_key_reports_only_key_and_length():
    auditor, _ = load(env={"DB_PASSWORD": "s3cr3t-value", "GREETING": "hi"})
    findings = auditor.scan_env()
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.code, finding.severity) == ("IMAGE_ENV_SECRET", "high")
    assert finding.detail["key"] == "DB_PASSWORD"
    assert finding.detail["length"] == len("s3cr3t-value")
    assert finding.layer is None
    rendered = json.dumps(dataclasses.asdict(finding))
    assert "s3cr3t-value" not in rendered


def test_connection_string_value_is_flagged():
    auditor, _ = load(
        env={"DATABASE_URL": "postgres://svc:pw@db.internal/app", "GREETING": "hi"}
    )
    findings = auditor.scan_env()
    assert [finding.code for finding in findings] == ["IMAGE_ENV_CONNSTR"]
    assert findings[0].detail["key"] == "DATABASE_URL"
    assert findings[0].detail["length"] == len("postgres://svc:pw@db.internal/app")


def test_entrypoint_form_is_graded():
    auditor, _ = load(entrypoint="sh -c '/usr/bin/app'")
    findings = auditor.check_entrypoint()
    assert [(finding.code, finding.severity) for finding in findings] == [
        ("IMAGE_SHELL_ENTRYPOINT", "medium")
    ]
    assert findings[0].detail["form"] == "shell"

    exec_form, _ = load(entrypoint=["/usr/bin/app"])
    assert exec_form.check_entrypoint() == ()

    missing, _ = load(entrypoint=None)
    assert [(finding.code, finding.severity) for finding in missing.check_entrypoint()] == [
        ("IMAGE_NO_ENTRYPOINT", "low")
    ]


def test_privileged_ports_are_flagged():
    auditor, _ = load(exposed_ports=[443, 22, 8080])
    findings = auditor.check_ports()
    assert [(finding.code, finding.detail["port"]) for finding in findings] == [
        ("IMAGE_PRIVILEGED_PORT", 22),
        ("IMAGE_PRIVILEGED_PORT", 443),
    ]
    assert {finding.severity for finding in findings} == {"high"}

    plain, _ = load(exposed_ports=[8080])
    assert plain.check_ports() == ()


def test_base_image_requires_digest_pin():
    auditor, _ = load(digest=None)
    findings = auditor.check_base_image()
    assert [(finding.code, finding.severity) for finding in findings] == [
        ("IMAGE_UNPINNED_BASE", "medium")
    ]
    pinned, _ = load(digest=DIGEST)
    assert pinned.check_base_image() == ()


def test_deleted_files_in_layer_history_still_count():
    auditor, _ = load(
        layers=[
            {
                "index": 0,
                "stage": "build",
                "created_by": "RUN build",
                "deleted_files": ["/app/.env", "/root/.aws/credentials"],
            },
            {
                "index": 1,
                "stage": "final",
                "created_by": "RUN cleanup",
                "deleted_files": [],
            },
        ]
    )
    findings = auditor.check_layers()
    assert [
        (finding.code, finding.layer, finding.detail["path"]) for finding in findings
    ] == [
        ("IMAGE_DELETED_FILE_LEAK", 0, "/app/.env"),
        ("IMAGE_DELETED_FILE_LEAK", 0, "/root/.aws/credentials"),
    ]
    assert {finding.severity for finding in findings} == {"high"}

    clean, _ = load(layers=[])
    assert clean.check_layers() == ()


def test_audit_orders_findings_and_report_has_no_secret_value():
    auditor, _ = load(
        user="root",
        digest=None,
        entrypoint="sh -c app",
        env={"DB_PASSWORD": "s3cr3t"},
        exposed_ports=[22],
        healthcheck=None,
        layers=[
            {
                "index": 0,
                "stage": "build",
                "created_by": "RUN x",
                "deleted_files": ["/app/.env"],
            }
        ],
    )
    findings = auditor.audit()
    assert [finding.code for finding in findings] == [
        "IMAGE_DELETED_FILE_LEAK",
        "IMAGE_ENV_SECRET",
        "IMAGE_PRIVILEGED_PORT",
        "IMAGE_ROOT_USER",
        "IMAGE_SHELL_ENTRYPOINT",
        "IMAGE_UNPINNED_BASE",
        "IMAGE_NO_HEALTHCHECK",
    ]
    report = auditor.report()
    assert set(report) == {"image", "digest_pinned", "verdict", "counts", "findings", "audits"}
    assert report["counts"] == {"high": 4, "medium": 2, "low": 1}
    assert report["verdict"] == "fail"
    assert report["digest_pinned"] is False
    assert report["audits"] == 1
    assert "s3cr3t" not in json.dumps(report)
    assert auditor.stats()["audits"] == 1


def test_concurrent_audits_are_stable():
    auditor, _ = load(user="root", env={"DB_PASSWORD": "x"}, exposed_ports=[22])
    baseline = len(auditor.audit())
    assert baseline == 3

    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(len(auditor.audit()))
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert results == [baseline] * 8
    assert auditor.stats()["audits"] == 9
    assert len(auditor.report()["findings"]) == baseline


def test_snapshot_restore_roundtrip_and_invalid_state():
    auditor, _ = load(user="root", env={"DB_PASSWORD": "s3cr3t"})
    auditor.audit()
    state = auditor.snapshot()
    assert set(state) == {"version", "config", "findings", "stats"}
    pristine = copy.deepcopy(state)
    state["findings"].clear()
    state["stats"]["audits"] = 99
    state["config"]["user"] = "app"
    assert len(auditor.report()["findings"]) == 2
    assert auditor.stats()["audits"] == 1

    clone = ica.ImageConfigAuditor()
    clone.restore(pristine)
    assert clone.stats() == auditor.stats()
    assert [row["code"] for row in clone.report()["findings"]] == [
        "IMAGE_ENV_SECRET",
        "IMAGE_ROOT_USER",
    ]

    for bad in ({}, None, {"version": 1}, {"version": 1, "config": {},
                                         "findings": "nope", "stats": {}}):
        with pytest.raises(ica.ImageAuditError) as exc:
            clone.restore(bad)
        assert exc.value.code == "IMAGE_SNAPSHOT_INVALID"
    assert clone.stats()["audits"] == 1
