import copy
import threading

import pytest

import authenticator_clone_detector as acd

T0 = 1_800_000_000


def detector(**kwargs):
    return acd.CloneDetector(**kwargs)


def seeded(account="acct-1", credential="cred-1", **kwargs):
    det = detector(**kwargs)
    det.register_credential(account, credential_id=credential, at=T0)
    return det


def test_register_creates_active_credential_with_zero_watermark():
    det = detector()
    view = det.register_credential("acct-1", credential_id="cred-2", at=T0)
    assert view.account == "acct-1"
    assert view.credential_id == "cred-2"
    assert view.status == "active"
    assert view.counter_capable is True
    assert view.watermark == 0
    assert view.regressions == 0
    det.register_credential("acct-1", credential_id="cred-1", at=T0)
    assert [row.credential_id for row in det.list_credentials("acct-1")] == [
        "cred-1", "cred-2"]
    assert det.stats() == {"credentials": 2, "observations": 0, "regressions": 0,
                           "quarantines": 0, "releases": 0, "revocations": 0}


def test_duplicate_credential_registration_is_refused():
    det = seeded()
    with pytest.raises(acd.CloneDetectorError) as exc:
        det.register_credential("acct-2", credential_id="cred-1", at=T0)
    assert exc.value.code == "CTR_CREDENTIAL_EXISTS"
    assert det.stats()["credentials"] == 1


def test_increasing_counters_raise_watermark():
    det = seeded()
    first = det.observe("acct-1", credential_id="cred-1", counter=7, at=T0)
    assert first.status == "pass"
    assert first.code == "CTR_OK"
    assert first.watermark == 7
    assert first.quarantined is False
    second = det.observe("acct-1", credential_id="cred-1", counter=9, at=T0 + 5)
    assert second.watermark == 9
    assert det.credential_state("cred-1").watermark == 9
    assert det.stats()["observations"] == 2


def test_counter_rollback_warns_and_keeps_watermark():
    det = seeded()
    det.observe("acct-1", credential_id="cred-1", counter=10, at=T0)
    verdict = det.observe("acct-1", credential_id="cred-1", counter=4, at=T0 + 5)
    assert verdict.status == "warn"
    assert verdict.code == "CTR_ROLLBACK"
    assert verdict.watermark == 10
    assert verdict.regressions == 1
    state = det.credential_state("cred-1")
    assert state.watermark == 10
    assert state.regressions == 1
    assert state.status == "active"
    assert det.login_allowed("acct-1", credential_id="cred-1") is True


def test_second_regression_quarantines_credential():
    det = seeded()
    det.observe("acct-1", credential_id="cred-1", counter=10, at=T0)
    det.observe("acct-1", credential_id="cred-1", counter=4, at=T0 + 5)
    verdict = det.observe("acct-1", credential_id="cred-1", counter=3, at=T0 + 10)
    assert verdict.status == "quarantine"
    assert verdict.code == "CTR_REPEAT_REGRESSION"
    assert verdict.quarantined is True
    assert verdict.regressions == 2
    assert det.credential_state("cred-1").status == "quarantined"
    assert det.login_allowed("acct-1", credential_id="cred-1") is False
    assert det.account_summary("acct-1")["quarantined"] == 1
    assert det.stats()["quarantines"] == 1


def test_counterless_authenticator_is_not_a_regression():
    det = detector()
    det.register_credential("acct-1", credential_id="cred-1",
                            counter_capable=False, at=T0)
    verdict = det.observe("acct-1", credential_id="cred-1", counter=0, at=T0)
    assert verdict.status == "pass"
    assert verdict.code == "CTR_NOT_APPLICABLE"
    assert verdict.watermark == 0
    assert verdict.regressions == 0
    assert det.credential_state("cred-1").counter_capable is False


def test_quarantined_credential_is_refused_on_observe():
    det = seeded()
    assert det.quarantine("cred-1", reason="suspected clone", at=T0 + 5) is True
    verdict = det.observe("acct-1", credential_id="cred-1", counter=50, at=T0 + 10)
    assert verdict.status == "deny"
    assert verdict.code == "CTR_QUARANTINED"
    assert verdict.watermark == 0
    assert det.login_allowed("acct-1", credential_id="cred-1") is False


def test_manual_quarantine_is_idempotent_and_reports_state():
    det = seeded()
    det.observe("acct-1", credential_id="cred-1", counter=6, at=T0)
    assert det.quarantine("cred-1", reason="ops", at=T0 + 10) is True
    assert det.quarantine("cred-1", reason="ops", at=T0 + 20) is False
    assert det.credential_state("cred-1").status == "quarantined"
    assert det.account_summary("acct-1") == {"credentials": 1, "active": 0,
                                             "quarantined": 1, "revoked": 0,
                                             "regressions": 0}


def test_review_release_requires_quarantine():
    det = seeded()
    det.quarantine("cred-1", reason="suspected clone", at=T0 + 5)
    view = det.release_after_review("cred-1", reviewer="ops-7", at=T0 + 60)
    assert view.status == "active"
    assert det.login_allowed("acct-1", credential_id="cred-1") is True
    records = det.reviews("cred-1")
    assert len(records) == 1
    assert records[0].reviewer == "ops-7"
    assert records[0].at == T0 + 60
    assert det.stats()["releases"] == 1
    with pytest.raises(acd.CloneDetectorError) as exc:
        det.release_after_review("cred-1", reviewer="ops-7", at=T0 + 120)
    assert exc.value.code == "CTR_NOT_QUARANTINED"


def test_unknown_credentials_are_refused():
    det = seeded()
    with pytest.raises(acd.CloneDetectorError) as exc:
        det.observe("acct-1", credential_id="cred-9", counter=1, at=T0)
    assert exc.value.code == "CTR_UNKNOWN_CREDENTIAL"
    with pytest.raises(acd.CloneDetectorError) as exc:
        det.observe("acct-2", credential_id="cred-1", counter=1, at=T0)
    assert exc.value.code == "CTR_UNKNOWN_CREDENTIAL"
    with pytest.raises(acd.CloneDetectorError) as exc:
        det.credential_state("cred-9")
    assert exc.value.code == "CTR_UNKNOWN_CREDENTIAL"
    with pytest.raises(acd.CloneDetectorError) as exc:
        det.login_allowed("acct-2", credential_id="cred-1")
    assert exc.value.code == "CTR_UNKNOWN_CREDENTIAL"


def test_invalid_counter_values_are_refused():
    det = seeded()
    for bad in (-1, "5", True, 3.5):
        with pytest.raises(acd.CloneDetectorError) as exc:
            det.observe("acct-1", credential_id="cred-1", counter=bad, at=T0)
        assert exc.value.code == "CTR_INVALID_COUNTER"
    assert det.credential_state("cred-1").watermark == 0
    assert det.stats()["observations"] == 0


def test_revoked_credential_stops_observations_and_login():
    det = seeded()
    assert det.revoke_credential("cred-1") is True
    assert det.revoke_credential("cred-1") is False
    verdict = det.observe("acct-1", credential_id="cred-1", counter=12, at=T0)
    assert verdict.status == "deny"
    assert verdict.code == "CTR_CREDENTIAL_REVOKED"
    assert det.login_allowed("acct-1", credential_id="cred-1") is False
    assert det.account_summary("acct-1")["revoked"] == 1
    assert det.stats()["revocations"] == 1


def test_account_summary_and_stats_count_each_credential():
    det = detector()
    det.register_credential("acct-1", credential_id="cred-1", at=T0)
    det.register_credential("acct-1", credential_id="cred-2", at=T0)
    det.register_credential("acct-2", credential_id="cred-3", at=T0)
    det.quarantine("cred-2", reason="ops", at=T0 + 5)
    det.observe("acct-1", credential_id="cred-1", counter=5, at=T0 + 10)
    summary = det.account_summary("acct-1")
    assert summary == {"credentials": 2, "active": 1, "quarantined": 1,
                       "revoked": 0, "regressions": 0}
    assert det.account_summary("acct-2")["credentials"] == 1
    assert det.stats()["credentials"] == 3
    assert det.stats()["quarantines"] == 1
    assert det.stats()["observations"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    det = seeded()
    det.observe("acct-1", credential_id="cred-1", counter=11, at=T0)
    det.quarantine("cred-1", reason="suspected clone", at=T0 + 5)
    det.release_after_review("cred-1", reviewer="ops-7", at=T0 + 30)
    state = det.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "credentials", "reviews", "stats"}
    state["credentials"].clear()
    state["reviews"].clear()
    state["stats"]["observations"] = 99
    assert det.stats()["observations"] == 1
    assert det.credential_state("cred-1").watermark == 11
    clone = detector()
    clone.restore(pristine)
    assert clone.stats() == det.stats()
    assert clone.credential_state("cred-1") == det.credential_state("cred-1")
    assert clone.login_allowed("acct-1", credential_id="cred-1") is True
    assert [row.reviewer for row in clone.reviews("cred-1")] == ["ops-7"]
    assert clone.observe("acct-1", credential_id="cred-1",
                         counter=12, at=T0 + 60).status == "pass"


def test_concurrent_observation_updates_watermark_once():
    det = seeded()
    verdicts = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            verdicts.append(det.observe("acct-1", credential_id="cred-1",
                                       counter=3, at=T0))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(verdicts) == 8
    assert sum(1 for row in verdicts if row.status == "pass") == 1
    assert sum(1 for row in verdicts if row.regressions == 0) == 1
    state = det.credential_state("cred-1")
    assert state.watermark == 3
    assert state.status == "quarantined"
    assert 1 <= state.regressions <= 7
    assert det.stats()["observations"] == 8
