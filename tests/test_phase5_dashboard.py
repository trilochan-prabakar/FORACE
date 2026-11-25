import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from forace.auth import generate_key, sign_baseline
from forace.baseline import create_baseline, save_baseline
from forace.dashboard_data import (
    filter_findings, get_audit_status, get_baseline_status,
    get_database_status, get_monitor_status, load_evaluation_results,
    load_audit_events, load_findings,
)
import forace.dashboard_data as dashboard_data
from forace.monitor_status import write_monitor_status
from forace.store import initialize_database, store_finding_once
from streamlit.testing.v1 import AppTest


def test_missing_database_does_not_create_a_file(tmp_path):
    db = tmp_path / "missing" / "state.sqlite"
    status = get_database_status(db)
    assert status["status"] == "missing"
    assert not db.exists()
    assert load_findings(db)["findings"] == []


def test_dashboard_renders_when_selected_database_is_missing(tmp_path):
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    app.sidebar.text_input[0].set_value(str(tmp_path / "missing" / "state.sqlite")).run()
    assert not app.exception


def test_dashboard_reads_real_findings_and_applies_search_and_severity_filters(tmp_path):
    db = tmp_path / "state.sqlite"
    initialize_database(db)
    store_finding_once(db, {"file_path": "etc/ssh/sshd_config", "change_type": "PermitRootLogin=yes",
                            "rule_id": "R01", "severity": "High", "attack_id": "T1021.004",
                            "explanation": "Root SSH login was enabled"}, "a" * 64)
    loaded = load_findings(db)
    assert loaded["status"] == "available"
    assert loaded["count"] == 1
    assert filter_findings(loaded["findings"], search="root ssh", severities={"High"}) == loaded["findings"]
    assert filter_findings(loaded["findings"], severities={"Critical"}) == []
    assert get_database_status(db)["status"] == "available"
    assert get_audit_status(db)["status"] == "valid"
    events = load_audit_events(db)["events"]
    assert events[0]["event_type"] == "finding"
    assert events[0]["summary"] == "Root SSH login was enabled"


def test_invalid_database_is_not_treated_as_available(tmp_path):
    db = tmp_path / "bad.sqlite"
    db.write_bytes(b"not sqlite")
    assert get_database_status(db)["status"] == "error"
    assert load_findings(db)["status"] == "error"


def test_findings_return_error_if_database_disappears_after_status_check(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite"
    initialize_database(db)
    real_read = dashboard_data._read_connection
    calls = 0

    def disappear(path):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise FileNotFoundError("database disappeared")
        return real_read(path)

    monkeypatch.setattr(dashboard_data, "_read_connection", disappear)
    assert dashboard_data.load_findings(db)["status"] == "error"


def test_baseline_authentication_status_distinguishes_missing_and_valid(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    baseline = tmp_path / "baseline.json"
    save_baseline(create_baseline(lab), baseline)
    key, signature = tmp_path / "key", tmp_path / "baseline.hmac"
    assert get_baseline_status(baseline, key, signature)["status"] == "failed"
    generate_key(key)
    sign_baseline(baseline, key, signature)
    assert get_baseline_status(baseline, key, signature)["status"] == "verified"
    baseline.write_bytes(baseline.read_bytes() + b" ")
    assert get_baseline_status(baseline, key, signature)["status"] == "failed"


def test_baseline_authentication_reports_artifact_availability_separately(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    baseline = tmp_path / "baseline.json"
    key = tmp_path / "key"
    signature = tmp_path / "baseline.hmac"

    missing = get_baseline_status(baseline, key, signature)
    assert (missing["baseline_available"], missing["key_available"], missing["signature_available"]) == (False, False, False)
    assert missing["status"] == "failed"

    save_baseline(create_baseline(lab), baseline)
    missing_key = get_baseline_status(baseline, key, signature)
    assert (missing_key["baseline_available"], missing_key["key_available"], missing_key["signature_available"]) == (True, False, False)
    assert missing_key["status"] == "failed"

    key_bytes = generate_key(key)
    key_only = get_baseline_status(baseline, key, signature)
    assert (key_only["baseline_available"], key_only["key_available"], key_only["signature_available"]) == (True, True, False)
    assert key_only["status"] == "failed"

    sign_baseline(baseline, key, signature)
    verified = get_baseline_status(baseline, key, signature)
    assert (verified["baseline_available"], verified["key_available"], verified["signature_available"]) == (True, True, True)
    assert verified["status"] == "verified"
    assert key_bytes.hex() not in repr(verified)


def test_monitor_status_is_not_green_when_missing_or_stale(tmp_path):
    status_file = tmp_path / "monitor.json"
    assert get_monitor_status(status_file)["status"] == "not_running"
    write_monitor_status(status_file, root="/tmp/lab", mode="smart", pid=os.getpid())
    current = get_monitor_status(status_file, now=datetime.now(timezone.utc))
    assert current["status"] == "running"
    assert current["last_error"] is None
    assert get_monitor_status(status_file, now=datetime.now(timezone.utc).replace(year=2000))["status"] == "not_running"


def test_monitor_status_surfaces_current_scan_error_without_losing_liveness(tmp_path):
    status_file = tmp_path / "monitor.json"
    write_monitor_status(status_file, root="/tmp/lab", mode="smart", pid=os.getpid(),
                         last_error="Periodic reconciliation failed")

    status = get_monitor_status(status_file, now=datetime.now(timezone.utc))

    assert status["status"] == "running"
    assert status["last_error"] == "Periodic reconciliation failed"


def test_monitor_status_rejects_a_fresh_heartbeat_with_dead_process(tmp_path):
    status_file = tmp_path / "monitor.json"
    write_monitor_status(status_file, root="/tmp/lab", mode="smart", pid=2_000_000_000)

    assert get_monitor_status(status_file, now=datetime.now(timezone.utc))["status"] == "not_running"


def test_monitor_status_rejects_malformed_process_ids(tmp_path):
    status_file = tmp_path / "monitor.json"
    for invalid_pid in (0, -1, True, "1", 10**100):
        write_monitor_status(status_file, root="/tmp/lab", mode="smart", pid=invalid_pid)
        assert get_monitor_status(status_file, now=datetime.now(timezone.utc))["status"] == "not_running"


def test_baseline_authentication_rejects_wrong_key_and_malformed_trust_files(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    baseline = tmp_path / "baseline.json"
    save_baseline(create_baseline(lab), baseline)
    key = tmp_path / "baseline.key"
    signature = tmp_path / "baseline.hmac"
    original_key = generate_key(key)
    sign_baseline(baseline, key, signature)
    wrong_key = tmp_path / "wrong.key"
    generate_key(wrong_key)

    key.write_bytes(wrong_key.read_bytes())
    mismatched = get_baseline_status(baseline, key, signature)
    assert mismatched["status"] == "failed"
    assert (mismatched["baseline_available"], mismatched["key_available"], mismatched["signature_available"]) == (True, True, True)

    key.write_bytes(b"short")
    malformed_key = get_baseline_status(baseline, key, signature)
    assert malformed_key["status"] == "failed"
    assert (malformed_key["baseline_available"], malformed_key["key_available"], malformed_key["signature_available"]) == (True, True, True)

    key.write_bytes(original_key)
    signature.write_text("not-a-signature", encoding="ascii")
    malformed_signature = get_baseline_status(baseline, key, signature)
    assert malformed_signature["status"] == "failed"
    assert (malformed_signature["baseline_available"], malformed_signature["key_available"], malformed_signature["signature_available"]) == (True, True, True)


def test_evaluation_csv_is_loaded_from_actual_rows_and_missing_file_is_clear(tmp_path):
    csv_path = tmp_path / "results.csv"
    fields = ["scenario_id", "category", "description", "expected_rule_id", "smart_expected_rule_detected",
              "smart_finding_count", "smart_rule_ids", "smart_findings_json", "hash_only_change_detected",
              "hash_only_finding_count", "hash_only_findings_json", "false_positive", "false_negative",
              "benign_correctly_handled", "explanation_covered", "attack_mapping_covered"]
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerow(dict.fromkeys(fields, "" ) | {"scenario_id": "R01", "category": "attack",
                         "expected_rule_id": "R01", "smart_expected_rule_detected": "True",
                         "smart_finding_count": "1", "hash_only_finding_count": "1",
                         "hash_only_change_detected": "True", "false_positive": "False",
                         "false_negative": "False", "benign_correctly_handled": "False",
                         "explanation_covered": "True", "attack_mapping_covered": "True"})
    result = load_evaluation_results(csv_path)
    assert result["status"] == "available"
    assert result["metrics"]["detection_rate"] == 1.0
    assert load_evaluation_results(tmp_path / "absent.csv")["status"] == "missing"
