from pathlib import Path
import sqlite3
import importlib.util
import os
import re
import sys

from streamlit.testing.v1 import AppTest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_dashboard_spec = importlib.util.spec_from_file_location(
    "dashboard", Path(__file__).resolve().parents[1] / "dashboard.py"
)
dashboard = importlib.util.module_from_spec(_dashboard_spec)
_dashboard_spec.loader.exec_module(dashboard)
from integritywatch.auth import generate_key, sign_baseline
from integritywatch.baseline import create_baseline, save_baseline
from integritywatch.dashboard_data import load_file_inventory, sort_findings
import integritywatch.dashboard_data as dashboard_data
from integritywatch.scanner import scan_directory
from integritywatch.store import initialize_database, store_finding_once, verify_audit_chain
from integritywatch.monitor_status import write_monitor_status


def test_project_paths_resolve_relative_values_from_dashboard_directory(tmp_path, monkeypatch):
    project_root = Path(dashboard.__file__).resolve().parent
    monkeypatch.chdir(tmp_path)

    assert dashboard._project_path("data/state.sqlite") == str(project_root / "data/state.sqlite")
    assert dashboard._project_path(tmp_path / "custom.sqlite") == str(tmp_path / "custom.sqlite")


def test_default_paths_stay_with_project_when_launched_elsewhere(tmp_path, monkeypatch):
    project_root = Path(dashboard.__file__).resolve().parent
    monkeypatch.chdir(tmp_path)

    assert dashboard._default_paths() == {
        "db": str(project_root / "data/integritywatch.db"),
        "baseline": str(project_root / "data/baseline.json"),
        "key": str(project_root / "data/baseline.key"),
        "signature": str(project_root / "data/baseline.json.hmac"),
        "monitor": str(project_root / "data/monitor_status.json"),
        "evaluation": str(project_root / "results.csv"),
        "root": str(project_root / "lab"),
    }
    app = AppTest.from_file(project_root / "dashboard.py", default_timeout=20).run()
    assert app.sidebar.text_input(key="iw_db_path").value == str(project_root / "data/integritywatch.db")
    assert app.sidebar.text_input(key="iw_baseline_path").value == str(
        project_root / "data/baseline.json"
    )
    assert app.sidebar.text_input(key="iw_monitor_path").value == str(project_root / "data/monitor_status.json")
    assert all(widget.key != "iw_root_path" for widget in app.sidebar.text_input)
    assert any("Monitored directory" in item.value and "fixed" in item.value.lower()
               for item in app.sidebar.caption)
    assert not app.exception


def test_file_inventory_is_unverified_when_baseline_authentication_fails(tmp_path, monkeypatch):
    root = tmp_path / "lab"
    root.mkdir()
    monkeypatch.setattr(dashboard_data, "PROJECT_ROOT", tmp_path, raising=False)
    (root / "sample.conf").write_text("safe=true\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    save_baseline(create_baseline(root), baseline_path)

    inventory = load_file_inventory(root, baseline_path, tmp_path / "missing.key")

    assert inventory["baseline_status"] == "failed"
    assert inventory["files"][0]["file_path"] == "sample.conf"
    assert inventory["files"][0]["integrity_state"] == "Unverified"
    assert inventory["files"][0]["sha256"]


def test_file_inventory_compares_only_an_authenticated_baseline(tmp_path, monkeypatch):
    root = tmp_path / "lab"
    root.mkdir()
    monkeypatch.setattr(dashboard_data, "PROJECT_ROOT", tmp_path, raising=False)
    file_path = root / "sample.conf"
    file_path.write_text("before=true\n", encoding="utf-8")
    baseline_path, key_path, signature_path = (tmp_path / name for name in ("baseline.json", "key", "sig"))
    save_baseline(create_baseline(root), baseline_path)
    generate_key(key_path)
    sign_baseline(baseline_path, key_path, signature_path)
    file_path.write_text("after=true\n", encoding="utf-8")

    inventory = load_file_inventory(root, baseline_path, key_path, signature_path)

    assert inventory["baseline_status"] == "verified"
    assert inventory["files"][0]["integrity_state"] == "Modified"


def test_file_inventory_rejects_a_symlink_as_the_selected_root(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_data, "PROJECT_ROOT", tmp_path, raising=False)
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "sample.conf").write_text("value=true\n", encoding="utf-8")
    alias = tmp_path / "lab"
    alias.symlink_to(actual, target_is_directory=True)

    try:
        load_file_inventory(alias, tmp_path / "baseline.json", tmp_path / "missing.key")
    except ValueError as error:
        assert "symbolic link" in str(error).lower()
    else:
        raise AssertionError("inventory accepted a symlink as its root")


def test_file_inventory_rejects_parent_traversal_outside_project_lab(tmp_path, monkeypatch):
    project_root = tmp_path / "project"
    lab = project_root / "lab"
    outside = project_root / "outside"
    lab.mkdir(parents=True)
    outside.mkdir()
    monkeypatch.setattr(dashboard_data, "PROJECT_ROOT", project_root, raising=False)

    try:
        load_file_inventory(lab / ".." / "outside", tmp_path / "baseline.json", tmp_path / "missing.key")
    except ValueError as error:
        assert "lab" in str(error).lower()
    else:
        raise AssertionError("inventory accepted a path that traverses outside project lab")


def test_file_inventory_rejects_symlink_escape_in_path_ancestors(tmp_path, monkeypatch):
    project_root = tmp_path / "project"
    lab = project_root / "lab"
    outside_child = project_root / "outside" / "child"
    lab.mkdir(parents=True)
    outside_child.mkdir(parents=True)
    (lab / "escape").symlink_to(project_root / "outside", target_is_directory=True)
    monkeypatch.setattr(dashboard_data, "PROJECT_ROOT", project_root, raising=False)

    try:
        load_file_inventory(lab / "escape" / "child", tmp_path / "baseline.json", tmp_path / "missing.key")
    except ValueError as error:
        assert "lab" in str(error).lower() or "symbolic link" in str(error).lower()
    else:
        raise AssertionError("inventory followed a symlink ancestor outside project lab")


def test_file_inventory_rejects_nonexistent_project_lab_path(tmp_path, monkeypatch):
    project_root = tmp_path / "project"
    (project_root / "lab").mkdir(parents=True)
    outside = project_root / "outside"
    outside.mkdir()
    monkeypatch.setattr(dashboard_data, "PROJECT_ROOT", project_root, raising=False)

    try:
        load_file_inventory(outside, tmp_path / "baseline.json", tmp_path / "missing.key")
    except ValueError as error:
        assert "lab" in str(error).lower()
    else:
        raise AssertionError("inventory accepted a directory outside project lab")

    try:
        load_file_inventory(project_root / "lab" / "missing", tmp_path / "baseline.json",
                            tmp_path / "missing.key")
    except (OSError, ValueError):
        pass
    else:
        raise AssertionError("inventory accepted a nonexistent path")


def test_sort_findings_sorts_timestamps_and_severity_without_mutating_source():
    findings = [
        {"id": 1, "timestamp_utc": "2025-01-01T00:00:00+00:00", "severity": "Low"},
        {"id": 2, "timestamp_utc": "2025-01-02T00:00:00+00:00", "severity": "Critical"},
    ]

    newest = sort_findings(findings, "Newest first")
    critical = sort_findings(findings, "Severity")

    assert [row["id"] for row in newest] == [2, 1]
    assert [row["id"] for row in critical] == [2, 1]
    assert [row["id"] for row in findings] == [1, 2]


def test_all_six_pages_render_and_navigation_switches_page():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    assert not app.exception
    pages = [
        ("Security Findings", "nav_security_findings", "Security Findings"),
        ("File Integrity", "nav_file_integrity", "File Integrity"),
        ("Audit & Verification", "nav_audit_and_verification", "Audit & Verification"),
        ("Evaluation", "nav_evaluation", "Detection Performance & Evaluation"),
        ("Demo / About", "nav_demo_about", "Project Overview"),
        ("Overview", "nav_overview", "IntegrityWatch Lite"),
    ]
    for label, key, page_heading in pages:
        app.sidebar.button(key=key).click().run()
        assert not app.exception
        assert any(page_heading in item.value for item in app.title)


def test_dashboard_view_does_not_modify_baseline_or_database():
    root = Path(__file__).resolve().parents[1]
    protected = [root / "data/baseline.json", root / "data/baseline.key",
                 root / "data/baseline.json.hmac", root / "data/integritywatch.db",
                 root / "data/monitor_status.json"]

    before = {path: (path.read_bytes() if path.exists() else None) for path in protected}
    app = AppTest.from_file(root / "dashboard.py", default_timeout=20).run()
    app.sidebar.button(key="nav_audit_and_verification").click().run()
    app.sidebar.button(key="nav_file_integrity").click().run()
    assert not app.exception
    after = {path: (path.read_bytes() if path.exists() else None) for path in protected}
    assert after == before


def test_findings_page_searches_and_clear_filters_resets_controls(tmp_path):
    db = tmp_path / "events.sqlite"
    initialize_database(db)
    store_finding_once(db, {"file_path": "etc/ssh/sshd_config", "change_type": "PermitRootLogin=yes",
                            "rule_id": "R01", "severity": "High", "attack_id": "T1021.004",
                            "explanation": "Root SSH login was enabled"}, "b" * 64)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    app.sidebar.text_input[0].set_value(str(db)).run()
    app.sidebar.button(key="nav_security_findings").click().run()
    app.text_input(key="iw_findings_search").set_value("does-not-match").run()
    assert any("Showing 0 of 1" in item.value for item in app.caption)
    app.button(key="iw_clear_findings").click().run()
    assert app.text_input(key="iw_findings_search").value == ""
    assert any("Showing 1 of 1" in item.value for item in app.caption)
    assert not app.exception


def test_findings_summary_table_keeps_detail_in_the_investigation_panel(tmp_path):
    db = tmp_path / "events.sqlite"
    initialize_database(db)
    store_finding_once(db, {"file_path": "etc/ssh/" + "very-long-config-name.conf", "change_type": "modified",
                            "rule_id": "R01", "severity": "High", "attack_id": "T1021.004",
                            "explanation": "A long explanation that stays available in the finding details."}, "d" * 64)
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    app.sidebar.text_input(key="iw_db_path").set_value(str(db)).run()
    app.sidebar.button(key="nav_security_findings").click().run()

    assert list(app.dataframe[0].value.columns) == ["Timestamp (UTC)", "Severity", "File path", "Change type", "Rule ID"]
    assert any("A long explanation" in item.value for item in app.markdown)
    assert not app.exception


def test_file_integrity_uses_compact_table_and_copyable_full_hash(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    root = project_root / "lab"
    root.mkdir(exist_ok=True)
    test_file = root / "dashboard_test_sample.txt"
    test_file.write_text("IntegrityWatch dashboard test\\n", encoding="utf-8")

    try:
        scanned = scan_directory(root)["files"]
        baseline = tmp_path / "baseline.json"
        save_baseline(create_baseline(root), baseline)
        key = tmp_path / "key"
        signature = tmp_path / "baseline.hmac"
        generate_key(key)
        sign_baseline(baseline, key, signature)

        app = AppTest.from_file(project_root / "dashboard.py", default_timeout=20).run()
        for widget_key, value in (("iw_baseline_path", baseline),
                                  ("iw_key_path", key), ("iw_signature_path", signature)):
            app.sidebar.text_input(key=widget_key).set_value(str(value)).run()
        app.sidebar.button(key="nav_file_integrity").click().run()

        inventory_frame = app.dataframe[0].value
        assert list(inventory_frame.columns) == ["File path", "Integrity state", "Size (bytes)", "Modified (UTC)"]
        expected_hash = scanned["dashboard_test_sample.txt"]["sha256"]
        assert any(expected_hash in item.value for item in app.code)
        assert not app.exception
    finally:
        test_file.unlink(missing_ok=True)
        try:
            root.rmdir()
        except OSError:
            pass


def test_overview_summarizes_real_monitored_files_without_trusting_missing_key(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "one.conf").write_text("one=true\n", encoding="utf-8")
    (root / "two.conf").write_text("two=true\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    save_baseline(create_baseline(root), baseline)
    db = tmp_path / "events.sqlite"
    initialize_database(db)
    paths = {"iw_db_path": db, "iw_baseline_path": baseline,
             "iw_key_path": tmp_path / "missing.key", "iw_signature_path": tmp_path / "missing.hmac"}

    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    for widget_key, value in paths.items():
        app.sidebar.text_input(key=widget_key).set_value(str(value)).run()

    metrics = {item.label: item.value for item in app.metric}
    files_scanned = len(scan_directory(Path(__file__).resolve().parents[1] / "lab")["files"])
    assert metrics["Files scanned"] == str(files_scanned)
    assert metrics["Unverified"] == str(files_scanned)
    assert any("not trusted for comparison" in item.value for item in app.warning)
    assert not app.exception


def test_demo_page_shows_architecture_stages_and_limitations():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    app.sidebar.button(key="nav_demo_about").click().run()
    rendered = "\n".join(item.value for item in app.markdown)
    assert "Security architecture" in rendered
    assert "Monitoring" in rendered
    assert any("Limitations" in item.value for item in app.markdown)
    assert not app.exception


def test_default_anchor_is_not_assumed_to_exist_on_a_fresh_clone():
    root = Path(__file__).resolve().parents[1]
    app = AppTest.from_file(root / "dashboard.py", default_timeout=20).run()
    app.sidebar.button(key="nav_audit_and_verification").click().run()
    assert any("EMPTY" in item.value for item in app.info)
    assert {metric.label: metric.value for metric in app.metric}["Authentication"] != "VERIFIED"
    assert not app.exception


def test_overview_and_audit_share_health_states_and_recovery_guidance(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "settings.conf").write_text("safe=true\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    save_baseline(create_baseline(lab), baseline)
    db = tmp_path / "health.sqlite"
    initialize_database(db)
    key = tmp_path / "missing.key"
    signature = tmp_path / "missing.hmac"
    monitor = tmp_path / "monitor.json"
    write_monitor_status(monitor, root=str(lab), mode="smart", pid=os.getpid(),
                         last_error="Periodic reconciliation failed")

    app = AppTest.from_file(project_root / "dashboard.py", default_timeout=20).run()
    for widget_key, value in (
        ("iw_db_path", db),
        ("iw_baseline_path", baseline),
        ("iw_key_path", key),
        ("iw_signature_path", signature),
        ("iw_monitor_path", monitor),
    ):
        app.sidebar.text_input(key=widget_key).set_value(str(value)).run()

    def card_states():
        values = []
        for item in app.markdown:
            match = re.search(r'class="iw-status-value">([^<]+)</div>', item.value)
            if match:
                values.append(match.group(1))
        return values

    overview_states = card_states()
    assert overview_states == ["FAILED", "EMPTY", "AVAILABLE", "RUNNING"]
    assert any("Baseline file: AVAILABLE" in item.value for item in app.caption)
    assert any("HMAC key file: MISSING" in item.value for item in app.caption)
    assert any("Detached signature: MISSING" in item.value for item in app.caption)
    assert any("restore its matching key" in item.value for item in app.warning)
    assert any("Periodic reconciliation failed" in item.value for item in app.warning)
    assert any("not a verified chain" in item.value for item in app.info)

    app.sidebar.button(key="nav_audit_and_verification").click().run()

    assert card_states() == overview_states
    audit_metrics = {item.label: item.value for item in app.metric}
    assert audit_metrics["Baseline file"] == "AVAILABLE"
    assert audit_metrics["HMAC key"] == "MISSING"
    assert audit_metrics["Detached signature"] == "MISSING"
    assert audit_metrics["Authentication"] == "FAILED"
    assert any("Baseline file: AVAILABLE" in item.value for item in app.caption)
    assert any("HMAC key file: MISSING" in item.value for item in app.caption)
    assert any("Detached signature: MISSING" in item.value for item in app.caption)
    assert any("restore its matching key" in item.value for item in app.warning)
    assert any("Periodic reconciliation failed" in item.value for item in app.warning)
    assert any("not a verified chain" in item.value for item in app.info)
    assert not app.exception


def test_evaluation_page_keeps_all_metrics_and_synthetic_results_notice():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    app.sidebar.button(key="nav_evaluation").click().run()
    metrics = {item.label: item.value for item in app.metric}
    assert {"Smart detection rate", "False-positive rate", "False-negative rate",
            "Attack scenarios", "Attacks detected", "Benign scenarios"} <= set(metrics)
    assert any("Synthetic scenarios" in item.value for item in app.caption)
    assert not app.exception


def test_audit_tampering_is_reported_as_invalid(tmp_path):
    db = tmp_path / "tampered.sqlite"
    initialize_database(db)
    store_finding_once(db, {"file_path": "sample", "change_type": "modified", "rule_id": "R01",
                            "severity": "High", "attack_id": None, "explanation": "change"}, "c" * 64)
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE audit_log SET event_type='tampered' WHERE id=1")
    assert verify_audit_chain(db)["status"] == "invalid"

    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "dashboard.py", default_timeout=20).run()
    app.sidebar.text_input[0].set_value(str(db)).run()
    app.sidebar.button(key="nav_audit_and_verification").click().run()
    assert any("INVALID" in item.value for item in app.error)
    app.sidebar.button(key="nav_overview").click().run()
    assert any("INVALID" in item.value for item in app.markdown)
    assert not app.exception
