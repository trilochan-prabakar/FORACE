import sqlite3
import time

import pytest

from watchdog.events import FileModifiedEvent, FileMovedEvent

from forace.auth import generate_key, sign_baseline
from forace.baseline import create_baseline, save_baseline
from forace.monitor import IntegrityMonitor
from forace.store import initialize_database, verify_audit_chain


def make_monitor(tmp_path, *, mode="smart", debounce=0.15):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "sample.txt").write_text("original\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    save_baseline(create_baseline(root), baseline_path)
    key_path = tmp_path / "baseline.key"
    generate_key(key_path)
    signature_path = tmp_path / "baseline.json.hmac"
    sign_baseline(baseline_path, key_path, signature_path)
    db = tmp_path / "state.db"
    initialize_database(db)
    return IntegrityMonitor(root, baseline_path, key_path, signature_path, db, mode=mode,
                            debounce_seconds=debounce, reconcile_interval=30), root, db


def test_event_modification_is_debounced_and_stored_once(tmp_path):
    monitor, root, db = make_monitor(tmp_path)
    file_path = root / "sample.txt"
    file_path.write_text("changed\n", encoding="utf-8")
    first = monitor.handle_event("modified", file_path)
    second = monitor.handle_event("modified", file_path)
    assert len(first) == 1
    assert second == []
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_creation_deletion_and_move_events_scan_sandbox(tmp_path):
    monitor, root, _ = make_monitor(tmp_path, debounce=0)
    new_path = root / "new.txt"
    new_path.write_text("new\n", encoding="utf-8")
    assert any(item["change_type"] == "added" for item in monitor.handle_event("created", new_path))
    moved = root / "moved.txt"
    original = root / "sample.txt"
    original.rename(moved)
    assert any(item["change_type"] == "renamed" for item in monitor.handle_event("moved", original, moved))
    moved.unlink()
    assert any(item["change_type"] == "deleted" for item in monitor.handle_event("deleted", moved))


def test_outside_events_and_symlinks_are_not_followed(tmp_path):
    monitor, root, _ = make_monitor(tmp_path, debounce=0)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    assert monitor.handle_event("modified", outside) == []
    link = root / "link.txt"
    link.symlink_to(outside)
    assert any(item["change_type"] == "symlink_added" for item in monitor.handle_event("created", link))
    assert outside.read_text(encoding="utf-8") == "secret"


def test_temporary_files_are_ignored_until_reconciliation(tmp_path):
    monitor, root, _ = make_monitor(tmp_path, debounce=0)
    temporary = root / ".write.tmp"
    temporary.write_text("partial", encoding="utf-8")
    assert monitor.handle_event("created", temporary) == []
    assert any(item["file_path"] == ".write.tmp" for item in monitor.reconcile_once())


def test_directory_event_scans_new_children(tmp_path):
    monitor, root, _ = make_monitor(tmp_path, debounce=0)
    directory = root / "nested"
    directory.mkdir()
    (directory / "child.txt").write_text("new", encoding="utf-8")
    found = monitor.handle_event("created", directory, is_directory=True)
    assert any(item["file_path"] == "nested/child.txt" for item in found)


def test_reconciliation_detects_unobserved_changes_and_deduplicates_events(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0)
    (root / "sample.txt").write_text("changed without event\n", encoding="utf-8")
    found = monitor.reconcile_once()
    assert len(found) == 1
    assert monitor.handle_event("modified", root / "sample.txt") == []
    assert monitor.reconcile_once() == []
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_reconciliation_detects_deleted_and_new_files(tmp_path):
    monitor, root, _ = make_monitor(tmp_path, debounce=0)
    (root / "sample.txt").unlink()
    (root / "added.txt").write_text("added", encoding="utf-8")
    found = monitor.reconcile_once()
    assert {item["change_type"] for item in found} == {"added", "deleted"}


def test_inaccessible_path_is_not_reported_as_deleted(tmp_path):
    monitor, root, _ = make_monitor(tmp_path, debounce=0)
    result = {"files": {}, "errors": {"sample.txt": "permission denied"}}
    findings = monitor.reconcile_once(scan_result=result)
    assert {item["change_type"] for item in findings} >= {"unreadable", "deleted"}


def test_hash_only_monitor_persists_plain_change_without_semantics(tmp_path):
    monitor, root, db = make_monitor(tmp_path, mode="hash-only", debounce=0)
    (root / "sample.txt").write_text("changed\n", encoding="utf-8")
    findings = monitor.reconcile_once()
    assert findings[0]["change_type"] == "modified"
    assert findings[0]["rule_id"] is None
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT rule_id, attack_id FROM findings").fetchone()
        assert row == (None, None)


def test_monitor_persists_combined_cron_rules_once_across_repeated_scans(tmp_path):
    root = tmp_path / "lab"
    crontab = root / "etc" / "crontab"
    crontab.parent.mkdir(parents=True)
    baseline_text = "SHELL=/bin/sh\n"
    crontab.write_text(baseline_text, encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    save_baseline(create_baseline(root), baseline_path)
    key_path = tmp_path / "baseline.key"
    generate_key(key_path)
    signature_path = tmp_path / "baseline.json.hmac"
    sign_baseline(baseline_path, key_path, signature_path)
    db = tmp_path / "state.db"
    initialize_database(db)
    monitor = IntegrityMonitor(root, baseline_path, key_path, signature_path, db,
                               debounce_seconds=0, reconcile_interval=30)

    crontab.write_text(
        baseline_text
        + "17 3 * * * root /bin/echo normal-fixture\n"
        + "23 4 * * * root /bin/echo 'curl inert-fixture'\n",
        encoding="utf-8",
    )

    first_scan = monitor.reconcile_once()
    second_scan = monitor.reconcile_once()

    assert {item["rule_id"] for item in first_scan} == {"R04", "R05"}
    assert second_scan == []
    with sqlite3.connect(db) as conn:
        rows = conn.execute(
            "SELECT rule_id, severity, attack_id, explanation FROM findings ORDER BY rule_id"
        ).fetchall()
        audit_findings = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_type = 'finding'"
        ).fetchone()[0]
    assert {row[0] for row in rows} == {"R04", "R05"}
    assert len(rows) == 2
    assert audit_findings == 2
    assert verify_audit_chain(db)["status"] == "valid"


def test_monitor_refuses_baseline_after_authentication_failure(tmp_path):
    monitor, _, _ = make_monitor(tmp_path, debounce=0)
    with monitor.baseline_path.open("ab") as stream:
        stream.write(b" ")
    assert monitor.handle_event("modified", monitor.root / "sample.txt") == []
    assert "signature" in monitor.last_error.lower()


def test_stop_is_graceful_and_idempotent(tmp_path):
    monitor, _, _ = make_monitor(tmp_path)
    monitor.stop()
    monitor.stop()
    assert monitor.stopped


def test_watchdog_handler_dispatches_filesystem_events(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0)
    target = root / "sample.txt"
    target.write_text("changed through watchdog handler\n", encoding="utf-8")
    monitor.on_modified(FileModifiedEvent(str(target)))
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_monitor_can_start_and_stop_watchdog_observer(tmp_path):
    monitor, _, _ = make_monitor(tmp_path)
    monitor.start()
    monitor.stop()
    assert monitor.stopped


def test_monitor_start_is_idempotent_and_reuses_observer(tmp_path):
    monitor, _, _ = make_monitor(tmp_path)
    monitor.start()
    first_observer = monitor._observer

    monitor.start()

    assert monitor._observer is first_observer
    monitor.stop()


def test_monitor_refuses_to_start_with_invalid_audit_chain(tmp_path):
    monitor, _, db = make_monitor(tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO audit_log (timestamp_utc, event_type, record_data, previous_hash, record_hash) VALUES ('2026-01-01T00:00:00+00:00', 'tampered', '{}', ?, ?)", ('0' * 64, 'f' * 64))
    with pytest.raises(RuntimeError, match="audit chain"):
        monitor.start()


def test_monitor_does_not_recreate_missing_audit_table_in_existing_database(tmp_path):
    monitor, root, db = make_monitor(tmp_path)
    monitor.stop()
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE audit_log")

    with pytest.raises(RuntimeError, match="audit"):
        IntegrityMonitor(root, monitor.baseline_path, monitor.key_path,
                         monitor.signature_path, db)
    with sqlite3.connect(db) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "audit_log" not in tables


def test_real_watchdog_observer_detects_a_lab_change(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0.05)
    monitor.start()
    try:
        (root / "sample.txt").write_text("observed by watchdog\n", encoding="utf-8")
        deadline = time.monotonic() + 3
        found = False
        while time.monotonic() < deadline:
            with sqlite3.connect(db) as conn:
                if conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]:
                    found = True
                    break
            time.sleep(0.03)
        assert found
    finally:
        monitor.stop()


def test_replacing_baseline_file_with_symlink_persists_error_and_deletion(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0)
    target = root / "sample.txt"
    outside = tmp_path / "outside-key"
    outside.write_text("not followed", encoding="utf-8")
    target.unlink()
    target.symlink_to(outside)

    findings = monitor.reconcile_once()
    assert {item["change_type"] for item in findings} >= {"symlink_replaced", "deleted"}
    with sqlite3.connect(db) as connection:
        rows = connection.execute(
            "SELECT change_type, severity FROM findings WHERE file_path = ?",
            ("sample.txt",),
        ).fetchall()
    assert ("symlink_replaced", "High") in rows
    assert ("deleted", None) in rows


def test_attack_recurrence_is_recorded_after_returning_to_baseline(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0)
    sample = root / "sample.txt"
    baseline_text = sample.read_text(encoding="utf-8")
    attacked = baseline_text + "second line\n"

    sample.write_text(attacked, encoding="utf-8")
    assert monitor.reconcile_once()
    sample.write_text(baseline_text, encoding="utf-8")
    assert monitor.reconcile_once() == []
    sample.write_text(attacked, encoding="utf-8")
    assert monitor.reconcile_once()
    with sqlite3.connect(db) as connection:
        count = connection.execute("SELECT COUNT(*) FROM findings WHERE file_path='sample.txt'").fetchone()[0]
    assert count == 2


def test_monitor_records_scan_lifecycle_and_watchdog_trigger(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0)
    monitor.reconcile_once()
    target = root / "sample.txt"
    target.write_text("changed\n", encoding="utf-8")
    monitor.handle_event("modified", target)
    with sqlite3.connect(db) as connection:
        rows = connection.execute(
            "SELECT trigger, status, files_observed FROM scan_runs ORDER BY id"
        ).fetchall()
    assert rows[0][0] == "reconciliation"
    assert rows[-1][0] == "watchdog:modified"
    assert all(row[1] == "completed" and row[2] == 1 for row in rows)
    from forace.observations import verify_observation_history
    assert verify_observation_history(db)["status"] == "valid"


def test_monitor_records_failed_observation_when_baseline_authentication_fails(tmp_path):
    monitor, root, db = make_monitor(tmp_path, debounce=0)
    with monitor.baseline_path.open("ab") as stream:
        stream.write(b" ")
    monitor.handle_event("modified", root / "sample.txt")
    with sqlite3.connect(db) as connection:
        row = connection.execute(
            "SELECT status, error_message FROM scan_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row[0] == "failed"
    assert "signature" in row[1].lower()
    from forace.observations import verify_observation_history
    assert verify_observation_history(db)["status"] == "valid"


def test_partial_observation_sets_monitor_error_state(tmp_path):
    monitor, _, db = make_monitor(tmp_path, debounce=0)
    result = {"files": {}, "errors": {"sample.txt": "Permission denied"}}
    monitor.reconcile_once(scan_result=result)
    assert "1 scanner error" in monitor.last_error
    with sqlite3.connect(db) as connection:
        status = connection.execute("SELECT status FROM scan_runs ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert status == "completed_with_errors"
