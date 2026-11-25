import hashlib
import os
import sqlite3

import pytest

from forace.baseline import create_baseline, load_baseline, save_baseline
from forace.scanner import scan_directory
from forace.store import initialize_database
import forace.scanner as scanner


def test_scanner_hash_metadata_and_text_snapshot(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    target = root / "sample.conf"
    target.write_text("safe=true\n", encoding="utf-8")
    target.chmod(0o640)

    result = scan_directory(root)
    entry = result["files"]["sample.conf"]

    assert not result["errors"]
    assert entry["sha256"] == hashlib.sha256(b"safe=true\n").hexdigest()
    assert entry["size"] == 10
    assert entry["mode"] == 0o640
    assert entry["uid"] == os.stat(target).st_uid
    assert entry["gid"] == os.stat(target).st_gid
    assert entry["mtime_ns"] == os.stat(target).st_mtime_ns
    assert entry["snapshot"] == "safe=true\n"


def test_scanner_reports_symlink_without_following_it(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (root / "linked").symlink_to(outside)

    result = scan_directory(root)

    assert "linked" not in result["files"]
    assert "linked" in result["errors"]


def test_scanner_file_helpers_do_not_follow_final_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("outside secret", encoding="utf-8")
    link = tmp_path / "linked"
    link.symlink_to(outside)

    with pytest.raises(OSError):
        scanner.calculate_sha256(link)
    with pytest.raises(OSError):
        scanner.collect_metadata(link)
    with pytest.raises(OSError):
        scanner.read_text_snapshot(link, outside.stat().st_size)


def test_scanner_rejects_file_swapped_to_symlink_at_open_time(tmp_path, monkeypatch):
    root = tmp_path / "lab"
    root.mkdir()
    target = root / "victim"
    target.write_text("in-sandbox", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("outside secret", encoding="utf-8")
    original_open = os.open
    swapped = False

    def swapping_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "victim" and kwargs.get("dir_fd") is not None and not swapped:
            target.unlink()
            target.symlink_to(outside)
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", swapping_open)
    result = scanner.scan_directory(root)
    assert swapped
    assert "victim" not in result["files"]
    assert "victim" in result["errors"]


def test_scan_file_rejects_parent_traversal(tmp_path):
    root = tmp_path / "lab"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    with pytest.raises(ValueError, match="beneath|traversal"):
        scanner.scan_file(root / ".." / "outside", root)


def test_baseline_round_trip_and_explicit_overwrite(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "a").write_text("value", encoding="utf-8")
    path = tmp_path / "baseline.json"
    baseline = create_baseline(lab)

    save_baseline(baseline, path)
    assert load_baseline(path) == baseline
    with pytest.raises(FileExistsError):
        save_baseline(baseline, path)


def test_baseline_does_not_follow_symlinked_directories(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "outside-link").symlink_to(tmp_path)
    result = scan_directory(lab)
    assert result["files"] == {}
    assert "outside-link" in result["errors"]
    with pytest.raises(RuntimeError, match="could not be scanned"):
        create_baseline(lab)


def test_database_schema_and_repeatable_initialization(tmp_path):
    db = tmp_path / "nested" / "state.sqlite"
    initialize_database(db)
    initialize_database(db)

    with sqlite3.connect(db) as connection:
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"findings", "audit_log"} <= tables
        expected = {
            "findings": ["id", "timestamp_utc", "file_path", "change_type", "rule_id", "severity", "attack_id", "explanation"],
            "audit_log": ["id", "timestamp_utc", "event_type", "record_data", "previous_hash", "record_hash"],
        }
        for table, columns in expected.items():
            assert [r[1] for r in connection.execute(f"PRAGMA table_info({table})")] == columns
        indexes = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert {"idx_findings_timestamp", "idx_findings_severity", "idx_audit_timestamp"} <= indexes
