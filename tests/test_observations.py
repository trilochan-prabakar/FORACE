import sqlite3
from forace.observations import ensure_observation_schema, load_scan_history, record_failed_scan, record_scan, verify_observation_history
from forace.store import initialize_database


def sample():
    return {"files":{"etc/test.conf":{"sha256":"a"*64,"size":4,"mode":420,
            "uid":1000,"gid":1000,"mtime_ns":123,"snapshot":"safe"}},"errors":{}}


def test_additive_v2_migration_preserves_v1_tables(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db); ensure_observation_schema(db)
    with sqlite3.connect(db) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 3
        tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"findings","audit_log","scan_runs","file_observations","observation_errors"} <= tables


def test_completed_scan_manifest_is_audit_linked(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db)
    result=record_scan(db,sample(),trigger="startup",mode="smart",findings_count=1)
    assert result["status"] == "completed"
    assert verify_observation_history(db)["status"] == "valid"
    history=load_scan_history(db)
    assert history["count"] == 1 and history["scans"][0]["trigger"] == "startup"


def test_partial_scan_is_not_misrepresented_as_clean(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db)
    scan=sample(); scan["errors"]={"etc/blocked":"Permission denied"}
    assert record_scan(db,scan,trigger="reconciliation",mode="smart",findings_count=0)["status"] == "completed_with_errors"
    assert verify_observation_history(db)["status"] == "valid"


def test_failed_scan_is_persisted_without_fabricating_file_state(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db)
    record_failed_scan(db,trigger="reconciliation",mode="smart",error_message="baseline authentication failed")
    row=load_scan_history(db)["scans"][0]
    assert row["status"] == "failed" and row["files_observed"] == 0
    assert verify_observation_history(db)["status"] == "valid"


def test_tampered_observation_manifest_is_detected(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db)
    record_scan(db,sample(),trigger="manual",mode="hash-only",findings_count=0)
    with sqlite3.connect(db) as con: con.execute("UPDATE file_observations SET sha256=?",( "b"*64,))
    result=verify_observation_history(db)
    assert result["status"] == "invalid" and "manifest mismatch" in result["message"].lower()


def test_v1_database_reports_history_unavailable(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db)
    assert load_scan_history(db)["status"] == "unavailable"
    assert verify_observation_history(db)["status"] == "unavailable"


def test_scan_lifecycle_metadata_tampering_is_detected(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db)
    record_scan(db,sample(),trigger="startup",mode="smart",findings_count=1)
    with sqlite3.connect(db) as con:
        con.execute("UPDATE scan_runs SET trigger='forged-trigger'")
    result=verify_observation_history(db)
    assert result["status"] == "invalid"


def test_invalid_timezone_is_rejected_before_writing(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db)
    try:
        record_scan(db,sample(),trigger="manual",mode="smart",findings_count=0,
                    started_at_utc="2026-01-01T12:00:00")
    except ValueError as error:
        assert "UTC" in str(error)
    else:
        raise AssertionError("naive scan timestamp was accepted")



def test_orphaned_file_observation_is_rejected_even_without_scan_runs(tmp_path):
    db = tmp_path / "orphan.db"
    initialize_database(db)
    ensure_observation_schema(db)
    with sqlite3.connect(db) as con:
        con.execute(
            "INSERT INTO file_observations(scan_id,file_path,sha256,size,mode,uid,gid,mtime_ns) "
            "VALUES(999,'etc/orphan','" + "a" * 64 + "',1,420,1000,1000,1)"
        )
    result = verify_observation_history(db)
    assert result["status"] == "invalid"
    assert "orphan" in result["message"].lower()


def test_orphaned_observation_error_is_rejected(tmp_path):
    db = tmp_path / "orphan-error.db"
    initialize_database(db)
    ensure_observation_schema(db)
    with sqlite3.connect(db) as con:
        con.execute(
            "INSERT INTO observation_errors(scan_id,path,error) VALUES(999,'etc/blocked','denied')"
        )
    result = verify_observation_history(db)
    assert result["status"] == "invalid"
    assert "orphan" in result["message"].lower()


def test_scan_history_includes_file_observations_and_scanner_errors(tmp_path):
    db = tmp_path / "details.db"
    initialize_database(db)
    ensure_observation_schema(db)
    scan = sample()
    scan["errors"] = {"etc/blocked": "Permission denied"}
    record_scan(db, scan, trigger="manual", mode="smart", findings_count=0)
    row = load_scan_history(db)["scans"][0]
    assert row["files"][0]["file_path"] == "etc/test.conf"
    assert row["files"][0]["sha256"] == "a" * 64
    assert row["errors"] == [{"path": "etc/blocked", "error": "Permission denied"}]



def test_findings_are_linked_to_scan_and_committed_with_manifest(tmp_path):
    db = tmp_path / "linked.db"
    initialize_database(db)
    ensure_observation_schema(db)
    finding = {
        "file_path": "etc/test.conf", "change_type": "modified", "rule_id": "R01",
        "severity": "High", "attack_id": "T1021.004", "explanation": "SSH root login enabled",
    }
    recorded = record_scan(
        db, sample(), trigger="watchdog:modified", mode="smart", findings_count=1,
        finding_records=[{"finding": finding, "fingerprint": "c" * 64}],
    )
    assert recorded["scan_id"] == 1
    assert recorded["new_findings"] == [finding]
    with sqlite3.connect(db) as con:
        row = con.execute("SELECT scan_id FROM findings").fetchone()
        audit_payload = con.execute(
            "SELECT record_data FROM audit_log WHERE event_type='finding'"
        ).fetchone()[0]
    assert row[0] == recorded["scan_id"]
    assert '"scan_id":1' in audit_payload
    from forace.dashboard_data import load_findings
    loaded = load_findings(db)
    assert loaded["findings"][0]["scan_id"] == recorded["scan_id"]
    assert verify_observation_history(db)["status"] == "valid"


def test_failed_finding_write_rolls_back_scan_and_observations(tmp_path):
    db = tmp_path / "atomic.db"
    initialize_database(db)
    ensure_observation_schema(db)
    finding = {"file_path": "etc/test.conf", "change_type": "modified"}
    try:
        record_scan(
            db, sample(), trigger="manual", mode="smart", findings_count=1,
            finding_records=[{"finding": finding, "fingerprint": "not-a-sha256"}],
        )
    except ValueError as error:
        assert "SHA-256" in str(error)
    else:
        raise AssertionError("invalid finding fingerprint was accepted")
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM file_observations").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_verify_evidence_returns_nonzero_for_v1_database(tmp_path, capsys):
    from forace.cli import main

    db = tmp_path / "v1.db"
    initialize_database(db)
    assert main(["verify-evidence", "--db", str(db)]) == 1
    assert '"status": "unavailable"' in capsys.readouterr().out



def test_failed_or_partial_scan_does_not_clear_unobserved_finding(tmp_path):
    db = tmp_path / "partial-preserve.db"
    initialize_database(db)
    ensure_observation_schema(db)
    finding = {
        "file_path": "etc/test.conf", "change_type": "modified", "rule_id": "R01",
        "severity": "High", "attack_id": "T1021.004", "explanation": "SSH root login enabled",
    }
    record_scan(
        db, sample(), trigger="watchdog:modified", mode="smart", findings_count=1,
        finding_records=[{"finding": finding, "fingerprint": "d" * 64}],
    )
    partial = {"files": {}, "errors": {"etc": "Permission denied"}}
    record_scan(db, partial, trigger="reconciliation", mode="smart", findings_count=0)
    with sqlite3.connect(db) as con:
        cleared = con.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_type='finding_cleared'"
        ).fetchone()[0]
    assert cleared == 0
    assert verify_observation_history(db)["status"] == "valid"


def test_v1_audit_verification_remains_compatible_before_v3_migration(tmp_path):
    from forace.store import verify_audit_chain

    db = tmp_path / "legacy.db"
    initialize_database(db)
    assert verify_audit_chain(db)["status"] == "empty"
    assert verify_observation_history(db)["status"] == "unavailable"



def test_v1_finding_and_audit_rows_survive_scan_provenance_migration(tmp_path):
    from forace.store import store_finding_once, verify_audit_chain

    db = tmp_path / "legacy-findings.db"
    initialize_database(db)
    finding = {
        "file_path": "etc/legacy.conf", "change_type": "modified", "rule_id": None,
        "severity": None, "attack_id": None, "explanation": None,
    }
    assert store_finding_once(db, finding, "e" * 64) is True
    assert verify_audit_chain(db)["status"] == "valid"
    ensure_observation_schema(db)
    assert verify_audit_chain(db)["status"] == "valid"
    with sqlite3.connect(db) as con:
        row = con.execute("SELECT scan_id,file_path FROM findings").fetchone()
    assert row == (None, "etc/legacy.conf")
