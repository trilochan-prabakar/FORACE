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
