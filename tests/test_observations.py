import sqlite3
from forace.observations import ensure_observation_schema, load_scan_history, record_failed_scan, record_scan, verify_observation_history
from forace.store import initialize_database


def sample():
    return {"files":{"etc/test.conf":{"sha256":"a"*64,"size":4,"mode":420,
            "uid":1000,"gid":1000,"mtime_ns":123,"snapshot":"safe"}},"errors":{}}


def test_additive_v2_migration_preserves_v1_tables(tmp_path):
    db=tmp_path/"state.db"; initialize_database(db); ensure_observation_schema(db); ensure_observation_schema(db)
    with sqlite3.connect(db) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0] == 2
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
