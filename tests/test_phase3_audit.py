import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from integritywatch.store import (
    append_audit_record, calculate_record_hash, initialize_database,
    store_finding_once, verify_audit_chain,
)


def test_audit_chain_verifies_sequential_writes(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    first = append_audit_record(db, "started", {"path": "lab"})
    second = append_audit_record(db, "finding", {"count": 2})
    result = verify_audit_chain(db)
    assert first["id"] == 1 and second["id"] == 2
    assert second["previous_hash"] == first["record_hash"]
    assert result["status"] == "valid" and result["records_checked"] == 2
    assert calculate_record_hash(second["id"], second["timestamp_utc"], second["event_type"], second["record_data"], second["previous_hash"]) == second["record_hash"]


def test_empty_audit_chain_is_distinguished(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    assert verify_audit_chain(db)["status"] == "empty"


def test_missing_audit_database_returns_error_status(tmp_path):
    result = verify_audit_chain(tmp_path / "missing" / "audit.db")
    assert result["status"] == "error"
    assert result["valid"] is False


def test_symlink_loop_audit_database_returns_error_status(tmp_path):
    db = tmp_path / "loop.db"
    db.symlink_to(db)
    result = verify_audit_chain(db)
    assert result["status"] == "error"
    assert result["valid"] is False


def test_deleting_entire_chain_is_not_mistaken_for_an_empty_database(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "event", {"x": 1})
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_log")
    result = verify_audit_chain(db)
    assert result["status"] == "invalid"
    assert "genesis" in result["message"].lower()


def test_audit_record_edit_delete_and_link_break_are_detected(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "one", {"x": 1})
    append_audit_record(db, "two", {"x": 2})
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET event_type='edited' WHERE id=1")
    assert verify_audit_chain(db)["status"] == "invalid"


def test_audit_row_deletion_and_reordering_are_detected(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    for i in range(3):
        append_audit_record(db, "event", {"i": i})
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_log WHERE id=2")
    assert verify_audit_chain(db)["status"] == "invalid"


def test_audit_trailing_deletion_and_previous_hash_tampering_are_detected(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "one", {"x": 1})
    append_audit_record(db, "two", {"x": 2})
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_log WHERE id=2")
    assert verify_audit_chain(db)["status"] == "invalid"

    db2 = tmp_path / "other.db"
    initialize_database(db2)
    append_audit_record(db2, "one", {"x": 1})
    append_audit_record(db2, "two", {"x": 2})
    with sqlite3.connect(db2) as conn:
        conn.execute("UPDATE audit_log SET previous_hash=? WHERE id=2", ("f" * 64,))
    assert "linkage" in verify_audit_chain(db2)["message"]


def test_reordering_record_ids_and_invalid_hash_are_detected(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "one", {"x": 1})
    append_audit_record(db, "two", {"x": 2})
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET id=10 WHERE id=2")
    assert verify_audit_chain(db)["status"] == "invalid"

    db2 = tmp_path / "other.db"
    initialize_database(db2)
    append_audit_record(db2, "event", {"x": 1})
    with sqlite3.connect(db2) as conn:
        conn.execute("UPDATE audit_log SET record_hash=? WHERE id=1", ("f" * 64,))
    assert "hash" in verify_audit_chain(db2)["message"].lower()


def test_audit_chain_verification_is_read_only(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "event", {"x": 1})
    before = db.read_bytes()
    verify_audit_chain(db)
    assert db.read_bytes() == before


def test_concurrent_audit_writers_produce_valid_chain(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(lambda i: append_audit_record(db, "event", {"i": i}), range(15)))
    result = verify_audit_chain(db)
    assert result["status"] == "valid" and result["records_checked"] == 15


def test_malformed_record_data_is_rejected(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "event", {"x": 1})
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET record_data='not-json' WHERE id=1")
    assert verify_audit_chain(db)["status"] == "invalid"


def test_invalid_chain_refuses_new_audit_appends_and_findings(tmp_path):
    db = tmp_path / "audit.db"
    initialize_database(db)
    append_audit_record(db, "event", {"x": 1})
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET event_type='tampered' WHERE id=1")

    with pytest.raises(RuntimeError, match="audit chain"):
        append_audit_record(db, "after_tamper", {"x": 2})
    with pytest.raises(RuntimeError, match="audit chain"):
        store_finding_once(db, {"file_path": "x", "change_type": "modified"}, "fingerprint")
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


def test_unreadable_or_corrupt_database_returns_error_status(tmp_path):
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"not a SQLite database")
    result = verify_audit_chain(db)
    assert result["status"] == "error"
    assert "database" in result["message"].lower()
