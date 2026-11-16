import sqlite3

from integritywatch.store import initialize_database


def test_database_schema_and_repeatable_initialization(tmp_path):
    db_path = tmp_path / "integritywatch.db"
    initialize_database(db_path)
    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        )}
        assert {"findings", "audit_log"} <= tables

        expected_columns = {
            "findings": ["id", "timestamp_utc", "file_path", "change_type", "rule_id", "severity", "attack_id", "explanation"],
            "audit_log": ["id", "timestamp_utc", "event_type", "record_data", "previous_hash", "record_hash"],
        }
        for table_name, expected in expected_columns.items():
            actual = [row[1] for row in connection.execute(f"PRAGMA table_info({table_name})")]
            assert actual == expected

        indexes = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'"
        )}
        assert {"idx_findings_timestamp", "idx_findings_severity", "idx_audit_timestamp"} <= indexes


def test_database_initialization_refuses_symlink_path(tmp_path):
    target = tmp_path / "existing.db"
    initialize_database(target)
    linked = tmp_path / "linked.db"
    linked.symlink_to(target)
    before = target.read_bytes()

    try:
        initialize_database(linked)
    except ValueError as error:
        assert "symbolic link" in str(error).lower()
    else:
        raise AssertionError("database symlink was accepted")
    assert target.read_bytes() == before
