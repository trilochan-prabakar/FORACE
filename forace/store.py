
import hashlib
import json
import sqlite3
from datetime import datetime, timezone, timedelta

from pathlib import Path


from forace.paths import DEFAULT_DB_PATH
GENESIS_HASH = "0" * 64


def canonical_json(value):
    """Serialize JSON data deterministically as UTF-8-compatible text."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def calculate_record_hash(record_id, timestamp_utc, event_type, record_data, previous_hash):
    """Hash the canonical JSON serialization of all authenticated record fields."""
    payload = canonical_json({
        "id": record_id,
        "timestamp_utc": timestamp_utc,
        "event_type": event_type,
        "record_data": record_data,
        "previous_hash": previous_hash,
    }).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _append_audit_in_transaction(connection, event_type, encoded_data, timestamp):
    previous = connection.execute(
        "SELECT id, record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    sequence = connection.execute(
        "SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'"
    ).fetchone()
    record_id = max(previous["id"] if previous else 0, sequence["seq"] if sequence else 0) + 1
    previous_hash = previous["record_hash"] if previous else GENESIS_HASH
    record_hash = calculate_record_hash(record_id, timestamp, event_type, encoded_data, previous_hash)
    connection.execute(
        "INSERT INTO audit_log (id, timestamp_utc, event_type, record_data, previous_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?)",
        (record_id, timestamp, event_type, encoded_data, previous_hash, record_hash),
    )
    return {"id": record_id, "timestamp_utc": timestamp, "event_type": event_type,
            "record_data": encoded_data, "previous_hash": previous_hash, "record_hash": record_hash}


def _verify_audit_connection(connection):
    """Verify the chain using an existing connection and its current snapshot."""
    try:
        check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if check != "ok":
            return {"status": "error", "valid": False, "records_checked": 0,
                    "record_id": None, "message": f"Database integrity check failed: {check}"}
        records = connection.execute(
            "SELECT id, timestamp_utc, event_type, record_data, previous_hash, record_hash FROM audit_log ORDER BY id"
        ).fetchall()
        sequence = connection.execute(
            "SELECT seq FROM sqlite_sequence WHERE name = 'audit_log'"
        ).fetchone()
        if not records:
            if sequence and sequence["seq"] > 0:
                return {"status": "invalid", "valid": False, "records_checked": 0,
                        "record_id": 1, "message": "Missing genesis record; audit rows may have been deleted"}
            findings_count = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            if findings_count:
                return {"status": "invalid", "valid": False, "records_checked": 0,
                        "record_id": None, "message": "Findings table contains rows without audited finding records"}
            return {"status": "empty", "valid": True, "records_checked": 0,
                    "record_id": None, "message": "Audit chain is empty"}
        previous_hash = GENESIS_HASH
        for expected_id, record in enumerate(records, start=1):
            if record["id"] != expected_id:
                return {"status": "invalid", "valid": False, "records_checked": expected_id - 1,
                        "record_id": record["id"], "message": f"Sequence gap: expected record {expected_id}"}
            if not isinstance(record["event_type"], str) or not record["event_type"].strip():
                return {"status": "invalid", "valid": False, "records_checked": expected_id - 1,
                        "record_id": record["id"], "message": "Malformed empty event type"}
            try:
                record_time = datetime.fromisoformat(record["timestamp_utc"])
                if record_time.tzinfo is None or record_time.utcoffset() != timedelta(0):
                    raise ValueError("timestamp is not UTC")
            except (TypeError, ValueError) as error:
                return {"status": "invalid", "valid": False, "records_checked": expected_id - 1,
                        "record_id": record["id"], "message": f"Malformed UTC timestamp: {error}"}
            try:
                parsed = json.loads(record["record_data"])
                if canonical_json(parsed) != record["record_data"]:
                    raise ValueError("record_data is not canonical JSON")
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                return {"status": "invalid", "valid": False, "records_checked": expected_id - 1,
                        "record_id": record["id"], "message": f"Malformed record data: {error}"}
            if record["previous_hash"] != previous_hash:
                return {"status": "invalid", "valid": False, "records_checked": expected_id - 1,
                        "record_id": record["id"], "message": "Previous-hash linkage mismatch"}
            expected_hash = calculate_record_hash(
                record["id"], record["timestamp_utc"], record["event_type"],
                record["record_data"], record["previous_hash"],
            )
            if record["record_hash"] != expected_hash:
                return {"status": "invalid", "valid": False, "records_checked": expected_id - 1,
                        "record_id": record["id"], "message": "Record hash mismatch"}
            previous_hash = record["record_hash"]
        if sequence and sequence["seq"] != records[-1]["id"]:
            return {"status": "invalid", "valid": False, "records_checked": len(records),
                    "record_id": sequence["seq"], "message": "Sequence tail mismatch: one or more trailing records are missing"}
        audit_findings = []
        for record in records:
            if record["event_type"] == "finding":
                try:
                    payload = json.loads(record["record_data"])
                    if "finding" not in payload:
                        continue
                    finding = payload["finding"]
                    audit_findings.append((record["timestamp_utc"], finding.get("file_path"),
                        finding.get("change_type"), finding.get("rule_id"), finding.get("severity"),
                        finding.get("attack_id"), finding.get("explanation"), payload.get("scan_id")))
                except (KeyError, TypeError, json.JSONDecodeError):
                    return {"status": "invalid", "valid": False, "records_checked": len(records),
                            "record_id": record["id"], "message": "Malformed finding audit record"}
        finding_columns = {row["name"] for row in connection.execute("PRAGMA table_info(findings)")}
        scan_id_column = "scan_id" if "scan_id" in finding_columns else "NULL AS scan_id"
        table_findings = connection.execute(
            "SELECT timestamp_utc, file_path, change_type, rule_id, severity, attack_id, explanation, "
            + scan_id_column + " FROM findings ORDER BY id").fetchall()
        stored = [tuple(row) for row in table_findings]
        if stored != audit_findings:
            return {"status": "invalid", "valid": False, "records_checked": len(records),
                    "record_id": None, "message": "Findings table does not match audited finding records"}
        return {"status": "valid", "valid": True, "records_checked": len(records),
                "record_id": None, "message": "Audit chain and findings table are valid"}
    except sqlite3.Error as error:
        return {"status": "error", "valid": False, "records_checked": 0,
                "record_id": None, "message": f"Database access or corruption error: {error}"}


def _require_valid_audit_connection(connection):
    status = _verify_audit_connection(connection)
    if status["status"] not in {"empty", "valid"}:
        raise RuntimeError(f"Refusing to append to invalid audit chain: {status['message']}")


def append_audit_record(db_path, event_type, record_data, timestamp_utc=None):
    """Append one chained record under an immediate SQLite write transaction."""
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("event_type must be a non-empty string")
    encoded_data = canonical_json(record_data)
    timestamp = timestamp_utc or datetime.now(timezone.utc).isoformat()
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError) as error:
        raise ValueError("timestamp_utc must be an ISO 8601 UTC timestamp") from error
    if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() != timedelta(0):
        raise ValueError("timestamp_utc must include a UTC timezone")
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_valid_audit_connection(connection)
        record = _append_audit_in_transaction(connection, event_type, encoded_data, timestamp)
        connection.commit()
        return record
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def store_finding_once(db_path, finding, fingerprint):
    """Atomically store a finding once, using chained audit data as a dedupe ledger."""
    timestamp = datetime.now(timezone.utc).isoformat()
    audit_data = canonical_json({"fingerprint": fingerprint, "finding": finding})
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_valid_audit_connection(connection)
        prior = connection.execute(
            "SELECT event_type FROM audit_log WHERE event_type IN ('finding', 'finding_cleared') "
            "AND json_extract(record_data, '$.fingerprint') = ? ORDER BY id DESC LIMIT 1",
            (fingerprint,),
        ).fetchone()
        if prior and prior["event_type"] == "finding":
            connection.commit()
            return False
        connection.execute(
            "INSERT INTO findings (timestamp_utc, file_path, change_type, rule_id, severity, attack_id, explanation) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (timestamp, finding["file_path"], finding["change_type"], finding.get("rule_id"),
             finding.get("severity"), finding.get("attack_id"), finding.get("explanation")),
        )
        _append_audit_in_transaction(connection, "finding", audit_data, timestamp)
        connection.commit()
        return True
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()



def clear_inactive_findings(db_path, active_fingerprints):
    """Record transitions out of the active state so a later recurrence is reportable."""
    active = set(active_fingerprints)
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_valid_audit_connection(connection)
        rows = connection.execute(
            "SELECT event_type, record_data FROM audit_log "
            "WHERE event_type IN ('finding', 'finding_cleared') ORDER BY id"
        ).fetchall()
        latest = {}
        for row in rows:
            data = json.loads(row["record_data"])
            latest[data["fingerprint"]] = row["event_type"]
        for fingerprint, state in latest.items():
            if state == "finding" and fingerprint not in active:
                timestamp = datetime.now(timezone.utc).isoformat()
                _append_audit_in_transaction(connection, "finding_cleared",
                                             canonical_json({"fingerprint": fingerprint}), timestamp)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def verify_audit_chain(db_path):
    """Read-only verification of the audit chain, returning its first failure."""
    try:
        path = Path(db_path).resolve()
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        return _verify_audit_connection(connection)
    except (sqlite3.Error, OSError, RuntimeError, ValueError) as error:
        return {"status": "error", "valid": False, "records_checked": 0,
                "record_id": None, "message": f"Database access or corruption error: {error}"}
    finally:
        if "connection" in locals():
            connection.close()


def get_connection(db_path=DEFAULT_DB_PATH):
    """Create and return a SQLite database connection."""

    db_path = Path(db_path)

    if db_path.is_symlink():
        raise ValueError("SQLite database path must not be a symbolic link")

    # Ensure the database directory exists.
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)

    # Return database rows as dictionary-like objects.
    connection.row_factory = sqlite3.Row

    # Enable foreign-key enforcement.
    connection.execute("PRAGMA foreign_keys = ON")

    # Wait up to 5 seconds if the database is busy.
    connection.execute("PRAGMA busy_timeout = 5000")

    return connection


def initialize_database(db_path=DEFAULT_DB_PATH):
    """Create the initial FORACE database schema."""

    connection = get_connection(db_path)

    try:
        connection.executescript("""

            CREATE TABLE IF NOT EXISTS findings (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp_utc TEXT NOT NULL,

                file_path TEXT NOT NULL,

                change_type TEXT NOT NULL,

                rule_id TEXT,

                severity TEXT,

                attack_id TEXT,

                explanation TEXT

            );


            CREATE TABLE IF NOT EXISTS audit_log (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp_utc TEXT NOT NULL,

                event_type TEXT NOT NULL,

                record_data TEXT NOT NULL,

                previous_hash TEXT,

                record_hash TEXT

            );


            CREATE INDEX IF NOT EXISTS
            idx_findings_timestamp
            ON findings(timestamp_utc);


            CREATE INDEX IF NOT EXISTS
            idx_findings_severity
            ON findings(severity);


            CREATE INDEX IF NOT EXISTS
            idx_audit_timestamp
            ON audit_log(timestamp_utc);

        """)

        connection.commit()

    finally:
        connection.close()

    return Path(db_path)


if __name__ == "__main__":

    database_path = initialize_database()

    print("FORACE database initialized.")
    print(f"Database location: {database_path}")
