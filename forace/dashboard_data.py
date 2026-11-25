"""Read-only data access and filtering helpers for the Streamlit dashboard."""
import csv
import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from forace.auth import load_authenticated_baseline
from forace.monitor_status import read_monitor_status
from forace.paths import PROJECT_ROOT
from forace.store import verify_audit_chain
from forace.scanner import scan_directory


REQUIRED_FINDING_COLUMNS = {"id", "timestamp_utc", "file_path", "change_type", "rule_id",
                            "severity", "attack_id", "explanation"}
BOOL_COLUMNS = {"smart_expected_rule_detected", "hash_only_change_detected", "false_positive",
                "false_negative", "benign_correctly_handled", "explanation_covered", "attack_mapping_covered"}
INT_COLUMNS = {"smart_finding_count", "hash_only_finding_count"}


def _read_connection(db_path):
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"Database does not exist: {path}")
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def get_database_status(db_path):
    try:
        connection = _read_connection(db_path)
        try:
            check = connection.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                return {"status": "error", "message": f"SQLite integrity check failed: {check}"}
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"findings", "audit_log"} <= tables:
                return {"status": "error", "message": "Database is missing required FORACE tables"}
            count = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            return {"status": "available", "message": "Database is accessible and schema is present", "finding_count": count}
        finally:
            connection.close()
    except FileNotFoundError as error:
        return {"status": "missing", "message": str(error)}
    except (sqlite3.Error, OSError) as error:
        return {"status": "error", "message": f"Database unavailable: {error}"}


def load_findings(db_path, limit=None):
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    status = get_database_status(db_path)
    if status["status"] != "available":
        return {**status, "findings": [], "count": 0}
    connection = None
    try:
        connection = _read_connection(db_path)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(findings)")}
        if not REQUIRED_FINDING_COLUMNS <= columns:
            return {"status": "error", "message": "Findings table has an unsupported schema", "findings": [], "count": 0}
        query = "SELECT id, timestamp_utc, file_path, change_type, rule_id, severity, attack_id, explanation FROM findings ORDER BY timestamp_utc DESC, id DESC"
        cursor = connection.execute(query if limit is None else query + " LIMIT ?", () if limit is None else (limit,))
        rows = [dict(row) for row in cursor]
        return {"status": "available", "message": status["message"],
                "findings": rows, "count": status["finding_count"]}
    except (sqlite3.Error, OSError) as error:
        return {"status": "error", "message": f"Could not load findings: {error}", "findings": [], "count": 0}
    finally:
        if connection is not None:
            connection.close()


def load_audit_events(db_path, limit=50):
    """Load actual chained SQLite events without modifying the audit database."""
    if limit < 1:
        raise ValueError("limit must be positive")
    status = get_database_status(db_path)
    if status["status"] != "available":
        return {**status, "events": []}
    connection = None
    try:
        connection = _read_connection(db_path)
        cursor = connection.execute(
            "SELECT id, timestamp_utc, event_type, record_data FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        events = []
        for row in cursor:
            event = dict(row)
            try:
                payload = json.loads(event["record_data"])
            except (TypeError, ValueError):
                payload = None
            event["payload"] = payload
            finding = payload.get("finding") if isinstance(payload, dict) else None
            event["summary"] = (finding.get("explanation") or finding.get("change_type")
                                if isinstance(finding, dict) else event["event_type"])
            events.append(event)
        return {"status": "available", "message": status["message"], "events": events}
    except (sqlite3.Error, OSError) as error:
        return {"status": "error", "message": f"Could not load audit events: {error}", "events": []}
    finally:
        if connection is not None:
            connection.close()


def filter_findings(findings, search="", severities=None):
    severity_filter = set(severities or [])
    needle = search.strip().casefold()
    result = []
    for finding in findings:
        if severity_filter and finding.get("severity") not in severity_filter:
            continue
        if needle and needle not in " ".join(str(value or "") for value in finding.values()).casefold():
            continue
        result.append(finding)
    return result


def sort_findings(findings, order="Newest first"):
    """Return a sorted copy of findings using stable, explicit sort rules."""
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows = list(findings)
    if order == "Oldest first":
        return sorted(rows, key=lambda row: (row.get("timestamp_utc") or "", row.get("id") or 0))
    if order == "Severity":
        return sorted(rows, key=lambda row: (severity_rank.get(row.get("severity"), 4),
                                              row.get("timestamp_utc") or ""))
    if order == "File path":
        return sorted(rows, key=lambda row: (row.get("file_path") or "").casefold())
    return sorted(rows, key=lambda row: (row.get("timestamp_utc") or "", row.get("id") or 0), reverse=True)


def _resolve_inventory_root(root_directory):
    """Resolve only the project's real lab directory for dashboard inventory scans."""
    project_root = PROJECT_ROOT.resolve(strict=True)
    lab_path = project_root / "lab"
    if lab_path.is_symlink():
        raise ValueError("The project lab directory must not be a symbolic link")
    if not lab_path.is_dir():
        raise NotADirectoryError(f"Project lab directory is unavailable: {lab_path}")

    requested_root = Path(root_directory)
    if ".." in requested_root.parts:
        raise ValueError("Inventory paths may not traverse outside the project lab directory")
    if not requested_root.is_absolute():
        requested_root = project_root / requested_root
    requested_root = Path(os.path.abspath(requested_root))

    current = Path(requested_root.anchor)
    for part in requested_root.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("Inventory paths must not traverse symbolic links")

    root = requested_root.resolve(strict=True)
    lab = lab_path.resolve(strict=True)
    if root != lab:
        raise ValueError("File Integrity inventory is restricted to the project's lab directory")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")
    return root


def load_file_inventory(root_directory, baseline_path, key_path, signature_path=None):
    """Scan only the project's controlled lab and compare its authenticated baseline."""
    root = _resolve_inventory_root(root_directory)
    scan = scan_directory(root)
    baseline = None
    try:
        authenticated = load_authenticated_baseline(baseline_path, key_path, signature_path)
        if Path(authenticated["root_directory"]).resolve() != root:
            baseline_result = {"status": "failed", "message":
                               "Authenticated baseline belongs to a different directory"}
        else:
            baseline = authenticated
            baseline_result = {"status": "verified", "message": "Baseline HMAC verified"}
    except (OSError, ValueError, PermissionError) as error:
        baseline_result = {"status": "failed", "message": f"Baseline authentication failed: {error}"}

    current_files = scan["files"]
    baseline_files = baseline.get("files", {}) if baseline else {}
    rows = []

    def add_row(relative_path, current, original, state_override=None):
        if state_override:
            state = state_override
        elif not baseline:
            state = "Inaccessible" if current is None else "Unverified"
        elif current is None:
            state = "Deleted"
        elif original is None:
            state = "Added"
        elif current["sha256"] != original["sha256"] or current["size"] != original["size"]:
            state = "Modified"
        elif current["mode"] != original["mode"]:
            state = "Permission changed"
        elif (current["uid"], current["gid"]) != (original["uid"], original["gid"]):
            state = "Ownership changed"
        else:
            state = "Unchanged"
        item = current or original or {}
        rows.append({"file_path": relative_path,
                     "sha256": current.get("sha256") if current else (original or {}).get("sha256"),
                     "size": item.get("size"), "permissions": f"{item['mode']:04o}" if "mode" in item else "—",
                     "uid": item.get("uid"), "gid": item.get("gid"),
                     "modified_utc": _mtime_utc(item.get("mtime_ns")),
                     "integrity_state": state, "details": current or original})

    error_paths = set(scan["errors"])
    for relative in sorted(current_files):
        add_row(relative, current_files[relative], baseline_files.get(relative))
    if baseline:
        for relative in sorted(set(baseline_files) - set(current_files)):
            if any(relative == error or relative.startswith(error.rstrip("/") + "/")
                   for error in error_paths if error not in {".", ""}):
                add_row(relative, None, baseline_files[relative], state_override="Inaccessible")
            elif error_paths.intersection({".", ""}):
                add_row(relative, None, baseline_files[relative], state_override="Inaccessible")
            else:
                add_row(relative, None, baseline_files[relative])
    for relative, message in sorted(scan["errors"].items()):
        rows.append({"file_path": relative, "sha256": None, "size": None, "permissions": "—",
                     "uid": None, "gid": None, "modified_utc": "—",
                     "integrity_state": "Inaccessible", "details": message})
    return {"status": "available", "root_directory": str(root),
            "baseline_status": baseline_result["status"], "baseline_message": baseline_result["message"],
            "scan_errors": scan["errors"], "files": rows}


def _mtime_utc(mtime_ns):
    if mtime_ns is None:
        return "—"
    return datetime.fromtimestamp(mtime_ns / 1_000_000_000, timezone.utc).isoformat(timespec="seconds")


def get_audit_summary(db_path):
    """Return read-only audit record counts and timestamps for the verification page."""
    status = get_database_status(db_path)
    if status["status"] != "available":
        return {"status": status["status"], "message": status["message"], "count": None,
                "first_timestamp": None, "latest_timestamp": None}
    connection = None
    try:
        connection = _read_connection(db_path)
        row = connection.execute("SELECT COUNT(*), MIN(timestamp_utc), MAX(timestamp_utc) FROM audit_log").fetchone()
        return {"status": "available", "message": status["message"], "count": row[0],
                "first_timestamp": row[1], "latest_timestamp": row[2]}
    except (sqlite3.Error, OSError) as error:
        return {"status": "error", "message": f"Could not read audit summary: {error}", "count": None,
                "first_timestamp": None, "latest_timestamp": None}
    finally:
        if connection is not None:
            connection.close()


def get_baseline_status(baseline_path, key_path, signature_path=None):
    baseline_file = Path(baseline_path)
    key_file = Path(key_path)
    signature_file = Path(signature_path) if signature_path else Path(f"{baseline_path}.hmac")
    artifacts = {
        "baseline_available": baseline_file.is_file(),
        "key_available": key_file.is_file(),
        "signature_available": signature_file.is_file(),
    }
    try:
        baseline = load_authenticated_baseline(baseline_path, key_path, signature_path)
        return {"status": "verified", "message": "Baseline HMAC verified",
                "root_directory": baseline["root_directory"], **artifacts}
    except (OSError, ValueError, PermissionError) as error:
        return {"status": "failed", "message": f"Baseline authentication failed: {error}", **artifacts}


def get_audit_status(db_path):
    return verify_audit_chain(db_path)


def get_monitor_status(status_path, *, now=None, stale_after_seconds=10):
    return read_monitor_status(status_path, now=now, stale_after_seconds=stale_after_seconds)


def _parse_bool(value):
    if value == "":
        return False
    if value not in {"True", "False"}:
        raise ValueError(f"Invalid boolean value in evaluation CSV: {value}")
    return value == "True"


def load_evaluation_results(csv_path):
    path = Path(csv_path)
    if not path.exists():
        return {"status": "missing", "message": f"Evaluation results not found: {path}", "rows": [], "metrics": None}
    try:
        from evaluate import calculate_metrics

        with path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        required = {"scenario_id", "category", "expected_rule_id", "smart_expected_rule_detected",
                    "smart_finding_count", "hash_only_change_detected", "hash_only_finding_count",
                    "false_positive", "false_negative", "benign_correctly_handled",
                    "explanation_covered", "attack_mapping_covered"}
        if not rows or not required <= set(rows[0]):
            raise ValueError("Evaluation CSV is empty or missing required columns")
        converted = []
        for original in rows:
            row = dict(original)
            for key in BOOL_COLUMNS:
                row[key] = _parse_bool(row.get(key, ""))
            for key in INT_COLUMNS:
                row[key] = int(row[key])
            converted.append(row)
        metrics = calculate_metrics(converted)
        return {"status": "available", "message": f"Loaded {len(converted)} measured scenarios",
                "rows": converted, "metrics": metrics}
    except (OSError, csv.Error, KeyError, TypeError, ValueError) as error:
        return {"status": "error", "message": f"Could not read evaluation results: {error}", "rows": [], "metrics": None}
