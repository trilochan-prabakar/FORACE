"""V2 persistent scan observations with audit-linked manifests."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from forace.store import _append_audit_in_transaction, _verify_audit_connection, canonical_json, get_connection

SCHEMA_VERSION = 3

def _now():
    return datetime.now(timezone.utc).isoformat()

def _validate_utc(value, field):
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{field} must be timezone-aware UTC")
    return value

def ensure_observation_schema(db_path):
    connection = get_connection(db_path)
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"Database schema {version} is newer than supported schema {SCHEMA_VERSION}")
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS scan_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          started_at_utc TEXT NOT NULL, completed_at_utc TEXT NOT NULL,
          trigger TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('smart','hash-only')),
          status TEXT NOT NULL CHECK(status IN ('completed','completed_with_errors','failed')),
          files_observed INTEGER NOT NULL CHECK(files_observed >= 0),
          errors_count INTEGER NOT NULL CHECK(errors_count >= 0),
          findings_count INTEGER NOT NULL CHECK(findings_count >= 0),
          manifest_sha256 TEXT NOT NULL, error_message TEXT
        );
        CREATE TABLE IF NOT EXISTS file_observations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
          file_path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
          mode INTEGER NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL,
          mtime_ns INTEGER NOT NULL, UNIQUE(scan_id,file_path)
        );
        CREATE TABLE IF NOT EXISTS observation_errors (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
          path TEXT NOT NULL, error TEXT NOT NULL, UNIQUE(scan_id,path)
        );
        CREATE INDEX IF NOT EXISTS idx_scan_runs_completed ON scan_runs(completed_at_utc,id);
        CREATE INDEX IF NOT EXISTS idx_observations_path ON file_observations(file_path,scan_id);
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(findings)")}
        if "scan_id" not in columns:
            connection.execute("ALTER TABLE findings ADD COLUMN scan_id INTEGER REFERENCES scan_runs(id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
    finally:
        connection.close()
    return Path(db_path)

def _payload(files, errors):
    rows = [{"file_path": path, "sha256": item["sha256"], "size": int(item["size"]),
             "mode": int(item["mode"]), "uid": int(item["uid"]), "gid": int(item["gid"]),
             "mtime_ns": int(item["mtime_ns"])} for path, item in sorted(files.items())]
    errs = [{"path": path, "error": str(message)} for path, message in sorted(errors.items())]
    body = {"files": rows, "errors": errs}
    return body, hashlib.sha256(canonical_json(body).encode()).hexdigest()

def _record(db_path, *, trigger, mode, started, completed, status,
            files, errors, findings_count, error_message=None):
    body, digest = _payload(files, errors)
    connection = get_connection(db_path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        audit = _verify_audit_connection(connection)
        if audit["status"] not in {"empty", "valid"}:
            raise RuntimeError(f"Cannot record observation: audit chain {audit['status']}: {audit['message']}")
        cur = connection.execute(
          """INSERT INTO scan_runs(started_at_utc,completed_at_utc,trigger,mode,status,
             files_observed,errors_count,findings_count,manifest_sha256,error_message)
             VALUES(?,?,?,?,?,?,?,?,?,?)""",
          (started,completed,trigger,mode,status,len(files),len(errors),findings_count,digest,error_message))
        scan_id = cur.lastrowid
        connection.executemany(
          """INSERT INTO file_observations(scan_id,file_path,sha256,size,mode,uid,gid,mtime_ns)
             VALUES(?,?,?,?,?,?,?,?)""",
          [(scan_id,x["file_path"],x["sha256"],x["size"],x["mode"],x["uid"],x["gid"],x["mtime_ns"])
           for x in body["files"]])
        connection.executemany(
          "INSERT INTO observation_errors(scan_id,path,error) VALUES(?,?,?)",
          [(scan_id,x["path"],x["error"]) for x in body["errors"]])
        event = "scan_failed" if status == "failed" else "scan_completed"
        data = {"scan_id":scan_id,"trigger":trigger,"mode":mode,"status":status,
                "started_at_utc":started,"completed_at_utc":completed,
                "files_observed":len(files),"errors_count":len(errors),
                "findings_count":findings_count,"manifest_sha256":digest}
        data["error_message"] = error_message
        _append_audit_in_transaction(connection,event,canonical_json(data),completed)
        connection.commit()
        return {"scan_id":scan_id,"status":status,"manifest_sha256":digest,
                "files_observed":len(files),"errors_count":len(errors)}
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()

def record_scan(db_path, scan_result, *, trigger, mode, findings_count,
                started_at_utc=None, completed_at_utc=None):
    if mode not in {"smart","hash-only"} or not isinstance(trigger,str) or not trigger.strip():
        raise ValueError("A valid mode and non-empty trigger are required")
    if type(findings_count) is not int or findings_count < 0:
        raise ValueError("findings_count must be a non-negative integer")
    files, errors = scan_result.get("files",{}), scan_result.get("errors",{})
    if not isinstance(files,dict) or not isinstance(errors,dict):
        raise ValueError("scan_result must contain file and error mappings")
    started = _validate_utc(started_at_utc or _now(), "started_at_utc")
    completed = _validate_utc(completed_at_utc or _now(), "completed_at_utc")
    status = "completed_with_errors" if errors else "completed"
    return _record(db_path,trigger=trigger,mode=mode,started=started,completed=completed,
                   status=status,files=files,errors=errors,findings_count=findings_count)

def record_failed_scan(db_path, *, trigger, mode, error_message):
    if mode not in {"smart","hash-only"} or not isinstance(trigger,str) or not trigger.strip():
        raise ValueError("A valid mode and non-empty trigger are required")
    now = _now()
    message = str(error_message)[:2000] or "Unknown scan failure"
    return _record(db_path,trigger=trigger,mode=mode,started=now,completed=now,status="failed",
                   files={},errors={},findings_count=0,error_message=message)

def verify_observation_history(db_path):
    path = Path(db_path)
    if not path.exists():
        return {"status":"missing","valid":False,"scans_checked":0,"message":f"Database does not exist: {path}"}
    connection = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True,timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"scan_runs","file_observations","observation_errors","audit_log"} <= tables:
            return {"status":"unavailable","valid":False,"scans_checked":0,"message":"V2 observation schema is not installed"}
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            return {"status":"invalid","valid":False,"scans_checked":0,
                    "message":"Observation database contains foreign-key violations"}
        orphan_checks = [
            ("file_observations", "SELECT COUNT(*) FROM file_observations o LEFT JOIN scan_runs s ON s.id=o.scan_id WHERE s.id IS NULL"),
            ("observation_errors", "SELECT COUNT(*) FROM observation_errors o LEFT JOIN scan_runs s ON s.id=o.scan_id WHERE s.id IS NULL"),
        ]
        for table, query in orphan_checks:
            if connection.execute(query).fetchone()[0]:
                return {"status":"invalid","valid":False,"scans_checked":0,
                        "message":"Orphaned rows detected in " + table}
        audit = _verify_audit_connection(connection)
        if audit["status"] not in {"empty","valid"}:
            return {"status":"invalid","valid":False,"scans_checked":0,"message":f"Audit chain is {audit['status']}: {audit['message']}"}
        runs = connection.execute("SELECT * FROM scan_runs ORDER BY id").fetchall()
        events = {}
        for row in connection.execute("SELECT timestamp_utc,event_type,record_data FROM audit_log WHERE event_type IN ('scan_completed','scan_failed')"):
            data = json.loads(row["record_data"])
            sid = data.get("scan_id")
            if sid in events:
                return {"status":"invalid","valid":False,"scans_checked":0,"message":f"Duplicate audit event for scan {sid}"}
            events[sid] = (row["event_type"],data,row["timestamp_utc"])
        if not runs and not events:
            return {"status":"empty","valid":True,"scans_checked":0,"message":"No scan observations have been recorded"}
        for run in runs:
            sid = run["id"]
            event = events.pop(sid,None)
            expected = "scan_failed" if run["status"] == "failed" else "scan_completed"
            if event is None or event[0] != expected:
                return {"status":"invalid","valid":False,"scans_checked":sid-1,"message":f"Missing audit event for scan {sid}"}
            file_rows = [dict(x) for x in connection.execute(
              "SELECT file_path,sha256,size,mode,uid,gid,mtime_ns FROM file_observations WHERE scan_id=? ORDER BY file_path",(sid,))]
            error_rows = [dict(x) for x in connection.execute(
              "SELECT path,error FROM observation_errors WHERE scan_id=? ORDER BY path",(sid,))]
            manifest = {"files":[{"file_path":x["file_path"],"sha256":x["sha256"],"size":x["size"],
                       "mode":x["mode"],"uid":x["uid"],"gid":x["gid"],"mtime_ns":x["mtime_ns"]} for x in file_rows],
                       "errors":error_rows}
            digest = hashlib.sha256(canonical_json(manifest).encode()).hexdigest()
            data = event[1]
            if (digest != run["manifest_sha256"] or digest != data.get("manifest_sha256")
                or len(file_rows) != run["files_observed"] or len(error_rows) != run["errors_count"]
                or run["status"] != data.get("status")
                or run["trigger"] != data.get("trigger") or run["mode"] != data.get("mode")
                or run["files_observed"] != data.get("files_observed")
                or run["errors_count"] != data.get("errors_count")
                or run["findings_count"] != data.get("findings_count")
                or run["error_message"] != data.get("error_message")
                or run["started_at_utc"] != data.get("started_at_utc")
                or run["completed_at_utc"] != data.get("completed_at_utc")
                or run["completed_at_utc"] != event[2]
                or (run["status"] == "failed" and run["error_message"] != data.get("error_message"))):
                return {"status":"invalid","valid":False,"scans_checked":sid-1,"message":f"Observation manifest mismatch for scan {sid}"}
        if events:
            return {"status":"invalid","valid":False,"scans_checked":len(runs),"message":"Orphaned scan audit event"}
        return {"status":"valid","valid":True,"scans_checked":len(runs),
                "message":"Scan observations match their audit-linked manifests"}
    except (sqlite3.Error,OSError,TypeError,ValueError,KeyError) as error:
        return {"status":"error","valid":False,"scans_checked":0,"message":f"Could not verify observation history: {error}"}
    finally:
        if connection is not None:
            connection.close()

def load_scan_history(db_path, limit=50):
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    path = Path(db_path)
    if not path.exists():
        return {"status":"missing","message":f"Database does not exist: {path}","scans":[]}
    connection = None
    try:
        connection = sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True,timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "scan_runs" not in tables:
            return {"status":"unavailable","message":"Scan history is not available in this V1 database","scans":[]}
        scans = [dict(r) for r in connection.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?",(limit,))]
        for scan in scans:
            sid = scan["id"]
            scan["files"] = [dict(row) for row in connection.execute(
                "SELECT file_path,sha256,size,mode,uid,gid,mtime_ns FROM file_observations WHERE scan_id=? ORDER BY file_path",
                (sid,),
            )] if "file_observations" in tables else []
            scan["errors"] = [dict(row) for row in connection.execute(
                "SELECT path,error FROM observation_errors WHERE scan_id=? ORDER BY path",
                (sid,),
            )] if "observation_errors" in tables else []
        count = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
        return {"status":"available","message":f"Loaded {len(scans)} scan records with file details","scans":scans,"count":count}
    except (sqlite3.Error,OSError) as error:
        return {"status":"error","message":f"Could not load scan history: {error}","scans":[]}
    finally:
        if connection is not None:
            connection.close()
