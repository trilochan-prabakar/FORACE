"""Command-line interface for baseline trust, verification, monitoring, and reports."""
import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from forace.auth import generate_key, load_authenticated_baseline, load_key, sign_baseline
from forace.baseline import create_baseline, save_baseline
from forace.detection import compare_scans
from forace.monitor import IntegrityMonitor
from forace.monitor_status import clear_monitor_status, write_monitor_status
from forace.paths import (
    DEFAULT_BASELINE_PATH, DEFAULT_KEY_PATH, default_database_path, project_path,
)
from forace.recovery import establish_recovery_baseline
from forace.scanner import scan_directory
from forace.store import append_audit_record, get_connection, initialize_database, verify_audit_chain


def _add_storage_arguments(parser):
    parser.add_argument("--baseline", default=DEFAULT_BASELINE_PATH, help="Baseline JSON path")
    parser.add_argument("--key", default=DEFAULT_KEY_PATH, help="Owner-only HMAC key path")
    parser.add_argument("--signature", help="Detached baseline signature path (default: <baseline>.hmac)")
    parser.add_argument("--db", help="SQLite database path (default: data/forace.db)")


def _parser():
    parser = argparse.ArgumentParser(prog="python -m forace", description="FORACE sandbox integrity monitor")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create and authenticate a lab baseline")
    init.add_argument("folder", help="Controlled sandbox directory (normally lab/)")
    _add_storage_arguments(init)
    init.add_argument("--approve-update", action="store_true", help="Explicitly replace and re-authenticate an existing baseline")

    rebaseline = commands.add_parser(
        "rebaseline",
        help="Review the lab and establish a new trust anchor at separate recovery paths",
    )
    rebaseline.add_argument("folder", nargs="?", default="lab", help="Controlled sandbox directory")
    rebaseline.add_argument("--source-baseline", default="data/baseline.json", help="Existing unauthenticated baseline to preserve")
    rebaseline.add_argument("--source-signature", default="data/baseline.json.hmac", help="Existing detached signature to preserve")
    rebaseline.add_argument("--recovery-dir", default="data/recovery", help="Private directory for new recovery files")
    rebaseline.add_argument("--bundle-name", default="new-trust-anchor", help="New recovery bundle directory name")

    verify = commands.add_parser("verify", help="Authenticate baseline and compare current lab state")
    verify.add_argument("--lab", default="lab", help="Controlled sandbox directory")
    verify.add_argument("--mode", choices=("smart", "hash-only"), default="smart")
    _add_storage_arguments(verify)

    watch = commands.add_parser("watch", help="Watch lab and periodically reconcile it")
    watch.add_argument("--lab", default="lab", help="Controlled sandbox directory")
    watch.add_argument("--mode", choices=("smart", "hash-only"), default="smart")
    watch.add_argument("--debounce", type=float, default=0.5, help="Duplicate-event debounce window in seconds")
    watch.add_argument("--interval", type=float, default=30.0, help="Full reconciliation interval in seconds")
    _add_storage_arguments(watch)

    verify_log = commands.add_parser("verify-log", help="Read-only verification of the SQLite audit chain")
    _add_storage_arguments(verify_log)

    report = commands.add_parser("report", help="Print findings stored in SQLite as JSON")
    _add_storage_arguments(report)
    return parser


def _require_lab_directory(path):
    root = Path(path).resolve()
    if root.name != "lab" or not root.is_dir():
        raise ValueError("The configured monitor root must be an existing controlled directory named lab")
    return root


def _initialize(args):
    db_path = Path(args.db)
    if db_path.is_symlink():
        raise ValueError("SQLite database path must not be a symbolic link")
    if db_path.exists():
        chain = verify_audit_chain(db_path)
        if chain["status"] not in {"empty", "valid"}:
            raise RuntimeError(f"Refusing to update baseline with an invalid audit log: {chain['message']}")

    root = _require_lab_directory(args.folder)
    baseline_path, key_path = Path(args.baseline), Path(args.key)
    signature_path = Path(args.signature) if args.signature else Path(f"{baseline_path}.hmac")
    exists = any(path.exists() or path.is_symlink() for path in (baseline_path, signature_path))
    if exists and not args.approve_update:
        raise FileExistsError("Baseline or signature exists; pass --approve-update only when deliberately re-baselining")
    baseline = create_baseline(root)
    # Validate an existing key before replacing any trust artifact.
    if key_path.exists() or key_path.is_symlink():
        load_key(key_path)
    else:
        generate_key(key_path)
    save_baseline(baseline, baseline_path, approve_update=args.approve_update)
    sign_baseline(baseline_path, key_path, signature_path, approve_replace=args.approve_update)
    initialize_database(args.db)
    chain = verify_audit_chain(args.db)
    if chain["status"] not in {"empty", "valid"}:
        raise RuntimeError(f"Refusing to append to invalid audit log: {chain['message']}")
    append_audit_record(args.db, "baseline_initialized", {"root_directory": str(root), "sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest()})
    print(f"Baseline authenticated: {baseline_path}")
    print(f"HMAC key: {key_path} (permissions 0600)")
    return 0


def _verify(args):
    audit = verify_audit_chain(args.db)
    if audit["status"] not in {"valid", "empty"}:
        raise RuntimeError(f"Audit verification failed: {audit['message']}")
    root = _require_lab_directory(args.lab)
    signature_path = args.signature or f"{args.baseline}.hmac"
    baseline = load_authenticated_baseline(args.baseline, args.key, signature_path)
    if Path(baseline["root_directory"]).resolve() != root:
        raise ValueError("Authenticated baseline root does not match --lab")
    current = scan_directory(root)
    findings = compare_scans(baseline, current, mode=args.mode)
    print(json.dumps({"mode": args.mode, "findings": findings, "scan_errors": current["errors"],
                      "audit": audit}, indent=2))
    if current["errors"]:
        return 3
    if findings:
        return 2
    return 0


def _rebaseline(args):
    recovery_directory = Path(args.recovery_dir)
    establish_recovery_baseline(
        args.folder,
        args.source_baseline,
        args.source_signature,
        recovery_directory,
        args.bundle_name,
    )
    return 0


def _watch(args):
    root = _require_lab_directory(args.lab)
    signature_path = args.signature or f"{args.baseline}.hmac"
    monitor = IntegrityMonitor(root, args.baseline, args.key, signature_path, args.db,
                               mode=args.mode, debounce_seconds=args.debounce,
                               reconcile_interval=args.interval)
    status_path = project_path("data/monitor_status.json")
    monitor.start()
    print(f"Monitoring {root} in {args.mode} mode. Press Ctrl+C to stop.")
    try:
        while True:
            write_monitor_status(status_path, root=root, mode=args.mode, last_error=monitor.last_error)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping FORACE...")
    finally:
        try:
            monitor.stop()
        finally:
            clear_monitor_status(status_path, pid=os.getpid())
    print("Monitor stopped gracefully.")
    return 0


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    database_commands = {"init", "verify", "watch", "verify-log", "report"}
    if args.command in database_commands and getattr(args, "db", None) is None:
        try:
            args.db = str(default_database_path())
        except ValueError as error:
            parser.error(str(error))
    for name in ("folder", "lab", "baseline", "key", "signature", "db",
                 "source_baseline", "source_signature", "recovery_dir"):
        value = getattr(args, name, None)
        if value is not None:
            setattr(args, name, str(project_path(value)))
    try:
        if args.command == "init":
            return _initialize(args)
        if args.command == "rebaseline":
            return _rebaseline(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "watch":
            return _watch(args)
        if args.command == "verify-log":
            result = verify_audit_chain(args.db)
            print(json.dumps(result, indent=2))
            return 0 if result["status"] in {"valid", "empty"} else 1
        if args.command == "report":
            connection = get_connection(args.db)
            try:
                findings = [dict(row) for row in connection.execute("SELECT * FROM findings ORDER BY id")]
            finally:
                connection.close()
            print(json.dumps(findings, indent=2))
            return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(f"FORACE: {error}", file=sys.stderr)
        return 1
    return 2
