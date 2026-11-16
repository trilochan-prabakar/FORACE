"""Repeatable, safe demonstration using a temporary lab, key, baseline, and database."""
import argparse
import json
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

from attacks.R01_permit_root_login import apply as apply_r01
from evaluate import _isolation_marker
from integritywatch.auth import generate_key, load_authenticated_baseline, sign_baseline
from integritywatch.baseline import create_baseline, save_baseline
from integritywatch.detection import compare_scans
from integritywatch.monitor import IntegrityMonitor
from integritywatch.scanner import scan_directory
from integritywatch.store import initialize_database, verify_audit_chain


def _read_findings(db_path):
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute("SELECT * FROM findings ORDER BY id")]


def _execute_demo(workspace, source_lab):
    workspace = Path(workspace)
    isolated_lab = workspace / "lab"
    _isolation_marker(workspace, "DEMO-R01")
    shutil.copytree(Path(source_lab).resolve(), isolated_lab, symlinks=True)
    baseline_path = workspace / "baseline.json"
    key_path = workspace / "baseline.key"
    signature_path = workspace / "baseline.json.hmac"
    db_path = workspace / "demo.sqlite"

    baseline = create_baseline(isolated_lab)
    save_baseline(baseline, baseline_path)
    generate_key(key_path)
    sign_baseline(baseline_path, key_path, signature_path)
    trusted = load_authenticated_baseline(baseline_path, key_path, signature_path)
    clean_findings = compare_scans(trusted, scan_directory(isolated_lab), mode="smart")
    if clean_findings:
        raise RuntimeError(f"Clean baseline scan unexpectedly reported {len(clean_findings)} finding(s)")
    print("Step 1 — Clean baseline HMAC: VERIFIED; initial findings: 0")

    initialize_database(db_path)
    monitor = IntegrityMonitor(isolated_lab, baseline_path, key_path, signature_path, db_path,
                               mode="smart", debounce_seconds=0.1, reconcile_interval=30)
    monitor.start()
    print("Step 2 — Watchdog monitoring started on the isolated lab copy")
    try:
        apply_r01(isolated_lab)
        print("Step 3 — Applied safe R01 text change in lab/etc/ssh/sshd_config")
        deadline = time.monotonic() + 4
        findings = []
        while time.monotonic() < deadline:
            monitor.reconcile_once()
            findings = _read_findings(db_path)
            if findings:
                break
            time.sleep(0.05)
        if not findings:
            raise RuntimeError("Demo change was not recorded by the monitor")
        print("Step 4 — Change detected and stored")
        finding = findings[-1]
        print("Step 5 — Security explanation and ATT&CK mapping:")
        print(json.dumps({key: finding.get(key) for key in
                          ("file_path", "rule_id", "severity", "attack_id", "explanation")}, indent=2))
        print(f"Step 6 — SQLite contains {len(findings)} actual finding(s) in {db_path.name}")
    finally:
        monitor.stop()

    current = scan_directory(isolated_lab)
    smart_findings = compare_scans(trusted, current, mode="smart")
    hash_only_findings = compare_scans(trusted, current, mode="hash-only")
    audit_before_tamper = verify_audit_chain(db_path)
    if audit_before_tamper["status"] != "valid":
        raise RuntimeError(f"Audit chain should be valid before isolated tampering: {audit_before_tamper}")
    print(f"Step 7 — Audit chain before tampering: {audit_before_tamper['status']}")
    print(f"Step 8 — Smart findings: {len(smart_findings)}; hash-only findings: {len(hash_only_findings)}")

    # This database lives only in this demo workspace and is removed by default.
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE audit_log SET event_type = event_type || '_tampered' WHERE id = 1")
    audit_after_tamper = verify_audit_chain(db_path)
    if audit_after_tamper["status"] != "invalid":
        raise RuntimeError(f"Audit-chain tampering was not detected: {audit_after_tamper}")
    print(f"Step 9 — Isolated demo DB tampering check: {audit_after_tamper['status']}")
    return {
        "finding": finding,
        "smart_findings": smart_findings,
        "hash_only_findings": hash_only_findings,
        "audit_before_tamper": audit_before_tamper,
        "audit_after_tamper": audit_after_tamper,
        "summary": {"baseline_verified": True, "initial_findings": len(clean_findings),
                    "rule_detected": finding.get("rule_id"), "audit_before": audit_before_tamper["status"],
                    "audit_after_tamper": audit_after_tamper["status"],
                    "smart_finding_count": len(smart_findings),
                    "hash_only_finding_count": len(hash_only_findings)},
        "workspace_path": str(workspace),
        "dashboard_paths": {"db": str(db_path), "baseline": str(baseline_path),
                            "key": str(key_path), "signature": str(signature_path)},
    }


def run_demo(source_lab="lab", *, keep=False):
    source = Path(source_lab).resolve(strict=True)
    if source.name != "lab" or not source.is_dir():
        raise ValueError("Demo source must be the controlled lab/ directory")
    if keep:
        workspace = Path(tempfile.mkdtemp(prefix="integritywatch-demo-"))
        result = _execute_demo(workspace, source)
        print(f"Temporary demo workspace retained at: {workspace}")
        print("To view its real findings, launch dashboard.py and select the printed DB, baseline, key, and signature paths.")
        return result
    with tempfile.TemporaryDirectory(prefix="integritywatch-demo-") as directory:
        result = _execute_demo(Path(directory), source)
    print("Temporary demo workspace cleaned up safely.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the safe IntegrityWatch Lite demonstration")
    parser.add_argument("--lab", default="lab", help="Synthetic source lab directory (copied; never modified)")
    parser.add_argument("--keep", action="store_true", help="Keep the isolated temporary workspace to inspect it in the dashboard")
    args = parser.parse_args(argv)
    run_demo(args.lab, keep=args.keep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
