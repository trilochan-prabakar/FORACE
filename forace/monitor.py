"""Sandbox-only watchdog monitoring with debouncing and periodic reconciliation."""
import hashlib
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from forace.auth import load_authenticated_baseline
from forace.detection import compare_scans
from forace.scanner import scan_directory
from forace.store import canonical_json, initialize_database, store_finding_once, verify_audit_chain, clear_inactive_findings
from forace.observations import ensure_observation_schema, record_failed_scan, record_scan


TEMP_SUFFIXES = {".swp", ".tmp", ".temp", ".part", ".lock"}
LOGGER = logging.getLogger("forace.monitor")


class IntegrityMonitor(FileSystemEventHandler):
    """Watch and reconcile one configured sandbox against a signed baseline."""

    def __init__(self, root_directory, baseline_path, key_path, signature_path,
                 db_path, *, mode="smart", debounce_seconds=0.5,
                 reconcile_interval=30.0):
        super().__init__()
        if mode not in {"smart", "hash-only"}:
            raise ValueError("mode must be 'smart' or 'hash-only'")
        if debounce_seconds < 0 or reconcile_interval <= 0:
            raise ValueError("debounce must be non-negative and reconciliation interval positive")
        self.root = Path(root_directory).resolve()
        if self.root.name != "lab" or not self.root.is_dir():
            raise ValueError("Monitoring is restricted to an existing controlled directory named lab")
        self.baseline_path = Path(baseline_path)
        self.key_path = Path(key_path)
        self.signature_path = Path(signature_path)
        self.db_path = Path(db_path)
        self.mode = mode
        self.debounce_seconds = debounce_seconds
        self.reconcile_interval = reconcile_interval
        self._lock = threading.RLock()
        self._scan_lock = threading.Lock()
        self._last_event = {}
        self._stop_event = threading.Event()
        self._observer = None
        self._reconcile_thread = None
        self.stopped = False
        self.last_error = None
        self._trusted_baseline()
        if self.db_path.is_symlink():
            raise ValueError("SQLite database path must not be a symbolic link")
        if self.db_path.exists():
            audit_status = verify_audit_chain(self.db_path)
            if audit_status["status"] not in {"empty", "valid"}:
                raise RuntimeError(f"Refusing to initialize an invalid audit database: {audit_status['message']}")
        initialize_database(self.db_path)
        ensure_observation_schema(self.db_path)

    def _trusted_baseline(self):
        baseline = load_authenticated_baseline(self.baseline_path, self.key_path, self.signature_path)
        if Path(baseline["root_directory"]).resolve() != self.root:
            raise ValueError("Authenticated baseline root does not match monitored sandbox")
        return baseline

    def _inside_root(self, value):
        candidate = Path(os.path.abspath(os.fspath(value)))
        return candidate == self.root or candidate.is_relative_to(self.root)

    @staticmethod
    def _temporary(path):
        name = Path(path).name
        return name.endswith("~") or Path(name).suffix.lower() in TEMP_SUFFIXES or name.startswith(".#")

    def process_scan(self, scan_result=None, *, trigger="manual"):
        """Compare a scan and persist findings plus its observation manifest."""
        started = datetime.now(timezone.utc).isoformat()
        with self._scan_lock:
            baseline = self._trusted_baseline()
            current = scan_result if scan_result is not None else scan_directory(self.root)
            findings = compare_scans(baseline, current, mode=self.mode)
            stored = []
            active_fingerprints = []
            for finding in findings:
                entry = current.get("files", {}).get(finding["file_path"], {})
                fingerprint_payload = canonical_json({
                    "finding": finding,
                    "current_sha256": entry.get("sha256"),
                    "baseline_sha256": baseline["files"].get(finding["file_path"], {}).get("sha256"),
                }).encode("utf-8")
                fingerprint = hashlib.sha256(fingerprint_payload).hexdigest()
                active_fingerprints.append(fingerprint)
                if store_finding_once(self.db_path, finding, fingerprint):
                    stored.append(finding)
            clear_inactive_findings(self.db_path, active_fingerprints)
            self.last_scan = record_scan(
                self.db_path, current, trigger=trigger, mode=self.mode,
                findings_count=len(findings), started_at_utc=started,
            )
            self.last_error = None
            return stored

    def _record_failure(self, trigger, error):
        self.last_error = str(error)
        try:
            record_failed_scan(self.db_path, trigger=trigger, mode=self.mode,
                               error_message=self.last_error)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as audit_error:
            LOGGER.error("Could not persist failed scan state: %s", audit_error)

    def reconcile_once(self, scan_result=None, *, trigger="reconciliation"):
        """Run one full scan independently of watchdog event delivery."""
        return self.process_scan(scan_result=scan_result, trigger=trigger)

    def handle_event(self, event_type, src_path, dest_path=None, *, is_directory=False):
        """Process a relevant in-root event after suppressing duplicate bursts."""
        paths = [p for p in (src_path, dest_path) if p]
        inside = [p for p in paths if self._inside_root(p)]
        if not inside or all(self._temporary(p) for p in inside):
            return []
        key = (event_type, tuple(sorted(os.path.abspath(os.fspath(p)) for p in inside)))
        now = time.monotonic()
        with self._lock:
            previous = self._last_event.get(key)
            self._last_event[key] = now
            if previous is not None and now - previous < self.debounce_seconds:
                return []
        try:
            self.last_error = None
            return self.process_scan()
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
            self._record_failure(f"watchdog:{event_type}", error)
            LOGGER.warning("Filesystem event scan failed: %s", error)
            return []

    def _dispatch(self, event_type, event):
        if getattr(event, "event_type", "") == "closed_no_write":
            return
        return self.handle_event(event_type, event.src_path,
                                 getattr(event, "dest_path", None),
                                 is_directory=event.is_directory)

    def on_created(self, event):
        self._dispatch("created", event)

    def on_modified(self, event):
        self._dispatch("modified", event)

    def on_deleted(self, event):
        self._dispatch("deleted", event)

    def on_moved(self, event):
        self._dispatch("moved", event)

    def _reconciliation_loop(self):
        while not self._stop_event.wait(self.reconcile_interval):
            try:
                self.reconcile_once(trigger="reconciliation")
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                self._record_failure("reconciliation", error)
                LOGGER.warning("Periodic reconciliation failed: %s", error)

    def start(self):
        """Start watchdog plus periodic reconciliation; both use the same sandbox."""
        if self._observer is not None:
            return
        self._trusted_baseline()
        audit_status = verify_audit_chain(self.db_path)
        if audit_status["status"] not in {"empty", "valid"}:
            raise RuntimeError(f"Refusing to monitor with an invalid audit chain: {audit_status['message']}")
        self.reconcile_once(trigger="startup")
        observer = Observer()
        observer.schedule(self, str(self.root), recursive=True)
        observer.start()
        self._observer = observer
        self._stop_event.clear()
        self.stopped = False
        self._reconcile_thread = threading.Thread(target=self._reconciliation_loop,
                                                  name="forace-reconcile", daemon=True)
        self._reconcile_thread.start()

    def stop(self):
        """Stop observer and reconciliation worker safely; repeated calls are okay."""
        self._stop_event.set()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            if self._observer.is_alive():
                raise RuntimeError("Watchdog observer did not stop within five seconds")
            self._observer = None
        if self._reconcile_thread is not None:
            self._reconcile_thread.join(timeout=max(5, self.reconcile_interval + 1))
            if self._reconcile_thread.is_alive():
                raise RuntimeError("Reconciliation worker did not stop cleanly")
            self._reconcile_thread = None
        self.stopped = True
