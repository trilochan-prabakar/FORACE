# FORACE V2 — Persistent Scan Observations

## Purpose
V2 adds a persistent observation layer between monitoring and future
investigation. Each scan records the file states actually observed, its trigger
and mode, counts, and a deterministic manifest digest. Partial scans are
marked completed-with-errors; failed attempts are recorded separately and
never represented as clean scans.

This is the foundation for V3 timelines. It does not reconstruct transient
changes that occurred entirely between observations.

## Data model
- scan_runs: one lifecycle record per completed, partial, or failed scan.
- file_observations: SHA-256 and selected metadata per observed regular file.
- observation_errors: path-scoped errors from partial scans.
- audit_log: chained scan_completed and scan_failed events bind scan IDs and
  manifest digests to the existing local audit history.

The manifest covers sorted relative paths, SHA-256, size, mode, UID, GID,
nanosecond mtime, and scanner errors. File contents and text snapshots are not
copied into the observation ledger.

## Migration and commands
The migration is additive. Existing V1 findings and audit rows are preserved.
PRAGMA user_version advances to 2. A newer unsupported schema is rejected.
V1 databases remain readable; history is reported unavailable until V2
monitoring initializes the observation schema.

Run:
  python -m forace history --limit 50
  python -m forace verify-evidence

## Trust and limitations
The manifest is linked to the local SHA-256 audit chain. This makes edits to
observation rows detectable while the chain remains trusted, but is not
tamper-proof storage or an external timestamp authority. An attacker able to
rewrite the whole database can rebuild local records. A scan proves only what
was observed at that time; watchdog notifications may be coalesced, while
periodic reconciliation reduces but does not eliminate observation gaps.
