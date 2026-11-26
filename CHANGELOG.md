# Changelog

All notable FORACE changes are documented here.

## 2.0.0 — 2026-11-27

### Added
- Persistent scan lifecycle history with completed, completed-with-errors, and failed states.
- Per-file SHA-256 and selected metadata observations for each completed scan.
- Path-scoped scanner error records, preserving partial observation status.
- Deterministic observation manifests linked to the existing SHA-256 audit chain in the same SQLite transaction.
- Read-only observation verification through `python -m forace verify-evidence`.
- Scan history through `python -m forace history --limit 50` and a new Scan History dashboard page.
- Bounded watchdog event de-duplication cache and visible partial-scan error status.
- Expanded isolated evaluation corpus: 20 synthetic attack scenarios across R01–R12 and 10 benign edits.
- V2 migration, orphan-observation integrity, atomic scan/finding persistence, monitoring, evaluation-artifact, and dashboard regression tests.
- Per-file observation and scanner-error details in the Scan History dashboard.
- Pinned direct dependencies, a resolved Linux dependency lock, and Python 3.11/3.12 CI coverage.

### Compatibility
- Existing V1 findings, baseline HMAC authentication, R01–R12 rules, audit chain, and CLI operations are retained.
- The V2 observation schema is additive and advances `PRAGMA user_version` to 3; the latest migration adds nullable `findings.scan_id` provenance while preserving V1 rows.
- The checked-in `results.csv` now represents the 30-scenario V2 corpus.

### Limitations
- Scan observations describe point-in-time states; they do not prove every transient state between scans.
- The audit chain is local and tamper-evident, not externally timestamped or immutable against an attacker who can rewrite the complete database.
- Synthetic evaluation results are not real-world detection-rate estimates.
