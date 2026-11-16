# Phase 3 monitoring and audit security

## Monitoring pipeline

`IntegrityMonitor` authenticates and validates the detached-signed baseline before use. It requires the baseline's recorded root to match the configured `lab/` directory. Watchdog create, modify, delete, and move events are debounced and cause a sandbox scan. Directory events also trigger a full scan so child changes are covered. Temporary editor files are excluded from monitor comparisons. The watcher never opens a path supplied by an event; it rescans using the existing scanner, which does not follow symlinks.

The monitor also runs a periodic full scan independently of event delivery. Both paths call the same Phase 2 comparison engine. Finding fingerprints include the finding and current/baseline SHA-256 values; the fingerprint and finding are recorded in the audit chain in the same SQLite transaction as the finding row. Repeated observer events and reconciliation of the same state therefore do not create duplicate findings. Scan failures are kept separate from missing paths, and errors for a directory suppress inferred deletion of its descendants.

The configured root must be an existing directory named `lab`; use the project's controlled synthetic sandbox. `watch` stops the observer and reconciliation worker on Ctrl+C.

## Baseline HMAC

The key is 32 bytes from `secrets.token_bytes()` and is created exclusively with owner-only `0600` permissions. The detached `.hmac` file contains the lowercase hexadecimal HMAC-SHA256 over the exact baseline file bytes, including whitespace and final newline. Verification uses `hmac.compare_digest()`. The key is never added to the baseline or database.

`init <folder>` creates and signs a baseline only when neither the baseline nor its detached signature exists. Replacing trust data requires `--approve-update`. A missing or invalid key/signature causes verification and monitoring to fail closed. The operator must protect the key separately: an attacker able to change both baseline and key can create a new valid HMAC. If the key is missing, follow the backup and explicit recovery procedure in [security-design.md](security-design.md); never sign the old baseline with an automatically generated key.

## Audit chain

Audit `id` values are sequential and AUTOINCREMENT-backed. The first record's `previous_hash` is 64 zero characters (the genesis value). Record data is canonical JSON: UTF-8, sorted object keys, no insignificant spaces, and NaN values rejected. `record_hash` is SHA-256 over canonical JSON containing exactly `id`, `timestamp_utc`, `event_type`, `record_data` (the canonical JSON text as a string), and `previous_hash`. Every append uses `BEGIN IMMEDIATE`; verification checks data canonicality, record hash, previous-hash link, sequential identifiers, and the SQLite sequence high-water mark to detect deletion of trailing records. Verification uses a read-only database connection and never repairs data.

This is tamper-evident logging, not tamper-proof storage. A privileged attacker who can rewrite the database and every chain row can construct a replacement chain because there is no external trusted anchor. An attacker who controls the baseline and its HMAC key can likewise re-sign altered baseline data. Audit append operations verify the current chain inside the SQLite write transaction and refuse to extend invalid or unreadable chains.

## CLI

From the project directory:

```bash
python -m integritywatch init lab
python -m integritywatch verify --mode smart
python -m integritywatch verify --mode hash-only
python -m integritywatch watch --mode smart --debounce 0.5 --interval 30
python -m integritywatch verify-log
python -m integritywatch report
```

The original project baseline and signature remain preserved without their original key, so their authenticity is unavailable. CLI verification and monitoring now default to the separate official V1.0 trust anchor under `data/recovery/new-trust-anchor/`. This bundle authenticates the current controlled lab but does not recover the original baseline's authenticity. On a fresh project with no baseline or signature, use `python -m integritywatch init lab`. Use `--baseline`, `--key`, `--signature`, and `--db` to select storage paths. When `--signature` is omitted, it defaults to `<baseline>.hmac`. `verify-log` prints `valid`, `empty`, `invalid`, or `error`, with the first invalid record where applicable.

The existing Phase 2 sudoers parser and suspicious-cron command marker limitations are documented in [phase2-detection.md](phase2-detection.md).
