# Security design and threat model

## Security goals

- Refuse to use a baseline unless its exact bytes authenticate with the local
  HMAC key and detached signature.
- Restrict scans and synthetic simulations to their intended trees; do not
  follow symbolic links during scanning.
- Preserve evidence of finding changes and refuse new appends when the existing
  audit chain is already invalid.
- Keep dashboard reads read-only and display missing, invalid, or unverified
  state without a success indicator.
- Keep demonstrations and evaluations isolated from project trust data and
  host configuration.

## Threat model

| Threat or event | Project response | Limit |
|---|---|---|
| Accidental or unauthorized configuration change under the selected lab | Compare scan to authenticated baseline; report content, metadata, or supported semantic finding | Only selected paths and implemented semantics are covered |
| Missed or coalesced filesystem notification | Periodic full reconciliation checks current state | Does not reconstruct every intermediate event |
| Static symlink or symlink swap while scanning | Directory descriptors and `O_NOFOLLOW`; metadata/content from same open file; changed inode becomes an error | Does not protect against a compromised kernel or a same-user attacker who can replace the trusted root itself |
| Baseline JSON modified without its key | HMAC verification fails before parsing/use | Availability is lost until original key is restored or operator explicitly re-baselines |
| Audit row edited, removed, reordered, or truncated | Record hash, previous-hash linkage, sequence IDs, and SQLite sequence tail are checked | Full database rewrite can rebuild the chain without an external anchor |
| Invalid audit chain followed by new findings | Append operation verifies chain inside the write transaction and refuses invalid/error state | Local DB access controls remain necessary |
| Hostile or malformed SQLite file | Dashboard opens read-only, checks schema and `quick_check`; monitor refuses invalid chains | The app is not a general-purpose SQLite sandbox |
| Misuse of attack simulators | Marker, temp-directory, lab-name, relative-path, and symlink checks | Simulators are intended for private `tempfile` workspaces; same-user hostile concurrent access is outside the model |
| Compromised account/root | Not prevented | A privileged attacker can alter the key, baseline, database, process, and files |

The project assumes a trusted Linux kernel, Python runtime, project installation,
and operator. The intended deployment target is a local single-user Linux or
WSL2 lab, not a multi-user or remote service.

## HMAC-SHA256 baseline authentication

The baseline is JSON describing the resolved sandbox root and each scanned
file's SHA-256 digest, size, permission mode, UID, GID, nanosecond modification
time, and optional bounded UTF-8 snapshot. Its detached `.hmac` signature is
the lowercase hexadecimal HMAC-SHA256 over the exact serialized baseline
bytes, including whitespace and final newline.

The key contains 32 bytes from Python's `secrets.token_bytes()`. It is created
exclusively (no replacement) with owner-only mode `0600`; key loading rejects
symlinks, non-regular files, wrong ownership, wrong permissions, or wrong
length. Verification compares digests with `hmac.compare_digest()` and
authenticates the exact byte snapshot before parsing and validating JSON.

HMAC provides authenticity and integrity only while the key remains secret. It
does not encrypt the baseline. If both baseline and key are available to an
attacker, the attacker can produce a new valid signature. A lost key cannot be
reconstructed from the signature.

### Default trust files and optional recovery workflow

The standard CLI defaults are `data/baseline.json`,
`data/baseline.key`, `data/baseline.json.hmac`, and
`data/integritywatch.db`. A fresh installation creates its own baseline,
owner-only HMAC key, detached signature, and database with
`python -m integritywatch init lab`. The `verify` and `watch` commands use
these same standard paths unless the operator supplies explicit alternatives.

The optional `python -m integritywatch rebaseline` workflow creates a
separate recovery bundle beneath `data/recovery/` (default bundle name:
`new-trust-anchor`). It is an explicit, operator-reviewed workflow and does
not silently change the standard defaults used by `init`, `verify`, or
`watch`. Keep recovery material private and protect its key with owner-only
permissions. See the CLI help and recovery implementation for its review
requirements and limitations.

## SHA-256 hash-chained audit log

For record `i`, `record_hash` is SHA-256 over canonical JSON containing:

```json
{"event_type":"...","id":1,"previous_hash":"...","record_data":"...","timestamp_utc":"..."}
```

Canonical JSON sorts object keys, removes insignificant spaces, uses UTF-8
compatible JSON, and rejects NaN. `record_data` is itself stored as canonical
JSON text. The first row links to a 64-character all-zero genesis value.
Subsequent rows include the preceding record's hash.

Every writer starts `BEGIN IMMEDIATE`; the chain is checked within that
transaction before new records are appended. Findings and their audit entries
are committed together. Verification checks SQLite `quick_check`, IDs starting
at one, timestamp format/timezone, canonical event data, previous-hash links,
record hashes, and the AUTOINCREMENT high-water mark to detect trailing row
deletion. Verification opens the database read-only and does not repair it.

This is **tamper-evident**, not tamper-proof. A local privileged attacker who
can rewrite every database record can construct a replacement chain. An
external append-only service, signed checkpoints, or hardware-backed anchor
would be needed to detect full-file replacement; those are outside project
scope.

## Linux permissions and SUID/SGID

The scanner records the permission mode and owner/group IDs. New SUID or SGID
bits are significant metadata changes. A SUID executable normally runs with
the file owner's effective UID; SGID similarly affects effective group
identity. The R10 fixture changes metadata on inert text, not on an executable.
It is never run. The project does not claim that every SUID/SGID change is
malicious; legitimate system software can use these bits.

## Database and dashboard controls

- Dashboard reads use SQLite `mode=ro` and `PRAGMA query_only`.
- SQLite write connections refuse a database path that is itself a symbolic link.
- Finding writes use parameterized SQL and one transaction with the audit row.
- Audit appenders refuse to extend an invalid/error chain.
- Monitor start checks HMAC, baseline root identity, and audit status.
- Monitor status is a timestamped local heartbeat plus process-presence check;
  it is operational information, not cryptographic evidence of monitor health.
- Streamlit is intended to bind to localhost. It has no login layer or
  authorization model for remote users.

## Safe simulation boundary

`evaluate.py` and `demo.py` copy the synthetic `lab/` to fresh private
temporary directories. They create new local keys, baselines, signatures, and
SQLite files there. Simulators write only configuration-like text or
metadata; they do not invoke cron, sudo, systemd, sshd, account tools, network
clients, or persistence mechanisms. Demo audit tampering is limited to its
temporary SQLite file, which is discarded by default.


## Known limitations

The audit log is an unkeyed SHA-256 hash chain; audit records do not have per-record HMACs or an external trusted checkpoint. A privileged or same-user attacker able to rewrite the database and recompute the chain can defeat this evidence. The baseline HMAC key is owner-only, but the local threat model assumes an attacker cannot simultaneously replace the key, baseline, and database. Monitoring thread scheduling, watchdog event delivery, debounce, and heartbeat edge cases remain limitations. Semantic analysis covers six supported file types only: SSH daemon configuration, authorized keys, crontab, passwd, sudoers, and systemd service files. Linux/WSL is supported; the dashboard has no authentication and must remain localhost-only.
