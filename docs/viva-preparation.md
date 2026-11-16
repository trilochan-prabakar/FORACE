# Viva preparation

Answers describe this implementation and its limits rather than idealized
production behavior.

## Basic questions

### 1. What does file-integrity monitoring do?

It compares a current file state with a known baseline and reports unexpected
content or metadata changes. IntegrityWatch also explains selected changes in
Linux-style configuration files.

### 2. What is a baseline?

A baseline is a recorded reference state. Here it maps lab-relative paths to
SHA-256 content hashes, size, mode, owner/group IDs, modification time, and a
small optional text snapshot. The baseline also records the resolved lab root.

### 3. What is SHA-256?

SHA-256 is a cryptographic hash function that maps input bytes to a 256-bit
digest. A changed input is expected to produce a different digest. It does not
prove who created the input, and it is not encryption.

### 4. Why does the project use HMAC as well as SHA-256?

The file hashes identify content changes. HMAC-SHA256 authenticates the
baseline using a secret key, so changing the baseline without the key makes
verification fail. An unkeyed hash stored beside a replaceable baseline would
not establish who approved it.

### 5. What does mode `0600` mean?

The owner may read and write the key; group and other users have no permissions.
The loader also checks that the key is a regular file owned by the current
effective user and exactly 32 bytes.

### 6. What are SUID and SGID?

They are special permission bits. An executable with SUID set can run with its
owner's effective UID; SGID can run with its owning group's effective GID.
IntegrityWatch reports newly added bits as metadata changes. The R10 fixture
sets SUID on inert text and never executes it.

### 7. What is Watchdog used for?

Watchdog provides create, modify, delete, and move notifications. The monitor
debounces repeated event bursts and rescans the lab; it does not trust an event
path as a file to open.

### 8. Why add periodic reconciliation?

Operating-system notifications may be lost, coalesced, or unavailable during
some filesystem conditions. Periodic full scans compare current state again.
They can find a persistent missed change but cannot reconstruct every
intermediate state.

### 9. What is semantic detection?

It parses supported configuration meaning instead of treating every byte
difference alike. For example, it recognizes a newly enabled SSH root-login
directive and can ignore a harmless comment-only edit.

### 10. How do smart and hash-only modes differ?

Both use SHA-256 file content to detect additions, deletions, and content
changes. Smart mode also applies supported semantic analyzers and selected
metadata comparisons. Hash-only does not alert on metadata-only changes such as
the R10 SUID scenario.

### 11. Why use SQLite?

SQLite is a local, transactional database with no separate server process. It
stores finding rows and audit-chain records. Dashboard reads are opened
read-only.

### 12. What is MITRE ATT&CK?

It is a knowledge base of adversary tactics and techniques. This project uses
technique IDs as context for supported change types. A mapping is not proof of
an attack and the project does not implement every ATT&CK detection analytic.

## Technical questions

### 13. How does HMAC-SHA256 work here?

The project loads the 32-byte secret key and computes HMAC-SHA256 over the exact
baseline bytes. It checks the detached lowercase hex digest using
`hmac.compare_digest`, then parses and validates those same authenticated
bytes. The key is not stored in the baseline or SQLite database.

### 14. Why authenticate bytes before parsing JSON?

If the program parsed untrusted data first, an altered baseline could influence
behavior before its authenticity was established. Authenticating the same
byte snapshot that is later parsed also avoids a verify-then-reopen race.

### 15. What happens when the original HMAC key is missing?

The original baseline cannot be authenticated, and the app never creates a new
key to sign those old bytes. V1.0 defaults use the separately established,
authenticated trust anchor under `data/recovery/new-trust-anchor/`. That new
anchor does not recover the former trust relationship.

### 16. How is a file scanned without following symlinks?

The scanner opens the root and child directories as file descriptors, uses
`O_NOFOLLOW`, and opens files relative to the parent directory descriptor. It
hashes and snapshots through the same descriptor whose metadata it records.
Symlink entries become scan errors; if an opened file changes while read, the
scanner reports an error.

### 17. What is a hash-chained audit log?

Each record hash covers its ID, UTC timestamp, event type, canonical event data,
and previous record hash. The first record links to an all-zero genesis hash.
Changing a record breaks its digest or a later link. Verification also checks
sequence continuity and SQLite's AUTOINCREMENT high-water mark.

### 18. Is the audit chain tamper-proof?

No. It is tamper-evident against row edits, deletions, reordering, and trailing
deletion detectable through the local sequence value. A privileged attacker
who can rewrite the whole database can construct a new chain because the
project has no external trusted checkpoint.

### 19. Why verify the chain inside the append transaction?

Checking before the transaction would leave a window for another writer to
change the chain before an append. `BEGIN IMMEDIATE` serializes writers, and
the existing chain is checked through that same transaction before new rows
are committed.

### 20. How are duplicate findings avoided?

The monitor hashes a canonical fingerprint containing the finding, current
file digest, and baseline digest. The SQLite transaction checks the audit
ledger for that fingerprint before inserting the finding and audit record.
Repeated notifications and reconciliation of unchanged state are deduplicated.

### 21. What is a false positive in the evaluation?

The unit is a benign scenario: one or more smart findings in a benign scenario
count as one false-positive scenario. The false-positive rate is false-positive
benign scenarios divided by all benign scenarios. It is not a per-file or
per-finding rate.

### 22. What is a false negative?

For an attack scenario, the expected rule is not present in the smart findings.
The false-negative rate is missed expected-rule attack scenarios divided by
all attack scenarios. Extra findings do not convert a miss into success.

### 23. How are results made reproducible?

Each scenario copies the source lab into a fresh marked temporary workspace,
creates a fresh baseline/key/signature, applies one simulator, scans once, and
uses that same scan for smart and hash-only comparison. Each workspace is
removed after its scenario.

### 24. Why does hash-only miss R10?

R10 changes the SUID permission bit but leaves file content unchanged. Hash-only
looks for additions, deletions, and content changes; smart mode compares file
mode metadata and detects the new SUID bit.

### 25. Why can the baseline not be trusted with only the `.hmac` file?

HMAC verification requires the secret key. The detached digest cannot reveal or
reconstruct that key. Replacing the missing key with a new one and signing the
existing baseline would establish new trust without proving the old baseline
was authentic.

## Difficult questions

### 26. Can an attacker restore a file's content and evade detection?

If the monitor runs only after the content has been restored, a state-based
scanner may see no difference. Event handling improves timeliness, while
reconciliation catches persistent state differences; neither is a complete
forensic event recorder. File-system journaling or external telemetry would be
needed to preserve every intermediate change.

### 27. Can an attacker change the baseline and the HMAC key?

Yes, if they can access both. HMAC assumes the key is protected separately.
The project uses owner-only permissions but does not use hardware-backed
storage or remote key management. A root or same-user compromise may defeat
that local boundary.

### 28. What if a directory becomes inaccessible during a scan?

The scanner records an error. The comparison logic suppresses inferred
deletions for paths beneath the error, avoiding false deletion alerts caused
by incomplete visibility. Baseline creation fails if any scan error occurs.

### 29. Does a valid hash chain prove the database was never replaced?

No. It proves the rows currently present are internally consistent under the
chain rules. Without an external signed checkpoint or remote append-only copy,
an attacker with write access can replace the complete database and rebuild a
consistent chain.

### 30. Why not use one global hash for every file?

Per-file hashes let the detector identify which path changed and support
add/delete/rename comparisons. A Merkle tree could make large-scale proofs
more efficient, but is unnecessary for this small lab project.

### 31. Are the rule analyzers complete Linux configuration parsers?

No. They cover a documented subset. SSH `Include` and `Match` semantics,
complete sudoers aliases/includes/precedence, arbitrary shell behavior in
cron, and all service-manager behavior are outside scope. The project reports
known gaps and treats ATT&CK IDs as contextual mappings.

### 32. Do the reported 100% attack detection and 0% smart false-positive rates
mean the product is production-ready?

No. There are 12 deterministic attacks, one per rule, and four benign
scenarios. These tests measure expected behavior on this corpus. They do not
estimate generalization, host event delivery, attacker adaptation, or
real-world alert quality.

### 33. What is the role of the database transaction?

It makes the finding row and its corresponding audit record atomic. If either
write fails, the transaction rolls back. `BEGIN IMMEDIATE` serializes writer
transactions and makes the deduplication check safe against concurrent monitor
callbacks.

### 34. Why does the dashboard not repair a bad baseline or audit chain?

Repairing or re-signing would change trust and evidence. The dashboard is
read-only: it reports status and leaves recovery to an operator using explicit
CLI steps and backups.

### 35. What remains if the OS denies Streamlit's socket bind?

The Streamlit AppTest can still exercise application pages, but it does not
prove the HTTP server can bind. This workspace denied local socket creation;
the same WSL/Linux command should be run in an environment that permits local
binding. The project records that limitation rather than claiming a live
server was verified.
