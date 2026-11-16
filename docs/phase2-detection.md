# Phase 2 detection notes

## Phase 2 closure

Phase 2 implements six scoped analyzers (SSH daemon configuration, authorized
keys, system crontab, passwd, sudoers, and systemd service files) and rules
R01–R12 with severity, ATT&CK mapping, and explanation metadata. Smart mode
combines semantic and metadata findings; hash-only mode reports content
changes. The implementation covers file additions/deletions, reliable unique
hash renames, permissions and ownership, SUID/SGID changes, and authentication
log deletion/truncation. Unavailable snapshots, unsupported semantic changes,
or analyzer failures produce a generic modification finding rather than
silently dropping a detected content change. Cron batches can produce one R04
finding for normal additions and one R05 finding for suspicious additions;
additional entries matching either rule do not duplicate that rule finding.

Rule tests assert every R01–R12 trigger and its severity, ATT&CK ID, and
explanation metadata. The full suite was run with
`venv/bin/python -B -m pytest -p no:cacheprovider -q`: **164 passed**. The
suite uses temporary fixtures for mutation and preserves the project lab and
trust artifacts.

## Analyzer scope and limits

The analyzers consume UTF-8 snapshots from the controlled lab. They do not open system configuration paths. `sshd_config` handles the security directives listed in `integritywatch/analyzers.py`; authorized keys are compared by key algorithm and key blob so comments and whitespace do not look like new keys. Cron analysis supports system crontab entries and a conservative list of suspicious command markers. Passwd analysis parses seven colon-separated fields. Systemd analysis normalizes comments and surrounding whitespace while preserving directive values.

The sudoers analyzer supports line-based rules and detects added or removed lines containing the `ALL` privilege token, plus newly added `NOPASSWD:` rules. It is deliberately not a full sudoers parser. It does not expand `User_Alias`, `Runas_Alias`, `Host_Alias`, or `Cmnd_Alias`; it does not evaluate Defaults, include directives, tags other than detecting `NOPASSWD:`, negation, command argument matching, or precedence. Such constructs may require human review and can produce incomplete results. Comments and whitespace-only differences are ignored for the supported line subset.

The YAML `file_glob` values are required rule metadata, but current rule
dispatch uses hardcoded path checks in `integritywatch/detection.py`. Editing
a glob alone will not change matching behavior; treat the YAML globs as
documentation until dispatch is made data-driven.

Generic rename detection is limited to unique old/new paths with an identical SHA-256 digest. Duplicate-content files are reported as separate additions and deletions because their rename correspondence is ambiguous. A scan error for a previously known path is not treated as deletion.

Hash-only mode reports file additions, deletions, and SHA-256 content modifications. Smart mode additionally compares semantics and metadata. Modification time alone does not create a finding.

Files without usable UTF-8 snapshots (including files at least 1 MiB) receive
generic integrity findings on content changes, without semantic rule
classification. Cron suspicious markers are conservative text substrings,
not shell analysis; they can miss unlisted patterns or match harmless text.

## ATT&CK mapping review

Technique IDs were checked against the official MITRE ATT&CK Enterprise technique pages on 2026-11-01. R11 uses `T1685.006` (Clear Linux or Mac System Logs), which is the current MITRE technique for authentication log truncation/deletion. The original project table listed `T1070.002`; that identifier is no longer a listed sub-technique of Indicator Removal in current ATT&CK. R11 was updated to the current applicable identifier.

The mappings are behavioral context for these file changes; they do not assert that an adversary caused the change. The sudoers file uses conservative local syntax detection, and the ATT&CK mapping does not imply full policy interpretation.
