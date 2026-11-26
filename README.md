# FORACE

<div align="center">
  <a href="https://trilochan-prabakar.github.io/trilochan-prabakar/"><img src="https://img.shields.io/badge/PORTFOLIO-Trilochan%20Prabakar-0E7490?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Portfolio website" /></a>
  <a href="https://github.com/trilochan-prabakar"><img src="https://img.shields.io/badge/GITHUB-Developer%20Profile-164E63?style=for-the-badge&logo=github&logoColor=white" alt="GitHub profile" /></a>
</div>

FORACE is a local file-integrity monitor for a controlled Linux-like
lab. It records what changed and explains supported security-relevant changes
with rules, severity, and MITRE ATT&CK references. It combines a signed baseline,
SHA-256 file scans, semantic configuration checks, a SQLite finding store with
a hash-chained audit log, repeatable simulations, and a Streamlit dashboard.

> **Scope:** this is a local, single-user teaching and evaluation tool for the
> synthetic `lab/` directory, not an enterprise endpoint security product.
> Each installation creates its own baseline, HMAC key, detached signature,
> and SQLite database under `data/`. Optional recovery bundles are created
> only through the explicit recovery workflow described below.

## Contents

- [Problem and objectives](#problem-and-objectives)
- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Technology](#technology)
- [Install on Linux or WSL2](#install-on-linux-or-wsl2)
- [Create and initialize the sandbox](#create-and-initialize-the-sandbox)
- [Initialize and protect local trust material](#initialize-and-protect-local-trust-material)
- [Verify and monitor](#verify-and-monitor)
- [Dashboard](#dashboard)
- [Simulations and evaluation](#simulations-and-evaluation)
- [CLI reference](#cli-reference)
- [Documentation](#documentation)
- [Limitations](#limitations)

## Problem and objectives

Traditional file-integrity checks can say that a file changed without helping
an operator understand whether the change matters. FORACE compares
files to an authenticated baseline and adds a small semantic layer for common
Linux configuration files. The project demonstrates how to explain changes
such as enabling SSH root login, adding a cron entry, changing account records,
or setting SUID metadata.

The project aims to:

1. Detect content and selected metadata changes in a deliberately controlled
   sandbox.
2. Explain supported configuration changes with a rule ID, severity, and
   ATT&CK technique reference.
3. Authenticate the baseline with HMAC-SHA256 and make stored findings
   tamper-evident with a SHA-256 hash chain.
4. Compare semantic “smart” detection with content-only “hash-only” detection
   using reproducible synthetic scenarios.

## Capabilities

- SHA-256 content hashes, size, mode, owner/group IDs, modification time, and
  bounded UTF-8 text snapshots for regular files.
- No-follow, directory-descriptor-based scanning beneath the selected root;
  symlinks and scan errors are reported rather than followed or mistaken for
  deletions.
- Smart semantic checks for the supported SSH, authorized-keys, cron, passwd,
  sudoers, systemd, authentication-log, and SUID cases. Matching logic is
  implemented in `forace/detection.py`; `rules.yaml` stores rule metadata.
- Rules R01–R02 cover SSH, R03 authorized keys, R04–R05 cron, R06–R08 passwd,
  R09 sudoers, R10 SUID, R11 authentication-log loss, and R12 systemd.
- Hash-only mode for additions, deletions, and content changes.
- Watchdog events with debouncing and independent periodic full reconciliation
  (`--interval`, 30 seconds by default).
- HMAC-SHA256 baseline authentication using a 32-byte, owner-only key.
- SQLite findings and sequential SHA-256 hash-chained audit records.
- V2 scan lifecycle history with per-file SHA-256/metadata observations, explicit partial/failed scan states, and audit-linked manifest verification.
- Read-only Streamlit views for system status, findings, ATT&CK links, audit
  events, and measured evaluation output.
- Isolated attack and benign simulations, an evaluation CSV/report generator,
  and a repeatable temporary-workspace demonstration.

## Architecture

```text
synthetic lab/
    │
    ├── scanner ──> SHA-256 + metadata + bounded text snapshots
    │                    │
signed baseline ─────────┤
                         ├── smart semantic rules / hash-only comparison
watchdog events ─────────┤                 │
periodic reconciliation ─┘                 v
                                     SQLite findings
                                     SHA-256 audit chain
                                          │
                       Streamlit read-only dashboard
                       evaluation results.csv / report
```

The monitor rescans the sandbox after relevant filesystem events and at a
periodic interval. It does not trust event paths as files to open. Both paths
use the scanner and comparison engine. Findings and their audit record are
written in one SQLite transaction. See [architecture and data flow](docs/architecture.md)
for module responsibilities and details.

## Technology

- Python 3.10 or later; tested in the supplied Python 3.12 environment.
- Watchdog for filesystem event notifications.
- PyYAML for the local rule file.
- SQLite for findings and audit records.
- Streamlit and pandas for the local dashboard and tabular evaluation views.
- Python standard library for HMAC, SHA-256, temporary workspaces, filesystem
  traversal, and evaluation tooling.

No AI/ML or external service is used. The dashboard serves locally to the
browser, and data collection stays on the machine. ATT&CK references are links
opened by the user.

## Install on Linux or WSL2

Use a Linux filesystem location for the project when running under WSL2 (for
example, `~/Projects/FORACE`) to avoid Windows-mounted filesystem
event and permission differences.

```bash
cd ~/Projects/FORACE
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -r requirements.txt
```

Run commands from the project root. Use `venv/bin/python` so the application,
tests, and dashboard use the installed project dependencies.

## Create and initialize the sandbox

A fresh clone does not include the generated `lab/` directory. Create the
synthetic sandbox before initializing the application:

```bash
venv/bin/python -B make_lab.py
```

Do not use `venv/bin/python -B make_lab.py --force` unless you intend to overwrite the
synthetic sample files. This sandbox contains text fixtures only; it does not
apply settings to the host.

On a fresh project with no baseline or signature, create and authenticate a
baseline:

```bash
venv/bin/python -B -m forace init lab
```

The command creates a new baseline, owner-only HMAC key (mode `0600`),
detached signature, and SQLite database under `data/`. Existing trust data is
not silently replaced; use `--approve-update` only when you deliberately
intend to update it. Exact default paths and key-handling guidance follow below.

## Initialize and protect local trust material

A fresh installation creates its own baseline, 32-byte HMAC key, detached
signature, and SQLite database under `data/` with the `init` command above.
The default paths are:

- Baseline: `data/baseline.json`
- HMAC key: `data/baseline.key` (owner-only permissions, `0600`)
- Detached signature: `data/baseline.json.hmac`
- SQLite database: `data/forace.db` by default. Use `--db` only when
  deliberately selecting a separate database.

Verify the initialized baseline with:

```bash
venv/bin/python -B -m forace verify --lab lab --mode smart
```

Back up the HMAC key securely and separately. Do not share it or commit it to
Git. Existing baseline or signature files are not silently replaced; use
`--approve-update` only after reviewing the consequences.

The optional `rebaseline` command creates a separately reviewed recovery
bundle under `data/recovery/<bundle-name>/` (the default bundle name is
`new-trust-anchor`). This optional bundle is not the default input for
`init`, `verify`, or `watch`; those commands use the standard paths listed
above unless explicit paths are supplied. See the
[security design](docs/security-design.md) for the recovery workflow and its
limitations.

## Verify and monitor

Compare the current lab to the authenticated baseline:

```bash
venv/bin/python -B -m forace verify --lab lab --mode smart
venv/bin/python -B -m forace verify --lab lab --mode hash-only
```

Start event monitoring plus periodic reconciliation:

```bash
venv/bin/python -B -m forace watch --lab lab --mode smart --debounce 0.5 --interval 30
```

Stop with Ctrl+C. The CLI writes a local heartbeat while monitoring and removes
its own heartbeat on graceful shutdown. The monitor refuses to start if
baseline authentication fails or if the existing audit chain is invalid. It
also refuses any attempt to append a finding to an invalid chain.

Verify the audit chain without changing the database, or print stored findings:

```bash
venv/bin/python -B -m forace verify-log
venv/bin/python -B -m forace history --limit 50
venv/bin/python -B -m forace verify-evidence
venv/bin/python -B -m forace report
```

`verify-log` returns `empty`, `valid`, `invalid`, or `error`. An empty chain is
not shown as verified by the dashboard because there are no records to check.

The `verify` command uses these process exit codes: `0` = clean verification,
`2` = one or more findings, `3` = one or more scan errors, and `1` = baseline
trust or audit verification failure. Scan errors take precedence over the
finding status.

## Dashboard

Run the dashboard from the project root:

```bash
venv/bin/python -B -m streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
```

Open `http://localhost:8501` in the Linux or Windows browser. If WSL does not
open a browser automatically, copy the URL into the browser. The dashboard is
read-only and shows SQLite, baseline authentication, monitor status, scan
history, observation manifest verification, and `results.csv`. File Integrity is fixed to the project's `lab/` directory.
Missing or invalid inputs are shown as such; the dashboard does not invent
sample alerts. Its seven sections are Overview, Security Findings, File
Integrity, Audit & Verification, Evaluation, Scan History, and Demo / About. The command
binds the server to localhost. See
[dashboard operation](docs/phase5-dashboard-demo.md).

## Testing

Run the full suite from the project root:

```bash
venv/bin/python -B -m pytest -q -p no:cacheprovider
```

Tests that change files or databases use temporary workspaces. Dashboard
database access is read-only.

## Simulations and evaluation

Run the safe repeatable R01 demonstration:

```bash
venv/bin/python -B demo.py
```

The demo copies `lab/` to a private temporary directory, creates a fresh
authenticated baseline and SQLite database, starts the monitor, applies one
safe SSH configuration text edit, reports the finding, compares detection
modes, verifies the chain, then tampers with only its temporary database. The
workspace is removed by default. Use `venv/bin/python -B demo.py --keep` to
retain the temporary workspace for dashboard inspection.

With `--keep`, use the printed temporary database and baseline paths in the
dashboard data-source fields. The demo database is intentionally tampered
after its valid-chain check, so the dashboard should show it as invalid. The
workspace contains temporary trust material; do not publish or share it.

Run the complete 30-scenario evaluation without replacing the repository's
existing Phase 4 outputs:

```bash
venv/bin/python -B evaluate.py --output-dir /tmp/FORACE-evaluation
```

The output directory receives `results.csv` and `evaluation_report.md`.
Every scenario uses a separate copied lab and fresh baseline/key/signature.
Metrics are recalculated from the generated rows. The expanded V2 corpus contains 20 attack scenarios and 10 benign scenarios. The test suite measures 20/20 expected-rule detections and 0/10 smart false-positive scenarios; hash-only detects 18/20 attacks and alerts on 9/10 benign content edits. These are synthetic corpus results, not real-world rates.
See [evaluation methodology and results](docs/phase4-evaluation.md).

## CLI reference

| Command | Purpose | Common options |
|---|---|---|
| `venv/bin/python -B -m forace init lab` | Create/authenticate baseline and initialize database | `--baseline`, `--key`, `--signature`, `--db`, `--approve-update` |
| `venv/bin/python -B -m forace verify` | Compare authenticated baseline to current lab | `--lab`, `--mode smart\|hash-only`, storage options |
| `venv/bin/python -B -m forace watch` | Watch events and reconcile periodically | `--lab`, `--mode`, `--debounce`, `--interval`, storage options |
| `venv/bin/python -B -m forace verify-log` | Read-only audit-chain check | `--db` |
| `venv/bin/python -B -m forace report` | Print stored finding rows as JSON | `--db` |
| `venv/bin/python -B -m forace history` | List recent scan observations and verification status | `--limit`, `--db` |
| `venv/bin/python -B -m forace verify-evidence` | Verify scan manifests against the audit chain | `--db` |

When omitted, storage defaults are `data/baseline.json`, the owner-only
`data/baseline.key`, its detached signature `data/baseline.json.hmac`, and the
default database at `data/forace.db`. Use `--db` to select a separate
database explicitly.
The optional `rebaseline --source-*` options identify the source baseline and
signature for the separately reviewed recovery workflow; they do not change
the standard storage defaults.
Relative paths supplied to the CLI or dashboard resolve from the project
root, regardless of the current working directory; absolute paths are used
unchanged.

## Documentation

- [V2 scan observation history](docs/v2-observation-history.md)
- [Architecture and data flow](docs/architecture.md)
- [Detailed data flow](docs/data-flow.md)
- [Threat model, security design, HMAC and hash chain](docs/security-design.md)
- [Detection rules and ATT&CK references](docs/detection-rules.md)
- [Evaluation methodology and measured results](docs/phase4-evaluation.md)
- [Dashboard operation](docs/phase5-dashboard-demo.md)
- [Timed project demo and presentation guide](docs/demo-guide.md)
- [Final test and audit report](docs/final-test-report.md)

## Security model

FORACE assumes a trusted local operating system and one operator working within the synthetic `lab/` directory.

HMAC-SHA256 authenticates the selected baseline using a locally stored, owner-only key. The SQLite audit log uses sequential SHA-256 hash chaining to make unauthorized changes detectable during verification.

These mechanisms provide tamper evidence, not complete tamper prevention. An attacker with sufficient access to the local machine may modify the database, key, and audit records. The audit chain currently has no independent external trust anchor.

The dashboard provides read-only views of stored data and has no authentication. Keep it bound to localhost. Simulations modify only disposable text fixtures and do not execute attack payloads.

## Limitations

- This is a local, single-user lab tool, not an enterprise endpoint security product. It monitors the controlled `lab/` directory, not a complete production host.
- Detection is limited to exactly R01–R12 and the supported syntax described in [Phase 2 detection notes](docs/phase2-detection.md). The sudoers analyzer recognizes include directives but is not a complete sudoers policy parser; aliases, nested include expansion, and full policy precedence are out of scope.
- The audit log uses an **unkeyed SHA-256 hash chain**. Audit records do not have individual HMAC authentication or an external trusted checkpoint. It detects accidental edits and many unsophisticated tampering attempts, but a capable attacker who can rewrite the database and recompute the chain can defeat it.
- The baseline is HMAC-authenticated with an owner-only local key. The threat model is single-user: an attacker who can edit the key, baseline, and database together can defeat the local trust model.
- Monitoring uses a watchdog thread plus periodic reconciliation. Thread scheduling, event delivery, debounce, and heartbeat edge cases can delay or miss transient changes; periodic scans reduce but do not eliminate this limitation.
- Only six configuration/content types receive semantic analysis: SSH daemon configuration, authorized keys, crontab, passwd, sudoers, and systemd service files. Other files receive generic integrity findings.
- Linux and WSL are the supported environments. Native Windows execution is not supported.
- The Streamlit dashboard has no authentication. Keep it bound to localhost and do not expose it to an untrusted network.
- Hash-only mode does not detect metadata-only changes such as SUID changes.
- The evaluation set contains 20 synthetic attack scenarios covering R01–R12 and 10 benign scenarios. Additional monitoring edge cases and unsupported parser semantics remain outside the evaluation corpus; the evaluation does not estimate performance against real adversaries or production filesystems.
