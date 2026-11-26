# Phase 5 dashboard and demonstration

## Architecture

`dashboard.py` is a read-only Streamlit interface. Its data access layer in
`forace/dashboard_data.py` opens SQLite in read-only mode, checks the
FORACE schema, reads actual finding rows, invokes the existing
baseline-HMAC and audit-chain verifiers, checks the monitor heartbeat, and
recalculates evaluation metrics from the Phase 4 CSV. A missing or invalid
source is reported as such; the interface does not manufacture example
findings or write to the database.

The `Audit & Verification` section can repeat baseline, audit, and database checks. The
monitor heartbeat is operational status only. It does not prove that the
baseline or audit data is trustworthy. Finding history is limited to finding
rows stored by the monitor; raw filesystem notifications are not persisted as
a separate event stream.

## Install and start

From the project root, install the dependencies in `requirements.txt` and run:

```bash
venv/bin/python -m pip install -r requirements.txt
venv/bin/python -B -m streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
```

The dashboard opens in the browser. The sidebar paths default to the project
database, baseline, HMAC key, signature, monitor status file, and `results.csv`.
Change a path there to inspect a retained demo workspace or another local
FORACE data set. The default baseline, key, signature, and database
paths are the standard per-installation files under `data/` (see the README).
The File Integrity root is fixed to the project's `lab/` directory and cannot
be changed in the dashboard.

The dashboard is local and read-only. Start the monitor separately with the
project's normal CLI when you want live findings and the configured baseline
authenticates successfully:

```bash
venv/bin/python -B -m forace watch --lab lab --mode smart
```

Use Ctrl+C in that terminal to stop monitoring. The CLI updates
`data/monitor_status.json` while its watch loop is running and removes its own
heartbeat on shutdown. The monitor uses the standard baseline, key, and
signature paths unless explicit alternatives are supplied.

## Dashboard features

- **Overview:** baseline HMAC, audit-chain SHA-256 verification, database
  accessibility, monitor process status, finding severity counts, finding
  timeline, rule counts, and recent events read from the SQLite audit log.
- **Security Findings:** case-insensitive search over stored finding fields,
  severity filters, newest-first ordering, detailed explanations, and ATT&CK
  technique links.
- **File Integrity:** read-only inventory of the project's controlled `lab/`,
  compared only with an authenticated baseline.
- **Audit & Verification:** trust artifact status, audit-chain state, and
  database health.
- **Evaluation:** detection, false-positive, and false-negative rates;
  smart/hash-only scenario comparison; rule coverage; and measured benign and
  attack scenario outcomes loaded from `results.csv`.
- **Scan History:** scan lifecycle, per-file SHA-256/metadata observations,
  scanner errors, manifest digests, and audit-linked evidence verification.
- **Demo / About:** project architecture, demo commands, and known limitations.

## Repeatable demo

Run the short demonstration from the project root:

```bash
venv/bin/python -B demo.py
```

The demo copies the controlled synthetic `lab/` to an operating-system
temporary directory, creates and authenticates a fresh baseline, starts the
monitor on that copy, applies the safe R01 SSH configuration text change,
prints the resulting stored explanation and ATT&CK mapping, verifies the audit
chain, compares smart and hash-only findings, and tampers with only the
temporary demo database to show that verification fails. The temporary
workspace is removed on exit. The original lab, project baseline, and project
database are not used as demo write targets.

To inspect the actual SQLite finding in the dashboard after the demo:

```bash
venv/bin/python -B demo.py --keep
venv/bin/python -B -m streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
```

Copy the printed temporary database and baseline artifact paths into the
matching data-source fields. The retained
database contains the intentionally tampered audit record, so the dashboard
should report an invalid chain. Delete the printed temporary workspace when
finished. Running `venv/bin/python -B demo.py` again creates a fresh isolated
workspace. Do not share key contents or sensitive local paths.

## Capturing screenshots

Capture each of the seven sections separately. For populated findings, run
`venv/bin/python -B demo.py --keep` and enter its temporary data-source paths.
The retained database intentionally fails audit verification. Do not edit
screenshots to imply that a failed or empty state passed. Redact local paths and
never show HMAC key contents.

## Known limitations

- This is a local single-user dashboard without login or remote access
  controls. Keep Streamlit bound to localhost unless a separate deployment
  security design is added.
- The dashboard exposes recorded point-in-time file observations and scanner errors, but it does not retain raw Watchdog notifications or prove transient states between scans.
- Monitor status is a PID and heartbeat check; it cannot prove the watcher's
  internal health or detect a compromised host.
- Baseline authentication requires the correct locally protected key and
  detached signature. The dashboard reports missing or invalid files as
  failure. Each installation must initialize and protect its own trust files.
- Semantic detection is limited to R01–R12 and supported syntax. The sudoers
  parser is line-based; cron suspicious markers are text matches, not shell
  analysis. Semantic rule matching is controlled by the Python dispatch table;
  see [Phase 2 detection notes](phase2-detection.md).
- Evaluation metrics describe the small synthetic Phase 4 corpus only. They
  are not estimates of real-world detection performance.
- MITRE ATT&CK links require an internet connection when opened, though the
  dashboard itself does not load external fonts or require network access.
