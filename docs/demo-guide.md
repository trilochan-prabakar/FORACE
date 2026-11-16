# Final project demonstration and presentation guide

## Preparation

From the project root, use the project virtual environment to check the source
data and official V1.0 default trust anchor:

```bash
venv/bin/python -B -m integritywatch verify --lab lab --mode smart
venv/bin/python -B -m integritywatch verify-log --db data/integritywatch.db
```

The normal project monitor uses the official V1.0 trust anchor under
`data/recovery/new-trust-anchor/`. The preserved original baseline remains
unauthenticated because its original key is missing. Do not reinitialize the
project trust files during a presentation. The demo creates its own key and
baseline in a fresh temporary directory.

The semantic rule set covers R01–R12: SSH, authorized keys, cron, local account
records, sudoers, SUID, authentication-log loss, and systemd changes. See
[Phase 2 detection notes](phase2-detection.md) for exact supported syntax and
limits, including the line-based sudoers parser and text-only cron markers.

For the dashboard portion, use two terminals. In terminal one:

```bash
venv/bin/python -B demo.py --keep
```

Copy the printed workspace paths. In terminal two:

```bash
venv/bin/python -B -m streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
```

Enter the printed temporary database and baseline artifact paths in the
dashboard data-source fields. The retained demo database is deliberately
tampered after its valid-chain check, so Audit & Verification should report
the audit chain invalid. The workspace contains temporary trust material;
delete only the exact temporary workspace printed by the demo after the
presentation. The no-argument demo removes its workspace automatically.
Never include key contents or sensitive local paths in screenshots or shared
recordings.

## Three-to-five-minute script (about four minutes)

| Time | Presenter action and talk track | Expected result |
|---|---|---|
| 0:00–0:35 | State the problem: hashes detect differences but do not explain what the change means. Introduce IntegrityWatch as a local monitor for a synthetic Linux-like lab. | Emphasize bounded project scope; no host settings are changed. |
| 0:35–1:05 | Show the architecture: scanner, HMAC baseline, semantic rules, monitor/reconciliation, SQLite audit chain, dashboard, evaluation. | Describe the data path in one sentence: authenticate, scan, compare, explain, persist. |
| 1:05–2:00 | Run `venv/bin/python -B demo.py`. Point out temporary lab copy, fresh baseline authentication, and Watchdog start. | Step 1: HMAC verified, zero initial findings. Step 2: monitor starts on isolated copy. |
| 2:00–2:40 | Show the R01 safe text edit and the printed result. | Rule R01, High severity, `T1021.004`, plain-English SSH root-login explanation. No SSH service is restarted. |
| 2:40–3:15 | Show smart/hash-only counts and audit results. | Both modes detect the content edit; audit is valid before demo-only tampering and invalid after. Workspace cleanup is reported. |
| 3:15–3:45 | Show the dashboard using retained demo paths and navigate its six sections. | Actual SQLite finding appears; tampered isolated audit database appears invalid. |
| 3:45–4:15 | Show Evaluation page or actual `results.csv` results. Explain the small synthetic corpus and its limits. | 12/12 expected attack rules detected, 0/4 smart benign false-positive scenarios, hash-only 11/12 attacks and 3/4 benign alerts. |
| 4:15–4:30 | Close with the key security decision and limitation. | The original project baseline's authenticity was not recovered; the separately established V1.0 anchor is used by default. |

If time is short, skip the retained dashboard workspace and use the CLI output;
the default demo cleans up safely. The original baseline's authenticity was
not recovered; current defaults use the separate official V1.0 bundle.

## Expected demo output

The successful run includes lines equivalent to:

```text
Step 1 — Clean baseline HMAC: VERIFIED; initial findings: 0
Step 2 — Watchdog monitoring started on the isolated lab copy
Step 3 — Applied safe R01 text change in lab/etc/ssh/sshd_config
Step 4 — Change detected and stored
Step 5 — ... "rule_id": "R01", "severity": "High", "attack_id": "T1021.004"
Step 7 — Audit chain before tampering: valid
Step 8 — Smart findings: 1; hash-only findings: 1
Step 9 — Isolated demo DB tampering check: invalid
Temporary demo workspace cleaned up safely.
```

The exact timestamp and temporary directory name vary per run. The final cleanup
line is absent when `--keep` is selected; that option prints the retained path.

## Screenshot checklist

- [ ] Overview with actual project status, V1.0 baseline status, and audit state.
- [ ] Security Findings showing the actual R01 finding from the retained demo database.
- [ ] File Integrity showing the fixed project `lab/` inventory.
- [ ] Finding detail with explanation and ATT&CK technique reference.
- [ ] Evaluation page with measured CSV-derived metrics and rule coverage.
- [ ] Audit & Verification showing invalid audit status for the intentionally
  tampered demo database.
- [ ] Demo / About with current trust-anchor history and limitations.
- [ ] Terminal output showing demo verification and cleanup; redact any
  temporary or local path before sharing.
- [ ] No screenshot edited to imply a failed or unperformed check passed.
- [ ] Redact sensitive local paths; never show HMAC key contents.

## Presentation talking points and design decisions

- **Explainable rules over opaque scoring:** rules make a small project
  auditable and let the dashboard state which supported behavior matched.
- **HMAC for baseline trust:** plain SHA-256 is not enough to authenticate a
  baseline if an attacker can replace both baseline content and hash; a
  separately protected key supplies authenticity.
- **Separate trust anchors:** the original baseline and signature are preserved
  but unauthenticated; the separate V1.0 bundle supplies current defaults.
  Missing or invalid selected trust still fails closed.
- **Descriptor-based scanning:** no-follow opens and rooted directory
  descriptors reduce symlink/path races; one file descriptor supplies both
  content and metadata.
- **Watchdog plus reconciliation:** event notifications provide low latency;
  periodic full scans recover from missed/coalesced notifications.
- **SQLite transaction and hash chain:** one transaction commits a finding and
  its audit entry, while the chain makes individual tampering detectable.
- **Synthetic isolated evaluation:** attack-like changes are safe configuration
  text/metadata in disposable copies; no payload is executed.
- **Explicit limits:** a small corpus does not estimate production accuracy;
  the sudoers parser is line-based, cron markers are simple text matches, YAML
  file globs do not drive matching, and a local hash chain has no external
  anchor. This is a local single-user lab tool, not an enterprise endpoint
  security product.

## Workspace cleanup

The default command cleans up on completion. For a retained demo, remove only
the exact path printed by that run after closing the dashboard. Do not use a
wildcard cleanup command. Project `data/`, `lab/`, and `results.csv` are not demo
write targets.
