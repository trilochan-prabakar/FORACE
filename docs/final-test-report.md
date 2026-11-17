# Phase 6 final audit and verification report

**Run date:** 2026-11-01  
**Scope:** Phase 1–5 code audit, Phase 6 security hardening and documentation.  
**Project data:** no project baseline, signature, key, lab file, database row, or
`results.csv` was intentionally changed by Phase 6 verification. Evaluation
output was written under `/tmp/integritywatch-phase6-final/`; test databases
and demo workspaces used temporary directories.

> Historical verification snapshot: the detailed checks and machine-state
> observations in this report were recorded on 2026-11-01. They are retained
> as historical evidence and must not be treated as current installation
> instructions or as a description of another user's fresh clone. For current
> defaults and setup, follow the repository README. Subsequent release
> validation on the fresh-clone environment passed 170 automated tests and
> completed the isolated end-to-end demo.

## Final verification results

| Check | Command or evidence | Result |
|---|---|---|
| Complete suite | `python -m pytest -q` | **103 passed** |
| Python compilation | `python -m compileall -q integritywatch attacks tests dashboard.py demo.py evaluate.py make_lab.py test_baseline.py test_scanner.py test_store.py` | Passed; exit 0 |
| Scanner script | `python test_scanner.py` | 7 files scanned, 0 errors |
| Scanner tests | Included in full suite; descriptor traversal, static symlinks, symlink swap, and `..` path escape covered | Passed |
| Baseline script | `python test_baseline.py` | Temporary baseline save/load and overwrite protection passed |
| HMAC tests | `tests/test_phase3_auth.py` in Phase 3 focused run | Passed; temporary key/signature fixtures verified, malformed/tampered/missing trust rejected |
| Database/audit tests | Phase 3 focused run and `test_store.py` | Passed; schema, repeatable initialization, write-path symlink refusal, hash-chain integrity and fail-closed append covered |
| Smart detection | `python -m pytest -q tests/test_phase2.py` | **21 passed** |
| Phase 3 auth/audit/database | `python -m pytest -q tests/test_phase3_auth.py tests/test_phase3_audit.py test_store.py` | **24 passed** |
| Evaluation framework | `python evaluate.py --output-dir /tmp/integritywatch-phase6-final` | 16 scenarios executed; report and CSV generated |
| Raw evaluation cross-check | Recounted `/tmp/integritywatch-phase6-final/results.csv` and compared with dashboard metric loader | 12/12 expected smart attack detections; 0/4 smart benign alerts; 11 hash-only attack detections; 3 hash-only benign alerts; counts agree |
| Dashboard | Streamlit AppTest on Overview, Findings, Evaluation, and Integrity; includes missing database case | All pages rendered without application exceptions |
| Live Streamlit startup | `streamlit run dashboard.py --server.headless=true --server.address=127.0.0.1 --server.port=8501` | Could not start: workspace denied `socket.socket()` with `PermissionError: Operation not permitted`. A direct Python socket test failed the same way, identifying an environment restriction before app binding. |
| Demo | `python demo.py` | R01 detected; audit valid before isolated tamper, invalid after; temporary workspace cleaned |

### Measured evaluation

- Smart expected-rule detection: **12 / 12 attacks** (100%); false negatives:
  **0 / 12** (0%).
- Smart benign handling: **4 / 4**; scenario-level false-positive rate:
  **0 / 4** (0%).
- Hash-only attack scenarios with content changes: **11 / 12** (91.7%). R10 is
  metadata-only.
- Hash-only benign scenarios with alerts: **3 / 4** (75%).
- Explanation coverage: **12 / 12**; ATT&CK mapping coverage: **12 / 12**.
- Rule coverage: R01 through R12 each detected in its one synthetic scenario.

The exact definitions and raw scenario details are in
[phase4-evaluation.md](phase4-evaluation.md). These results apply only to the
included synthetic scenarios.

## Current project data status

Observed from the actual project paths after verification:

- SQLite database: accessible; findings table contains 0 rows.
- Baseline HMAC: **failed** because `data/baseline.key` is missing.
- Audit chain: **empty**, with 0 records; no records were available to verify.
- Monitor: not running; no heartbeat file is present.
- Evaluation CSV: available and loaded.
- `python -m integritywatch verify --lab lab --mode smart` and the same command
  with `--mode hash-only` both exit 1 with the missing-key error. This is
  expected fail-closed behavior, not a detection result.
- The project baseline/key/signature were not reinitialized. Safe options are
  restoring the original key or following the explicit backed-up
  `--approve-update` recovery in the [README](../README.md#safe-recovery-for-the-missing-baseline-key).

## Code audit findings and actions

1. **Audit append on invalid history:** fixed. Appenders validate the complete
   chain inside `BEGIN IMMEDIATE`; monitor startup refuses an invalid chain;
   missing audit schema is not silently recreated; a missing/corrupt chain
   returns structured error state.
2. **Unsafe initialization order:** fixed. CLI checks an existing database
   chain before changing trust files, requires explicit approval when either
   baseline or signature exists, validates an existing key before replacement,
   and refuses a symbolic-link SQLite write path.
3. **Scanner symlink/path race:** fixed. Scans walk from directory file
   descriptors, open files with `O_NOFOLLOW`, use the same inode for metadata
   and bytes, detect concurrent content changes, and reject parent traversal
   in `scan_file()`.
4. **Dashboard missing-database crash:** fixed. Audit verification reports
   missing paths and symlink loops as errors; findings/audit readers handle a
   database disappearing between status and data reads. AppTest covers a
   selected missing database.
5. **Test side effects:** fixed. The root database schema test uses `tmp_path`
   instead of initializing the project database during pytest collection.

The simulation helpers still assume their marked `tempfile` workspace is
private to the current run. A hostile same-user process racing that private
directory is outside the project threat model. The audit chain has no external
trusted checkpoint, and a privileged attacker able to rewrite the full
database can rebuild it.

## Dashboard startup finding

The failure occurs when Streamlit asks the OS for a socket, before the app can
serve HTTP. The workspace runs on WSL2 Linux, and a standalone Python socket
creation/bind also returns `EPERM`. Therefore the server limitation is an
environment restriction; AppTest demonstrates page execution only and is not
reported as proof of live HTTP operation.

On a normal local WSL2 environment, start it from the project root with:

```bash
source venv/bin/activate
streamlit run dashboard.py --server.address 127.0.0.1 --server.port 8501
```

Then open `http://localhost:8501`. This workspace could not verify that network
startup command because socket creation is blocked.

## Final project file structure

```text
IntegrityWatch-Lite/
├── attacks/                         # 12 synthetic security changes + 4 benign scenarios
├── data/                            # Local per-installation trust files and SQLite database
├── docs/
│   ├── architecture.md              # Component design and architecture diagram
│   ├── data-flow.md                 # Baseline, monitor, evaluation, dashboard flows
│   ├── demo-guide.md                # Timed demo, expected output, screenshots, talking points
│   ├── detection-rules.md           # R01–R12 scope and ATT&CK references
│   ├── final-test-report.md         # This report
│   ├── phase2-detection.md          # Analyzer behavior and limits
│   ├── phase3-security.md           # Monitoring, HMAC, audit, CLI details
│   ├── phase4-evaluation.md         # Method, metric formulas, measured results
│   ├── phase5-dashboard-demo.md     # Dashboard operation and screenshots
│   ├── security-design.md           # Threat model, HMAC, hash chain, recovery
│   └── viva-preparation.md          # Basic and difficult oral-exam Q&A
├── integritywatch/                  # Scanner, trust, detection, monitor, SQLite, dashboard data
├── lab/                             # Synthetic Linux-like files only
├── tests/                           # Phase 1–6 unit/integration/regression tests
├── README.md                        # Setup, operation, recovery, CLI reference
├── dashboard.py                     # Streamlit local dashboard
├── demo.py                          # Isolated repeatable demonstration
├── evaluate.py                      # Isolated scenario evaluation and metric generation
├── make_lab.py                      # Synthetic sandbox creation
├── requirements.txt                 # Python dependencies
├── results.csv                      # Existing measured Phase 4 rows
└── rules.yaml                       # R01–R12 rule definitions
```

`tests/test_store.py` is the isolated schema test. The complete
suite has 103 passing tests across scanner, baseline, detection, authentication,
audit, monitoring, evaluation, dashboard, demo, and database behavior.
