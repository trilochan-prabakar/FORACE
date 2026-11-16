# Data flow

## Baseline creation

```text
lab tree -> safe scanner -> validated JSON baseline -> HMAC-SHA256 signature
                                          key -> owner-only local file
```

The scanner opens regular files relative to directory descriptors beneath the
resolved root, refusing symlinks and parent traversal. It captures hashes,
metadata, and bounded text snapshots. Any scan error aborts baseline creation.
The HMAC covers the exact serialized JSON bytes. Verification authenticates
those bytes before parsing them; an unauthenticated baseline is not used.

## Monitor path

```text
Watchdog event ──> debounce ──┐
                              ├──> complete safe scan ──> compare to trusted baseline
periodic timer ───────────────┘                                  │
                                                                 v
                                              smart rules or hash-only result
                                                                 │
                                            fingerprint + duplicate check
                                                                 │
                                     BEGIN IMMEDIATE transaction
                                       ├── finding row
                                       └── chained audit row
```

Events are hints to rescan; they are not persisted as a complete raw event
stream. The periodic scan reduces dependence on notification delivery. If a
known path cannot be scanned, the detector avoids treating that path as
deleted. Baseline authentication and audit-chain validity are checked before
the monitor operates; invalid audit data blocks appends.

## Evaluation path

Every scenario receives a new temporary directory, copied `lab/`, isolation
marker, baseline, random HMAC key, and signature. The simulator writes only to
that copy. One post-change scan is passed to smart and hash-only comparison so
the mode comparison sees identical inputs. `calculate_metrics` derives
scenario-level rates and per-rule coverage from actual returned rows, then
`evaluate.py` writes CSV and Markdown output. No results are inserted into the
project database.

## Dashboard path

The Streamlit application reads configured local files. SQLite is opened with
read-only URI mode and `query_only`; baseline and audit code runs verification
only. Evaluation is recalculated from `results.csv`. Missing or invalid sources
produce explicit status/error UI; no example findings are added to make the
screens look populated.
