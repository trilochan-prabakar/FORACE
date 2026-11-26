# Phase 4 simulation and evaluation

## Method

`attacks/` contains 20 attack scenarios covering R01–R12 and 10 benign scenarios. The V2 additions include alternate SSH directive syntax, authorized-key options, wget cron text, UID-zero account rows, sudoers additions, systemd changes, SUID metadata, and benign comment/formatting variants. Each module exposes `apply(lab_directory)` and can be invoked with `python -m attacks.<module> <temporary-lab-copy>`. Simulators require a marked `lab/` directory beneath the operating system temporary directory; they refuse the repository's original lab and paths outside the temporary area. Commands such as the R05 URL and R12 service directive are written as configuration text only and are never executed. R10 applies SUID metadata to an inert text file.

`evaluate.py` copies the project lab into a new temporary directory for each scenario, writes a scenario marker, creates a fresh baseline, generates a fresh key, signs the exact baseline bytes, authenticates that baseline, applies one scenario, scans once, then passes that same post-change scan to smart and hash-only detection. Temporary scenario data is removed on context exit. The source lab and existing project baseline are read-only inputs.

Run from the project directory:

```bash
python evaluate.py
```

Use `--output-dir /path/to/output` to choose a results directory. The run writes `results.csv` and `evaluation_report.md` there.

## Metrics

- **Attack scenario detected:** the smart findings contain the expected rule ID for that scenario. The count is scenario-level, not a finding count.
- **Detection rate:** expected-rule-detected attack scenarios divided by attack scenarios.
- **False-negative rate:** attack scenarios missing their expected rule divided by attack scenarios.
- **Benign scenario correctly handled:** the smart findings list is empty.
- **False-positive rate:** benign scenarios with one or more smart findings divided by benign scenarios. This is a scenario-level rate.
- **Hash-only attack detected:** the hash-only mode reports at least one addition, deletion, or content modification. Metadata-only R10 is therefore not detected by hash-only mode.
- **Explanation and ATT&CK coverage:** attack scenarios whose expected-rule finding contains a non-empty explanation or ATT&CK ID, respectively, divided by all attack scenarios, including misses.
- **Rule-wise coverage:** scenarios detecting a rule divided by scenarios evaluated for that expected rule.

The CSV preserves each scenario's expected rule, actual smart findings, actual hash-only findings, and scenario-level success/error flags. The Markdown report derives its totals and rates from those rows.

## Experimental limits

The corpus remains deliberately synthetic: 20 attack scenarios exercise R01–R12 with selected syntax variants, alongside 10 benign edits. It is a repeatable regression corpus, not a representative sample of production host activity. R05 uses a static list of suspicious command markers. These results measure the current rule implementation against its own supported scenarios; they are not a real-world effectiveness estimate. The synthetic account/key/service/log data is not usable on a host, and no crontab or service command is executed. Every scenario starts from a fresh copy and a newly authenticated baseline, so one scenario cannot contaminate another.

## Actual V2 results

The expanded 30-scenario evaluation is exercised by the V2 test suite. The measured corpus results are:

- Smart mode detected **20/20 attack scenarios** (1.000 scenario-level detection rate; 0 false negatives).
- Smart mode handled **10/10 benign scenarios** without alerts (0.000 scenario-level false-positive rate).
- Hash-only mode detected **18/20 attack scenarios**. The two metadata-only SUID cases (R10 and V2A08) do not change content hashes.
- Hash-only mode alerted on **9/10 benign content edits**; the timestamp-only B04 case does not change the content hash.
- All expected-rule findings contain an explanation and ATT&CK mapping.

These results are limited to this synthetic regression corpus. They are not a real-world detection-rate estimate. The generated CSV and Markdown report should be produced with the evaluation command when a local results artifact is required.
 
## Evaluation scope note

The V2 corpus expands the published scenario set to 20 attacks and 10 benign edits. It adds targeted syntax and formatting variants while retaining the original R01–R12 scenarios. Symlink replacement, recurring attacks, temporary-file handling, sudoers include directives, and rsync command lookalikes remain covered only by focused regression tests where present; they are not claimed as part of the scenario metrics. Do not interpret the existing CSV as a measurement of those additional cases.
