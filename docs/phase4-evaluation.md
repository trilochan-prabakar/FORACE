# Phase 4 simulation and evaluation

## Method

`attacks/` contains 12 rule-specific scenarios and four benign scenarios. Each module exposes `apply(lab_directory)` and can be invoked with `python -m attacks.<module> <temporary-lab-copy>`. Simulators require a marked `lab/` directory beneath the operating system temporary directory; they refuse the repository's original lab and paths outside the temporary area. Commands such as the R05 URL and R12 service directive are written as configuration text only and are never executed. R10 applies SUID metadata to an inert text file.

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

The corpus is deliberately small: one deterministic scenario per rule and four benign edits. R05 uses a static list of suspicious command markers. These results measure the current rule implementation against its own supported scenarios; they are not a real-world effectiveness estimate. The synthetic account/key/service/log data is not usable on a host, and no crontab or service command is executed. Every scenario starts from a fresh copy and a newly authenticated baseline, so one scenario cannot contaminate another.

## Actual run

The executed 16-scenario run detected the expected rule in **12 of 12 attack scenarios** (detection rate 1.000, false-negative rate 0.000). Smart mode handled **4 of 4 benign scenarios** without alerts (scenario-level false-positive rate 0.000). Hash-only mode detected a content change in **11 of 12 attacks** and alerted on **3 of 4 benign edits**; R10 changed metadata without changing file content, so hash-only did not detect it. Every R01–R12 scenario was detected (one scenario per rule), and explanation and ATT&CK mapping coverage were each 1.000. These are measured results for this specific synthetic corpus, not projected real-world performance.

## Evaluation scope note

The checked-in evaluation set remains the original 12 synthetic attack scenarios (one authored to exercise each rule R01–R12) and four benign scenarios. It has not been expanded with dedicated evasion cases for symlink replacement, recurring attacks, temporary-file handling, sudoers include directives, or rsync command lookalikes. Those behaviors have focused regression tests, but are not included in the published evaluation metrics. Do not interpret the existing CSV as a measurement of those additional cases.
