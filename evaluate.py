"""Run isolated, reproducible smart/hash-only evaluations of the lab detector."""
from dataclasses import dataclass
import argparse
import csv
import importlib
import json
import shutil
import tempfile
from pathlib import Path

from forace.auth import generate_key, load_authenticated_baseline, sign_baseline
from forace.baseline import create_baseline, save_baseline
from forace.detection import compare_scans
from forace.scanner import scan_directory


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    category: str
    description: str
    module: str
    expected_rule_id: str | None = None


SCENARIOS = (
    Scenario("R01", "attack", "Enable SSH root login", "attacks.R01_permit_root_login", "R01"),
    Scenario("R02", "attack", "Enable SSH password authentication", "attacks.R02_password_authentication", "R02"),
    Scenario("R03", "attack", "Add a synthetic authorized SSH key", "attacks.R03_add_authorized_key", "R03"),
    Scenario("R04", "attack", "Add an echo-only cron entry", "attacks.R04_add_cron_entry", "R04"),
    Scenario("R05", "attack", "Add inert suspicious-looking cron text", "attacks.R05_add_suspicious_cron_text", "R05"),
    Scenario("R06", "attack", "Add a synthetic local account row", "attacks.R06_add_passwd_user", "R06"),
    Scenario("R07", "attack", "Add a synthetic non-root account with UID zero", "attacks.R07_add_uid_zero_user", "R07"),
    Scenario("R08", "attack", "Give synthetic service account an interactive shell", "attacks.R08_enable_service_login_shell", "R08"),
    Scenario("R09", "attack", "Add a synthetic sudoers NOPASSWD line", "attacks.R09_add_sudo_nopasswd", "R09"),
    Scenario("R10", "attack", "Enable SUID metadata on inert service text", "attacks.R10_enable_suid_bit", "R10"),
    Scenario("R11", "attack", "Truncate the synthetic authentication log", "attacks.R11_truncate_auth_log", "R11"),
    Scenario("R12", "attack", "Modify a synthetic systemd service", "attacks.R12_modify_systemd_service", "R12"),
    Scenario("B01", "benign", "Add a harmless SSH configuration comment", "attacks.benign_comment"),
    Scenario("B02", "benign", "Reformat SSH configuration whitespace", "attacks.benign_whitespace"),
    Scenario("B03", "benign", "Add a harmless crontab comment", "attacks.benign_cron_comment"),
    Scenario("B04", "benign", "Change a file timestamp without changing content", "attacks.benign_touch"),
    Scenario("V2A01", "attack", "Enable SSH root login using equals syntax", "attacks.V2A01_sshd_equals_root_login", "R01"),
    Scenario("V2A02", "attack", "Enable SSH password authentication using equals syntax", "attacks.V2A02_sshd_equals_password_auth", "R02"),
    Scenario("V2A03", "attack", "Add an authorized key with source options", "attacks.V2A03_authorized_key_with_options", "R03"),
    Scenario("V2A04", "attack", "Add inert suspicious-looking wget cron text", "attacks.V2A04_cron_wget_text", "R05"),
    Scenario("V2A05", "attack", "Add a non-root account with UID zero", "attacks.V2A05_passwd_uid_zero", "R07"),
    Scenario("V2A06", "attack", "Add a synthetic sudoers NOPASSWD entry", "attacks.V2A06_sudoers_nopasswd", "R09"),
    Scenario("V2A07", "attack", "Modify a synthetic systemd ExecStart directive", "attacks.V2A07_systemd_execstart", "R12"),
    Scenario("V2A08", "attack", "Enable SUID metadata on inert service text", "attacks.V2A08_suid_metadata", "R10"),
    Scenario("V2B01", "benign", "Reformat SSH directives using equivalent equals syntax", "attacks.V2B01_sshd_equals_format"),
    Scenario("V2B02", "benign", "Add an authorized_keys comment", "attacks.V2B02_authorized_keys_comment"),
    Scenario("V2B03", "benign", "Add a systemd semicolon comment", "attacks.V2B03_systemd_comment"),
    Scenario("V2B04", "benign", "Reformat cron whitespace without changing the job", "attacks.V2B04_cron_whitespace"),
    Scenario("V2B05", "benign", "Add a sudoers comment", "attacks.V2B05_sudoers_comment"),
    Scenario("V2B06", "benign", "Add a passwd inventory comment", "attacks.V2B06_passwd_comment"),
)


CSV_FIELDS = [
    "scenario_id", "category", "description", "expected_rule_id",
    "smart_expected_rule_detected", "smart_finding_count", "smart_rule_ids",
    "smart_findings_json", "hash_only_change_detected", "hash_only_finding_count",
    "hash_only_findings_json", "false_positive", "false_negative",
    "benign_correctly_handled", "explanation_covered", "attack_mapping_covered",
]


def _compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _isolation_marker(temp_root, scenario_id):
    marker = temp_root / ".integritywatch-scenario.json"
    marker.write_text(json.dumps({"schema": 1, "scenario_id": scenario_id}, sort_keys=True) + "\n", encoding="utf-8")


def _run_one(source_lab, scenario, rules_path):
    """Copy one lab, sign a fresh baseline, apply one scenario, compare both modes."""
    with tempfile.TemporaryDirectory(prefix=f"integritywatch-{scenario.scenario_id}-") as temporary:
        work = Path(temporary)
        _isolation_marker(work, scenario.scenario_id)
        isolated_lab = work / "lab"
        shutil.copytree(source_lab, isolated_lab, symlinks=True)
        baseline_path, key_path = work / "baseline.json", work / "baseline.key"
        signature_path = work / "baseline.json.hmac"
        baseline = create_baseline(isolated_lab)
        save_baseline(baseline, baseline_path)
        generate_key(key_path)
        sign_baseline(baseline_path, key_path, signature_path)
        trusted_baseline = load_authenticated_baseline(baseline_path, key_path, signature_path)
        simulator = importlib.import_module(scenario.module)
        if getattr(simulator, "RULE_ID", scenario.scenario_id) != scenario.scenario_id:
            raise ValueError(f"Scenario ID mismatch for {scenario.module}")
        simulator.apply(isolated_lab)
        current = scan_directory(isolated_lab)
        smart = compare_scans(trusted_baseline, current, mode="smart", rules_path=rules_path)
        hash_only = compare_scans(trusted_baseline, current, mode="hash-only", rules_path=rules_path)
        expected = scenario.expected_rule_id
        expected_finding = next((finding for finding in smart if finding.get("rule_id") == expected), None) if expected else None
        attack = scenario.category == "attack"
        detected = bool(expected_finding) if attack else None
        false_positive = scenario.category == "benign" and bool(smart)
        false_negative = attack and not detected
        return {
            "scenario_id": scenario.scenario_id,
            "category": scenario.category,
            "description": scenario.description,
            "expected_rule_id": expected or "",
            "smart_expected_rule_detected": detected if detected is not None else "",
            "smart_finding_count": len(smart),
            "smart_rule_ids": _compact(sorted({f["rule_id"] for f in smart if f.get("rule_id")})),
            "smart_findings_json": _compact(smart),
            "hash_only_change_detected": bool(hash_only),
            "hash_only_finding_count": len(hash_only),
            "hash_only_findings_json": _compact(hash_only),
            "false_positive": false_positive,
            "false_negative": bool(false_negative),
            "benign_correctly_handled": scenario.category == "benign" and not smart,
            "explanation_covered": bool(expected_finding and expected_finding.get("explanation")),
            "attack_mapping_covered": bool(expected_finding and expected_finding.get("attack_id")),
        }


def calculate_metrics(rows):
    """Calculate scenario-level metrics; expected-rule hits define attack detection."""
    attacks = [row for row in rows if row["category"] == "attack"]
    benign = [row for row in rows if row["category"] == "benign"]
    attack_count = len(attacks)
    benign_count = len(benign)
    detected = sum(bool(row["smart_expected_rule_detected"]) for row in attacks)
    missed = attack_count - detected
    false_positives = sum(bool(row["false_positive"]) for row in benign)
    benign_correct = benign_count - false_positives
    hash_detected = sum(bool(row["hash_only_change_detected"]) for row in attacks)
    rules = {}
    for row in attacks:
        rule = row["expected_rule_id"]
        result = rules.setdefault(rule, {"scenarios": 0, "detected": 0, "missed": 0})
        result["scenarios"] += 1
        result["detected"] += int(bool(row["smart_expected_rule_detected"]))
        result["missed"] += int(not bool(row["smart_expected_rule_detected"]))
    for result in rules.values():
        result["coverage"] = result["detected"] / result["scenarios"] if result["scenarios"] else 0.0
    return {
        "total_attack_scenarios": attack_count,
        "successfully_detected_attack_scenarios": detected,
        "missed_attack_scenarios": missed,
        "detection_rate": detected / attack_count if attack_count else 0.0,
        "false_negative_rate": missed / attack_count if attack_count else 0.0,
        "total_benign_scenarios": benign_count,
        "benign_scenarios_correctly_handled": benign_correct,
        "false_positive_scenarios": false_positives,
        "false_positive_rate": false_positives / benign_count if benign_count else 0.0,
        "rule_wise_coverage": rules,
        "hash_only_detected_attack_scenarios": hash_detected,
        "hash_only_attack_detection_rate": hash_detected / attack_count if attack_count else 0.0,
        "smart_benign_alert_scenarios": false_positives,
        "hash_only_benign_alert_scenarios": sum(bool(row["hash_only_change_detected"]) for row in benign),
        "explanation_coverage": sum(bool(row["explanation_covered"]) for row in attacks) / attack_count if attack_count else 0.0,
        "attack_mapping_coverage": sum(bool(row["attack_mapping_covered"]) for row in attacks) / attack_count if attack_count else 0.0,
    }


def _write_results(rows, metrics, output_directory):
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    csv_path = output_directory / "results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    report = [
        "# FORACE Phase 4 Evaluation",
        "",
        "## Metrics and definitions",
        "",
        "- **Attack scenario detected:** the smart findings contain that scenario's expected rule ID. Extra valid findings do not count as extra detected scenarios.",
        "- **Detection rate:** detected attack scenarios / total attack scenarios.",
        "- **False-negative rate:** missed expected-rule attack scenarios / total attack scenarios.",
        "- **Benign scenario correctly handled:** smart mode produces no findings for the scenario.",
        "- **False-positive rate:** benign scenarios with one or more smart findings / total benign scenarios (scenario-level rate).",
        "- **Hash-only attack detection:** at least one SHA-256 file addition, deletion, or modification finding for the scenario.",
        "- **Explanation and ATT&CK coverage:** attack scenarios whose expected-rule finding has a non-empty explanation or ATT&CK ID, respectively, divided by all attack scenarios.",
        "- **Rule-wise coverage:** scenarios detecting a given expected rule / scenarios evaluated for that rule.",
        "",
        "## Measured summary",
        "",
        f"- Attack scenarios: {metrics['total_attack_scenarios']}",
        f"- Smart detected / missed: {metrics['successfully_detected_attack_scenarios']} / {metrics['missed_attack_scenarios']}",
        f"- Smart detection rate / false-negative rate: {metrics['detection_rate']:.3f} / {metrics['false_negative_rate']:.3f}",
        f"- Benign scenarios correctly handled: {metrics['benign_scenarios_correctly_handled']} / {metrics['total_benign_scenarios']}",
        f"- Smart false-positive scenarios / rate: {metrics['false_positive_scenarios']} / {metrics['false_positive_rate']:.3f}",
        f"- Hash-only attack detections / rate: {metrics['hash_only_detected_attack_scenarios']} / {metrics['hash_only_attack_detection_rate']:.3f}",
        f"- Explanation coverage / ATT&CK mapping coverage: {metrics['explanation_coverage']:.3f} / {metrics['attack_mapping_coverage']:.3f}",
        f"- Benign alerts, smart / hash-only: {metrics['smart_benign_alert_scenarios']} / {metrics['hash_only_benign_alert_scenarios']}",
        "",
        "## Rule-wise results",
        "",
        "| Rule | Scenarios | Detected | Missed | Coverage |",
        "|---|---:|---:|---:|---:|",
    ]
    for rule_id in sorted(metrics["rule_wise_coverage"]):
        item = metrics["rule_wise_coverage"][rule_id]
        report.append(f"| {rule_id} | {item['scenarios']} | {item['detected']} | {item['missed']} | {item['coverage']:.3f} |")
    report.extend(["", "## Scenario results", "", "| Scenario | Type | Expected rule | Smart result | Smart findings | Hash-only findings |", "|---|---|---|---|---:|---:|"])
    for row in rows:
        smart_state = "correct" if row["category"] == "benign" and row["benign_correctly_handled"] else ("alert" if row["category"] == "benign" else ("detected" if row["smart_expected_rule_detected"] else "missed"))
        report.append(f"| {row['scenario_id']} | {row['category']} | {row['expected_rule_id'] or '—'} | {smart_state} | {row['smart_finding_count']} | {row['hash_only_finding_count']} |")
    report.extend([
        "",
        "## Limitations",
        "",
        "This is a deterministic synthetic corpus with 20 attack scenarios exercising R01–R12 and 10 benign scenarios. It measures only the documented analyzers and command markers; it does not model a real host, arbitrary malicious commands, attacker adaptation, filesystem event delivery, or analyst judgment. R05 stores suspicious-looking command text in a file and never executes it. The R10 SUID bit is set on inert text and is never executed. A perfect score here is not a general real-world detection-rate estimate.",
        "",
        "Each scenario receives a fresh temporary lab copy, random HMAC key, baseline, and signature. Only those copies are modified; the source lab and project baseline are read-only inputs.",
        "",
    ])
    report_path = output_directory / "evaluation_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    return csv_path, report_path


def run_evaluation(source_lab="lab", output_directory=".", *, scenarios=SCENARIOS, rules_path="rules.yaml"):
    """Execute every scenario from a fresh copy and write raw plus summarized results."""
    source = Path(source_lab).resolve(strict=True)
    if source.name != "lab" or not source.is_dir():
        raise ValueError("Evaluation source must be the project's controlled lab/ directory")
    rows = [_run_one(source, scenario, rules_path) for scenario in scenarios]
    metrics = calculate_metrics(rows)
    csv_path, report_path = _write_results(rows, metrics, output_directory)
    return {"rows": rows, "metrics": metrics, "csv_path": csv_path, "report_path": report_path}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate smart and hash-only detection on isolated synthetic scenarios")
    parser.add_argument("--lab", default="lab", help="Source synthetic lab/ directory (copied; never modified)")
    parser.add_argument("--output-dir", default=".", help="Directory for results.csv and evaluation_report.md")
    parser.add_argument("--rules", default="rules.yaml", help="YAML detection rules")
    args = parser.parse_args(argv)
    result = run_evaluation(args.lab, args.output_dir, rules_path=args.rules)
    print(json.dumps({"metrics": result["metrics"], "csv_path": str(result["csv_path"]),
                      "report_path": str(result["report_path"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
