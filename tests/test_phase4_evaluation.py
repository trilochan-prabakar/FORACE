import csv
import hashlib
import importlib
import json
import shutil
from pathlib import Path

import pytest

from evaluate import SCENARIOS, _run_one, calculate_metrics, run_evaluation


PROJECT = Path(__file__).resolve().parents[1]
SOURCE_LAB = PROJECT / "lab"
RULES = PROJECT / "rules.yaml"


@pytest.mark.parametrize("scenario", [scenario for scenario in SCENARIOS if scenario.category == "attack"], ids=lambda s: s.scenario_id)
def test_every_attack_simulation_triggers_its_expected_rule(scenario):
    row = _run_one(SOURCE_LAB, scenario, RULES)
    assert row["smart_expected_rule_detected"] is True, scenario.scenario_id
    assert row["false_negative"] is False
    assert row["explanation_covered"] is True
    assert row["attack_mapping_covered"] is True
    assert row["hash_only_change_detected"] is (scenario.scenario_id not in {"R10", "V2A08"})


@pytest.mark.parametrize("scenario", [scenario for scenario in SCENARIOS if scenario.category == "benign"], ids=lambda s: s.scenario_id)
def test_every_benign_simulation_has_no_smart_alert(scenario):
    row = _run_one(SOURCE_LAB, scenario, RULES)
    assert row["smart_finding_count"] == 0
    assert row["benign_correctly_handled"] is True
    assert row["false_positive"] is False
    assert row["hash_only_change_detected"] is (scenario.scenario_id != "B04")


def _tree_digest(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root)).encode()
        digest.update(relative)
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
            digest.update(str(path.stat().st_mode & 0o7777).encode())
    return digest.hexdigest()


def test_simulator_refuses_original_project_lab_and_evaluation_preserves_inputs(tmp_path):
    before_lab = _tree_digest(SOURCE_LAB)
    baseline = PROJECT / "data" / "baseline.json"
    before_baseline = baseline.read_bytes() if baseline.exists() else None
    simulator = importlib.import_module("attacks.R01_permit_root_login")
    with pytest.raises(ValueError, match="temporary directory"):
        simulator.apply(SOURCE_LAB)

    run_evaluation(SOURCE_LAB, tmp_path / "eval")
    assert _tree_digest(SOURCE_LAB) == before_lab
    assert (baseline.read_bytes() if baseline.exists() else None) == before_baseline


def test_metrics_are_scenario_level_and_use_expected_rule_hits():
    rows = [
        {"category": "attack", "expected_rule_id": "R01", "smart_expected_rule_detected": True,
         "hash_only_change_detected": True, "explanation_covered": True, "attack_mapping_covered": True},
        {"category": "attack", "expected_rule_id": "R02", "smart_expected_rule_detected": False,
         "hash_only_change_detected": True, "explanation_covered": False, "attack_mapping_covered": False},
        {"category": "benign", "false_positive": True, "benign_correctly_handled": False,
         "hash_only_change_detected": True},
        {"category": "benign", "false_positive": False, "benign_correctly_handled": True,
         "hash_only_change_detected": False},
    ]
    metrics = calculate_metrics(rows)
    assert metrics["successfully_detected_attack_scenarios"] == 1
    assert metrics["missed_attack_scenarios"] == 1
    assert metrics["detection_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["hash_only_attack_detection_rate"] == 1.0
    assert metrics["rule_wise_coverage"]["R01"]["coverage"] == 1.0
    assert metrics["rule_wise_coverage"]["R02"]["coverage"] == 0.0


def test_evaluation_writes_raw_csv_and_report_consistently(tmp_path):
    first = run_evaluation(SOURCE_LAB, tmp_path / "first")
    second = run_evaluation(SOURCE_LAB, tmp_path / "second")
    assert first["csv_path"].read_bytes() == second["csv_path"].read_bytes()
    assert first["report_path"].read_bytes() == second["report_path"].read_bytes()
    with first["csv_path"].open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == len(SCENARIOS)
    assert sum(row["category"] == "attack" for row in rows) == 20
    assert sum(row["category"] == "benign" for row in rows) == 10
    summary = first["metrics"]
    assert summary["total_attack_scenarios"] == 20
    assert summary["total_benign_scenarios"] == 10
    assert set(summary["rule_wise_coverage"]) == {f"R{i:02}" for i in range(1, 13)}
    assert summary["successfully_detected_attack_scenarios"] == 20
    assert summary["false_positive_scenarios"] == 0
    assert summary["hash_only_detected_attack_scenarios"] == 18
    assert summary["hash_only_benign_alert_scenarios"] == 9
    report = first["report_path"].read_text(encoding="utf-8")
    assert "Detection rate" in report and "False-positive rate" in report


def test_isolated_simulation_copy_does_not_change_source_files(tmp_path):
    source_hash = _tree_digest(SOURCE_LAB)
    one_scenario = [next(s for s in SCENARIOS if s.scenario_id == "R09")]
    result = run_evaluation(SOURCE_LAB, tmp_path, scenarios=one_scenario)
    assert result["rows"][0]["smart_expected_rule_detected"] is True
    assert _tree_digest(SOURCE_LAB) == source_hash


def test_checked_in_results_csv_matches_expanded_v2_corpus():
    from forace.dashboard_data import load_evaluation_results

    result = load_evaluation_results(PROJECT / "results.csv")
    assert result["status"] == "available"
    assert len(result["rows"]) == 30
    assert [row["scenario_id"] for row in result["rows"]] == [scenario.scenario_id for scenario in SCENARIOS]
    assert result["metrics"]["total_attack_scenarios"] == 20
    assert result["metrics"]["total_benign_scenarios"] == 10
    assert result["metrics"]["successfully_detected_attack_scenarios"] == 20
    assert result["metrics"]["false_positive_scenarios"] == 0
    assert result["metrics"]["hash_only_detected_attack_scenarios"] == 18
    assert result["metrics"]["hash_only_benign_alert_scenarios"] == 9
