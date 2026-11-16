"""Load and validate the project's YAML detection rules."""
from pathlib import Path
import yaml

REQUIRED = {"id", "description", "file_glob", "trigger", "severity", "attack_id", "explanation_template"}


def load_rules(path="rules.yaml"):
    with Path(path).open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list) or len(rules) != 12:
        raise ValueError("rules.yaml must contain exactly 12 rules")
    ids = set()
    for rule in rules:
        if not isinstance(rule, dict) or not REQUIRED <= rule.keys():
            raise ValueError("Each rule must include all required fields")
        if rule["id"] in ids:
            raise ValueError(f"Duplicate rule id: {rule['id']}")
        if rule["severity"] not in {"Low", "Medium", "High", "Critical"}:
            raise ValueError(f"Invalid severity for {rule['id']}")
        ids.add(rule["id"])
    if ids != {f"R{i:02}" for i in range(1, 13)}:
        raise ValueError("Rule IDs must be R01 through R12")
    return rules
