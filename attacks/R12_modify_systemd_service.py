"""R12 simulation: modify a synthetic service command string without starting it."""
from attacks.common import replace_text, run_script, target_file

RULE_ID = "R12"
PATH = "etc/systemd/system/backup.service"


def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    text = path.read_text(encoding="utf-8")
    old = "ExecStart=/usr/bin/echo Sample backup service executed"
    if old not in text:
        raise ValueError("Expected sample ExecStart directive is missing")
    replace_text(lab_directory, PATH, text.replace(old, "ExecStart=/usr/bin/echo altered simulation text", 1))


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: modified service text inside isolated lab; no service is run")
