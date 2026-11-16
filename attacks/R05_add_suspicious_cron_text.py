"""R05 simulation: store a suspicious-looking command as inert crontab text only."""
from attacks.common import append_text, run_script, target_file

RULE_ID = "R05"
PATH = "etc/crontab"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    # This is never executed; example.invalid is reserved and the line only exists as text.
    append_text(lab_directory, PATH, "\n23 5 * * * root curl http://example.invalid/simulation\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: stored a suspicious cron string in isolated lab only")
