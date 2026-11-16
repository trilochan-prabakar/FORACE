"""Benign scenario: add a comment to the synthetic crontab."""
from attacks.common import append_text, run_script, target_file

SCENARIO_ID = "B03"


def apply(lab_directory):
    target_file(lab_directory, "etc/crontab")
    append_text(lab_directory, "etc/crontab", "\n# routine maintenance note; no job added\n")


if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: added a harmless crontab comment")
