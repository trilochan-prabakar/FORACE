"""R09 simulation: add a synthetic NOPASSWD policy line without invoking sudo."""
from attacks.common import append_text, run_script, target_file

RULE_ID = "R09"
PATH = "etc/sudoers"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "\niw-sim-user ALL=(ALL) NOPASSWD: /usr/bin/echo simulation-only\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed only isolated lab/etc/sudoers")
