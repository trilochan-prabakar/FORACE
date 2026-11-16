"""Benign scenario: add an sshd_config comment only."""
from attacks.common import append_text, run_script, target_file

SCENARIO_ID = "B01"


def apply(lab_directory):
    target_file(lab_directory, "etc/ssh/sshd_config")
    append_text(lab_directory, "etc/ssh/sshd_config", "# reviewed by IntegrityWatch benign scenario\n")


if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: added a harmless SSH configuration comment")
