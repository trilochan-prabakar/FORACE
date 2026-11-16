"""R11 simulation: truncate only the synthetic authentication log in the lab copy."""
from attacks.common import replace_text, run_script, target_file

RULE_ID = "R11"
PATH = "var/log/auth.log"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    replace_text(lab_directory, PATH, "")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: truncated only isolated lab/var/log/auth.log")
