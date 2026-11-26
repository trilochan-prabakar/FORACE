"""V2 benign regression: add a sudoers comment only."""
from attacks.common import append_text, run_script, target_file
SCENARIO_ID = "V2B05"
PATH = "etc/sudoers"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "\n# routine policy review note\n")
if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: sudoers comment-only change")
