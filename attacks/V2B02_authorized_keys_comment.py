"""V2 benign regression: add a comment without changing authorized keys."""
from attacks.common import append_text, run_script, target_file
SCENARIO_ID = "V2B02"
PATH = "home/user/.ssh/authorized_keys"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "# reviewed synthetic key inventory\n")
if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: comment-only authorized_keys change")
