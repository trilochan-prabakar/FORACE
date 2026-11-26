"""V2 benign regression: add a comment and blank line to passwd fixture."""
from attacks.common import append_text, run_script, target_file
SCENARIO_ID = "V2B06"
PATH = "etc/passwd"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "\n# inventory reviewed\n")
if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: passwd comment-only change")
