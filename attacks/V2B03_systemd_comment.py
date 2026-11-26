"""V2 benign regression: add a systemd comment only."""
from attacks.common import append_text, run_script, target_file
SCENARIO_ID = "V2B03"
PATH = "etc/systemd/system/backup.service"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "; reviewed by FORACE V2 test\n")
if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: systemd comment-only change")
