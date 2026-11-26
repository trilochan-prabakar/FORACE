"""V2 regression: detect SUID metadata on an inert synthetic service file."""
import os
from attacks.common import run_script, target_file
RULE_ID = "V2A08"
PATH = "etc/systemd/system/backup.service"
def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    os.chmod(path, (path.stat().st_mode & 0o777) | 0o4000)
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed metadata on inert text; never executed")
