"""V2 regression: detect a non-root account assigned UID zero."""
from attacks.common import append_text, run_script, target_file
RULE_ID = "V2A05"
PATH = "etc/passwd"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "forace-v2-rootlike:x:0:1003:Simulation:/home/forace-v2:/usr/sbin/nologin\n")
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: added synthetic passwd row inside isolated lab")
