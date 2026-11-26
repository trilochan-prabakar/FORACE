"""V2 regression: detect a NOPASSWD sudoers addition."""
from attacks.common import append_text, run_script, target_file
RULE_ID = "V2A06"
PATH = "etc/sudoers"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "\nforace-v2 ALL=(ALL) NOPASSWD: /usr/bin/id\n")
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed isolated sudoers text only")
