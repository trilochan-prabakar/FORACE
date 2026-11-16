"""R06 simulation: add a harmless synthetic local-account record."""
from attacks.common import append_text, run_script, target_file

RULE_ID = "R06"
PATH = "etc/passwd"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "iw-sim-user:x:1001:1001:Simulation User:/home/iw-sim-user:/usr/sbin/nologin\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: appended a synthetic account row inside isolated lab")
