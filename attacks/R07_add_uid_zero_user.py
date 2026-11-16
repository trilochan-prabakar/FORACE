"""R07 simulation: assign UID 0 to a synthetic account record; no account is created."""
from attacks.common import append_text, run_script, target_file

RULE_ID = "R07"
PATH = "etc/passwd"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "iw-sim-rootlike:x:0:1002:Simulation UID Test:/home/iw-sim-rootlike:/usr/sbin/nologin\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: appended a synthetic UID-zero row inside isolated lab")
