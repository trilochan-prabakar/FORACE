"""V2 regression: detect a new authorized key with source options."""
from attacks.common import append_text, run_script, target_file
RULE_ID = "V2A03"
PATH = "home/user/.ssh/authorized_keys"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, 'from="192.0.2.10" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3R2MnN5bnRoZXRpY2tleQ== forace-v2-simulation\n')
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: appended a synthetic key to isolated lab")
