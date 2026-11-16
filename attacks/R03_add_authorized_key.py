"""R03 simulation: append a synthetic public key; no matching private key exists."""
from attacks.common import append_text, run_script, target_file

RULE_ID = "R03"
PATH = "home/user/.ssh/authorized_keys"
SYNTHETIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3Rvbmx5a2V5bm90cmVhbA== integritywatch-simulation"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, SYNTHETIC_KEY + "\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: appended one synthetic key to isolated lab")
