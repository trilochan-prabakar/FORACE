"""R02 simulation: enable SSH password authentication in the isolated lab."""
from attacks.common import replace_text, run_script, target_file

RULE_ID = "R02"
PATH = "etc/ssh/sshd_config"


def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    lines = path.read_text(encoding="utf-8").splitlines()
    changed = False
    for index, line in enumerate(lines):
        if line.strip().lower().startswith("passwordauthentication "):
            lines[index] = "PasswordAuthentication yes"
            changed = True
    if not changed:
        lines.append("PasswordAuthentication yes")
    replace_text(lab_directory, PATH, "\n".join(lines) + "\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed only isolated lab/etc/ssh/sshd_config")
