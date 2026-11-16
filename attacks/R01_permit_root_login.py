"""R01 simulation: enable root SSH login in an isolated synthetic configuration."""
from attacks.common import append_text, replace_text, run_script, target_file

RULE_ID = "R01"
PATH = "etc/ssh/sshd_config"


def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    text = path.read_text(encoding="utf-8")
    lines = ["PermitRootLogin yes" if line.strip().lower().startswith("permitrootlogin ") else line for line in text.splitlines()]
    if not any(line.strip().lower().startswith("permitrootlogin ") for line in text.splitlines()):
        lines.append("PermitRootLogin yes")
    replace_text(lab_directory, PATH, "\n".join(lines) + "\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed only isolated lab/etc/ssh/sshd_config")
