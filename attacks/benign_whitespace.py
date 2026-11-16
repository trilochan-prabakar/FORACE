"""Benign scenario: reformat sshd_config whitespace without changing values."""
from attacks.common import replace_text, run_script, target_file

SCENARIO_ID = "B02"


def apply(lab_directory):
    path = target_file(lab_directory, "etc/ssh/sshd_config")
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("Port "):
            lines.append("Port\t22")
        elif line.startswith("PermitRootLogin "):
            lines.append("PermitRootLogin    no")
        elif line.startswith("PasswordAuthentication "):
            lines.append("PasswordAuthentication\tno")
        else:
            lines.append(line)
    replace_text(lab_directory, "etc/ssh/sshd_config", "\n".join(lines) + "\n")


if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: reformatted whitespace only")
