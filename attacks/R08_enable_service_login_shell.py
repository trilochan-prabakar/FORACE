"""R08 simulation: change the synthetic service account shell to a login shell."""
from attacks.common import replace_text, run_script, target_file

RULE_ID = "R08"
PATH = "etc/passwd"


def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    lines = path.read_text(encoding="utf-8").splitlines()
    changed = False
    for index, line in enumerate(lines):
        fields = line.split(":")
        if len(fields) == 7 and fields[0] == "svc-backup":
            fields[6] = "/bin/bash"
            lines[index] = ":".join(fields)
            changed = True
    if not changed:
        raise ValueError("Synthetic svc-backup record is missing from the lab")
    replace_text(lab_directory, PATH, "\n".join(lines) + "\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed only isolated lab/etc/passwd")
