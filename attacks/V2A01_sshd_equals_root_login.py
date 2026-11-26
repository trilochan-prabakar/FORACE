"""V2 regression: detect SSH root-login directive with equals syntax."""
from attacks.common import replace_text, run_script, target_file
RULE_ID = "V2A01"
PATH = "etc/ssh/sshd_config"
def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = ["PermitRootLogin = yes" if line.strip().lower().startswith("permitrootlogin ") else line for line in lines]
    replace_text(lab_directory, PATH, "\n".join(lines) + "\n")
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed isolated SSH configuration text")
