"""V2 benign regression: equivalent SSH directive formatting."""
from attacks.common import replace_text, run_script, target_file
SCENARIO_ID = "V2B01"
PATH = "etc/ssh/sshd_config"
def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [("PermitRootLogin = no" if line.strip().lower().startswith("permitrootlogin ") else
              "PasswordAuthentication = no" if line.strip().lower().startswith("passwordauthentication ") else line)
             for line in lines]
    replace_text(lab_directory, PATH, "\n".join(lines) + "\n")
if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: equivalent SSH directive formatting only")
