"""V2 regression: detect a systemd ExecStart change without starting the service."""
from attacks.common import replace_text, run_script, target_file
RULE_ID = "V2A07"
PATH = "etc/systemd/system/backup.service"
def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    text = path.read_text(encoding="utf-8")
    old = "ExecStart=/usr/bin/echo Sample backup service executed"
    if old not in text:
        raise ValueError("Expected synthetic ExecStart directive is missing")
    replace_text(lab_directory, PATH, text.replace(old, "ExecStart=/usr/bin/echo V2 simulation text", 1))
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: changed service text only; no service is run")
