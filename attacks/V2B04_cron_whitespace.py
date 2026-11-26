"""V2 benign regression: reformat cron whitespace without changing the job."""
from attacks.common import replace_text, run_script, target_file
SCENARIO_ID = "V2B04"
PATH = "etc/crontab"
def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    text = path.read_text(encoding="utf-8")
    old = "0 2 * * * root echo 'Daily lab backup check'"
    if old not in text:
        raise ValueError("Expected synthetic cron entry is missing")
    replace_text(lab_directory, PATH, text.replace(old, "0   2 * * *   root   echo 'Daily lab backup check'", 1))
if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: cron whitespace-only change")
