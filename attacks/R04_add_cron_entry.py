"""R04 simulation: add a harmless echo-only synthetic scheduled entry."""
from attacks.common import append_text, run_script, target_file

RULE_ID = "R04"
PATH = "etc/crontab"


def apply(lab_directory):
    target_file(lab_directory, PATH)
    append_text(lab_directory, PATH, "\n17 4 * * * root echo integritywatch harmless simulation\n")


if __name__ == "__main__":
    run_script(apply, f"{RULE_ID}: added an echo-only entry to isolated lab/etc/crontab")
