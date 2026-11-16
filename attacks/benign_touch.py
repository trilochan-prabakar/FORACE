"""Benign scenario: change only the timestamp of an existing synthetic file."""
import os
import time

from attacks.common import run_script, target_file

SCENARIO_ID = "B04"
PATH = "etc/ssh/sshd_config"


def apply(lab_directory):
    path = target_file(lab_directory, PATH)
    before = path.stat()
    new_mtime = max(before.st_mtime_ns + 2_000_000_000, time.time_ns())
    os.utime(path, ns=(before.st_atime_ns, new_mtime))


if __name__ == "__main__":
    run_script(apply, f"{SCENARIO_ID}: changed file timestamp only")
