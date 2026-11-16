"""Safe helpers shared by simulations; writes are restricted to marked /tmp labs."""
import json
import os
import stat
import tempfile
from pathlib import Path


MARKER_NAME = ".integritywatch-scenario.json"


def isolated_lab(path):
    root = Path(path).resolve(strict=True)
    temp_root = Path(tempfile.gettempdir()).resolve()
    marker = root.parent / MARKER_NAME
    if root.name != "lab" or not root.is_dir() or not root.is_relative_to(temp_root):
        raise ValueError("Simulation target must be a lab/ copy under the system temporary directory")
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("Simulation target is not marked as an isolated evaluation copy")
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Invalid scenario isolation marker") from error
    if data.get("schema") != 1 or not isinstance(data.get("scenario_id"), str):
        raise ValueError("Invalid scenario isolation marker")
    return root


def target_file(lab, relative_path):
    root = isolated_lab(lab)
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Simulation path must remain relative to lab/")
    target = root / relative
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Simulations refuse to write through symbolic links")
    if not target.resolve(strict=False).is_relative_to(root):
        raise ValueError("Simulation path escapes lab/")
    return target


def replace_text(lab, relative_path, text):
    target = target_file(lab, relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else None
    if mode is not None and not mode & 0o200:
        os.chmod(target, mode | 0o200)
    try:
        target.write_text(text, encoding="utf-8")
    finally:
        if mode is not None and not mode & 0o200:
            os.chmod(target, mode)


def append_text(lab, relative_path, text):
    target = target_file(lab, relative_path)
    mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else None
    if mode is not None and not mode & 0o200:
        os.chmod(target, mode | 0o200)
    try:
        with target.open("a", encoding="utf-8") as stream:
            stream.write(text)
    finally:
        if mode is not None and not mode & 0o200:
            os.chmod(target, mode)


def run_script(apply, description):
    import argparse

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("lab_directory", help="Marked isolated copy of lab/ under the system temporary directory")
    args = parser.parse_args()
    apply(args.lab_directory)
    print(description)
