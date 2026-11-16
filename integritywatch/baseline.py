
import json
import re
import os
import tempfile

from pathlib import Path
from datetime import datetime, timezone

from integritywatch.scanner import scan_directory


SCHEMA_VERSION = 1

REQUIRED_FILE_FIELDS = {
    "sha256",
    "size",
    "mode",
    "uid",
    "gid",
    "mtime_ns",
    "snapshot",
}


def validate_baseline(baseline):
    """Validate the structure and contents of a baseline."""

    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a JSON object")

    if baseline.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported baseline schema version")

    if not isinstance(baseline.get("generated_at"), str):
        raise ValueError("Invalid baseline timestamp")

    if not isinstance(baseline.get("root_directory"), str):
        raise ValueError("Invalid root directory")

    files = baseline.get("files")

    if not isinstance(files, dict):
        raise ValueError("Baseline files must be an object")

    for relative_path, details in files.items():

        # Reject absolute paths and directory traversal.
        path = Path(relative_path)

        if (
            not isinstance(relative_path, str)
            or not relative_path
            or path.is_absolute()
            or ".." in path.parts
        ):
            raise ValueError("Invalid file path in baseline")

        if not isinstance(details, dict):
            raise ValueError(f"Invalid metadata for {relative_path}")

        if not REQUIRED_FILE_FIELDS.issubset(details):
            raise ValueError(f"Missing metadata for {relative_path}")

        file_hash = details["sha256"]

        if (
            not isinstance(file_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", file_hash) is None
        ):
            raise ValueError(f"Invalid SHA-256 hash for {relative_path}")

        # Validate integer metadata.
        for field in ("size", "mode", "uid", "gid", "mtime_ns"):

            value = details[field]

            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(
                    f"Invalid {field} for {relative_path}"
                )

            if value < 0:
                raise ValueError(
                    f"Negative {field} for {relative_path}"
                )

        if details["mode"] > 0o7777:
            raise ValueError(f"Invalid permissions for {relative_path}")

        snapshot = details["snapshot"]

        if snapshot is not None and not isinstance(snapshot, str):
            raise ValueError(f"Invalid snapshot for {relative_path}")

    return True


def create_baseline(root_directory):
    """Generate a baseline using the file scanner."""

    root_directory = Path(root_directory).resolve()

    result = scan_directory(root_directory)

    # Never create a trusted baseline from an incomplete scan.
    if result["errors"]:
        raise RuntimeError(
            f"Baseline creation stopped: "
            f"{len(result['errors'])} files could not be scanned"
        )

    baseline = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root_directory": str(root_directory),
        "files": result["files"],
    }

    validate_baseline(baseline)

    return baseline


def save_baseline(baseline, baseline_path, approve_update=False):
    """Save a baseline, requiring approval before replacement."""

    validate_baseline(baseline)

    baseline_path = Path(baseline_path)

    if baseline_path.exists() and not approve_update:
        raise FileExistsError(
            "A baseline already exists. "
            "Explicit approval is required to replace it."
        )

    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = None

    try:
        # Write to a temporary file in the same directory.
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=baseline_path.parent,
            delete=False
        ) as temporary_file:

            temporary_path = Path(temporary_file.name)

            json.dump(
                baseline,
                temporary_file,
                indent=4
            )

            temporary_file.write("\n")

        # Replace the destination only after writing succeeds.
        os.replace(temporary_path, baseline_path)

    finally:
        # Clean up temporary files after an unsuccessful write.
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return baseline_path


def load_baseline(baseline_path):
    """Load a baseline from JSON and validate it."""

    baseline_path = Path(baseline_path)

    with open(baseline_path, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    validate_baseline(baseline)

    return baseline
