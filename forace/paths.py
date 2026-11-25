"""Shared project-root path handling for the dashboard and CLI."""
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE_PATH = "data/baseline.json"
DEFAULT_KEY_PATH = "data/baseline.key"
DEFAULT_SIGNATURE_PATH = "data/baseline.json.hmac"
LEGACY_DB_PATH = Path("data/integritywatch.db")
DEFAULT_DB_PATH = Path("data/forace.db")


def project_path(value: str | Path) -> Path:
    """Return an absolute value unchanged or root a relative value at the project."""
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def default_database_path() -> Path:
    """Select an existing legacy database or the FORACE path for a fresh install.

    If both filenames exist, force an explicit choice to avoid splitting or
    silently switching an installation's history.
    """
    legacy = project_path(LEGACY_DB_PATH)
    current = project_path(DEFAULT_DB_PATH)
    if legacy.exists() and current.exists():
        raise ValueError(
            "Both data/integritywatch.db and data/forace.db exist; select one with explicit --db"
        )
    return legacy if legacy.exists() else current
