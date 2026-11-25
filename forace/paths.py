"""Shared project-root path handling for the dashboard and CLI."""
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE_PATH = "data/baseline.json"
DEFAULT_KEY_PATH = "data/baseline.key"
DEFAULT_SIGNATURE_PATH = "data/baseline.json.hmac"
DEFAULT_DB_PATH = Path("data/forace.db")


def project_path(value: str | Path) -> Path:
    """Return an absolute value unchanged or root a relative value at the project."""
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def default_database_path() -> Path:
    """Return the single default FORACE database path."""
    return project_path(DEFAULT_DB_PATH)
