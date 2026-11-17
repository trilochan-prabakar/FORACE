"""Prepare the generated synthetic lab for tests on a fresh clone."""
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def ensure_synthetic_lab():
    project_root = Path(__file__).resolve().parents[1]
    lab = project_root / "lab"
    if not lab.exists():
        from make_lab import create_lab
        if not create_lab():
            raise RuntimeError("Could not create the synthetic lab fixture")
    yield
