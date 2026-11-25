import importlib

import pytest


def test_forace_is_primary_package_and_old_imports_are_same_modules():
    forace_scanner = importlib.import_module("forace.scanner")
    legacy_scanner = importlib.import_module("integritywatch.scanner")
    forace_paths = importlib.import_module("forace.paths")
    legacy_paths = importlib.import_module("integritywatch.paths")

    assert forace_scanner is legacy_scanner
    assert forace_paths is legacy_paths


def test_default_database_prefers_existing_legacy_database(tmp_path, monkeypatch):
    from forace import paths

    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    legacy = tmp_path / "data" / "integritywatch.db"
    legacy.parent.mkdir()
    legacy.touch()

    assert paths.default_database_path() == legacy


def test_default_database_uses_forace_name_for_fresh_install(tmp_path, monkeypatch):
    from forace import paths

    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)

    assert paths.default_database_path() == tmp_path / "data" / "forace.db"


def test_default_database_requires_explicit_selection_when_both_exist(tmp_path, monkeypatch):
    from forace import paths

    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    (data / "integritywatch.db").touch()
    (data / "forace.db").touch()

    with pytest.raises(ValueError, match="explicit --db"):
        paths.default_database_path()
