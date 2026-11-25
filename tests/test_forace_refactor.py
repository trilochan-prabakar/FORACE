from forace import paths


def test_default_database_path_is_project_local_forace_database(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    assert paths.default_database_path() == tmp_path / "data" / "forace.db"


def test_default_database_path_does_not_switch_to_another_existing_database(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    unrelated = data / "other.sqlite"
    unrelated.touch()
    assert paths.default_database_path() == data / "forace.db"
    assert unrelated.exists()
