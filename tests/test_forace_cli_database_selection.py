import pytest

from forace.cli import main


def _make_ambiguous_databases(root):
    data = root / "data"
    data.mkdir()
    (data / "integritywatch.db").touch()
    (data / "forace.db").touch()


def test_rebaseline_does_not_select_a_database_when_both_databases_exist(
    tmp_path, monkeypatch
):
    from forace import cli, paths

    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    _make_ambiguous_databases(tmp_path)
    calls = []
    monkeypatch.setattr(
        cli,
        "establish_recovery_baseline",
        lambda *args: calls.append(args),
    )

    assert main(["rebaseline"]) == 0
    assert len(calls) == 1


def test_ambiguous_database_selection_fails_before_init_touches_trust_artifacts(
    tmp_path, monkeypatch
):
    from forace import paths

    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    _make_ambiguous_databases(tmp_path)
    lab = tmp_path / "lab"
    lab.mkdir()
    baseline = tmp_path / "baseline.json"
    key = tmp_path / "baseline.key"
    signature = tmp_path / "baseline.hmac"
    baseline.write_text("existing baseline", encoding="utf-8")
    key.write_text("existing key", encoding="utf-8")
    signature.write_text("existing signature", encoding="utf-8")
    before = tuple(path.read_bytes() for path in (baseline, key, signature))

    with pytest.raises(SystemExit) as error:
        main([
            "init", str(lab), "--baseline", str(baseline), "--key", str(key),
            "--signature", str(signature), "--approve-update",
        ])

    assert error.value.code == 2
    assert tuple(path.read_bytes() for path in (baseline, key, signature)) == before


@pytest.mark.parametrize("command", ["init", "verify", "watch", "verify-log", "report"])
def test_database_commands_require_explicit_selection_when_both_databases_exist(
    tmp_path, monkeypatch, command
):
    from forace import paths

    monkeypatch.setattr(paths, "PROJECT_ROOT", tmp_path)
    _make_ambiguous_databases(tmp_path)
    args = [command]
    if command == "init":
        args.append("lab")

    with pytest.raises(SystemExit) as error:
        main(args)

    assert error.value.code == 2
