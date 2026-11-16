import json
import os
import sqlite3
from pathlib import Path

from integritywatch.auth import load_authenticated_baseline
from integritywatch.cli import _parser, main
from integritywatch.store import initialize_database, verify_audit_chain


def test_cli_default_paths_use_project_root_outside_project_directory(tmp_path, monkeypatch, capsys):
    project_root = Path(__file__).resolve().parents[1]
    expected = verify_audit_chain(project_root / "data/integritywatch.db")
    monkeypatch.chdir(tmp_path)

    result = main(["verify-log"])

    assert result == (0 if expected["status"] in {"valid", "empty"} else 1)
    assert json.loads(capsys.readouterr().out) == expected
    assert not (tmp_path / "data" / "integritywatch.db").exists()


def test_default_verify_uses_fresh_install_paths():
    args = _parser().parse_args(["verify"])

    assert args.baseline == "data/baseline.json"
    assert args.key == "data/baseline.key"
    assert args.signature is None

def test_cli_relative_custom_paths_use_project_root(tmp_path, monkeypatch, capsys):
    project_root = Path(__file__).resolve().parents[1]
    working_directory = tmp_path / "launch"
    working_directory.mkdir()
    database = tmp_path / "storage" / "custom.sqlite"
    database.parent.mkdir()
    initialize_database(database)
    relative_path = os.path.relpath(database, project_root)
    monkeypatch.chdir(working_directory)

    assert main(["verify-log", "--db", relative_path]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "empty"


def test_init_authenticates_baseline_and_refuses_implicit_replacement(tmp_path, capsys):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "sample").write_text("safe\n", encoding="utf-8")
    args = ["init", str(root), "--baseline", str(tmp_path / "baseline.json"),
            "--key", str(tmp_path / "key"), "--db", str(tmp_path / "state.db")]
    assert main(args) == 0
    assert main(args) == 1
    assert main(args + ["--approve-update"]) == 0
    output = capsys.readouterr().out
    assert "baseline authenticated" in output.lower()


def test_verify_watch_options_audit_and_report_commands(tmp_path, capsys):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "sample").write_text("safe\n", encoding="utf-8")
    common = ["--baseline", str(tmp_path / "baseline.json"), "--key", str(tmp_path / "key"),
              "--signature", str(tmp_path / "sig"), "--db", str(tmp_path / "state.db")]
    assert main(["init", str(root), *common]) == 0
    assert main(["verify", "--lab", str(root), *common, "--mode", "smart"]) == 0
    assert main(["verify", "--lab", str(root), *common, "--mode", "hash-only"]) == 0
    assert main(["verify-log", *common]) == 0
    assert main(["report", *common]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == []


def test_verify_rejects_tampered_baseline(tmp_path, capsys):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "sample").write_text("safe", encoding="utf-8")
    common = ["--baseline", str(tmp_path / "baseline.json"), "--key", str(tmp_path / "key"),
              "--signature", str(tmp_path / "sig"), "--db", str(tmp_path / "state.db")]
    assert main(["init", str(root), *common]) == 0
    with (tmp_path / "baseline.json").open("ab") as stream:
        stream.write(b" ")
    assert main(["verify", "--lab", str(root), *common]) == 1
    assert "signature" in capsys.readouterr().err.lower()


def test_init_refuses_invalid_existing_audit_before_changing_trust_files(tmp_path, capsys):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "sample").write_text("safe\n", encoding="utf-8")
    baseline, key, signature, db = (tmp_path / "baseline.json", tmp_path / "key",
                                    tmp_path / "sig", tmp_path / "state.db")
    common = ["--baseline", str(baseline), "--key", str(key), "--signature", str(signature), "--db", str(db)]
    assert main(["init", str(root), *common]) == 0
    prior = (baseline.read_bytes(), key.read_bytes(), signature.read_bytes())
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET event_type='tampered' WHERE id=1")

    assert main(["init", str(root), *common, "--approve-update"]) == 1
    assert (baseline.read_bytes(), key.read_bytes(), signature.read_bytes()) == prior
    assert "audit" in capsys.readouterr().err.lower()


def test_init_requires_approval_when_signature_exists_without_baseline(tmp_path, capsys):
    root = tmp_path / "lab"
    root.mkdir()
    (root / "sample").write_text("safe\n", encoding="utf-8")
    baseline, key, signature = tmp_path / "baseline.json", tmp_path / "key", tmp_path / "sig"
    signature.write_text("orphaned signature\n", encoding="utf-8")
    args = ["init", str(root), "--baseline", str(baseline), "--key", str(key),
            "--signature", str(signature), "--db", str(tmp_path / "state.db")]

    assert main(args) == 1
    assert not baseline.exists()
    assert not key.exists()
    assert signature.read_text(encoding="utf-8") == "orphaned signature\n"
    assert "approve-update" in capsys.readouterr().err.lower()
