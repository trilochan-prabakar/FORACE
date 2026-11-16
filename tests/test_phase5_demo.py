import hashlib
from pathlib import Path

from demo import run_demo


PROJECT = Path(__file__).resolve().parents[1]
LAB = PROJECT / "lab"
BASELINE = PROJECT / "data" / "baseline.json"


def _digest_tree(root):
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(str(path.relative_to(root)).encode())
        if path.is_file() and not path.is_symlink():
            digest.update(path.read_bytes())
            digest.update(str(path.stat().st_mode & 0o7777).encode())
    return digest.hexdigest()


def test_demo_is_repeatable_detects_r01_and_cleans_temporary_workspace():
    lab_hash = _digest_tree(LAB)
    baseline_bytes = BASELINE.read_bytes() if BASELINE.exists() else None
    first = run_demo(source_lab=LAB)
    second = run_demo(source_lab=LAB)
    assert first["finding"]["rule_id"] == "R01"
    assert first["audit_before_tamper"]["status"] == "valid"
    assert first["audit_after_tamper"]["status"] == "invalid"
    assert first["hash_only_findings"]
    assert first["summary"] == second["summary"]
    assert not Path(first["workspace_path"]).exists()
    assert not Path(second["workspace_path"]).exists()
    assert _digest_tree(LAB) == lab_hash
    assert (BASELINE.read_bytes() if BASELINE.exists() else None) == baseline_bytes
