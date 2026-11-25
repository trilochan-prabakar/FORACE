import os

import pytest

from forace.auth import generate_key, load_key, load_authenticated_baseline, sign_baseline, verify_baseline_signature
from forace.baseline import create_baseline, save_baseline


def test_hmac_signatures_verify_exact_baseline_bytes(tmp_path):
    baseline = tmp_path / "baseline.json"
    key = tmp_path / "baseline.key"
    signature = tmp_path / "baseline.json.hmac"
    baseline.write_bytes(b'{"files":{}}\n')
    generate_key(key)
    sign_baseline(baseline, key, signature)
    assert verify_baseline_signature(baseline, key, signature) is True
    baseline.write_bytes(b'{"files":{}}')
    with pytest.raises(ValueError, match="signature"):
        verify_baseline_signature(baseline, key, signature)


def test_key_is_owner_only_and_cannot_be_overwritten(tmp_path):
    key = tmp_path / "baseline.key"
    first = generate_key(key)
    assert len(first) == 32
    assert key.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        generate_key(key)
    assert load_key(key) == first


@pytest.mark.parametrize("missing", ["signature", "key"])
def test_verification_rejects_missing_authentication_file(tmp_path, missing):
    baseline = tmp_path / "baseline.json"
    key = tmp_path / "baseline.key"
    signature = tmp_path / "baseline.json.hmac"
    baseline.write_text("{}", encoding="utf-8")
    generate_key(key)
    if missing == "signature":
        with pytest.raises((FileNotFoundError, ValueError)):
            verify_baseline_signature(baseline, key, signature)
    else:
        sign_baseline(baseline, key, signature)
        key.unlink()
        with pytest.raises((FileNotFoundError, ValueError)):
            verify_baseline_signature(baseline, key, signature)


def test_existing_signature_requires_explicit_replacement(tmp_path):
    baseline, key, sig = tmp_path / "baseline", tmp_path / "key", tmp_path / "sig"
    baseline.write_bytes(b"{}")
    generate_key(key)
    sign_baseline(baseline, key, sig)
    with pytest.raises(FileExistsError):
        sign_baseline(baseline, key, sig)
    sign_baseline(baseline, key, sig, approve_replace=True)


def test_key_with_group_or_world_permissions_is_rejected(tmp_path):
    key = tmp_path / "key"
    generate_key(key)
    key.chmod(0o640)
    with pytest.raises(PermissionError, match="0600"):
        load_key(key)


def test_malformed_detached_signature_is_rejected(tmp_path):
    baseline, key, signature = tmp_path / "baseline", tmp_path / "key", tmp_path / "signature"
    baseline.write_bytes(b"{}")
    generate_key(key)
    signature.write_text("not-a-digest", encoding="ascii")
    with pytest.raises(ValueError, match="Malformed baseline signature"):
        verify_baseline_signature(baseline, key, signature)


def test_authenticated_loader_validates_the_signed_baseline_structure(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    baseline_path = tmp_path / "baseline.json"
    save_baseline(create_baseline(lab), baseline_path)
    key_path = tmp_path / "key"
    generate_key(key_path)
    signature = tmp_path / "sig"
    sign_baseline(baseline_path, key_path, signature)
    assert load_authenticated_baseline(baseline_path, key_path, signature)["root_directory"] == str(lab)
