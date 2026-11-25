import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

from forace import recovery


PHRASE = recovery.CONFIRMATION_PHRASE
FILES = {"baseline.key", "baseline.json", "baseline.json.hmac", "recovery-record.json"}


@pytest.fixture
def recovery_inputs(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / "sample.txt").write_text("reviewed content\n")
    original = tmp_path / "original"
    original.mkdir()
    baseline = original / "baseline.json"
    signature = original / "baseline.json.hmac"
    database = original / "state.sqlite"
    baseline.write_bytes(b"original baseline bytes\n")
    signature.write_bytes(b"original signature bytes\n")
    database.write_bytes(b"sqlite fixture bytes\n")
    recovery_dir = tmp_path / "recovery"
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (baseline, signature, database)}
    return lab, baseline, signature, database, recovery_dir, before


def establish(inputs, **kwargs):
    lab, baseline, signature, _, recovery_dir, _ = inputs
    return recovery.establish_recovery_baseline(
        lab, baseline, signature, recovery_dir, input_fn=lambda _: PHRASE,
        output_fn=lambda _: None, **kwargs,
    )


def unchanged(inputs):
    _, baseline, signature, database, _, before = inputs
    assert {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (baseline, signature, database)} == before


def test_success_publishes_complete_verified_private_bundle_and_preserves_sources(recovery_inputs):
    inputs = recovery_inputs
    establish(inputs)
    bundle = inputs[4] / "new-trust-anchor"
    assert {p.name for p in bundle.iterdir()} == FILES
    assert bundle.stat().st_mode & 0o777 == 0o700
    assert (bundle / "baseline.key").stat().st_mode & 0o777 == 0o600
    fd = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert recovery.verify_recovery_signature(fd)
        assert recovery.load_recovery_baseline(fd)["files"]["sample.txt"]["sha256"]
    finally:
        os.close(fd)
    unchanged(inputs)


def test_confirmation_cancelled_before_recovery_directory_or_key(recovery_inputs):
    lab, baseline, signature, _, recovery_dir, _ = recovery_inputs
    with pytest.raises(RuntimeError, match="did not match"):
        recovery.establish_recovery_baseline(lab, baseline, signature, recovery_dir,
                                             input_fn=lambda _: "no", output_fn=lambda _: None)
    assert not recovery_dir.exists()


def test_eof_confirmation_cancels_without_creating_recovery_directory(recovery_inputs):
    lab, baseline, signature, _, recovery_dir, _ = recovery_inputs
    def no_input(_):
        raise EOFError
    with pytest.raises(RuntimeError, match="confirmation was not provided"):
        recovery.establish_recovery_baseline(lab, baseline, signature, recovery_dir,
                                             input_fn=no_input, output_fn=lambda _: None)
    assert not recovery_dir.exists()


def test_lab_change_during_operator_review_aborts_before_staging(recovery_inputs):
    lab, baseline, signature, _, recovery_dir, _ = recovery_inputs
    def change_lab(_):
        (lab / "late-file.txt").write_text("changed after review")
        return PHRASE
    with pytest.raises(RuntimeError, match="changed during review"):
        recovery.establish_recovery_baseline(lab, baseline, signature, recovery_dir,
                                             input_fn=change_lab, output_fn=lambda _: None)
    assert not recovery_dir.exists()


def test_existing_bundle_is_never_replaced(recovery_inputs):
    inputs = recovery_inputs
    bundle = inputs[4] / "new-trust-anchor"
    bundle.mkdir(parents=True)
    (bundle / "sentinel").write_text("keep")
    with pytest.raises(FileExistsError):
        establish(inputs)
    assert (bundle / "sentinel").read_text() == "keep"
    unchanged(inputs)


@pytest.mark.parametrize("bundle_name", ["../escape", ".", "a/b"])
def test_bundle_name_must_be_single_path_component(recovery_inputs, bundle_name):
    with pytest.raises(ValueError, match="simple directory"):
        establish(recovery_inputs, bundle_name=bundle_name)


def test_symlink_recovery_directory_is_rejected(recovery_inputs, tmp_path):
    lab, baseline, signature, _, recovery_dir, _ = recovery_inputs
    real = tmp_path / "real-recovery"
    real.mkdir()
    recovery_dir.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic links"):
        recovery.establish_recovery_baseline(lab, baseline, signature, recovery_dir,
                                             input_fn=lambda _: PHRASE, output_fn=lambda _: None)


@pytest.mark.parametrize("failure", ["signature", "baseline"])
def test_verification_failure_leaves_only_private_unpublished_stage(recovery_inputs, monkeypatch, failure):
    inputs = recovery_inputs
    if failure == "signature":
        monkeypatch.setattr(recovery, "verify_recovery_signature", lambda *_: False)
        expected = "signature verification failed"
    else:
        monkeypatch.setattr(recovery, "load_recovery_baseline", lambda *_: {"bad": True})
        expected = "did not match"
    with pytest.raises(RuntimeError, match=expected):
        establish(inputs)
    assert not (inputs[4] / "new-trust-anchor").exists()
    stages = list(inputs[4].glob(".rebaseline-*.staging"))
    assert len(stages) == 1 and stages[0].stat().st_mode & 0o777 == 0o700
    unchanged(inputs)


def test_concurrent_competing_publisher_is_not_overwritten_or_removed(recovery_inputs, monkeypatch):
    inputs = recovery_inputs
    real_rename = recovery._rename_bundle_noreplace

    def competitor(parent_fd, stage_name, bundle_name):
        os.mkdir(bundle_name, 0o700, dir_fd=parent_fd)
        fd = os.open(bundle_name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
        try:
            recovery._write_at(fd, "sentinel", b"other process")
        finally:
            os.close(fd)
        real_rename(parent_fd, stage_name, bundle_name)

    monkeypatch.setattr(recovery, "_rename_bundle_noreplace", competitor)
    with pytest.raises(FileExistsError):
        establish(inputs)
    assert (inputs[4] / "new-trust-anchor" / "sentinel").read_bytes() == b"other process"
    assert len(list(inputs[4].glob(".rebaseline-*.staging"))) == 1
    unchanged(inputs)


def test_stale_interrupted_stage_is_reported_and_not_cleaned(recovery_inputs):
    inputs = recovery_inputs
    recovery_dir = inputs[4]
    recovery_dir.mkdir(mode=0o700)
    stale = recovery_dir / ".rebaseline-interrupted.staging"
    stale.mkdir(mode=0o700)
    marker = stale / "marker"
    marker.write_text("preserve")
    with pytest.raises(RuntimeError, match="operator inspection"):
        establish(inputs)
    assert marker.read_text() == "preserve"
    unchanged(inputs)


def test_staging_write_failure_is_retained_without_unsafe_cleanup(recovery_inputs, monkeypatch):
    inputs = recovery_inputs
    real_write = recovery._write_at

    def fail_after_key(directory_fd, name, payload, mode=0o600):
        if name == "baseline.json":
            raise OSError("injected staging write failure")
        real_write(directory_fd, name, payload, mode)

    monkeypatch.setattr(recovery, "_write_at", fail_after_key)
    with pytest.raises(OSError, match="injected"):
        establish(inputs)
    assert not (inputs[4] / "new-trust-anchor").exists()
    stages = list(inputs[4].glob(".rebaseline-*.staging"))
    assert len(stages) == 1
    assert (stages[0] / "baseline.key").exists()
    unchanged(inputs)


def test_same_user_stage_modification_after_verification_is_rejected_before_publication(recovery_inputs, monkeypatch):
    inputs = recovery_inputs
    original_verify = recovery._verify_complete_bundle
    calls = 0

    def change_after_first_verification(stage_fd, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            fd = os.open("baseline.json", os.O_WRONLY | os.O_TRUNC, dir_fd=stage_fd)
            try:
                os.write(fd, b"tampered after initial verification")
                os.fsync(fd)
            finally:
                os.close(fd)
        return original_verify(stage_fd, *args, **kwargs)

    monkeypatch.setattr(recovery, "_verify_complete_bundle", change_after_first_verification)
    with pytest.raises(RuntimeError, match="Staged recovery file changed"):
        establish(inputs)
    assert calls == 2
    assert not (inputs[4] / "new-trust-anchor").exists()
    assert len(list(inputs[4].glob(".rebaseline-*.staging"))) == 1
    unchanged(inputs)


def test_recovery_record_readback_tampering_is_rejected(recovery_inputs, monkeypatch):
    inputs = recovery_inputs
    original_verify = recovery._verify_complete_bundle
    calls = 0

    def corrupt_record_before_final_check(stage_fd, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            fd = os.open("recovery-record.json", os.O_WRONLY | os.O_TRUNC, dir_fd=stage_fd)
            try:
                os.write(fd, b"not json")
                os.fsync(fd)
            finally:
                os.close(fd)
        return original_verify(stage_fd, *args, **kwargs)

    monkeypatch.setattr(recovery, "_verify_complete_bundle", corrupt_record_before_final_check)
    with pytest.raises(RuntimeError, match="Staged recovery file changed"):
        establish(inputs)
    assert not (inputs[4] / "new-trust-anchor").exists()
    unchanged(inputs)


@pytest.mark.parametrize("crash_after_commit", [False, True])
def test_process_crash_before_or_after_commit_never_publishes_partial_bundle(recovery_inputs, crash_after_commit):
    inputs = recovery_inputs
    lab, baseline, signature, _, recovery_dir, _ = inputs
    recovery_dir.mkdir(mode=0o700)
    script = r'''import os, sys
from forace import recovery
real = recovery._rename_bundle_noreplace
after = sys.argv[5] == "after"
def crash(parent, stage, bundle):
    if after:
        real(parent, stage, bundle)
    os._exit(73)
recovery._rename_bundle_noreplace = crash
recovery.establish_recovery_baseline(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], input_fn=lambda _: recovery.CONFIRMATION_PHRASE, output_fn=lambda _: None)
'''
    result = subprocess.run([sys.executable, "-c", script, str(lab), str(baseline), str(signature), str(recovery_dir), "after" if crash_after_commit else "before"], cwd=Path(__file__).resolve().parents[1], env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])})
    assert result.returncode == 73
    bundle = recovery_dir / "new-trust-anchor"
    if crash_after_commit:
        assert {p.name for p in bundle.iterdir()} == FILES
        fd = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert recovery.verify_recovery_signature(fd)
        finally:
            os.close(fd)
    else:
        assert not bundle.exists()
        assert len(list(recovery_dir.glob(".rebaseline-*.staging"))) == 1
    unchanged(inputs)
