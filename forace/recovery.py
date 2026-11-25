"""Explicit, crash-safe creation of a replacement HMAC trust anchor."""
from datetime import datetime, timezone
import ctypes
import errno
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path

from forace.auth import KEY_SIZE, load_authenticated_baseline_bytes, verify_baseline_signature_bytes
from forace.baseline import create_baseline, validate_baseline

CONFIRMATION_PHRASE = "ESTABLISH NEW TRUST ANCHOR"
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_STAGE_PREFIX = ".rebaseline-"
_STAGE_SUFFIX = ".staging"
_RENAME_NOREPLACE = 1
try:
    _libc = ctypes.CDLL(None, use_errno=True)
    _renameat2 = _libc.renameat2
    _renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _renameat2.restype = ctypes.c_int
except (AttributeError, OSError):
    _renameat2 = None


def _regular_source(path, label):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"{label} must be an existing regular file, not a symbolic link")
    return path


def _identity(path):
    info = Path(path).lstat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)


def _canonical_path(path):
    lexical = Path(os.path.abspath(path))
    if lexical != Path(path).resolve(strict=False):
        raise ValueError(f"Recovery paths must not traverse symbolic links: {path}")
    return lexical


def _open_recovery_directory(path, *, create):
    """Open each component without following symlinks and retain a directory fd."""
    path = Path(path)
    fd = os.open(os.path.sep, _DIRECTORY_FLAGS)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            try:
                child = os.open(part, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                os.mkdir(part, 0o700, dir_fd=fd)
                os.fsync(fd)
                child = os.open(part, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if index < len(parts) - 1:
                mode = stat.S_IMODE(info.st_mode)
                if mode & 0o022 and not mode & stat.S_ISVTX:
                    raise PermissionError("Recovery path traverses a group/world-writable directory")
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise PermissionError("Recovery directory must be a directory owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("Recovery directory must not be group- or world-writable")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _read_at(directory_fd, name, *, key=False):
    fd = os.open(name, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Recovery file is not regular: {name}")
        if key and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise PermissionError("Recovery HMAC key must be current-user owned with mode 0600")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        value = b"".join(chunks)
        if key and len(value) != KEY_SIZE:
            raise ValueError("Malformed recovery HMAC key")
        return value
    finally:
        os.close(fd)


def verify_recovery_signature(directory_fd, baseline_name="baseline.json", key_name="baseline.key", signature_name="baseline.json.hmac"):
    payload = _read_at(directory_fd, baseline_name)
    key = _read_at(directory_fd, key_name, key=True)
    signature = _read_at(directory_fd, signature_name)
    return verify_baseline_signature_bytes(payload, key, signature)


def load_recovery_baseline(directory_fd, baseline_name="baseline.json", key_name="baseline.key", signature_name="baseline.json.hmac"):
    payload = _read_at(directory_fd, baseline_name)
    key = _read_at(directory_fd, key_name, key=True)
    signature = _read_at(directory_fd, signature_name)
    return load_authenticated_baseline_bytes(payload, key, signature)


def _verify_complete_bundle(stage_fd, parent_fd, stage_name, reviewed, record,
                            expected_files, expected_directory_identity,
                            expected_file_identities=None):
    """Read one staged snapshot and verify every file before it can be published."""
    directory = os.fstat(stage_fd)
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
            or (directory.st_dev, directory.st_ino) != expected_directory_identity):
        raise RuntimeError("Staged recovery directory changed before publication")

    named_directory = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(named_directory.st_mode)
            or (named_directory.st_dev, named_directory.st_ino) != expected_directory_identity):
        raise RuntimeError("Staged recovery directory was replaced before publication")

    contents = {}
    identities = {}
    for name, expected_payload in expected_files.items():
        fd = os.open(name, os.O_RDONLY | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=stage_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise RuntimeError(f"Staged recovery file has unsafe permissions or type: {name}")
            identity = (info.st_dev, info.st_ino)
            if expected_file_identities is not None and identity != expected_file_identities[name]:
                raise RuntimeError(f"Staged recovery file was replaced before publication: {name}")
            chunks = []
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(fd)
        if payload != expected_payload:
            raise RuntimeError(f"Staged recovery file changed before publication: {name}")
        contents[name] = payload
        identities[name] = identity

    verify_baseline_signature_bytes(
        contents["baseline.json"], contents["baseline.key"], contents["baseline.json.hmac"]
    )
    authenticated = load_authenticated_baseline_bytes(
        contents["baseline.json"], contents["baseline.key"], contents["baseline.json.hmac"]
    )
    if authenticated != reviewed:
        raise RuntimeError("Verified recovery baseline does not match the reviewed lab inventory")
    try:
        parsed_record = json.loads(contents["recovery-record.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Recovery record read-back verification failed") from error
    if parsed_record != record:
        raise RuntimeError("Recovery record read-back verification failed")

    # Check the name again after all file reads; publication still assumes the
    # documented single-UID threat model described in README.
    named_directory = os.stat(stage_name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(named_directory.st_mode)
            or (named_directory.st_dev, named_directory.st_ino) != expected_directory_identity):
        raise RuntimeError("Staged recovery directory was replaced before publication")
    return identities


def _write_at(directory_fd, name, payload, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(name, flags, mode, dir_fd=directory_fd)
    try:
        os.fchmod(fd, mode)
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("Incomplete write to recovery staging file")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _rename_bundle_noreplace(parent_fd, stage_name, bundle_name):
    """Atomically expose one complete directory, failing closed without renameat2."""
    if _renameat2 is None:
        raise OSError(errno.ENOSYS, "Atomic no-replace directory publication requires renameat2")
    result = _renameat2(parent_fd, os.fsencode(stage_name), parent_fd, os.fsencode(bundle_name), _RENAME_NOREPLACE)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), bundle_name)


def _review_inventory(baseline, output_fn):
    output_fn("Lab inventory review (relative path · bytes · mode · SHA-256):")
    if not baseline["files"]:
        output_fn("  (no regular files)")
    for path, details in sorted(baseline["files"].items()):
        output_fn(f"  {path} · {details['size']} · {details['mode']:04o} · {details['sha256']}")
    output_fn("The original baseline and signature are not authenticated. Proceeding establishes a new trust anchor from this reviewed lab state.")


def _stale_stages(directory_fd):
    return sorted(name for name in os.listdir(directory_fd)
                  if name.startswith(_STAGE_PREFIX) and name.endswith(_STAGE_SUFFIX))


def _same_inventory(left, right):
    return left["root_directory"] == right["root_directory"] and left["files"] == right["files"]


def establish_recovery_baseline(lab_directory, source_baseline, source_signature,
                                recovery_directory, bundle_name="new-trust-anchor", *,
                                input_fn=None, output_fn=print):
    """Review, stage, verify, then atomically publish a complete recovery bundle.

    Interrupted private stages are deliberately retained for operator inspection;
    they are never removed automatically because a pathname could have been replaced.
    """
    requested_root = Path(lab_directory)
    if requested_root.is_symlink():
        raise ValueError("The configured monitor root must not be a symbolic link")
    root = requested_root.resolve()
    if root.name != "lab" or not root.is_dir():
        raise ValueError("The configured monitor root must be an existing controlled directory named lab")
    source_baseline = _regular_source(source_baseline, "Original baseline")
    source_signature = _regular_source(source_signature, "Original detached signature")
    original_ids = (_identity(source_baseline), _identity(source_signature))
    recovery_root = _canonical_path(recovery_directory)
    if recovery_root == root or recovery_root.is_relative_to(root):
        raise ValueError("Recovery directory must be outside the monitored lab")
    if Path(bundle_name).name != bundle_name or bundle_name in {"", ".", ".."}:
        raise ValueError("Recovery bundle name must be a simple directory name")

    parent_fd = _open_recovery_directory(recovery_root, create=False)
    try:
        if parent_fd is not None:
            try:
                os.stat(bundle_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(f"Recovery bundle already exists; refusing to replace it: {bundle_name}")
            stale = _stale_stages(parent_fd)
            if stale:
                raise RuntimeError("Interrupted private recovery stage requires operator inspection: " + ", ".join(stale))
    finally:
        if parent_fd is not None:
            os.close(parent_fd)

    reviewed = create_baseline(root)
    _review_inventory(reviewed, output_fn)
    if input_fn is None:
        input_fn = input
    try:
        answer = input_fn(f"Type {CONFIRMATION_PHRASE} to continue: ")
    except EOFError as error:
        raise RuntimeError("Operator confirmation was not provided; recovery cancelled") from error
    if answer != CONFIRMATION_PHRASE:
        raise RuntimeError("Confirmation phrase did not match; recovery cancelled")

    if not _same_inventory(create_baseline(root), reviewed):
        raise RuntimeError("Lab files changed during review; no recovery trust anchor was created")
    if (_identity(source_baseline), _identity(source_signature)) != original_ids:
        raise RuntimeError("Original trust files changed during review; recovery cancelled")

    parent_fd = _open_recovery_directory(recovery_root, create=True)
    stage_name = f"{_STAGE_PREFIX}{secrets.token_hex(16)}{_STAGE_SUFFIX}"
    stage_fd = None
    try:
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        stage_fd = os.open(stage_name, _DIRECTORY_FLAGS | _NOFOLLOW, dir_fd=parent_fd)
        stage_info = os.fstat(stage_fd)
        stage_identity = (stage_info.st_dev, stage_info.st_ino)
        key = secrets.token_bytes(KEY_SIZE)
        validate_baseline(reviewed)
        baseline_payload = (json.dumps(reviewed, indent=4) + "\n").encode("utf-8")
        signature_payload = (hmac.new(key, baseline_payload, hashlib.sha256).hexdigest() + "\n").encode("ascii")
        _write_at(stage_fd, "baseline.key", key)
        _write_at(stage_fd, "baseline.json", baseline_payload)
        _write_at(stage_fd, "baseline.json.hmac", signature_payload)

        if not verify_recovery_signature(stage_fd):
            raise RuntimeError("New recovery signature verification failed")
        authenticated = load_recovery_baseline(stage_fd)
        if authenticated != reviewed:
            raise RuntimeError("New baseline verification did not match the reviewed lab inventory")
        if (_identity(source_baseline), _identity(source_signature)) != original_ids:
            raise RuntimeError("Original trust files changed during recovery; recovery cancelled")
        if not _same_inventory(create_baseline(root), reviewed):
            raise RuntimeError("Lab files changed during recovery; recovery cancelled")

        record = {
            "event": "new_trust_anchor_established",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "lab_root": str(root),
            "original_authenticity_recovered": False,
            "original_baseline": str(source_baseline),
            "original_signature": str(source_signature),
            "bundle": str(recovery_root / bundle_name),
            "new_baseline": str(recovery_root / bundle_name / "baseline.json"),
            "new_baseline_sha256": hashlib.sha256(baseline_payload).hexdigest(),
            "new_signature": str(recovery_root / bundle_name / "baseline.json.hmac"),
            "new_signature_sha256": hashlib.sha256(signature_payload).hexdigest(),
            "new_key": str(recovery_root / bundle_name / "baseline.key"),
            "statement": "A new trust anchor was established; original baseline authenticity was not recovered.",
        }
        record_payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
        _write_at(stage_fd, "recovery-record.json", record_payload, 0o600)
        os.fsync(stage_fd)
        expected_files = {
            "baseline.key": key,
            "baseline.json": baseline_payload,
            "baseline.json.hmac": signature_payload,
            "recovery-record.json": record_payload,
        }
        file_identities = _verify_complete_bundle(
            stage_fd, parent_fd, stage_name, reviewed, record, expected_files, stage_identity
        )
        # Re-read all four files immediately before the commit point and require
        # the same directory and file inodes verified above.
        _verify_complete_bundle(
            stage_fd, parent_fd, stage_name, reviewed, record, expected_files,
            stage_identity, expected_file_identities=file_identities,
        )
        # No rollback deletion: failed or interrupted stages remain detectable.
        # renameat2(RENAME_NOREPLACE) is the single publication/commit point.
        _rename_bundle_noreplace(parent_fd, stage_name, bundle_name)
        os.fsync(parent_fd)
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(parent_fd)

    output_fn(f"New baseline authenticated: {recovery_root / bundle_name / 'baseline.json'}")
    output_fn(f"New detached HMAC verified: {recovery_root / bundle_name / 'baseline.json.hmac'}")
    output_fn(f"New HMAC key: {recovery_root / bundle_name / 'baseline.key'} (permissions 0600)")
    output_fn("A new trust anchor was established; the original baseline authenticity was not recovered.")
    return record
