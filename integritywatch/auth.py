"""HMAC-SHA256 authentication for the exact serialized baseline bytes."""
import hashlib
import hmac
import os
import re
import secrets
import stat
import json
import tempfile
from pathlib import Path


KEY_SIZE = 32


def generate_key(key_path):
    """Create a random owner-only key, refusing to replace an existing path."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_SIZE)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(key)
            stream.flush()
            os.fsync(fd)
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    os.close(fd)
    return key


def load_key(key_path):
    """Load a well-formed owner-only HMAC key without following symlinks."""
    path = Path(key_path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("HMAC key must be a regular file")
        if info.st_uid != os.geteuid():
            raise PermissionError("HMAC key must be owned by the current user")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise PermissionError("HMAC key permissions must be exactly 0600")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            key = stream.read(KEY_SIZE + 1)
    finally:
        os.close(fd)
    if len(key) != KEY_SIZE:
        raise ValueError("Malformed HMAC key: expected 32 bytes")
    return key


def _signature_for(baseline_path, key):
    payload = Path(baseline_path).read_bytes()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def sign_baseline(baseline_path, key_path, signature_path=None, *, approve_replace=False):
    """Sign baseline bytes, writing a detached hex digest without silent replacement."""
    baseline = Path(baseline_path)
    signature = Path(signature_path) if signature_path else Path(f"{baseline}.hmac")
    key = load_key(key_path)
    digest = (_signature_for(baseline, key) + "\n").encode("ascii")
    signature.parent.mkdir(parents=True, exist_ok=True)
    if signature.exists() and not approve_replace:
        raise FileExistsError("Baseline signature exists; explicit replacement approval is required")
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{signature.name}.", dir=signature.parent)
        temporary = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(digest)
            stream.flush()
            os.fsync(stream.fileno())
        if approve_replace:
            os.replace(temporary, signature)
        else:
            os.link(temporary, signature)
            temporary.unlink()
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return signature


def verify_baseline_signature(baseline_path, key_path, signature_path=None):
    """Validate detached HMAC; raise on missing, malformed, or invalid trust data."""
    baseline = Path(baseline_path)
    signature = Path(signature_path) if signature_path else Path(f"{baseline}.hmac")
    key = load_key(key_path)
    supplied = signature.read_bytes()
    return verify_baseline_signature_bytes(baseline.read_bytes(), key, supplied)


def verify_baseline_signature_bytes(payload, key, supplied):
    """Verify an already-read baseline/signature snapshot against key bytes."""
    if re.fullmatch(rb"[0-9a-f]{64}\n?", supplied) is None:
        raise ValueError("Malformed baseline signature")
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest().encode("ascii")
    actual = supplied.strip()
    if not hmac.compare_digest(expected, actual):
        raise ValueError("Baseline signature verification failed")
    return True


def load_authenticated_baseline(baseline_path, key_path, signature_path=None):
    """Authenticate and parse the same byte snapshot, avoiding verify/load races."""
    baseline = Path(baseline_path)
    signature = Path(signature_path) if signature_path else Path(f"{baseline}.hmac")
    payload = baseline.read_bytes()
    key = load_key(key_path)
    supplied = signature.read_bytes()
    return load_authenticated_baseline_bytes(payload, key, supplied)


def load_authenticated_baseline_bytes(payload, key, supplied):
    """Authenticate and validate one already-read baseline/signature snapshot."""
    from integritywatch.baseline import validate_baseline

    if re.fullmatch(rb"[0-9a-f]{64}\n?", supplied) is None:
        raise ValueError("Malformed baseline signature")
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest().encode("ascii")
    if not hmac.compare_digest(expected, supplied.strip()):
        raise ValueError("Baseline signature verification failed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Authenticated baseline is malformed JSON: {error}") from error
    validate_baseline(value)
    return value
