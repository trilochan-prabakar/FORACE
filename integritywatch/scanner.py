
import hashlib
import os
import stat

from pathlib import Path


# Maximum size for storing text snapshots: 1 MB.
MAX_SNAPSHOT_SIZE = 1024 * 1024

# Read files in chunks to avoid loading large files into memory.
CHUNK_SIZE = 65536


def _open_regular(file_path):
    """Open a regular file without following its final path component."""
    fd = os.open(file_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise ValueError("Only regular files are supported")
    return fd, info


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    fd, _ = _open_regular(file_path)
    try:
        while True:
            chunk = os.read(fd, CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)
    finally:
        os.close(fd)

    return sha256.hexdigest()


def collect_metadata(file_path):
    """Collect filesystem metadata for a file."""

    fd, file_stat = _open_regular(file_path)
    os.close(fd)

    return {
        "size": file_stat.st_size,
        "mode": stat.S_IMODE(file_stat.st_mode),
        "uid": file_stat.st_uid,
        "gid": file_stat.st_gid,
        "mtime_ns": file_stat.st_mtime_ns,
    }


def read_text_snapshot(file_path, file_size):
    """Read UTF-8 text files smaller than 1 MB."""

    if file_size >= MAX_SNAPSHOT_SIZE:
        return None

    fd, info = _open_regular(file_path)
    try:
        if info.st_size >= MAX_SNAPSHOT_SIZE:
            return None
        chunks = bytearray()
        while len(chunks) <= MAX_SNAPSHOT_SIZE:
            chunk = os.read(fd, min(CHUNK_SIZE, MAX_SNAPSHOT_SIZE + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        try:
            return chunks.decode("utf-8")
        except UnicodeDecodeError:
            return None
    finally:
        os.close(fd)


def scan_file(file_path, root_directory):
    """Scan a regular file beneath root using no-follow directory descriptors."""
    root = Path(root_directory).resolve(strict=True)
    target = Path(file_path)
    if ".." in target.parts:
        raise ValueError("Parent traversal is not allowed in scan paths")
    if not target.is_absolute():
        target = root / target
    target = target.absolute()
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise ValueError("File must be beneath the scan root") from error
    if not relative.parts:
        raise ValueError("The scan target must be a file")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd = os.open(root, flags | getattr(os, "O_NOFOLLOW", 0))
    parent_fd = root_fd
    try:
        for part in relative.parts[:-1]:
            child_fd = os.open(part, flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = child_fd
        return _scan_regular_at(parent_fd, relative.parts[-1])
    finally:
        if parent_fd != root_fd:
            os.close(parent_fd)
        os.close(root_fd)


def _scan_regular_at(directory_fd, name):
    """Hash and snapshot one opened inode so metadata and content share a handle."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Only regular files are supported")
        digest = hashlib.sha256()
        snapshot_bytes = bytearray() if before.st_size < MAX_SNAPSHOT_SIZE else None
        bytes_read = 0
        while True:
            chunk = os.read(fd, CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            bytes_read += len(chunk)
            if snapshot_bytes is not None:
                snapshot_bytes.extend(chunk)
        after = os.fstat(fd)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                           before.st_ctime_ns, before.st_mode, before.st_uid, before.st_gid)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                          after.st_ctime_ns, after.st_mode, after.st_uid, after.st_gid)
        if identity_before != identity_after or bytes_read != before.st_size:
            raise OSError("File changed while it was being scanned")
        snapshot = None
        if snapshot_bytes is not None:
            try:
                snapshot = snapshot_bytes.decode("utf-8")
            except UnicodeDecodeError:
                pass
        return {"sha256": digest.hexdigest(), "size": before.st_size,
                "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
                "gid": before.st_gid, "mtime_ns": before.st_mtime_ns,
                "snapshot": snapshot}
    finally:
        os.close(fd)


def scan_directory(root_directory):
    """Recursively scan files without following links or resolving paths by name."""
    root = Path(root_directory).resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd = os.open(root, flags | getattr(os, "O_NOFOLLOW", 0))
    if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
        os.close(root_fd)
        raise NotADirectoryError(f"Not a directory: {root}")

    files, errors = {}, {}

    def walk(directory_fd, parent):
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as error:
            errors[str(parent) if parent.parts else "."] = str(error)
            return
        for name in names:
            relative = parent / name
            relative_text = str(relative)
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    errors[relative_text] = "Symbolic links are not supported"
                elif stat.S_ISDIR(info.st_mode):
                    child_flags = flags | getattr(os, "O_NOFOLLOW", 0)
                    child_fd = os.open(name, child_flags, dir_fd=directory_fd)
                    try:
                        walk(child_fd, relative)
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(info.st_mode):
                    files[relative_text] = _scan_regular_at(directory_fd, name)
            except (OSError, ValueError) as error:
                errors[relative_text] = str(error)

    try:
        walk(root_fd, Path())
    finally:
        os.close(root_fd)
    return {"files": files, "errors": errors}
