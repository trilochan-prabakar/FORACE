"""Operational heartbeat file for showing whether the local watch command runs."""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def write_monitor_status(path, *, root, mode, pid=None, last_error=None):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = {"status": "running", "pid": pid if pid is not None else os.getpid(),
            "root": str(root), "mode": mode,
            "last_seen_utc": datetime.now(timezone.utc).isoformat(),
            "last_error": last_error}
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    finally:
        Path(temporary_name).unlink(missing_ok=True)
    return destination


def clear_monitor_status(path, *, pid=None):
    status_path = Path(path)
    try:
        current = json.loads(status_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return False
    if pid is not None and current.get("pid") != pid:
        return False
    status_path.unlink(missing_ok=True)
    return True


def read_monitor_status(path, *, now=None, stale_after_seconds=10):
    status_path = Path(path)
    try:
        data = json.loads(status_path.read_text(encoding="utf-8"))
        pid = data["pid"]
        stamp = datetime.fromisoformat(data["last_seen_utc"])
        current = now or datetime.now(timezone.utc)
        if stamp.tzinfo is None or current.tzinfo is None:
            raise ValueError("monitor timestamps must include a timezone")
        age = (current - stamp).total_seconds()
        if (data.get("status") != "running" or type(pid) is not int or pid <= 0
                or age < 0 or age > stale_after_seconds):
            raise ValueError("monitor heartbeat is stale or malformed")
        last_error = data.get("last_error")
        if last_error is not None and not isinstance(last_error, str):
            raise ValueError("monitor error state is malformed")
        os.kill(pid, 0)
        return {"status": "running", "pid": pid, "root": data["root"], "mode": data["mode"],
                "last_error": last_error,
                "message": f"Watch process {pid} is active; heartbeat age {age:.1f}s"}
    except FileNotFoundError:
        return {"status": "not_running", "message": "No local watch heartbeat is present"}
    except ProcessLookupError:
        return {"status": "not_running", "message": "The recorded watch process is no longer running"}
    except PermissionError:
        return {"status": "not_running", "message": "Cannot confirm the recorded watch process"}
    except (OSError, OverflowError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        return {"status": "not_running", "message": f"No current watch status: {error}"}
