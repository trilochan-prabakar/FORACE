"""Compare a validated baseline with a scan result in smart or hash-only mode."""
from pathlib import Path

from integritywatch.analyzers import (
    analyze_authorized_keys, analyze_crontab, analyze_passwd, changed_sshd_security_settings,
    analyze_sshd, analyze_sudoers, analyze_systemd,
)
from integritywatch.rules import load_rules


def _finding(path, kind, rule=None):
    return {"file_path": path, "change_type": kind,
            "rule_id": rule["id"] if rule else None,
            "severity": rule["severity"] if rule else None,
            "attack_id": rule["attack_id"] if rule else None,
            "explanation": rule["explanation_template"] if rule else None}


def _metadata_findings(path, old, new, by_id):
    findings = []
    if old.get("mode") != new.get("mode"):
        newly_suid = not old.get("mode", 0) & 0o4000 and bool(new.get("mode", 0) & 0o4000)
        newly_sgid = not old.get("mode", 0) & 0o2000 and bool(new.get("mode", 0) & 0o2000)
        if newly_suid:
            findings.append(_finding(path, "suid_enabled", by_id["R10"]))
        elif not newly_sgid:
            findings.append(_finding(path, "permission_changed"))
        if newly_sgid:
            findings.append(_finding(path, "sgid_enabled"))
    if old.get("uid") != new.get("uid") or old.get("gid") != new.get("gid"):
        findings.append(_finding(path, "ownership_changed"))
    return findings


def _active_lines(text):
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith(("#", ";"))]


def _semantic_signature(path, text):
    """Normalize supported formats enough to distinguish benign edits from unknown changes."""
    if path == "etc/ssh/sshd_config":
        signature = []
        for line in _active_lines(text):
            fields = line.split(None, 1)
            if len(fields) == 2:
                signature.append((fields[0].lower(), " ".join(fields[1].split()).lower()))
            else:
                signature.append(("raw", " ".join(line.split())))
        return tuple(signature)

    if path.endswith("/.ssh/authorized_keys"):
        keys, unsupported = {}, []
        for line in _active_lines(text):
            fields = line.split()
            algorithm_index = next((index for index, field in enumerate(fields)
                                    if field.startswith(("ssh-", "ecdsa-", "sk-"))), None)
            if algorithm_index is None or len(fields) <= algorithm_index + 1:
                unsupported.append(" ".join(fields))
                continue
            algorithm, blob = fields[algorithm_index:algorithm_index + 2]
            identity = f"{algorithm} {blob}"
            keys[identity] = " ".join(fields[:algorithm_index])
        return tuple(sorted(keys.items())), tuple(sorted(unsupported))

    if path == "etc/crontab":
        return tuple(sorted({" ".join(line.split()) for line in _active_lines(text)}))

    if path == "etc/passwd":
        return tuple(sorted(_active_lines(text)))

    if path == "etc/sudoers":
        return tuple(sorted({" ".join(line.split()) for line in _active_lines(text)}))

    if path.startswith("etc/systemd/system/") and path.endswith(".service"):
        signature = []
        for line in _active_lines(text):
            if "=" in line:
                key, value = line.split("=", 1)
                signature.append(f"{key.strip().lower()}={value.strip()}")
            else:
                signature.append(" ".join(line.split()).lower())
        return tuple(signature)

    return None

def _analyze_ssh(path, old_text, new_text):
    triggers = analyze_sshd(old_text, new_text)
    rule_ids = [
        "R01" if trigger.startswith("PermitRootLogin") else "R02"
        for trigger in triggers
    ]
    extra = []
    if not rule_ids and changed_sshd_security_settings(old_text, new_text):
        extra.append(_finding(path, "ssh_setting_changed"))
    return rule_ids, extra


def _analyze_authorized_keys(path, old_text, new_text):
    changes = analyze_authorized_keys(old_text, new_text)
    rule_ids = ["R03"] if changes["added"] else []
    extra = []
    if changes["removed"]:
        extra.append(_finding(path, "ssh_key_removed"))
    if changes["modified"]:
        extra.append(_finding(path, "ssh_key_options_changed"))
    return rule_ids, extra


def _analyze_cron(path, old_text, new_text):
    changes = analyze_crontab(old_text, new_text)
    rule_ids = []
    extra = []
    if changes["suspicious"]:
        rule_ids.append("R05")
    if any(entry not in changes["suspicious"] for entry in changes["added"]):
        rule_ids.append("R04")
    if changes["removed"]:
        extra.append(_finding(path, "cron_entry_removed"))
    return rule_ids, extra


def _analyze_passwd(path, old_text, new_text):
    changes = analyze_passwd(old_text, new_text)
    rule_ids = []
    extra = []
    if changes["new_users"]:
        rule_ids.append("R06")
    if changes["uid_zero"]:
        rule_ids.append("R07")
    if changes["service_shell"]:
        rule_ids.append("R08")
    for key, kind in (
        ("removed_users", "user_removed"),
        ("uid_changes", "uid_changed"),
        ("gid_changes", "gid_changed"),
    ):
        if changes[key]:
            extra.append(_finding(path, kind))
    return rule_ids, extra


def _analyze_sudoers(path, old_text, new_text):
    changes = analyze_sudoers(old_text, new_text)
    rule_ids = []
    extra = []
    if changes["nopasswd"]:
        rule_ids = ["R09"]
    elif changes["admin_privileges"]:
        extra.append(_finding(path, "admin_privileges_changed"))
    if changes["removed_admin_privileges"]:
        extra.append(_finding(path, "admin_privileges_removed"))
    return rule_ids, extra


def _analyze_systemd(path, old_text, new_text):
    rule_ids = ["R12"] if analyze_systemd(old_text, new_text) else []
    return rule_ids, []


SEMANTIC_DISPATCH = (
    (lambda path: path == "etc/ssh/sshd_config", _analyze_ssh),
    (lambda path: path.endswith("/.ssh/authorized_keys"), _analyze_authorized_keys),
    (lambda path: path == "etc/crontab", _analyze_cron),
    (lambda path: path == "etc/passwd", _analyze_passwd),
    (lambda path: path == "etc/sudoers", _analyze_sudoers),
    (
        lambda path: path.startswith("etc/systemd/system/") and path.endswith(".service"),
        _analyze_systemd,
    ),
)


def _dispatch_semantic_analysis(path, old_text, new_text):
    for matches, analyzer in SEMANTIC_DISPATCH:
        if matches(path):
            return analyzer(path, old_text, new_text)
    return [], []

def compare_scans(baseline, current, mode="smart", rules_path="rules.yaml"):
    """Return findings for paths relative to the controlled lab root only."""
    if mode not in {"smart", "hash-only"}:
        raise ValueError("mode must be 'smart' or 'hash-only'")
    before, after = baseline.get("files", {}), current.get("files", {})
    errors = current.get("errors", {})
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Baseline and scan files must be mappings")
    for relative_path in set(before) | set(after) | set(errors):
        path = Path(relative_path)
        if path.is_absolute() or ".." in path.parts or not relative_path:
            raise ValueError(f"Path is outside the lab-relative scope: {relative_path}")

    rules = load_rules(rules_path) if mode == "smart" else []
    by_id = {rule["id"]: rule for rule in rules}
    findings = []
    added = set(after) - set(before)
    deleted = {
        path for path in set(before) - set(after)
        if not any(path == failed or failed == "." or path.startswith(failed.rstrip("/") + "/")
                   for failed in errors)
    }
    # A unique identical hash pair is a reliable rename; ambiguous duplicates stay add/delete.
    if mode == "smart":
        for old_path in sorted(deleted.copy()):
            matches = [p for p in sorted(added) if before[old_path]["sha256"] == after[p]["sha256"]]
            reverse = [p for p in sorted(deleted) if before[p]["sha256"] == after[matches[0]]["sha256"]] if matches else []
            if len(matches) == 1 and len(reverse) == 1:
                findings.append(_finding(old_path, "renamed"))
                findings.extend(_metadata_findings(matches[0], before[old_path], after[matches[0]], by_id))
                deleted.remove(old_path)
                added.remove(matches[0])

    for path in sorted(added):
        rule = None
        if mode == "smart":
            if path.startswith("etc/systemd/system/") and path.endswith(".service"):
                rule = by_id["R12"]
            elif path.endswith("/.ssh/authorized_keys"):
                rule = by_id["R03"]
        findings.append(_finding(path, "added", rule))
    for path in sorted(deleted):
        rule = by_id["R11"] if mode == "smart" and path == "var/log/auth.log" else None
        findings.append(_finding(path, "deleted", rule))

    for path in sorted(set(before) & set(after)):
        old, new = before[path], after[path]
        if mode == "smart":
            findings.extend(_metadata_findings(path, old, new, by_id))
        if old.get("sha256") == new.get("sha256"):
            continue
        if mode == "hash-only":
            findings.append(_finding(path, "modified"))
            continue

        if path == "var/log/auth.log" and new.get("size", 0) < old.get("size", 0):
            findings.append(_finding(path, "truncated", by_id["R11"]))
            continue

        old_text, new_text = old.get("snapshot"), new.get("snapshot")
        semantic_start = len(findings)
        if not isinstance(old_text, str) or not isinstance(new_text, str):
            findings.append(_finding(path, "modified"))
            continue

        try:
            rule_ids, extra_findings = _dispatch_semantic_analysis(
                path, old_text, new_text
            )
            findings.extend(extra_findings)

            for rule_id in rule_ids:
                findings.append(
                    _finding(path, by_id[rule_id]["trigger"], by_id[rule_id])
                )
        except Exception:
            # A parser failure must not erase a content change or leave partial semantic results.
            del findings[semantic_start:]
            findings.append(_finding(path, "modified"))
            continue

        if len(findings) == semantic_start:
            try:
                old_signature = _semantic_signature(path, old_text)
                new_signature = _semantic_signature(path, new_text)
                if (old_text == new_text or old_signature is None or new_signature is None
                        or old_signature != new_signature):
                    findings.append(_finding(path, "modified"))
            except Exception:
                findings.append(_finding(path, "modified"))
    return findings
