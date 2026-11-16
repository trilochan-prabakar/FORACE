"""Conservative semantic analyzers for the supported lab configuration formats."""
import re


def _active_lines(text):
    return [line.strip() for line in (text or "").splitlines()
            if line.strip() and not line.lstrip().startswith(("#", ";"))]


def analyze_sshd(old, new):
    def parse(text):
        values = {}
        for line in _active_lines(text):
            parts = line.split()
            if len(parts) > 1:
                values.setdefault(parts[0].lower(), parts[1].lower())
        return values
    before, after = parse(old), parse(new)
    return [f"{key}=yes" for key in ("PermitRootLogin", "PasswordAuthentication")
            if after.get(key.lower()) == "yes" and before.get(key.lower()) != "yes"]


def changed_sshd_security_settings(old, new):
    security_keys = {"permitrootlogin", "passwordauthentication", "pubkeyauthentication",
                     "permitemptypasswords", "kbdinteractiveauthentication", "challengeresponseauthentication",
                     "authenticationmethods", "allowusers", "allowgroups", "denyusers", "denygroups",
                     "x11forwarding", "allowagentforwarding", "allowtcpforwarding", "permituserenvironment"}
    def values(text):
        result = {}
        for line in _active_lines(text):
            fields = line.split(None, 1)
            if len(fields) == 2 and fields[0].lower() in security_keys:
                result.setdefault(fields[0].lower(), " ".join(fields[1].split()).lower())
        return result
    before, after = values(old), values(new)
    return sorted(key for key in security_keys if before.get(key) != after.get(key) and key in before.keys() | after.keys())


def _keys(text):
    keys = {}
    for line in _active_lines(text):
        fields = line.split()
        algorithm_index = next((index for index, field in enumerate(fields)
                                if field.startswith(("ssh-", "ecdsa-", "sk-"))), None)
        if algorithm_index is None or len(fields) <= algorithm_index + 1:
            continue
        algorithm, blob = fields[algorithm_index:algorithm_index + 2]
        identity = f"{algorithm} {blob}"
        options = " ".join(fields[:algorithm_index])
        keys[identity] = options
    return keys


def analyze_authorized_keys(old, new):
    before, after = _keys(old), _keys(new)
    shared = before.keys() & after.keys()
    return {"added": sorted(after.keys() - before.keys()),
            "removed": sorted(before.keys() - after.keys()),
            "modified": sorted(key for key in shared if before[key] != after[key])}


def _cron(text):
    return {" ".join(line.split()) for line in _active_lines(text)
            if line.startswith("@") or len(line.split()) >= 6}


def analyze_crontab(old, new):
    old_entries, new_entries = _cron(old), _cron(new)
    added = sorted(new_entries - old_entries)
    suspicious = [line for line in added if any(token in line.lower() for token in
                  ("curl ", "wget ", "nc ", "/dev/tcp", "base64 -d", "python -c", "perl -e"))]
    return {"added": added, "removed": sorted(old_entries - new_entries), "suspicious": suspicious}


def _passwd(text):
    entries = {}
    for line in _active_lines(text):
        fields = line.split(":")
        if len(fields) == 7:
            entries[fields[0]] = fields
    return entries


def analyze_passwd(old, new):
    before, after = _passwd(old), _passwd(new)
    return {
        "new_users": sorted(after.keys() - before.keys()),
        "removed_users": sorted(before.keys() - after.keys()),
        "uid_changes": sorted(name for name in after.keys() & before.keys() if after[name][2] != before[name][2]),
        "gid_changes": sorted(name for name in after.keys() & before.keys() if after[name][3] != before[name][3]),
        "uid_zero": sorted(name for name, fields in after.items()
                            if name != "root" and fields[2] == "0" and
                            (name not in before or before[name][2] != "0")),
        "service_shell": sorted(name for name, fields in after.items()
                                 if name in before and name.startswith(("svc", "service", "daemon"))
                                 and before[name][6] in ("/usr/sbin/nologin", "/bin/false")
                                 and fields[6] in ("/bin/bash", "/bin/sh", "/bin/zsh")),
    }


def analyze_sudoers(old, new):
    def lines(text):
        return {" ".join(line.split()) for line in _active_lines(text)}
    before, after = lines(old), lines(new)
    added, removed = sorted(after - before), sorted(before - after)
    is_admin = lambda line: re.search(r"(?<![A-Za-z0-9_])ALL(?![A-Za-z0-9_])", line, re.IGNORECASE) is not None
    return {"nopasswd": [line for line in added if "NOPASSWD:" in line.upper()],
            "admin_privileges": [line for line in added if is_admin(line)],
            "removed_admin_privileges": [line for line in removed if is_admin(line)]}


def analyze_systemd(old, new):
    def normalized(text):
        # systemd keys are case-insensitive; values remain case-sensitive.
        lines = []
        for line in _active_lines(text):
            if "=" in line:
                key, value = line.split("=", 1)
                lines.append(f"{key.strip().lower()}={value.strip()}")
            else:
                lines.append(" ".join(line.split()).lower())
        return lines
    return normalized(old) != normalized(new)


ANALYZERS = {"sshd_config": analyze_sshd, "authorized_keys": analyze_authorized_keys,
             "crontab": analyze_crontab, "passwd": analyze_passwd,
             "sudoers": analyze_sudoers, "systemd": analyze_systemd}
