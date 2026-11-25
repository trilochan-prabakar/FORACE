# Detection rules and ATT&CK references

The detector compares two lab scans and loads rule metadata from `rules.yaml`.
The analyzers are intentionally conservative parsers for a narrow subset of
Linux-style configuration formats. A technique ID is contextual mapping for a
change type; it is not proof of adversary activity or a claim that FORACE
implements full ATT&CK analytics.

| Rule | Detected change | Detection behavior | Severity | ATT&CK mapping |
|---|---|---|---|---|
| R01 | `PermitRootLogin` newly set to `yes` in `etc/ssh/sshd_config` | SSH directive comparison | High | [T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004/) |
| R02 | `PasswordAuthentication` newly set to `yes` | SSH directive comparison | Medium | [T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004/) |
| R03 | New SSH public-key algorithm/blob in an `authorized_keys` file | Compare normalized key material, not comments/spacing | High | [T1098.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/) |
| R04 | New system crontab entry | Compare normalized active cron entries | Medium | [T1053.003 Cron](https://attack.mitre.org/techniques/T1053/003/) |
| R05 | New cron entry containing one of the supported suspicious text markers | Static markers such as `curl `, `wget `, `/dev/tcp`, and `base64 -d`; no command is run | Critical | [T1053.003 Cron](https://attack.mitre.org/techniques/T1053/003/) |
| R06 | New seven-field record in `etc/passwd` | Compare local account names | High | [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| R07 | Non-root account newly assigned UID 0 | Compare parsed passwd UID fields | Critical | [T1136.001 Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| R08 | Existing `svc*`, `service*`, or `daemon*` account changes from a non-login shell to an interactive shell | Compare supported shell fields | High | [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) |
| R09 | New sudoers line containing `NOPASSWD:` | Conservative line-based sudoers check | Critical | [T1548.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) |
| R10 | A file gains the SUID bit | Compare mode bits; metadata-only so hash-only mode does not detect this scenario | High | [T1548.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/) |
| R11 | `var/log/auth.log` is deleted or becomes smaller | Compare file presence and size | High | [T1685.006 Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1685/006/) |
| R12 | A `.service` file under `etc/systemd/system/` is added or modified | Normalize unit syntax and detect change | Medium | [T1543.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002/) |

The ATT&CK pages were checked on 2026-11-01. In particular, the current
authentication-log mapping in the rule set is T1685.006 (Clear Linux or Mac
System Logs). The mapping is not a claim that these isolated configuration
edits reproduce full adversary behavior.

## Smart versus hash-only behavior

Both modes use the scanner's SHA-256 content digests to determine file content
changes. Hash-only reports additions, deletions, and content modifications; it
does not interpret configuration or alert on metadata-only changes. Smart mode
adds supported semantic checks, mode/ownership comparisons, and ATT&CK-linked
rule explanations. Smart mode ignores selected benign SSH/comment/whitespace
edits, but parser scope is limited and other meaningful edits may yield generic
change findings rather than a named rule.

## Analyzer limits

- SSH analysis handles the supported directives listed in
  `forace/analyzers.py`; it is not a complete OpenSSH parser and does
  not evaluate `Include` files or all `Match` blocks.
- Authorized-key comparison extracts supported key algorithm/blob fields and
  records option changes, but does not validate key cryptography or evaluate
  every OpenSSH option.
- Cron analysis recognizes system crontab-like entries and static suspicious
  substrings. It does not parse shell semantics or scheduled execution context.
- Passwd parsing requires seven colon-separated fields and detects selected
  account/UID/shell changes; it does not inspect shadow credentials or groups.
- Sudoers analysis is line-based, not a full policy parser. Aliases, includes,
  precedence, Defaults, command argument matching, and complex negation require
  human review.
- Systemd analysis detects file changes but does not execute or validate units.
- Rename matching is only inferred for unique old/new paths with identical
  content hashes. Ambiguous duplicate contents remain separate add/delete
  events.

The simulation text is written only to private temporary lab copies. ATT&CK
links may require internet access when opened; no network calls are made by the
detector.
